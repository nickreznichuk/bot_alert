import Darwin
import Foundation

struct AlertEvent {
    let severity: Severity
    let title: String
    let detail: String
    let pid: pid_t?
    let processName: String?
    let processPath: String?
    let dedupeKey: String
    var frozen: [pid_t] = []
    /// What the "Trust" button stores (see Rules.trustKey); filled in by Monitor.emit.
    var trustKey: String?
}

struct ConnRow: Identifiable, Hashable {
    var id: String { "\(pid)-\(ip):\(port)" }
    let pid: pid_t
    let name: String
    let path: String
    let ip: String
    let port: UInt16
    let state: String
    let signLabel: String
    let flagged: Bool
}

struct MonitorStats {
    var watchedByCategory: [Category: Int] = [:]
    var processes = 0
    var scanned = 0
    var scanMs = 0.0
}

final class ProcRec {
    let pid: pid_t
    let ppid: pid_t
    let name: String
    let path: String
    let args: [String]
    let start: Date
    let sign: SignInfo
    let candidate: Bool
    let interpreter: Bool
    let ownerOf: Set<Int>
    let trustKey: String
    var execFlag: Severity?
    var netFlag: String?
    var criticalSent = false
    var remotes: Set<String> = []
    var strongTouch: (label: String, at: Date)?
    var weakTouch: (label: String, at: Date)?
    var rpcHits: Set<String> = []
    var lastConns: [Proc.TCPConn] = []

    init(pid: pid_t, ppid: pid_t, name: String, path: String, args: [String], start: Date, sign: SignInfo) {
        self.pid = pid; self.ppid = ppid; self.name = name; self.path = path; self.args = args
        self.start = start; self.sign = sign
        candidate = !sign.isApple || Rules.isLolbin(name)
        interpreter = Rules.isInterpreter(name)
        let joined = args.joined(separator: " ")
        var owns = Set<Int>()
        for (i, t) in Rules.targets.enumerated() where t.owners.matches(name: name, path: path, args: joined) { owns.insert(i) }
        ownerOf = owns
        trustKey = Rules.trustKey(name: name, path: path, args: args)
    }

    var display: String { "\(name) (pid \(pid))" }
    var highRisk: Bool { interpreter || sign.isAdhocOrUnsigned || execFlag != nil || weakTouch != nil }
}

final class WatchItem {
    let spec: WatchSpec
    let targetIndex: Int
    var ino: UInt64 = 0
    var mtime = timespec()
    var armed: timespec?

    init(spec: WatchSpec, targetIndex: Int) { self.spec = spec; self.targetIndex = targetIndex }
}

private func tsGreater(_ a: timespec, _ b: timespec) -> Bool {
    a.tv_sec != b.tv_sec ? a.tv_sec > b.tv_sec : a.tv_nsec > b.tv_nsec
}

private func tsEqual(_ a: timespec, _ b: timespec) -> Bool { a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec }

final class Monitor {
    let queue = DispatchQueue(label: "botalert.monitor", qos: .utility)

    // Callbacks are invoked on `queue`.
    var onAlert: ((AlertEvent) -> Void)?
    var onConnections: (([ConnRow]) -> Void)?
    var onStats: ((MonitorStats) -> Void)?

    // Settings, mutate only via queue.
    var trusted: Set<String> = []
    var autoFreeze = true
    var paused = false

    private var procs: [pid_t: ProcRec] = [:]
    private var foreign: Set<pid_t> = []
    /// pid -> fd -> index of the sensitive target it points to (-1 = nothing interesting).
    private var fdPaths: [pid_t: [Int32: Int]] = [:]
    private var exited: [(rec: ProcRec, at: Date)] = []
    private var items: [WatchItem] = []
    private var readEvents: [(at: Date, target: Int, label: String)] = []
    private var lastSweep = Date.distantPast
    private var persistence: [String: Set<String>] = [:]
    private var rcMtimes: [String: timespec] = [:]
    private var rpcIPs: [String: String] = [:]
    private var tick = 0
    private var timer: DispatchSourceTimer?
    private let myPid = getpid()
    private let myUid = getuid()
    private var stats = MonitorStats()

    private let persistenceDirs = [
        Rules.home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons",
    ]
    private let rcFiles = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"].map { Rules.home + "/" + $0 }

    func start() {
        queue.async { [self] in
            refreshWatchItems()
            loadPersistenceBaseline()
            scanProcesses()
            resolveRPCHosts()
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + 0.5, repeating: 0.5, leeway: .milliseconds(100))
            t.setEventHandler { [weak self] in self?.onTick() }
            t.resume()
            timer = t
        }
    }

    private func onTick() {
        tick += 1
        if paused { return }
        scanProcesses()
        if tick % 2 == 0 {
            checkAccessTimes()
            scanDescriptors(full: tick % 4 == 0)
        }
        if tick % 6 == 0 { checkPersistence() }
        if tick % 120 == 0 { refreshWatchItems() }
        if tick % 1200 == 0 { resolveRPCHosts() }
    }

    // MARK: - Processes

    private func scanProcesses() {
        let now = Date()
        var seen = Set<pid_t>()
        for pid in Proc.allPids() where pid != myPid {
            seen.insert(pid)
            if foreign.contains(pid) { continue }
            if let rec = procs[pid] {
                // A process caught between fork and exec still shows its parent's binary. Re-check young ones.
                if now.timeIntervalSince(rec.start) < 5, Proc.path(pid) != rec.path {
                    procs[pid] = nil
                } else { continue }
            }
            guard let bi = Proc.bsdInfo(pid) else { continue }
            guard bi.pbi_uid == myUid else { foreign.insert(pid); continue }
            let path = Proc.path(pid)
            var comm = bi.pbi_name
            let commName = withUnsafeBytes(of: &comm) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
            let name = path.isEmpty ? commName : (path as NSString).lastPathComponent
            let start = Date(timeIntervalSince1970: Double(bi.pbi_start_tvsec) + Double(bi.pbi_start_tvusec) / 1e6)
            let rec = ProcRec(pid: pid, ppid: pid_t(bi.pbi_ppid), name: name, path: path, args: Proc.args(pid),
                              start: start, sign: Signing.info(path))
            procs[pid] = rec
            evaluateExec(rec)
        }
        foreign = foreign.intersection(seen)
        for (pid, rec) in procs where !seen.contains(pid) {
            procs[pid] = nil
            exited.append((rec, now))
        }
        exited.removeAll { now.timeIntervalSince($0.at) > 60 }
        stats.processes = procs.count
    }

    private func evaluateExec(_ rec: ProcRec) {
        guard !trusted.contains(rec.trustKey),
              let (sev, title, why) = Rules.execVerdict(name: rec.name, path: rec.path, args: rec.args, sign: rec.sign)
        else { return }
        rec.execFlag = sev
        var ev = AlertEvent(severity: sev, title: title, detail: why + "\n\n" + describe(rec), pid: rec.pid,
                            processName: rec.name, processPath: rec.path, dedupeKey: "exec:\(title):\(rec.path)")
        if sev == .critical { ev.frozen = freeze(rec.pid) }
        emit(ev)
    }

    private func describe(_ rec: ProcRec) -> String {
        var lines = [
            "Process: \(rec.display)",
            "File: \(rec.path)",
            "Signature: \(rec.sign.label)",
            "Command: \(String(rec.args.joined(separator: " ").prefix(600)))",
        ]
        var chain: [String] = []
        var p = rec.ppid
        var guardCount = 0
        while p > 1, guardCount < 6 {
            guardCount += 1
            if let parent = procs[p] { chain.append(parent.display); p = parent.ppid } else { break }
        }
        if !chain.isEmpty { lines.append("Parent processes: " + chain.joined(separator: " ← ")) }
        if !rec.lastConns.isEmpty {
            lines.append("Connections: " + rec.lastConns.map { $0.key }.joined(separator: ", "))
        }
        if !rec.rpcHits.isEmpty { lines.append("Contacted blockchain nodes: " + rec.rpcHits.sorted().joined(separator: ", ")) }
        return lines.joined(separator: "\n")
    }

    // MARK: - Open files & sockets

    private func target(forPath p: String) -> Int? {
        for (i, t) in Rules.targets.enumerated()
        where t.prefixes.contains(where: { p.hasPrefix($0) || (p + "/") == $0 }) { return i }
        return nil
    }

    private func scanDescriptors(full: Bool) {
        let t0 = Date()
        var rows: [ConnRow] = []
        var scanned = 0
        for rec in procs.values where rec.candidate {
            if !full && !rec.highRisk { continue }
            scanned += 1
            var conns: [Proc.TCPConn] = []
            var touched: [Int: String] = [:]
            // Resolving every path is the expensive part. Risky processes get it every time (every 5 s if they
            // hold hundreds of files, like dev-server watchers); signed apps only for descriptors that are new
            // since the last scan, plus a full pass every 30 s. The atime tripwires cover reads in between.
            let oldPaths = fdPaths[rec.pid] ?? [:]
            let deep = tick % 60 == 0 || (rec.highRisk && (oldPaths.count < 300 || tick % 10 == 0))
            var newPaths: [Int32: Int] = [:]
            for f in Proc.fds(rec.pid) {
                if f.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
                    let ti: Int
                    if !deep, let cached = oldPaths[f.proc_fd] {
                        newPaths[f.proc_fd] = cached
                        guard cached >= 0 else { continue }
                        ti = cached
                    } else {
                        let found = Proc.vnodePath(rec.pid, f.proc_fd).flatMap { target(forPath: $0) }
                        newPaths[f.proc_fd] = found ?? -1
                        guard let found else { continue }
                        ti = found
                    }
                    guard !rec.ownerOf.contains(ti), let p = Proc.vnodePath(rec.pid, f.proc_fd) else { continue }
                    if Rules.targets[ti].category == .ssh, !rec.highRisk {
                        // Editors legitimately read ~/.ssh/config & known_hosts; only keys matter for them.
                        let name = (p as NSString).lastPathComponent
                        if ["config", "known_hosts", "known_hosts.old", "authorized_keys"].contains(name) || name.hasSuffix(".pub") { continue }
                    }
                    if Rules.targets[ti].category == .keychain, !rec.highRisk { continue }
                    touched[ti] = p
                } else if f.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET), let c = Proc.tcpRemote(rec.pid, f.proc_fd) {
                    conns.append(c)
                }
            }
            fdPaths[rec.pid] = newPaths
            rec.lastConns = conns
            let isTrusted = trusted.contains(rec.trustKey)
            if !isTrusted {
                for (ti, p) in touched { handleTouch(rec, target: ti, path: p) }
                for c in conns where !rec.remotes.contains(c.key) {
                    rec.remotes.insert(c.key)
                    evaluateConnection(rec, c)
                }
            }
            if full {
                for c in conns {
                    rows.append(ConnRow(pid: rec.pid, name: rec.name, path: rec.path, ip: c.ip, port: c.port,
                                        state: c.stateName, signLabel: rec.sign.label,
                                        flagged: !isTrusted && (rec.execFlag != nil || rec.strongTouch != nil || rec.weakTouch != nil)))
                }
            }
        }
        if full {
            for pid in fdPaths.keys where procs[pid] == nil { fdPaths[pid] = nil }
            stats.scanned = scanned
            stats.scanMs = Date().timeIntervalSince(t0) * 1000
            onConnections?(rows.sorted { ($0.flagged ? 0 : 1, $0.name, $0.ip) < ($1.flagged ? 0 : 1, $1.name, $1.ip) })
            onStats?(stats)
        }
    }

    private func handleTouch(_ rec: ProcRec, target ti: Int, path: String) {
        let t = Rules.targets[ti]
        let label = items.first(where: { $0.spec.path == path })?.spec.label ?? "\(t.title): \(path.replacingOccurrences(of: Rules.home, with: "~"))"
        let first = rec.strongTouch == nil
        rec.strongTouch = (label, Date())
        if !rec.lastConns.isEmpty {
            guard !rec.criticalSent else { return }
            rec.criticalSent = true
            var ev = AlertEvent(severity: .critical, title: "\(rec.name) is reading \(t.category.rawValue) while connected to the internet",
                                detail: "Opened: \(path)\nThis is typical stealer behaviour: read keys/passwords and send them right away.\n\n" + describe(rec),
                                pid: rec.pid, processName: rec.name, processPath: rec.path, dedupeKey: "exfil:\(rec.pid)")
            ev.frozen = freeze(rec.pid)
            emit(ev)
        } else if first {
            emit(AlertEvent(severity: .high, title: "\(rec.name) opened \(label)",
                                detail: "This process has no business reading this data.\nOpened: \(path)\n\n" + describe(rec),
                                pid: rec.pid, processName: rec.name, processPath: rec.path, dedupeKey: "touch:\(rec.pid):\(ti)"))
        }
    }

    private func evaluateConnection(_ rec: ProcRec, _ c: Proc.TCPConn) {
        let now = Date()
        if let host = rpcIPs[c.ip] { rec.rpcHits.insert(host) }
        if let st = rec.strongTouch, now.timeIntervalSince(st.at) < 600 {
            guard !rec.criticalSent else { return }
            rec.criticalSent = true
            var ev = AlertEvent(severity: .critical, title: "Possible data exfiltration: \(rec.name) → \(c.key)",
                                detail: "The process just read \"\(st.label)\" and is now connecting to \(c.key).\n\n" + describe(rec),
                                pid: rec.pid, processName: rec.name, processPath: rec.path, dedupeKey: "exfil:\(rec.pid)")
            ev.frozen = freeze(rec.pid)
            emit(ev)
            return
        }
        if let wt = rec.weakTouch, now.timeIntervalSince(wt.at) < 600 {
            emit(AlertEvent(severity: .high, title: "Suspected process \(rec.name) connected to \(c.key)",
                                detail: "While it was running, something read \"\(wt.label)\".\n\n" + describe(rec),
                                pid: rec.pid, processName: rec.name, processPath: rec.path, dedupeKey: "weaknet:\(rec.pid):\(c.key)"))
            return
        }
        guard rec.interpreter || rec.sign.isAdhocOrUnsigned else { return }
        if Rules.badPorts.contains(c.port) {
            rec.netFlag = "port \(c.port)"
            emit(AlertEvent(severity: .high, title: "\(rec.name) is connecting to port \(c.port)",
                                detail: "Port \(c.port) is used by the BeaverTail/InvisibleFerret backdoors (fake job-interview tasks and repositories).\nAddress: \(c.key)\n\n" + describe(rec),
                                pid: rec.pid, processName: rec.name, processPath: rec.path, dedupeKey: "badport:\(rec.pid):\(c.port)"))
        } else if let flag = rec.execFlag, flag >= .medium {
            emit(AlertEvent(severity: .high, title: "Suspicious process \(rec.name) connected to \(c.key)",
                                detail: describe(rec), pid: rec.pid, processName: rec.name, processPath: rec.path,
                                dedupeKey: "flagnet:\(rec.pid)"))
        } else if rec.interpreter, let host = rpcIPs[c.ip] {
            rec.netFlag = "blockchain \(host)"
            emit(AlertEvent(severity: .medium, title: "\(rec.name) is talking to blockchain node \(host)",
                                detail: "Malicious repositories load hidden code this way (it is stored in transactions). If you don't work with web3, this is very suspicious.\nAddress: \(c.key)\n\n" + describe(rec),
                                pid: rec.pid, processName: rec.name, processPath: rec.path, dedupeKey: "rpc:\(rec.pid)"))
        } else if rec.interpreter, !Rules.commonPorts.contains(c.port) {
            let devPorts: Set<UInt16> = [3306, 5432, 6543, 6379, 27017, 9200, 5672, 9092, 11211, 1433, 8080, 3000]
            let isDev = devPorts.contains(c.port)
            if !isDev { rec.netFlag = rec.netFlag ?? "port \(c.port)" }
            emit(AlertEvent(severity: isDev ? .info : .medium,
                                title: "\(rec.name) is connecting to an unusual port \(c.port)",
                                detail: "Address: \(c.key)\n\n" + describe(rec), pid: rec.pid, processName: rec.name,
                                processPath: rec.path, dedupeKey: "port:\(rec.pid):\(c.port)"))
        }
    }

    // MARK: - Access-time tripwires

    private func refreshWatchItems() {
        var old: [String: WatchItem] = [:]
        for i in items { old[i.spec.path] = i }
        var new: [WatchItem] = []
        var counts: [Category: Int] = [:]
        for (ti, t) in Rules.targets.enumerated() where t.atimeWatch {
            for spec in t.items() {
                new.append(old[spec.path] ?? WatchItem(spec: spec, targetIndex: ti))
                counts[t.category, default: 0] += 1
            }
        }
        items = new
        stats.watchedByCategory = counts
    }

    private func ownerActive(_ ti: Int, cache: inout [Int: Bool]) -> Bool {
        if let c = cache[ti] { return c }
        let now = Date()
        let active: Bool
        if Rules.targets[ti].ownerGraceOnly {
            // Browser helpers come and go all the time; only the main process starting or quitting counts.
            active = procs.values.contains { $0.ownerOf.contains(ti) && !$0.name.contains("Helper") && now.timeIntervalSince($0.start) < 60 }
                || exited.contains { $0.rec.ownerOf.contains(ti) && !$0.rec.name.contains("Helper") && now.timeIntervalSince($0.at) < 20 }
        } else {
            active = procs.values.contains { $0.ownerOf.contains(ti) }
                || exited.contains { $0.rec.ownerOf.contains(ti) && now.timeIntervalSince($0.at) < 20 }
        }
        cache[ti] = active
        return active
    }

    private func checkAccessTimes() {
        var cache: [Int: Bool] = [:]
        for item in items {
            var st = stat()
            guard lstat(item.spec.path, &st) == 0 else { item.armed = nil; continue }
            if ownerActive(item.targetIndex, cache: &cache) { item.armed = nil; continue }
            guard let armed = item.armed, st.st_ino == item.ino, tsEqual(st.st_mtimespec, item.mtime) else {
                arm(item)
                continue
            }
            if tsGreater(st.st_atimespec, armed) {
                readDetected(item)
                arm(item)
            }
        }
    }

    /// Pushes atime behind mtime so APFS records the next read (it only updates atime when atime <= mtime/ctime).
    private func arm(_ item: WatchItem) {
        var st = stat()
        guard lstat(item.spec.path, &st) == 0 else { return }
        if !(st.st_atimespec.tv_sec < st.st_mtimespec.tv_sec) {
            var times = [timespec(tv_sec: st.st_mtimespec.tv_sec - 1, tv_nsec: 0), timespec(tv_sec: 0, tv_nsec: -2 /* UTIME_OMIT */)]
            guard utimensat(AT_FDCWD, item.spec.path, &times, AT_SYMLINK_NOFOLLOW) == 0, lstat(item.spec.path, &st) == 0 else { return }
        }
        item.ino = st.st_ino
        item.mtime = st.st_mtimespec
        item.armed = st.st_atimespec
    }

    private func readDetected(_ item: WatchItem) {
        let now = Date()
        let ti = item.targetIndex
        // A process may still hold it open: try exact attribution first.
        scanDescriptors(full: true)
        if procs.values.contains(where: { ($0.strongTouch.map { now.timeIntervalSince($0.at) < 3 } ?? false) && $0.strongTouch?.label == item.spec.label }) {
            recordRead(at: now, target: ti, label: item.spec.label)
            return
        }
        let suspects = currentSuspects()
        for s in suspects where s.score >= 3 { s.rec.weakTouch = (item.spec.label, now) }
        let strong = suspects.first { $0.score >= 3 }
        if item.spec.listingOnly && strong == nil {
            // Some long-running app lists the folder on a timer; the secrets inside have their own tripwires.
            emit(AlertEvent(severity: .info, title: "Folder listed: \(item.spec.label)",
                                detail: "Only file names were read, not their contents. No suspicious processes, so this is most likely a regular app.",
                                pid: nil, processName: nil, processPath: nil, dedupeKey: "list:\(item.spec.path)"))
            return
        }
        var detail = "File: \(item.spec.path.replacingOccurrences(of: Rules.home, with: "~"))\n"
        detail += "None of the programs allowed to read this data was running at that moment.\n\n"
        if suspects.isEmpty {
            detail += "No suspicious processes found. If it was you (ls, Finder, an editor), all is fine. If not, the process may have already exited."
        } else {
            detail += "Likely culprits:\n" + describeSuspects(suspects)
        }
        emit(AlertEvent(severity: strong == nil ? .medium : .high, title: "Something read: \(item.spec.label)",
                            detail: detail, pid: strong?.rec.pid, processName: strong?.rec.name,
                            processPath: strong?.rec.path, dedupeKey: "read:\(item.spec.path)"))
        recordRead(at: now, target: ti, label: item.spec.label)
    }

    private func describeSuspects(_ list: [(rec: ProcRec, score: Int, reasons: [String])]) -> String {
        list.map { s in
            var line = "• \(s.rec.display) [\(s.reasons.joined(separator: ", "))]\n   \(String(s.rec.args.joined(separator: " ").prefix(200)))"
            if !s.rec.lastConns.isEmpty { line += "\n   connections: " + s.rec.lastConns.map(\.key).joined(separator: ", ") }
            return line
        }.joined(separator: "\n")
    }

    private func recordRead(at now: Date, target ti: Int, label: String) {
        readEvents.append((now, ti, label))
        readEvents.removeAll { now.timeIntervalSince($0.at) > 60 }
        let labels = Set(readEvents.map(\.label))
        let categories = Set(readEvents.map { Rules.targets[$0.target].category })
        guard labels.count >= 3 || categories.count >= 2, now.timeIntervalSince(lastSweep) > 300 else { return }
        lastSweep = now
        let suspects = currentSuspects()
        // Freeze only processes that concrete evidence points at, never "every node that happens to run".
        var frozen = Set<pid_t>()
        for s in suspects where s.score >= 4 { frozen.formUnion(freeze(s.rec.pid)) }
        let top = suspects.first { $0.score >= 3 }
        var detail = "\(plural(labels.count, "sensitive location was", "sensitive locations were")) read within a minute (\(categories.map(\.rawValue).joined(separator: ", "))):\n"
        detail += labels.sorted().map { "• " + $0 }.joined(separator: "\n")
        detail += suspects.isEmpty ? "\n\nNo culprit found among running processes." :
            "\n\nSuspects (reasons in brackets):\n" + describeSuspects(suspects)
        detail += "\n\nAdvice: turn off Wi-Fi, kill the suspicious processes, change passwords/keys from another device."
        var ev = AlertEvent(severity: .critical, title: "Looks like data theft (mass read)", detail: detail,
                            pid: top?.rec.pid, processName: top?.rec.name, processPath: top?.rec.path,
                            dedupeKey: "sweep")
        ev.frozen = frozen.sorted()
        emit(ev)
    }

    /// Ranks live processes. Score >= 3 marks a suspect, >= 4 is enough to freeze it; both need concrete
    /// evidence (a flagged command line or a flagged connection).
    private func currentSuspects() -> [(rec: ProcRec, score: Int, reasons: [String])] {
        let now = Date()
        var out: [(rec: ProcRec, score: Int, reasons: [String])] = []
        for r in procs.values where r.candidate && !trusted.contains(r.trustKey) && r.ownerOf.isEmpty {
            guard r.interpreter || r.sign.isAdhocOrUnsigned || r.execFlag != nil else { continue }
            var score = 0
            var reasons: [String] = []
            if let f = r.execFlag, f > .info { score += f.rawValue + 1; reasons.append("suspicious command") }
            if let n = r.netFlag { score += 3; reasons.append(n) }
            let age = now.timeIntervalSince(r.start)
            if age < 120 { score += 2; reasons.append("started \(Int(age)) s ago") }
            else if age < 900 { score += 1; reasons.append("started \(Int(age / 60)) min ago") }
            if !r.interpreter && r.sign.isAdhocOrUnsigned { score += 1; reasons.append("unsigned") }
            if !r.lastConns.isEmpty { score += 1; reasons.append("has connections") }
            // Age, missing signature and connections only rank candidates. On their own they just mean
            // "started around the same time" (a fresh `pnpm dev` coinciding with a benign periodic read),
            // so without concrete evidence a process can never reach suspect level.
            let evidence = (r.execFlag.map { $0 > .info } ?? false) || r.netFlag != nil
            if !evidence { score = min(score, 2) }
            if score >= 2 { out.append((r, score, reasons)) }
        }
        // When someone has real evidence against them, don't clutter the list with weak matches.
        if out.contains(where: { $0.score >= 3 }) { out.removeAll { $0.score < 3 } }
        return Array(out.sorted { ($0.score, $0.rec.start) > ($1.score, $1.rec.start) }.prefix(5))
    }

    // MARK: - Persistence

    private func listPlists(_ dir: String) -> Set<String> {
        Set((try? FileManager.default.contentsOfDirectory(atPath: dir))?.filter { $0.hasSuffix(".plist") } ?? [])
    }

    private func loadPersistenceBaseline() {
        let stored = UserDefaults.standard.dictionary(forKey: "persistenceBaseline") as? [String: [String]]
        for d in persistenceDirs {
            let now = listPlists(d)
            if let prev = stored?[d] {
                for f in now.subtracting(prev) { reportPersistence(dir: d, file: f, sinceLastRun: true) }
            }
            persistence[d] = now
        }
        savePersistence()
        for f in rcFiles {
            var st = stat()
            if lstat(f, &st) == 0 { rcMtimes[f] = st.st_mtimespec }
        }
    }

    private func savePersistence() {
        UserDefaults.standard.set(persistence.mapValues { Array($0) }, forKey: "persistenceBaseline")
    }

    private func checkPersistence() {
        var changed = false
        for d in persistenceDirs {
            let now = listPlists(d)
            let prev = persistence[d] ?? []
            if now != prev {
                for f in now.subtracting(prev) { reportPersistence(dir: d, file: f, sinceLastRun: false) }
                persistence[d] = now
                changed = true
            }
        }
        if changed { savePersistence() }
        for f in rcFiles {
            var st = stat()
            guard lstat(f, &st) == 0 else { continue }
            if let old = rcMtimes[f], !tsEqual(old, st.st_mtimespec) {
                let tail = (try? String(contentsOfFile: f, encoding: .utf8))?.split(separator: "\n").suffix(4).joined(separator: "\n") ?? ""
                emit(AlertEvent(severity: .medium, title: "Changed \(f.replacingOccurrences(of: Rules.home, with: "~"))",
                                    detail: "This file runs every time you open a terminal, and malware adds itself to it. If you edited it yourself, ignore this.\n\nLast lines:\n\(tail)",
                                    pid: nil, processName: nil, processPath: f, dedupeKey: "rc:\(f):\(st.st_mtimespec.tv_sec)"))
            }
            rcMtimes[f] = st.st_mtimespec
        }
    }

    private func reportPersistence(dir: String, file: String, sinceLastRun: Bool) {
        if file.lowercased().contains("botalert") { return }
        let path = dir + "/" + file
        var program = ""
        if let plist = NSDictionary(contentsOfFile: path) {
            if let args = plist["ProgramArguments"] as? [String] { program = args.joined(separator: " ") }
            else if let p = plist["Program"] as? String { program = p }
        }
        emit(AlertEvent(severity: .high,
                            title: sinceLastRun ? "A new launch item appeared while BotAlert was off" : "New launch item: \(file)",
                            detail: "File: \(path)\nRuns: \(program.isEmpty ? "?" : program)\n\nThis is how malware persists on a Mac. If you didn't install anything, delete this file.",
                            pid: nil, processName: nil, processPath: path, dedupeKey: "persist:\(path)"))
    }

    // MARK: - Helpers

    private func emit(_ ev: AlertEvent) {
        var ev = ev
        if let pid = ev.pid, let rec = procs[pid] { ev.trustKey = rec.trustKey }
        onAlert?(ev)
    }

    private func resolveRPCHosts() {
        DispatchQueue.global(qos: .background).async { [weak self] in
            var map: [String: String] = [:]
            for host in Rules.rpcHosts {
                var res: UnsafeMutablePointer<addrinfo>?
                var hints = addrinfo()
                hints.ai_socktype = SOCK_STREAM
                guard getaddrinfo(host, "443", &hints, &res) == 0, let first = res else { continue }
                var p: UnsafeMutablePointer<addrinfo>? = first
                while let ai = p {
                    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                        map[String(cString: buf)] = host
                    }
                    p = ai.pointee.ai_next
                }
                freeaddrinfo(first)
            }
            self?.queue.async { self?.rpcIPs.merge(map) { _, n in n } }
        }
    }

    /// SIGSTOP the process and its descendants (reversible with SIGCONT).
    private func freeze(_ pid: pid_t) -> [pid_t] {
        guard autoFreeze else { return [] }
        let tree = descendants(of: pid)
        for p in tree { kill(p, SIGSTOP) }
        return tree
    }

    private func descendants(of pid: pid_t) -> [pid_t] {
        var out = [pid]
        var i = 0
        while i < out.count {
            let cur = out[i]
            out += procs.values.filter { $0.ppid == cur && !out.contains($0.pid) }.map(\.pid)
            i += 1
        }
        return out
    }

    func processTree(_ pid: pid_t) -> [pid_t] { queue.sync { descendants(of: pid) } }
}
