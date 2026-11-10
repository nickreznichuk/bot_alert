import AppKit
import Foundation
import UserNotifications

struct Alert: Identifiable {
    let id = UUID()
    let date: Date
    let event: AlertEvent
    var frozen: [pid_t]
    var seen = false
    var killed = false
}

/// Fast-changing data: monitor stats, live connections, reverse-DNS names. Kept out of AlertStore so the
/// monitor's updates (every 2 s) redraw only the few views that show them, and are published only while a
/// BotAlert window is open. Republishing them into the whole popup every scan, even while it was closed, made
/// SwiftUI rebuild the full view tree non-stop; with the old segmented Picker that leaked observation records
/// (~600 MB and 60% CPU after five days) and made the popup crawl.
final class LiveState: ObservableObject {
    @Published private(set) var stats = MonitorStats()
    @Published private(set) var connections: [ConnRow] = []
    @Published private(set) var hosts: [String: String] = [:]

    private var latestStats = MonitorStats()
    private var latestConnections: [ConnRow] = []
    private var openViews = 0
    private var dnsPending: Set<String> = []
    private let dnsQueue = DispatchQueue(label: "botalert.dns", qos: .background, attributes: .concurrent)

    var isOpen: Bool { openViews > 0 }

    func viewAppeared() { openViews += 1; flush() }
    func viewDisappeared() { openViews = max(0, openViews - 1) }

    func update(stats s: MonitorStats) { latestStats = s; if isOpen { flush() } }
    func update(connections rows: [ConnRow]) { latestConnections = rows; if isOpen { flush() } }

    /// For the snapshot tool.
    func set(stats s: MonitorStats, connections rows: [ConnRow]) { latestStats = s; latestConnections = rows; flush() }

    private func flush() {
        if stats != latestStats { stats = latestStats }
        if connections != latestConnections { connections = latestConnections; lookupHosts(latestConnections) }
    }

    private func lookupHosts(_ rows: [ConnRow]) {
        if hosts.count > 2000 { hosts.removeAll() }
        for ip in Set(rows.map(\.ip)) where hosts[ip] == nil && !dnsPending.contains(ip) {
            dnsPending.insert(ip)
            dnsQueue.async { [weak self] in
                var name = ""
                var hints = addrinfo()
                hints.ai_flags = AI_NUMERICHOST
                var res: UnsafeMutablePointer<addrinfo>?
                if getaddrinfo(ip, nil, &hints, &res) == 0, let ai = res {
                    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NAMEREQD) == 0 {
                        name = String(cString: buf)
                    }
                    freeaddrinfo(ai)
                }
                DispatchQueue.main.async { self?.hosts[ip] = name; self?.dnsPending.remove(ip) }
            }
        }
    }
}

final class AlertStore: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published var alerts: [Alert] = [] { didSet { recount() } }
    /// Derived from `alerts`, cached: the menu-bar label and every row read them on each redraw.
    private(set) var visibleAlerts: [Alert] = []
    private(set) var unseenCount = 0
    private(set) var worstUnseen: Severity?
    let live = LiveState()
    @Published var paused = false { didSet { let v = paused; monitor.queue.async { self.monitor.paused = v } } }
    @Published var autoFreeze: Bool { didSet { defaults.set(autoFreeze, forKey: "autoFreeze"); sync() } }
    @Published var notifyMedium: Bool { didSet { defaults.set(notifyMedium, forKey: "notifyMedium") } }
    @Published var showInfo: Bool { didSet { defaults.set(showInfo, forKey: "showInfo"); recount() } }
    @Published var trusted: Set<String> { didSet { defaults.set(Array(trusted), forKey: "trusted"); sync() } }
    @Published var launchAtLogin: Bool

    let monitor = Monitor()
    private let defaults = UserDefaults.standard
    private var lastByKey: [String: Date] = [:]
    private let logURL: URL
    var openMainWindow: (() -> Void)?

    static let agentLabel = "local.botalert.agent"
    static var agentPlist: String { Rules.home + "/Library/LaunchAgents/\(agentLabel).plist" }

    /// `startMonitor: false` is for the snapshot tool: two monitors would fight over the same tripwires.
    init(startMonitor: Bool = true) {
        defaults.register(defaults: ["autoFreeze": true, "notifyMedium": true, "showInfo": false])
        autoFreeze = defaults.bool(forKey: "autoFreeze")
        notifyMedium = defaults.bool(forKey: "notifyMedium")
        showInfo = defaults.bool(forKey: "showInfo")
        trusted = Set(defaults.stringArray(forKey: "trusted") ?? [])
        launchAtLogin = FileManager.default.fileExists(atPath: AlertStore.agentPlist)
        let logDir = URL(fileURLWithPath: Rules.home + "/Library/Logs/BotAlert")
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        logURL = logDir.appendingPathComponent("alerts.log")
        super.init()

        monitor.onAlert = { [weak self] ev in DispatchQueue.main.async { self?.receive(ev) } }
        monitor.onConnections = { [weak self] rows in DispatchQueue.main.async { self?.live.update(connections: rows) } }
        monitor.onStats = { [weak self] s in DispatchQueue.main.async { self?.live.update(stats: s) } }
        sync()

        guard startMonitor else { return }
        if Bundle.main.bundleIdentifier != nil {
            let center = UNUserNotificationCenter.current()
            center.delegate = self
            center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
        }
        monitor.start()
    }

    private func sync() {
        let t = trusted, f = autoFreeze
        monitor.queue.async { self.monitor.trusted = t; self.monitor.autoFreeze = f }
    }

    private func recount() {
        visibleAlerts = showInfo ? alerts : alerts.filter { $0.event.severity > .info }
        let unseen = alerts.filter { !$0.seen && $0.event.severity > .info }
        unseenCount = unseen.count
        worstUnseen = unseen.map(\.event.severity).max()
    }

    private func receive(_ ev: AlertEvent) {
        let now = Date()
        if let last = lastByKey[ev.dedupeKey], now.timeIntervalSince(last) < 600 { return }
        lastByKey[ev.dedupeKey] = now
        if let k = ev.trustKey, trusted.contains(k), ev.frozen.isEmpty { return }
        var list = alerts
        list.insert(Alert(date: now, event: ev, frozen: ev.frozen), at: 0)
        if list.count > 400 { list.removeLast(list.count - 400) }
        alerts = list
        log(ev)
        if ev.severity >= .high || (ev.severity == .medium && notifyMedium) { notify(ev) }
        if ev.severity == .critical { NSSound(named: "Sosumi")?.play() }
    }

    private func log(_ ev: AlertEvent) {
        let df = ISO8601DateFormatter()
        let line = "[\(df.string(from: Date()))] [\(ev.severity.label)] \(ev.title)\n\(ev.detail)\n"
            + (ev.frozen.isEmpty ? "" : "Frozen pids: \(ev.frozen)\n") + "----\n"
        if let h = try? FileHandle(forWritingTo: logURL) {
            h.seekToEndOfFile(); h.write(line.data(using: .utf8)!); try? h.close()
        } else {
            try? line.write(to: logURL, atomically: true, encoding: .utf8)
        }
    }

    private func notify(_ ev: AlertEvent) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let c = UNMutableNotificationContent()
        c.title = (ev.severity == .critical ? "🚨 " : "⚠️ ") + ev.title
        var body = ev.frozen.isEmpty ? "" : "Process frozen. "
        body += ev.detail.split(separator: "\n").prefix(3).joined(separator: " ")
        c.body = String(body.prefix(240))
        if ev.severity >= .high { c.sound = .default }
        if #available(macOS 12.0, *) { c.interruptionLevel = ev.severity == .critical ? .timeSensitive : .active }
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async { self.openMainWindow?() }
        completionHandler()
    }

    // MARK: - Actions

    func markAllSeen() { alerts = alerts.map { var a = $0; a.seen = true; return a } }
    func clear() { alerts.removeAll() }

    static func isAlive(_ pid: pid_t) -> Bool { kill(pid, 0) == 0 }

    static func isStopped(_ pid: pid_t) -> Bool {
        guard let bi = Proc.bsdInfo(pid) else { return false }
        return bi.pbi_status == 4 // SSTOP
    }

    func freeze(_ alert: Alert) {
        guard let pid = alert.event.pid else { return }
        let tree = monitor.processTree(pid)
        for p in tree { kill(p, SIGSTOP) }
        update(alert) { $0.frozen = tree }
    }

    func resume(_ alert: Alert) {
        let pids = alert.frozen.isEmpty ? (alert.event.pid.map { [$0] } ?? []) : alert.frozen
        for p in pids { kill(p, SIGCONT) }
        update(alert) { $0.frozen = [] }
    }

    func killProcess(_ alert: Alert) {
        guard let pid = alert.event.pid else { return }
        let tree = Array(Set(monitor.processTree(pid) + alert.frozen))
        for p in tree { kill(p, SIGKILL) }
        update(alert) { $0.killed = true; $0.frozen = [] }
    }

    func trust(_ alert: Alert) {
        guard let key = alert.event.trustKey else { return }
        if !alert.frozen.isEmpty { resume(alert) }
        trusted.insert(key)
        update(alert) { $0.seen = true }
    }

    func reveal(_ alert: Alert) {
        guard let path = alert.event.processPath else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    private func update(_ alert: Alert, _ f: (inout Alert) -> Void) {
        guard let i = alerts.firstIndex(where: { $0.id == alert.id }) else { return }
        var list = alerts
        f(&list[i])
        alerts = list
    }

    func openLog() { NSWorkspace.shared.open(logURL) }

    func setLaunchAtLogin(_ on: Bool) {
        let path = AlertStore.agentPlist
        if on {
            let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
            let plist: NSDictionary = [
                "Label": AlertStore.agentLabel,
                "ProgramArguments": [exe],
                "RunAtLoad": true,
                // Restart if something kills us, but not after a normal "Quit".
                "KeepAlive": ["SuccessfulExit": false],
                "ProcessType": "Interactive",
            ]
            try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            plist.write(toFile: path, atomically: true)
            // Takes effect now: the launchd copy starts and replaces this one (see SingleInstance).
            SingleInstance.launchctl(["bootstrap", "gui/\(getuid())", path])
        } else {
            try? FileManager.default.removeItem(atPath: path)
        }
        launchAtLogin = FileManager.default.fileExists(atPath: path)
    }
}
