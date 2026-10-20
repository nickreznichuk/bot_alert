import Darwin
import Foundation
import Security

/// Thin wrappers over libproc / sysctl. Works without root for processes of the current user.
enum Proc {
    static func allPids() -> [pid_t] {
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return [] }
        var buf = [pid_t](repeating: 0, count: Int(n) + 128)
        let got = buf.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        return buf.prefix(Int(got)).filter { $0 > 0 }
    }

    static func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let r = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        return r == size ? info : nil
    }

    static func path(_ pid: pid_t) -> String {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let r = proc_pidpath(pid, &buf, UInt32(buf.count))
        return r > 0 ? String(cString: buf) : ""
    }

    private static var argBuf: [UInt8] = {
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        sysctl(&mib, 2, &argmax, &size, nil, 0)
        return [UInt8](repeating: 0, count: Int(max(argmax, 262_144)))
    }()

    /// argv of a process (KERN_PROCARGS2). Not thread-safe: call from the monitor queue only.
    static func args(_ pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = argBuf.count
        let ok = argBuf.withUnsafeMutableBytes { sysctl(&mib, 3, $0.baseAddress, &size, nil, 0) } == 0
        guard ok, size > 4 else { return [] }
        let argc = argBuf.withUnsafeBytes { $0.load(as: Int32.self) }
        var i = 4
        while i < size && argBuf[i] != 0 { i += 1 }   // exec path
        while i < size && argBuf[i] == 0 { i += 1 }   // padding
        var out: [String] = []
        while out.count < Int(argc) && i < size {
            let start = i
            while i < size && argBuf[i] != 0 { i += 1 }
            out.append(String(decoding: argBuf[start..<i], as: UTF8.self))
            i += 1
        }
        return out
    }

    static func fds(_ pid: pid_t) -> [proc_fdinfo] {
        let sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard sz > 0 else { return [] }
        let stride = MemoryLayout<proc_fdinfo>.stride
        var arr = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(sz) / stride + 16)
        let r = arr.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard r > 0 else { return [] }
        return Array(arr.prefix(Int(r) / stride))
    }

    static func vnodePath(_ pid: pid_t, _ fd: Int32) -> String? {
        var vi = vnode_fdinfowithpath()
        let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &vi, size) == size else { return nil }
        return withUnsafeBytes(of: &vi.pvip.vip_path) { raw -> String in
            String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
        }
    }

    struct TCPConn: Hashable {
        let ip: String
        let port: UInt16
        let state: Int32
        var key: String { "\(ip):\(port)" }
        var stateName: String {
            switch state {
            case 2: return "з'єднується"
            case 4: return "активне"
            default: return "закривається"
            }
        }
    }

    /// Remote endpoint of a TCP socket, only for outgoing/established connections to non-local addresses.
    static func tcpRemote(_ pid: pid_t, _ fd: Int32) -> TCPConn? {
        var si = socket_fdinfo()
        let size = Int32(MemoryLayout<socket_fdinfo>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, size) == size else { return nil }
        guard si.psi.soi_kind == SOCKINFO_TCP else { return nil }
        let tcp = si.psi.soi_proto.pri_tcp
        let state = tcp.tcpsi_state
        // 0 closed, 1 listen, 3 syn_received (incoming) are not interesting.
        guard state == 2 || state >= 4 else { return nil }
        let ini = tcp.tcpsi_ini
        let port = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport))
        guard port != 0 else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var ip = ""
        if ini.insi_vflag & 0x1 != 0 {
            var a = ini.insi_faddr.ina_46.i46a_addr4
            inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count))
            ip = String(cString: buf)
        } else {
            var a = ini.insi_faddr.ina_6
            inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
            ip = String(cString: buf)
            if ip.hasPrefix("::ffff:") { ip = String(ip.dropFirst(7)) }
        }
        guard isExternal(ip) else { return nil }
        return TCPConn(ip: ip, port: port, state: state)
    }

    static func isExternal(_ ip: String) -> Bool {
        if ip.contains(":") {
            let l = ip.lowercased()
            return !(l == "::" || l == "::1" || l.hasPrefix("fe80") || l.hasPrefix("fc") || l.hasPrefix("fd"))
        }
        let p = ip.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return false }
        switch (p[0], p[1]) {
        case (0, _), (127, _), (10, _), (192, 168), (169, 254): return false
        case (172, 16...31): return false
        case (100, 64...127): return false   // CGNAT / Tailscale
        default: return p[0] < 224
        }
    }
}

struct SignInfo {
    var teamID: String?
    var isApple: Bool
    var isAdhocOrUnsigned: Bool

    var label: String {
        if isApple { return "Apple" }
        if let teamID { return "підписано (\(teamID))" }
        return "БЕЗ ПІДПИСУ"
    }
}

enum Signing {
    private static var cache: [String: SignInfo] = [:]

    static func info(_ path: String) -> SignInfo {
        if let c = cache[path] { return c }
        var result = SignInfo(teamID: nil, isApple: false, isAdhocOrUnsigned: true)
        var code: SecStaticCode?
        if !path.isEmpty,
           SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
           let code {
            var dict: CFDictionary?
            SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &dict)
            if let d = dict as? [String: Any] {
                let flags = (d[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
                let team = d[kSecCodeInfoTeamIdentifier as String] as? String
                let platform = d[kSecCodeInfoPlatformIdentifier as String] != nil
                result.teamID = team
                result.isApple = platform
                result.isAdhocOrUnsigned = (flags & 0x2) != 0 || (team == nil && !platform)
            }
        }
        let systemPrefixes = ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "/Library/Apple/"]
        if systemPrefixes.contains(where: { path.hasPrefix($0) }) { result.isApple = true; result.isAdhocOrUnsigned = false }
        if cache.count > 4000 { cache.removeAll() }
        cache[path] = result
        return result
    }
}
