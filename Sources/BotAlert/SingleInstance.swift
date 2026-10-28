import AppKit

/// Exactly one BotAlert runs, and it is the launchd job when launch-at-login is on: only that copy gets
/// restarted if something kills it. Copies started any other way (Login Items, Finder, `open`) hand over.
enum SingleInstance {
    static func enforce() {
        guard let id = Bundle.main.bundleIdentifier else { return }
        let me = getpid()
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: id).filter { $0.processIdentifier != me }
        let isAgent = ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] == AlertStore.agentLabel

        if isAgent {
            others.forEach { $0.forceTerminate() }
            return
        }
        if FileManager.default.fileExists(atPath: AlertStore.agentPlist) {
            let job = "gui/\(getuid())/\(AlertStore.agentLabel)"
            // kickstart starts the job if it isn't running (e.g. after "Quit") and is a no-op otherwise.
            if launchctl(["kickstart", job]) || (launchctl(["bootstrap", "gui/\(getuid())", AlertStore.agentPlist]) && launchctl(["kickstart", job])) {
                exit(0)
            }
            // launchd refused: better to run unmanaged than not at all.
        }
        if !others.isEmpty { exit(0) }
    }

    @discardableResult
    static func launchctl(_ args: [String]) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }
}
