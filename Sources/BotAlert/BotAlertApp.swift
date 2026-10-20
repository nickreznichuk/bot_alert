import AppKit
import SwiftUI

@main
struct BotAlertApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    init() {
        // Must run before the store exists: a second monitor would fight over the same tripwires.
        SingleInstance.enforce()
    }

    var body: some Scene {
        MenuBarExtra {
            MainView(store: delegate.store)
        } label: {
            MenuLabel(store: delegate.store)
        }
        .menuBarExtraStyle(.window)
    }
}

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

final class AppDelegate: NSObject, NSApplicationDelegate {
    lazy var store = AlertStore()
    private var window: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        store.openMainWindow = { [weak self] in self?.showWindow() }
    }

    /// Standalone window, used when the user clicks a notification.
    func showWindow() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 600),
                             styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
            w.title = "BotAlert"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: MainView(store: store))
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}
