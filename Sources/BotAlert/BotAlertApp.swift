import AppKit
import SwiftUI

@main
struct BotAlertApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        MenuBarExtra {
            MainView(store: delegate.store)
        } label: {
            MenuLabel(store: delegate.store)
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    lazy var store = AlertStore()
    private var window: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let me = NSRunningApplication.current
        if let id = Bundle.main.bundleIdentifier,
           NSRunningApplication.runningApplications(withBundleIdentifier: id).contains(where: { $0 != me }) {
            exit(0)
        }
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
