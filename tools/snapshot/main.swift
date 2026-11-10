// Renders the UI offscreen to PNGs with demo alerts (no Screen Recording permission needed).
// Built by `./build.sh --snapshot <out-dir>` together with every source except BotAlertApp.swift.
import AppKit
import SwiftUI
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let store = AlertStore(startMonitor: false)
func ev(_ s: Severity, _ t: String, _ d: String, pid: pid_t? = nil, frozen: [pid_t] = []) -> Alert {
  Alert(date: Date(), event: AlertEvent(severity: s, title: t, detail: d, pid: pid, processName: "node", processPath: "/opt/homebrew/bin/node", dedupeKey: t), frozen: frozen)
}
let out = CommandLine.arguments[1]
DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
  store.alerts = [
    ev(.critical, "Looks like data theft (mass read)", "2 sensitive locations were read within a minute (SSH keys, Browsers):\n• Google Chrome [Default]: list of extensions\n• the ~/.ssh folder (list of keys)\n\nSuspects (reasons in brackets):\n• node (pid 49136) [port 1224, started 4 s ago, has connections]", pid: getpid(), frozen: [49136]),
    ev(.high, "node is connecting to port 1224", "Port 1224 is used by the BeaverTail/InvisibleFerret backdoors.\nAddress: 203.0.113.1:1224", pid: getpid()),
    ev(.medium, "Changed ~/.zshrc", "This file runs every time you open a terminal."),
  ]
  store.live.set(stats: MonitorStats(watchedByCategory: [.ssh: 4, .browser: 31, .wallet: 2, .messenger: 1, .devcreds: 3], processes: 512, scanned: 41, scanMs: 3.4),
                 connections: [ConnRow(pid: 49136, name: "node", path: "/opt/homebrew/bin/node", ip: "203.0.113.1", port: 1224, state: "established", signLabel: "signed (HX7739G8FX)", flagged: true),
                               ConnRow(pid: 812, name: "Telegram", path: "/Applications/Telegram.app", ip: "149.154.167.51", port: 443, state: "established", signLabel: "signed (6N38VWS5BX)", flagged: false)])
  func render(_ v: some View, _ name: String, _ size: NSSize) {
    let host = NSHostingView(rootView: v.frame(width: size.width, height: size.height))
    let w = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.borderless], backing: .buffered, defer: false)
    w.contentView = host; w.appearance = NSAppearance(named: .darkAqua); w.orderFrontRegardless(); host.layoutSubtreeIfNeeded()
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
      let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds)!; host.cacheDisplay(in: host.bounds, to: rep)
      try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out + "/" + name + ".png"))
    }
  }
  render(MainView(store: store).background(Color(nsColor: .windowBackgroundColor)), "alerts", NSSize(width: 480, height: 600))
  render(ConnectionsList(live: store.live).background(Color(nsColor: .windowBackgroundColor)), "net", NSSize(width: 480, height: 400))
  render(SettingsPane(store: store).background(Color(nsColor: .windowBackgroundColor)), "settings", NSSize(width: 480, height: 640))
  DispatchQueue.main.asyncAfter(deadline: .now() + 2) { exit(0) }
}
app.run()
