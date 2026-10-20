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
    ev(.critical, "Схоже на крадіжку даних (масове читання)", "За хвилину прочитано 2 чутливих місць (SSH-ключі, Браузери):\n• Google Chrome [Default]: дані розширень (гаманці)\n• папку ~/.ssh (перегляд списку ключів)\n\nПідозрювані (у дужках — чому):\n• node (pid 49136) [підозріла команда, порт 1224, запущено 4 с тому, є з'єднання]", pid: getpid(), frozen: [49136]),
    ev(.high, "node підключається на порт 1224", "Порт 1224 використовують бекдори BeaverTail/InvisibleFerret.\nАдреса: 203.0.113.1:1224", pid: getpid()),
    ev(.medium, "Змінено ~/.zshrc", "Цей файл виконується при кожному відкритті терміналу."),
  ]
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
  render(ConnectionsList(store: store).background(Color(nsColor: .windowBackgroundColor)), "net", NSSize(width: 480, height: 400))
  render(SettingsPane(store: store).background(Color(nsColor: .windowBackgroundColor)), "settings", NSSize(width: 480, height: 640))
  DispatchQueue.main.asyncAfter(deadline: .now() + 2) { exit(0) }
}
app.run()
