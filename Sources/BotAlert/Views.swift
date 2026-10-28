import AppKit
import SwiftUI

extension Severity {
    var color: Color {
        switch self {
        case .info: return .secondary
        case .medium: return .orange
        case .high: return .red
        case .critical: return Color(red: 0.85, green: 0, blue: 0.35)
        }
    }
}

enum StatusIcon {
    static func image(_ worst: Severity?, paused: Bool) -> NSImage {
        let name: String
        var color: NSColor?
        switch (paused, worst) {
        case (true, _): name = "shield.slash"
        case (_, nil), (_, .some(.info)): name = "checkmark.shield"
        case (_, .some(.medium)): name = "exclamationmark.shield.fill"; color = .systemOrange
        default: name = "exclamationmark.shield.fill"; color = .systemRed
        }
        var cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .medium)
        if let color { cfg = cfg.applying(NSImage.SymbolConfiguration(paletteColors: [color])) }
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "BotAlert")?.withSymbolConfiguration(cfg) ?? NSImage()
        img.isTemplate = color == nil
        return img
    }
}

struct MenuLabel: View {
    @ObservedObject var store: AlertStore
    var body: some View {
        let n = store.unseen.count
        HStack(spacing: 2) {
            Image(nsImage: StatusIcon.image(store.worstUnseen, paused: store.paused))
            if n > 0 { Text("\(n)") }
        }
    }
}

struct MainView: View {
    @ObservedObject var store: AlertStore
    @State private var tab = 0

    var body: some View {
        VStack(spacing: 0) {
            header
            Picker("", selection: $tab) {
                Text("Alerts (\(store.visibleAlerts.count))").tag(0)
                Text("Network (\(store.connections.count))").tag(1)
                Text("Settings").tag(2)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 12)
            .padding(.bottom, 8)
            Divider()
            switch tab {
            case 0: AlertsList(store: store)
            case 1: ConnectionsList(store: store)
            default: SettingsPane(store: store)
            }
        }
        .frame(width: 480, height: 600)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(nsImage: StatusIcon.image(store.worstUnseen, paused: store.paused))
                .resizable().frame(width: 26, height: 26)
            VStack(alignment: .leading, spacing: 2) {
                Text(statusTitle).font(.headline)
                Text("Watching \(store.stats.processes) processes · \(plural(store.stats.watchedByCategory.values.reduce(0, +), "file trap", "file traps"))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("Pause", isOn: $store.paused).toggleStyle(.switch).controlSize(.small)
        }
        .padding(12)
    }

    private var statusTitle: String {
        if store.paused { return "Monitoring paused" }
        let n = store.unseen.count
        return n == 0 ? "All quiet" : plural(n, "new alert", "new alerts")
    }
}

struct AlertsList: View {
    @ObservedObject var store: AlertStore

    var body: some View {
        VStack(spacing: 0) {
            if store.visibleAlerts.isEmpty {
                Spacer()
                Image(systemName: "checkmark.shield").font(.system(size: 40)).foregroundStyle(.green)
                Text("No suspicious activity detected").foregroundStyle(.secondary).padding(.top, 6)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(store.visibleAlerts) { AlertRow(store: store, alert: $0) }
                    }
                    .padding(10)
                }
            }
            Divider()
            HStack {
                Button("Mark all seen") { store.markAllSeen() }.disabled(store.unseen.isEmpty)
                Button("Clear") { store.clear() }.disabled(store.alerts.isEmpty)
                Spacer()
                Button("Log") { store.openLog() }
            }
            .controlSize(.small)
            .padding(8)
        }
    }
}

struct AlertRow: View {
    @ObservedObject var store: AlertStore
    let alert: Alert
    @State private var expanded = false

    var body: some View {
        let ev = alert.event
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(ev.severity.label.uppercased())
                    .font(.system(size: 9, weight: .bold))
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(ev.severity.color.opacity(0.18), in: Capsule())
                    .foregroundStyle(ev.severity.color)
                Text(ev.title).font(.system(size: 12, weight: .semibold)).lineLimit(expanded ? nil : 2)
                Spacer()
                Text(alert.date, style: .time).font(.caption2).foregroundStyle(.secondary)
            }
            if !alert.frozen.isEmpty {
                Label("Frozen: \(alert.frozen.map(String.init).joined(separator: ", "))", systemImage: "snowflake")
                    .font(.caption).foregroundStyle(.blue)
            }
            if alert.killed { Label("Process killed", systemImage: "xmark.octagon").font(.caption).foregroundStyle(.secondary) }
            Text(ev.detail)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(expanded ? nil : 4)
                .textSelection(.enabled)
                .onTapGesture { expanded.toggle() }
            HStack(spacing: 6) {
                if let pid = ev.pid, !alert.killed, AlertStore.isAlive(pid) {
                    if alert.frozen.isEmpty && !AlertStore.isStopped(pid) {
                        Button("Freeze") { store.freeze(alert) }
                    } else {
                        Button("Unfreeze") { store.resume(alert) }
                    }
                    Button("Kill") { store.killProcess(alert) }.tint(.red)
                }
                if ev.processPath != nil {
                    Button("Show in Finder") { store.reveal(alert) }
                }
                if ev.trustKey != nil {
                    Button(Rules.isInterpreter(ev.processName ?? "") ? "Trust this script" : "Trust") { store.trust(alert) }
                        .help(ev.trustKey ?? "")
                }
                Spacer()
                Button(expanded ? "Less" : "More") { expanded.toggle() }.buttonStyle(.link)
            }
            .controlSize(.small)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(alert.seen ? Color.clear : ev.severity.color.opacity(0.5)))
    }
}

struct ConnectionsList: View {
    @ObservedObject var store: AlertStore

    var body: some View {
        if store.connections.isEmpty {
            VStack { Spacer(); Text("No active connections").foregroundStyle(.secondary); Spacer() }
        } else {
            List(store.connections) { c in
                HStack(alignment: .top) {
                    Circle().fill(c.flagged ? Color.red : Color.green.opacity(0.6)).frame(width: 7, height: 7).padding(.top, 5)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(c.name)  ·  pid \(c.pid)").font(.system(size: 12, weight: .medium))
                        Text("\(c.ip):\(c.port)  \(store.hosts[c.ip].flatMap { $0.isEmpty ? nil : $0 } ?? "")")
                            .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        Text("\(c.state) · \(c.signLabel)").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

struct SettingsPane: View {
    @ObservedObject var store: AlertStore

    var body: some View {
        Form {
            Section("Response") {
                Toggle("Automatically freeze the process on a critical threat", isOn: $store.autoFreeze)
                Toggle("Notify on \"Warning\" level", isOn: $store.notifyMedium)
                Toggle("Show info events", isOn: $store.showInfo)
                Toggle("Start at login (and restart if killed)", isOn: Binding(
                    get: { store.launchAtLogin }, set: { store.setLaunchAtLogin($0) }))
            }
            Section("What is protected") {
                ForEach(Category.allCases, id: \.self) { c in
                    HStack {
                        Text(c.rawValue)
                        Spacer()
                        Text(c == .keychain ? "file opens" : plural(store.stats.watchedByCategory[c] ?? 0, "trap", "traps"))
                            .foregroundStyle(.secondary)
                    }
                }
                Text("Plus: suspicious commands (curl|sh, node -e, fake password prompts, security), interpreter connections (node/python), new launch items and ~/.zshrc changes.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !store.trusted.isEmpty {
                Section("Trusted programs") {
                    ForEach(store.trusted.sorted(), id: \.self) { p in
                        HStack {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(p.replacingOccurrences(of: Rules.home, with: "~"))
                                    .font(.caption).lineLimit(1).truncationMode(.middle)
                                // Entries from older versions trusted a whole interpreter; that is ignored now.
                                if !p.contains(" "), Rules.isInterpreter((p as NSString).lastPathComponent) {
                                    Text("Ignored: an interpreter (node, python…) can only be trusted for a specific script")
                                        .font(.caption2).foregroundStyle(.orange)
                                }
                            }
                            Spacer()
                            Button("Remove") { store.trusted.remove(p) }.controlSize(.small)
                        }
                    }
                }
            }
            Section {
                HStack {
                    Text("Scan: \(store.stats.scanned) processes in \(String(format: "%.1f", store.stats.scanMs)) ms").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Quit BotAlert") { NSApp.terminate(nil) }
                }
            }
        }
        .formStyle(.grouped)
    }
}
