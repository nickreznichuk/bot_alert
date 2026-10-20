import Foundation

/// Ukrainian plural: plural(1, "пастка", "пастки", "пасток").
func plural(_ n: Int, _ one: String, _ few: String, _ many: String) -> String {
    let m10 = n % 10, m100 = n % 100
    if m10 == 1 && m100 != 11 { return "\(n) \(one)" }
    if (2...4).contains(m10) && !(12...14).contains(m100) { return "\(n) \(few)" }
    return "\(n) \(many)"
}

enum Severity: Int, Codable, Comparable {
    case info = 0, medium, high, critical

    static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }

    var label: String {
        switch self {
        case .info: return "Інфо"
        case .medium: return "Увага"
        case .high: return "Небезпека"
        case .critical: return "КРИТИЧНО"
        }
    }
}

enum Category: String, CaseIterable {
    case ssh = "SSH-ключі"
    case browser = "Браузери (паролі, cookies, гаманці)"
    case wallet = "Крипто-гаманці"
    case messenger = "Месенджери"
    case keychain = "Keychain"
    case devcreds = "Ключі розробника (AWS, gcloud, kube, docker, gh)"
}

/// Which processes are expected to touch a target.
struct Owners {
    var names: Set<String> = []
    var namePrefixes: [String] = []
    var pathContains: [String] = []
    var argsContains: [String] = []
    /// Process name that counts only when one of these words is among its arguments.
    var nameWithArgs: [String: Set<String>] = [:]

    func matches(name: String, path: String, args: String) -> Bool {
        if names.contains(name) { return true }
        if let words = nameWithArgs[name], !words.isDisjoint(with: args.split(separator: " ").map(String.init)) { return true }
        if namePrefixes.contains(where: { name.hasPrefix($0) }) { return true }
        if pathContains.contains(where: { path.contains($0) }) { return true }
        if argsContains.contains(where: { args.contains($0) }) { return true }
        return false
    }
}

struct WatchSpec {
    let path: String
    let label: String
}

struct Target {
    let id: String
    let title: String
    let category: Category
    let owners: Owners
    /// Watch access time (catches any read, even a 1 ms one). Off for files the system reads constantly.
    let atimeWatch: Bool
    /// Absolute path prefixes used to recognize open file descriptors.
    let prefixes: [String]
    /// Owner keeps its files open, so its reads don't bump atime: only its startup/shutdown is excused.
    var ownerGraceOnly = false
    let items: () -> [WatchSpec]
}

enum Rules {
    static let home = NSHomeDirectory()
    static let appSupport = home + "/Library/Application Support"

    static let interpreters: Set<String> = [
        "node", "nodejs", "bun", "deno", "python", "python3", "Python", "ruby", "perl", "php",
        "osascript", "curl", "wget", "nc", "ncat", "socat", "pwsh",
    ]

    /// Apple binaries that malware commonly abuses. They are scanned even though they are Apple-signed.
    static let lolbins: Set<String> = interpreters.union([
        "sqlite3", "zip", "ditto", "tar", "cp", "cat", "scp", "rsync", "base64", "openssl", "security",
        "bash", "sh", "zsh", "dash", "ksh", "tclsh", "xxd", "dd", "mv", "dscl", "screencapture",
    ])

    static func isInterpreter(_ name: String) -> Bool {
        interpreters.contains(name) || name.hasPrefix("python3.") || name.hasPrefix("perl5")
    }

    static func isLolbin(_ name: String) -> Bool {
        lolbins.contains(name) || name.hasPrefix("python3.") || name.hasPrefix("perl5")
    }

    // Ports used by the "Contagious Interview" / BeaverTail / InvisibleFerret family and common C2 defaults.
    static let badPorts: Set<UInt16> = [1224, 1241, 1243, 1244, 1245, 1246, 1247, 1337, 2245, 4444, 6666, 7777, 31337]
    static let commonPorts: Set<UInt16> = [80, 443, 8443, 22, 53, 853, 993, 995, 465, 587, 9418, 5228]

    // Public blockchain endpoints abused to host payloads (EtherHiding-style loaders).
    static let rpcHosts = [
        "api.trongrid.io", "api.shasta.trongrid.io", "api.tronscan.org",
        "fullnode.mainnet.aptoslabs.com", "api.mainnet.aptoslabs.com",
        "bsc-dataseed.binance.org", "bsc-dataseed1.binance.org", "bsc-dataseed2.binance.org",
        "bsc-rpc.publicnode.com", "bsc.publicnode.com", "ethereum-rpc.publicnode.com",
        "api.mainnet-beta.solana.com", "rpc.ankr.com", "eth.llamarpc.com", "polygon-rpc.com",
        "mainnet.infura.io", "api.etherscan.io", "api.bscscan.com",
    ]

    /// Hidden dirs in home that belong to normal developer tooling.
    static let knownHiddenDirs: Set<String> = [
        ".nvm", ".npm", ".bun", ".deno", ".cargo", ".rustup", ".pyenv", ".rbenv", ".local", ".volta", ".yarn",
        ".pnpm", ".pnpm-store", ".vscode", ".vscode-server", ".cursor", ".claude", ".docker", ".orbstack", ".gem",
        ".sdkman", ".asdf", ".fnm", ".config", ".cache", ".gradle", ".m2", ".android", ".flutter", ".pub-cache",
        ".dotnet", ".swiftpm", ".oh-my-zsh", ".conda", ".miniconda3", ".anaconda3", ".bundle", ".kube", ".rd",
        ".colima", ".lima", ".terraform.d", ".codeium", ".windsurf", ".gemini", ".ollama", ".copilot", ".continue",
        ".lmstudio", ".zed", ".jenv", ".nodenv", ".goenv", ".go", ".vim", ".emacs.d", ".tmux", ".antigen", ".zinit",
        ".Trash", ".codex", ".kiro", ".aider", ".expo",
    ]

    /// Dropper directories seen in InvisibleFerret / BeaverTail campaigns.
    static let iocHiddenDirs: Set<String> = [".n2", ".n3", ".npl", ".pyp", ".sysinfo", ".nlp", ".vscode_ext"]

    static let chromiumBrowsers: [(title: String, base: String, owners: [String])] = [
        ("Google Chrome", "Google/Chrome", ["/Google Chrome.app/", "/Google Chrome Beta.app/", "GoogleUpdater", "Keystone"]),
        ("Brave", "BraveSoftware/Brave-Browser", ["/Brave Browser.app/"]),
        ("Microsoft Edge", "Microsoft Edge", ["/Microsoft Edge.app/", "Microsoft AutoUpdate"]),
        ("Arc", "Arc/User Data", ["/Arc.app/"]),
        ("Vivaldi", "Vivaldi", ["/Vivaldi.app/"]),
        ("Opera", "com.operasoftware.Opera", ["/Opera.app/"]),
        ("Chromium", "Chromium", ["/Chromium.app/"]),
        ("Yandex", "Yandex/YandexBrowser", ["/Yandex.app/"]),
    ]

    static let walletExtensions: [String: String] = [
        "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
        "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
        "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
        "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
        "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
        "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus",
        "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
        "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
        "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
        "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
        "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
        "ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask (Edge)",
    ]

    // ssh-agent is deliberately absent: it lives forever and gets keys via ssh-add, never by reading ~/.ssh.
    // Plain `git` is absent too: editors run `git status` every few seconds, which never touches ~/.ssh.
    static let sshOwners = Owners(
        names: ["ssh", "ssh-add", "ssh-keygen", "ssh-keyscan", "scp", "sftp", "sshd", "sshd-session",
                "rsync", "mosh", "mosh-client"],
        pathContains: ["/Termius.app/", "/Tower.app/", "/Fork.app/", "/GitHub Desktop.app/", "/Sourcetree.app/",
                       "/GitKraken.app/", "/Transmit.app/", "/Cyberduck.app/"],
        nameWithArgs: ["git": ["fetch", "pull", "push", "clone", "ls-remote", "submodule", "remote-ext"]]
    )

    static func existing(_ specs: [WatchSpec]) -> [WatchSpec] {
        let fm = FileManager.default
        return specs.filter { fm.fileExists(atPath: $0.path) }
    }

    static func subdirs(_ dir: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir))?.map { dir + "/" + $0 } ?? []
    }

    static let targets: [Target] = {
        var t: [Target] = []

        t.append(Target(id: "ssh", title: "~/.ssh", category: .ssh, owners: sshOwners, atimeWatch: true,
                        prefixes: [home + "/.ssh/"]) {
            let dir = home + "/.ssh"
            var specs = [WatchSpec(path: dir, label: "папку ~/.ssh (перегляд списку ключів)")]
            let skip: Set<String> = ["known_hosts", "known_hosts.old", "config", "authorized_keys", "environment", ".DS_Store"]
            for p in subdirs(dir) {
                let name = (p as NSString).lastPathComponent
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: p, isDirectory: &isDir), !isDir.boolValue else { continue }
                if name.hasSuffix(".pub") || skip.contains(name) { continue }
                specs.append(WatchSpec(path: p, label: "SSH-ключ ~/.ssh/\(name)"))
            }
            return specs
        })

        for b in chromiumBrowsers {
            let base = appSupport + "/" + b.base
            t.append(Target(id: "browser:" + b.base, title: b.title, category: .browser,
                            owners: Owners(pathContains: b.owners), atimeWatch: true, prefixes: [base + "/"],
                            ownerGraceOnly: true) {
                var specs = [WatchSpec(path: base + "/Local State", label: "\(b.title): ключ шифрування паролів (Local State)")]
                for profile in subdirs(base) where FileManager.default.fileExists(atPath: profile + "/Preferences") {
                    let pn = (profile as NSString).lastPathComponent
                    specs += [
                        WatchSpec(path: profile + "/Login Data", label: "\(b.title) [\(pn)]: збережені паролі"),
                        WatchSpec(path: profile + "/Cookies", label: "\(b.title) [\(pn)]: cookies (сесії)"),
                        WatchSpec(path: profile + "/Network/Cookies", label: "\(b.title) [\(pn)]: cookies (сесії)"),
                        WatchSpec(path: profile + "/Web Data", label: "\(b.title) [\(pn)]: картки й автозаповнення"),
                        WatchSpec(path: profile + "/Local Extension Settings", label: "\(b.title) [\(pn)]: дані розширень (гаманці)"),
                    ]
                    for (id, wallet) in walletExtensions {
                        specs.append(WatchSpec(path: profile + "/Local Extension Settings/" + id,
                                               label: "\(b.title) [\(pn)]: гаманець \(wallet)"))
                    }
                }
                return existing(specs)
            })
        }

        let ff = appSupport + "/Firefox/Profiles"
        t.append(Target(id: "firefox", title: "Firefox", category: .browser, owners: Owners(pathContains: ["/Firefox.app/"]),
                        atimeWatch: true, prefixes: [ff + "/"], ownerGraceOnly: true) {
            var specs: [WatchSpec] = []
            for p in subdirs(ff) {
                let pn = (p as NSString).lastPathComponent
                specs += [
                    WatchSpec(path: p + "/logins.json", label: "Firefox [\(pn)]: збережені паролі"),
                    WatchSpec(path: p + "/key4.db", label: "Firefox [\(pn)]: ключ паролів"),
                    WatchSpec(path: p + "/cookies.sqlite", label: "Firefox [\(pn)]: cookies"),
                ]
            }
            return existing(specs)
        })

        // securityd reads the keychain all the time, so only direct opens by other processes are flagged.
        t.append(Target(id: "keychain", title: "Keychain", category: .keychain, owners: Owners(), atimeWatch: false,
                        prefixes: [home + "/Library/Keychains/"]) { [] })

        let tg = appSupport + "/Telegram Desktop/tdata"
        t.append(Target(id: "telegram", title: "Telegram Desktop", category: .messenger,
                        owners: Owners(pathContains: ["/Telegram.app/", "Telegram Desktop"]), atimeWatch: true,
                        prefixes: [tg + "/"]) {
            existing([WatchSpec(path: tg, label: "Telegram: сесія (tdata)"),
                      WatchSpec(path: tg + "/key_datas", label: "Telegram: ключ сесії")])
        })

        let wallets: [(String, String, [String], [String])] = [
            ("exodus", appSupport + "/Exodus/exodus.wallet", ["/Exodus.app/"], []),
            ("electrum", home + "/.electrum/wallets", ["/Electrum.app/"], ["electrum"]),
            ("electrum2", appSupport + "/Electrum/wallets", ["/Electrum.app/"], ["electrum"]),
            ("atomic", appSupport + "/atomic/Local Storage/leveldb", ["/Atomic Wallet.app/"], []),
            ("ledger", appSupport + "/Ledger Live", ["/Ledger Live.app/"], []),
            ("bitcoin", appSupport + "/Bitcoin/wallets", ["/Bitcoin-Qt.app/"], ["bitcoind", "bitcoin-qt"]),
            ("solana", home + "/.config/solana/id.json", [], ["solana", "solana-keygen", "anchor"]),
        ]
        for w in wallets {
            t.append(Target(id: "wallet:" + w.0, title: (w.1 as NSString).lastPathComponent, category: .wallet,
                            owners: Owners(names: Set(w.3), pathContains: w.2), atimeWatch: true, prefixes: [w.1]) {
                existing([WatchSpec(path: w.1, label: "Гаманець: " + w.1.replacingOccurrences(of: home, with: "~"))])
            })
        }

        let dev: [(String, String, Owners)] = [
            ("aws", home + "/.aws/credentials", Owners(names: ["aws", "terraform", "sam", "aws-vault", "cdk"])),
            ("gcloud", home + "/.config/gcloud/application_default_credentials.json",
             Owners(names: ["gcloud", "terraform"], argsContains: ["gcloud", "google-cloud-sdk"])),
            ("gcloud-db", home + "/.config/gcloud/credentials.db",
             Owners(names: ["gcloud"], argsContains: ["gcloud", "google-cloud-sdk"])),
            ("kube", home + "/.kube/config",
             Owners(names: ["kubectl", "k9s", "helm", "kubectx", "kubens", "minikube", "kind"],
                    pathContains: ["/Docker.app/", "/OrbStack.app/", "/Lens.app/", "/Rancher Desktop.app/"])),
            ("docker", home + "/.docker/config.json",
             Owners(names: ["docker", "docker-compose"], namePrefixes: ["docker-credential-", "com.docker"],
                    pathContains: ["/Docker.app/", "/OrbStack.app/", "/Rancher Desktop.app/"])),
            ("git-credentials", home + "/.git-credentials", Owners(names: ["git"], namePrefixes: ["git-"])),
            ("gh", home + "/.config/gh/hosts.yml", Owners(names: ["gh"])),
        ]
        for d in dev {
            t.append(Target(id: "dev:" + d.0, title: d.1.replacingOccurrences(of: home, with: "~"), category: .devcreds,
                            owners: d.2, atimeWatch: true, prefixes: [d.1]) {
                existing([WatchSpec(path: d.1, label: "Ключі: " + d.1.replacingOccurrences(of: home, with: "~"))])
            })
        }
        return t
    }()

    /// Rules applied once to every new process. Returns (severity, title, explanation) for the first match.
    static func execVerdict(name: String, path: String, args: [String], sign: SignInfo) -> (Severity, String, String)? {
        let cmd = args.joined(separator: " ")
        let lc = cmd.lowercased()

        if name == "security" {
            if lc.contains("dump-keychain") || lc.contains("safe storage") {
                return (.critical, "Спроба витягти ключ паролів браузера з Keychain",
                        "Команда `security` запитує ключ шифрування паролів браузера або вивантажує весь Keychain. Так роблять стілери.")
            }
            if lc.contains("find-generic-password") || lc.contains("find-internet-password") {
                return (.info, "Програма читає пароль з Keychain", "Звичайно для деяких CLI (наприклад Claude Code), але перевір батьківський процес.")
            }
        }
        if name == "osascript" && (lc.contains("hidden answer") || lc.contains("password") || lc.contains("пароль")) {
            return (.critical, "Фейкове вікно запиту пароля",
                    "osascript показує діалог з прихованим вводом. Стілери (AMOS) так виманюють пароль від Mac. НЕ ВВОДЬ пароль.")
        }
        if name == "dscl" && lc.contains("authonly") {
            return (.critical, "Перевірка пароля користувача через dscl", "Стілери так перевіряють, чи правильний пароль ти ввів у фейкове вікно.")
        }
        if name == "sqlite3" && (lc.contains("login data") || lc.contains("cookies") || lc.contains("web data") || lc.contains("logins.json")) {
            return (.high, "sqlite3 читає базу паролів/cookies браузера", cmd)
        }
        if ["sh", "bash", "zsh", "dash"].contains(name), args.count >= 3, args[1] == "-c" {
            let c = args[2].lowercased()
            let fetch = c.contains("curl") || c.contains("wget")
            let pipe = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| python", "|python", "| node", "|node"].contains { c.contains($0) }
            if fetch && pipe {
                return (.high, "Завантаження і запуск скрипта з інтернету", "Команда виду `curl … | sh`:\n" + String(args[2].prefix(400)))
            }
        }
        for dir in iocHiddenDirs where cmd.contains(home + "/" + dir + "/") || path.contains(home + "/" + dir + "/") {
            return (.critical, "Відомий шкідливий каталог \(dir)", "Каталог ~/\(dir) використовують бекдори InvisibleFerret/BeaverTail.")
        }
        if isInterpreter(name), let flag = args.dropFirst().first(where: { ["-e", "--eval", "-p", "--print", "-c"].contains($0) }),
           let idx = args.firstIndex(of: flag), idx + 1 < args.count {
            let code = args[idx + 1]
            let tokens = ["eval(", "function(", "atob(", "buffer.from(", "base64", "child_process", "fromcharcode", "\\x", "exec(", "marshal", "zlib"]
            if code.count > 400 || tokens.contains(where: { code.lowercased().contains($0) }) {
                return (.medium, "\(name) виконує вбудований (можливо обфускований) код",
                        "Інлайн-код \(code.count) символів:\n" + String(code.prefix(300)))
            }
        }
        // Binaries / scripts living in hidden home dirs that aren't known tooling.
        let candidates = [path] + args.dropFirst().filter { $0.hasPrefix("/") }
        for p in candidates where p.hasPrefix(home + "/.") {
            let comp = String(p.dropFirst(home.count + 1).split(separator: "/").first ?? "")
            if !knownHiddenDirs.contains(comp) {
                return (isInterpreter(name) ? .high : .medium, "Запуск з прихованої папки ~/\(comp)",
                        "Шкідливі програми часто ховаються у ~/.щось. Файл: \(p)")
            }
        }
        let tmpPrefixes = ["/tmp/", "/private/tmp/", "/private/var/folders/", "/var/folders/", "/Users/Shared/"]
        if sign.isAdhocOrUnsigned, tmpPrefixes.contains(where: { path.hasPrefix($0) }) {
            return (.medium, "Непідписана програма запущена з тимчасової папки", path)
        }
        if isInterpreter(name), let script = args.dropFirst().first(where: { $0.hasPrefix("/") }),
           tmpPrefixes.contains(where: { script.hasPrefix($0) }) {
            return (.medium, "\(name) запускає скрипт з тимчасової папки", script)
        }
        return nil
    }
}
