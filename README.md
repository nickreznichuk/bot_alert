# BotAlert

A tiny macOS menu-bar app that warns you when something is stealing your data: reading SSH keys, browser
passwords, cookies and crypto wallets, Telegram sessions, AWS/gcloud/kube/docker/gh credentials, or making
suspicious network connections.

It was built after a real incident with a malicious "take-home assignment" repository (the BeaverTail /
InvisibleFerret family, a.k.a. "Contagious Interview"): a node script pulled hidden code from Vercel and a
blockchain, ran in the background and shipped the victim's keys to a remote IP. BotAlert is meant to make that
kind of thing loud.

- No root, no Xcode, no Apple Developer account needed.
- ~1% CPU, ~20 MB of memory.
- Sends nothing anywhere: everything stays on your Mac (the log lives in `~/Library/Logs/BotAlert`). The only
  network traffic is ordinary DNS lookups, used to learn blockchain-node IPs and to show host names in the
  Network tab.

## Requirements

- macOS 13 Ventura or newer (Apple Silicon or Intel).
- Apple's Command Line Tools (the Swift compiler). Check with `xcrun --find swiftc`. If it's missing:

```bash
xcode-select --install
```

Xcode is not required (it works too if you have it).

## Install

1. Get the project (git clone or zip) and open its folder in Terminal.
2. Run:

```bash
./build.sh --install
```

The script builds `BotAlert.app`, copies it to `/Applications`, starts it and enables launch at login.
If something kills BotAlert (malware, for instance), macOS starts it again automatically.
You don't need to add it to Login Items yourself: launch at login is already set up (BotAlert should be enabled
under *Allow in the Background*). Extra copies started by hand hand over to the main one and quit.

3. When macOS asks about notifications, **allow** them. If it doesn't ask: System Settings → Notifications →
   BotAlert → turn on *Allow notifications*.
4. A shield appears in the top-right corner. If you can't see it, the menu bar is too crowded (especially on a
   MacBook with a notch): remove some icons, or hold ⌘ and drag the shield further left.

Build only, without installing: `./build.sh` → `build/BotAlert.app` (run it with `open build/BotAlert.app`).

## Check that it works

`tools/simulate` has two **harmless** attack imitations. They connect to the test address 203.0.113.x (it goes
nowhere) and only list file names in `~/.ssh`: no key contents are read or sent.

```bash
node tools/simulate/stealer.js
```

Within ~5 seconds you should get "node is connecting to port 1224", "Something read…" and a **CRITICAL**
"Looks like data theft" notification, and the process gets frozen (the terminal prints
`suspended (signal)`). End it with *Kill* in BotAlert or `kill -9 %1`. Repeating the check within 10 minutes
shows fewer alerts, because identical alerts are not repeated.

```bash
python3 tools/simulate/exfil.py
```

Expected: **CRITICAL** "Python is reading SSH keys while connected to the internet" and a freeze (end it the
same way: *Kill* or `kill -9 %1`).

## Using it

- **Menu-bar shield**: plain means all quiet; orange/red with a number means new alerts.
- **Alerts** show what happened, which process, where it was started from, its parent process and where it
  connects.
  - *Freeze / Unfreeze* pauses the process (SIGSTOP) without losing anything, so you can look into it.
  - *Kill* ends the process and all its children.
  - *Show in Finder* reveals the program's file.
  - *Trust* stops alerting about this program (the list is in Settings, entries can be removed). For node,
    python and other interpreters it trusts only **that script**, never the whole interpreter: otherwise a
    malicious repository would become "trusted" too.
- **Network**: all current internet connections of the programs worth watching (a red dot marks a suspicious
  process).
- **Settings**: automatic freeze on a critical threat (on by default), notifications for the *Warning* level,
  launch at login, what is protected, quit.

Levels: **CRITICAL** (the process is frozen, sound), **Danger** (notification with sound), **Warning**
(notification), **Info** (log only; can be shown in Settings).

### If you get a critical alert

1. Don't type your password into any unexpected window.
2. Turn off Wi-Fi.
3. Kill the suspicious process with *Kill*, and use *Show in Finder* to see where it lives.
4. From **another** device, change passwords and your SSH keys on GitHub/GitLab, sign out other sessions
   (Google, Telegram, GitHub), and move crypto to a new wallet. Wiping the Mac does not undo keys that were
   already stolen.

## What is watched

| What | How |
|---|---|
| Reads of sensitive files | Access-time "tripwires": APFS marks any read, even a 1 ms one. If it wasn't the file's own program (the browser, `ssh`, `aws`…), you get an alert. A plain listing of the `~/.ssh` folder with no suspicious process around is only logged: regular apps do that, and the keys themselves have their own tripwires. |
| Who exactly is reading | Open files of processes are checked every second. A process holding keys/passwords **and** connected to the internet → CRITICAL, frozen. |
| Mass reads | 3+ sensitive locations or 2 categories within a minute is stealer behaviour → CRITICAL. Only processes with concrete evidence against them get frozen (a suspicious command, a backdoor port, a blockchain node), never "every node that happens to run". |
| Suspicious commands | `curl … \| sh`, obfuscated `node -e`, fake password prompts via `osascript`, `security … Safe Storage`, `dscl -authonly`, running from `/tmp` or hidden folders (`~/.n2`, `~/.npl`…). |
| Network | New connections of node/python/curl and unsigned programs: backdoor ports (1224, 1244, 1245…), blockchain nodes (TRON, Aptos, BSC), unusual ports. |
| Persistence | New files in `LaunchAgents` / `LaunchDaemons`, changes to `~/.zshrc`, `~/.zprofile` and friends. |

Protected: `~/.ssh`; Chrome, Brave, Edge, Arc, Vivaldi, Opera, Chromium, Yandex (passwords, cookies, cards, the
encryption key, wallet extensions MetaMask/Phantom/Coinbase/TronLink/Rabby/OKX…); Firefox; Telegram Desktop;
Exodus, Electrum, Atomic, Ledger Live, Bitcoin Core, Solana CLI; `~/.aws`, gcloud, `~/.kube/config`,
`~/.docker/config.json`, `~/.git-credentials`, `gh`; Keychain files.

## Update and uninstall

Update (after changing the code or pulling a new version) with the same command; settings are kept:

```bash
./build.sh --install
```

Uninstall:

```bash
./build.sh --uninstall
```

The log and settings stay; to wipe them completely:
`rm -rf ~/Library/Logs/BotAlert && defaults delete local.botalert.monitor`.

## Sharing it

Share the **source** (git or a zip without the `build` folder), not a prebuilt `BotAlert.app`, and let people
build it themselves with `./build.sh --install`. That way they can read the code before running it (you know
how third-party repositories can end 🙂), and macOS won't block the app. To make a zip:

```bash
cd .. && zip -r BotAlert.zip bot_alert -x 'bot_alert/build/*' 'bot_alert/.git/*' '*.DS_Store'
```

After unzipping: `cd bot_alert && ./build.sh --install` (if the zip was downloaded and the script won't run,
`chmod +x build.sh`).

If you do pass on a built `.app`: it is only signed locally, so macOS will say it "can't be opened". The
recipient can remove the quarantine flag (only if they trust you):

```bash
xattr -dr com.apple.quarantine /Applications/BotAlert.app
```

You can also sign it with your own Apple Developer certificate:
`SIGN_ID="Apple Development: Your Name (TEAMID)" ./build.sh`.

## Troubleshooting

| Problem | Fix |
|---|---|
| `swiftc not found` | `xcode-select --install` |
| `No macOS SDK compatible with the compiler` | Update the Command Line Tools (System Settings → Software Update) or reinstall them: `sudo rm -rf /Library/Developer/CommandLineTools && xcode-select --install` |
| No notifications | System Settings → Notifications → BotAlert → allow; turn off Focus |
| No menu-bar icon | The menu bar is full: remove other icons; check `pgrep -x BotAlert` |
| Alert about a program you trust | *Trust*. For node/python/… it trusts only that script, not all of node |
| "Something read an SSH key" and it was you | That's fine, it's a *Warning*: just ignore it |
| Want to know exactly who reads a file | `python3 tools/who_reads.py ~/.ssh` shows what was starting at each read |
| A process you need was frozen | *Unfreeze* in the alert, then *Trust* if needed |

## Limitations

- Without root it can't see processes of other users or of the system.
- Network activity is seen as IP:port, without domain names.
- If a file was read in a millisecond and the process exited right away, the read itself is detected, but the
  culprit can only be inferred indirectly.
- It's an extra layer, not an antivirus: don't run unknown repositories or "take-home assignments" outside a VM
  or container.

## For developers

Architecture, design decisions and how to test changes are in [CLAUDE.md](CLAUDE.md). Render the UI to PNGs
without running the app: `./build.sh --snapshot /tmp/shots`.
