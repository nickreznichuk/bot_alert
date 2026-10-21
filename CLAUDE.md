# BotAlert — notes for Claude

macOS menu-bar app (SwiftUI `MenuBarExtra`) that warns about info-stealer behaviour: reads of SSH keys /
browser passwords, cookies and wallets / dev credentials, suspicious command lines, odd network connections
from interpreters, new persistence. Personal tool, not distributed. Runs as the user, no root, no entitlements.
UI strings and user-facing docs are **Ukrainian**; code comments are English.

## Build & run

```bash
./build.sh                    # -> build/BotAlert.app (ad-hoc signed)
./build.sh --install          # -> /Applications + LaunchAgent local.botalert.agent (RunAtLoad, KeepAlive on crash)
./build.sh --uninstall
./build.sh --snapshot /tmp/x  # render UI to PNGs (alerts/net/settings) for visual checks
```

- Build is plain `swiftc` on purpose. **Do not add Package.swift / SwiftPM**: SwiftPM in the installed
  Command Line Tools crashes (dyld symbol error), and CLT ship an SDK newer than the compiler, so
  `build.sh` probes SDKs and picks the newest one that typechecks `import SwiftUI`. Override with `SDK=...`.
- Deployment target macOS 13 (MenuBarExtra). No Xcode needed.
- Alert log: `~/Library/Logs/BotAlert/alerts.log` — the easiest way to verify detections headlessly.
- Settings live in `UserDefaults` domain `local.botalert.monitor` (`trusted`, `autoFreeze`, `persistenceBaseline`, …).

## Files

| File | Role |
|---|---|
| `Sources/BotAlert/Proc.swift` | libproc/sysctl wrappers (pids, bsdinfo, argv via KERN_PROCARGS2, fds, vnode paths, TCP remotes), `Signing` (SecStaticCode, cached) |
| `Sources/BotAlert/Rules.swift` | All policy: sensitive `Target`s + their `Owners`, interpreter/LOLBin lists, bad/common ports, RPC hosts, hidden-dir allow/IOC lists, `execVerdict` command-line rules, `plural()` |
| `Sources/BotAlert/Monitor.swift` | Engine on a serial queue, 0.5 s timer: process diff → exec rules; atime tripwires; fd/socket scan; suspect scoring; sweep detection; freeze (SIGSTOP); LaunchAgents/rc-file watch |
| `Sources/BotAlert/AlertStore.swift` | Main-thread `ObservableObject`: dedupe (10 min per key), notifications (UNUserNotificationCenter), log file, actions (freeze/resume/kill/trust), LaunchAgent toggle, reverse DNS for the Network tab |
| `Sources/BotAlert/Views.swift` | Menu-bar label/icon, tabs: alerts, network, settings |
| `Sources/BotAlert/BotAlertApp.swift` | `@main`, single-instance guard, accessory activation policy, window opened from notification click |
| `tools/simulate/*` | Harmless attack simulations (TEST-NET IPs, only list dirs / hold a dir fd, never read secrets) |
| `tools/snapshot/main.swift` | Offscreen UI renderer used by `--snapshot` |
| `tools/who_reads.py` | Diagnoses false positives: polls a path's atime at 20 Hz and prints young processes + holders on each read |

## How detection works (and why — hard-won lessons)

- **atime tripwires.** APFS updates atime only when `atime <= mtime/ctime` (relatime-like), on file reads
  *and* directory listings. `arm()` sets atime to `mtime - 1` (mtime untouched via UTIME_OMIT); any later
  read bumps atime → `readDetected`. Inode/mtime change = owner rewrote the file → silently re-arm.
  `stat()` itself doesn't bump atime.
- **Owners** excuse reads. Pitfalls already hit:
  - `ssh-agent` runs forever → must NOT be an SSH owner (it disabled the SSH tripwire permanently).
  - Editors run `git status` every few seconds → plain `git` must NOT be an owner; only `git fetch/push/pull/clone…`
    via `Owners.nameWithArgs`.
  - Browsers keep their DBs open and reading via open fds does not bump atime, so browser targets use
    `ownerGraceOnly`: only the main (non-"Helper") process starting <60 s ago or quitting <20 s ago excuses a read.
    Keychain has no atime watch (securityd touches it constantly) — fd-open only.
- **Listing-only dirs** (`WatchSpec.listingOnly`: `~/.ssh` itself, Chromium `Local Extension Settings`): some
  long-running app on this Mac lists `~/.ssh` exactly every 60 s, which produced a "someone read ~/.ssh" alert
  every 10 min. A listing reveals no secret (keys / wallet dirs have their own tripwires), so without a
  score ≥3 suspect it is only an `.info` event and does not count toward the sweep. Use
  `python3 tools/who_reads.py PATH` to see what was running at each read when chasing such noise.
- **Trust is per script for interpreters** (`Rules.trustKey`: `path + " " + first non-flag arg`). Trusting the
  whole `node` binary (an early version allowed it, the user clicked it) would blind BotAlert to exactly the
  malicious-repo attack. Old bare-interpreter entries stay in the list but are ignored and flagged in Settings.
- **Attribution.** A read with no owner triggers an immediate fd scan; if nobody holds the file, live processes
  are scored (`currentSuspects`): suspicious exec +sev+1, net flag (bad port / RPC / odd port) +3, age <2 min +2
  (<15 min +1), unsigned non-interpreter +1, has connections +1. Score ≥3 = suspect (weak touch), **≥4 = may be
  frozen**. Never freeze "every node": an early version froze the user's `next dev` server.
- **Critical** = process holds a sensitive file AND has an external TCP connection (`criticalSent` prevents
  repeats), or a sweep (≥3 distinct items or ≥2 categories read within 60 s, rate-limited to once per 5 min).
- **CPU budget ~1%.** Resolving vnode paths is the hot spot. Risky processes (interpreters, unsigned, flagged)
  get full resolution each scan, but if they hold ≥300 fds (dev-server watchers) only every 5 s; signed apps
  only resolve fds new since last scan (`fdPaths` cache) plus a full pass every 30 s. Re-measure with
  `top -l 6 -s 3 -pid $(pgrep -x BotAlert) -stats pid,cpu,mem` after changing the scan loop.
- **Single instance** (`SingleInstance` in `BotAlertApp.swift`, runs in `App.init` before the store exists):
  the launchd job (`XPC_SERVICE_NAME == local.botalert.agent`) always wins and force-terminates other copies;
  any other launch (Login Items, Finder, `open -n`) does `launchctl kickstart` (bootstrap if needed) and exits,
  so a manual open after "Quit" still ends up launchd-managed. Without the plist it falls back to "exit if
  another copy runs". launchd throttles restarts to once per 10 s if the process died within 10 s of starting.
- Never run two monitors at once (e.g. a debug build next to the installed app): both re-arm the same
  tripwires and reads get missed. `AlertStore(startMonitor: false)` exists for the snapshot tool.
- A process caught between fork and exec shows the parent's binary — records younger than 5 s are rebuilt
  if their path changes.

## Testing a change

1. `./build.sh --install` (if testing `build/BotAlert.app` directly, first `launchctl bootout gui/$(id -u)/local.botalert.agent`
   so the installed copy doesn't run alongside; reinstall afterwards).
2. `rm ~/Library/Logs/BotAlert/alerts.log`, run `node tools/simulate/stealer.js &` and/or
   `python3 -I tools/simulate/exfil.py &`, wait ~8 s, read the log, check the process is frozen (`ps -o stat= -p PID` → `T`),
   then `kill -9` it. Also check unrelated long-running node processes were **not** frozen.
3. Leave it running a few minutes during normal work and check the log for false positives.
4. UI: `./build.sh --snapshot <dir>` and look at the PNGs (screen capture is not permitted in this environment).

Never test by reading the user's real keys/passwords; simulations only list directories or hold a directory fd.
