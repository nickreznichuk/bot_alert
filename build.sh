#!/bin/zsh
# BotAlert build script (swiftc only, no Xcode / SwiftPM needed).
#   ./build.sh                  build build/BotAlert.app
#   ./build.sh --install        build, copy to /Applications, enable launch at login (+ restart if killed)
#   ./build.sh --uninstall      stop, remove the app and the LaunchAgent (logs/settings are kept)
#   ./build.sh --snapshot DIR   render the UI to PNGs in DIR (dev check, needs no screen permissions)
set -euo pipefail
cd "$(dirname "$0")"

APP=build/BotAlert.app
BUNDLE_ID=local.botalert.monitor
LABEL=local.botalert.agent
DEST=/Applications/BotAlert.app
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
ARCH=$(uname -m)
MODE="${1:-}"

stop_running() {
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  pkill -x BotAlert 2>/dev/null || true
}

if [[ "$MODE" == "--uninstall" ]]; then
  stop_running
  rm -rf "$DEST" "$PLIST"
  echo "BotAlert removed. The log (~/Library/Logs/BotAlert) and settings were kept; to wipe them:"
  echo "  rm -rf ~/Library/Logs/BotAlert && defaults delete $BUNDLE_ID"
  exit 0
fi

if ! xcrun --find swiftc >/dev/null 2>&1; then
  echo "swiftc not found. Install the Command Line Tools: xcode-select --install" >&2
  exit 1
fi

# Command Line Tools sometimes ship an SDK newer than the compiler: pick the newest one that works.
pick_sdk() {
  local probe=$(mktemp -d)/probe.swift
  echo 'import SwiftUI' > "$probe"
  local sdks=("${SDK:-}" "$(xcrun --show-sdk-path 2>/dev/null)")
  for d in $(ls -d /Library/Developer/CommandLineTools/SDKs/MacOSX*.*.sdk 2>/dev/null | sort -rV); do sdks+=("$d"); done
  for sdk in "${sdks[@]}"; do
    [[ -n "$sdk" && -d "$sdk" ]] || continue
    if swiftc -typecheck -sdk "$sdk" -target "$ARCH-apple-macos13" "$probe" >/dev/null 2>&1; then echo "$sdk"; return; fi
  done
  echo "No macOS SDK compatible with the compiler. Reinstall the Command Line Tools or Xcode." >&2
  exit 1
}

SDK=$(pick_sdk)
echo "SDK: $SDK"

if [[ "$MODE" == "--snapshot" ]]; then
  OUT="${2:?Give an output folder: ./build.sh --snapshot /tmp/shots}"
  mkdir -p "$OUT" build
  swiftc -O -sdk "$SDK" -target "$ARCH-apple-macos13" -o build/snapshot \
    $(ls Sources/BotAlert/*.swift | grep -v BotAlertApp.swift) tools/snapshot/main.swift
  ./build/snapshot "$OUT"
  echo "Screenshots: $OUT/{alerts,net,settings}.png"
  exit 0
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -sdk "$SDK" -target "$ARCH-apple-macos13" -parse-as-library \
  -o "$APP/Contents/MacOS/BotAlert" Sources/BotAlert/*.swift

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleName</key><string>BotAlert</string>
  <key>CFBundleDisplayName</key><string>BotAlert</string>
  <key>CFBundleExecutable</key><string>BotAlert</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Ad-hoc signature is enough for personal use. Set SIGN_ID="Apple Development: ..." to use your developer cert.
codesign --force --sign "${SIGN_ID:--}" --identifier "$BUNDLE_ID" "$APP"
echo "Built: $APP"

if [[ "$MODE" == "--install" ]]; then
  stop_running
  rm -rf "$DEST"
  cp -R "$APP" "$DEST"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$DEST/Contents/MacOS/BotAlert</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "Installed to $DEST and started (launch at login enabled)."
fi
