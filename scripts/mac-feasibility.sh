#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in ''|--build-only) ;; *) echo 'Usage: bash scripts/mac-feasibility.sh [--build-only]' >&2; exit 64 ;; esac
[[ "$(uname -s)" == Darwin ]] || { echo 'Run this probe on macOS with Xcode command-line tools.' >&2; exit 1; }
cd -- "$(dirname "$0")/.."
out="$PWD/target/mac-feasibility"
app="$out/Flyw8tMacProbe.app"
mkdir -p "$app/Contents/MacOS"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
xcrun swiftc -swift-version 5 -sdk "$sdk" -target "$(uname -m)-apple-macos13.0" \
  -framework AppKit -framework ApplicationServices -framework ScreenCaptureKit \
  -framework CoreMedia -framework CoreVideo scripts/mac-feasibility.swift \
  -o "$app/Contents/MacOS/Flyw8tMacProbe"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Flyw8tMacProbe</string>
<key>CFBundleIdentifier</key><string>com.flyw8t.feasibility</string>
<key>CFBundleName</key><string>flyw8t Mac Probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSScreenCaptureUsageDescription</key><string>Capture this probe's test window to evaluate flyw8t's native Mac support. No images are saved.</string>
</dict></plist>
PLIST
codesign --force --sign - --identifier com.flyw8t.feasibility "$app"
codesign --verify --strict "$app"
if [[ "${1:-}" == --build-only ]]; then
  echo 'Mac probe compiled and ad-hoc signature verified. No permission or runtime gate has passed.'
  exit 0
fi
report="$out/report-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
echo "Observation report: $report (development probe, never an automatic gate pass)"
open -W -n "$app" --args "$report"
