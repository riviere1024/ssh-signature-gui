#!/usr/bin/env bash
# Build the macOS .app via PyInstaller, then wrap it in a .dmg via hdiutil.
#
# Usage:
#   ./build_mac.sh

set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="SSH Signature"
BUNDLE_ID="com.riviere1024.signature"
VERSION="0.1.0"

echo "==> Cleaning previous build artifacts"
rm -rf build dist

echo "==> Building .app with PyInstaller"
uv run pyinstaller \
  --name "$APP_NAME" \
  --windowed \
  --osx-bundle-identifier "$BUNDLE_ID" \
  --noconfirm \
  --clean \
  main.py

APP_PATH="dist/${APP_NAME}.app"
if [[ ! -d "$APP_PATH" ]]; then
  echo "ERROR: $APP_PATH was not produced" >&2
  exit 1
fi

# Add a Chinese display name to Info.plist so the dock/finder shows it.
PLIST="$APP_PATH/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Delete :CFBundleDisplayName" "$PLIST" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string SSH 文件签名工具" "$PLIST"
/usr/libexec/PlistBuddy -c "Delete :CFBundleShortVersionString" "$PLIST" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Delete :NSHighResolutionCapable" "$PLIST" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :NSHighResolutionCapable bool true" "$PLIST"

echo "==> Building DMG"
DMG_PATH="dist/${APP_NAME// /-}-${VERSION}.dmg"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP_PATH" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create \
  -volname "$APP_NAME" \
  -srcfolder "$STAGE" \
  -ov -format UDZO \
  "$DMG_PATH" >/dev/null

SIZE=$(du -h "$DMG_PATH" | awk '{print $1}')
echo ""
echo "✓ Done"
echo "  .app : $APP_PATH"
echo "  .dmg : $DMG_PATH  ($SIZE)"
echo ""
echo "Install: open \"$DMG_PATH\", drag the app to Applications."
echo "First launch on another Mac: right-click the app → Open (Gatekeeper warning)."
