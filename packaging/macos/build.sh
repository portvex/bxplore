#!/usr/bin/env bash
# Builds dist/bxplore-<version>-macos-universal.dmg: one .app for Intel and Apple
# Silicon. Runs on macOS only (lipo, iconutil, codesign, hdiutil).
#
# Signing (optional):
#   MACOS_SIGN_IDENTITY   "Developer ID Application: ..." ; default is an ad hoc
#                         signature, which Apple Silicon needs to run the app
#   MACOS_NOTARY_PROFILE  a keychain profile made with `xcrun notarytool
#                         store-credentials`; when set, the DMG is notarized
#                         and stapled
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/../common.sh"
[ "$(uname -s)" = Darwin ] || { echo "the DMG can only be built on macOS" >&2; exit 1; }

# A Homebrew cargo ahead of rustup in PATH knows only the host target.
if command -v rustup >/dev/null; then
  PATH="$(rustup run stable rustc --print sysroot)/bin:$PATH"
fi
export MACOSX_DEPLOYMENT_TARGET=11.0
cd "$ROOT"
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --profile standalone --target "$t"
done

work="$ROOT/target/packaging/macos"
app="$work/$APP_TITLE.app"
rm -rf "$work" && mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/$APP_NAME" \
  "target/aarch64-apple-darwin/standalone/$APP_NAME" "target/x86_64-apple-darwin/standalone/$APP_NAME"

sed -e "s/@TITLE@/$APP_TITLE/g" -e "s/@ID@/$APP_ID/g" -e "s/@NAME@/$APP_NAME/g" \
  -e "s/@VERSION@/$APP_VERSION/g" -e "s/@PUBLISHER@/$APP_PUBLISHER/g" \
  packaging/macos/Info.plist.in > "$app/Contents/Info.plist"

set="$work/$APP_NAME.iconset"
mkdir -p "$set"
i=packaging/icons
cp $i/bxplore-16.png "$set/icon_16x16.png";     cp $i/bxplore-32.png "$set/icon_16x16@2x.png"
cp $i/bxplore-32.png "$set/icon_32x32.png";     cp $i/bxplore-64.png "$set/icon_32x32@2x.png"
cp $i/bxplore-128.png "$set/icon_128x128.png";  cp $i/bxplore-256.png "$set/icon_128x128@2x.png"
cp $i/bxplore-256.png "$set/icon_256x256.png";  cp $i/bxplore-512.png "$set/icon_256x256@2x.png"
cp $i/bxplore-512.png "$set/icon_512x512.png";  cp $i/bxplore-1024.png "$set/icon_512x512@2x.png"
iconutil -c icns -o "$app/Contents/Resources/$APP_NAME.icns" "$set"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$app"
else
  codesign --force --sign - "$app"
fi
codesign --verify --strict "$app"

stage="$work/dmg"
mkdir -p "$stage" "$ROOT/dist"
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
dmg="$ROOT/dist/$APP_NAME-$APP_VERSION-macos-universal.dmg"
rm -f "$dmg"
hdiutil create -quiet -volname "$APP_TITLE $APP_VERSION" -srcfolder "$stage" -fs HFS+ -format UDZO "$dmg"
if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$dmg"
fi
if [ -n "${MACOS_NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$dmg" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$dmg"
fi
echo "built $dmg"
