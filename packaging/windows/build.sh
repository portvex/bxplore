#!/usr/bin/env bash
# Cross-builds the Windows packages for x64 and arm64 into dist/:
#   bxplore-<version>-windows-<arch>-portable.zip   bxplore.exe, nothing to install
#   bxplore-<version>-windows-<arch>-setup.exe      NSIS installer
# Runs inside the packaging VM (see packaging/vm.sh).
#
# Signing (optional, needs osslsigncode):
#   WINDOWS_SIGN_PFX       path of a PKCS#12 code signing certificate
#   WINDOWS_SIGN_PASSWORD  its password
#   WINDOWS_SIGN_TS        timestamp server (default http://timestamp.digicert.com)
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/../common.sh"
. "$HOME/.cargo/env"
export PATH="$HOME/llvm-mingw/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/target}"
DIST="${DIST:-$ROOT/dist}"
WORK="$HOME/work/windows"
mkdir -p "$DIST"

sign() {
  [ -n "${WINDOWS_SIGN_PFX:-}" ] || return 0
  osslsigncode sign -pkcs12 "$WINDOWS_SIGN_PFX" -pass "${WINDOWS_SIGN_PASSWORD:-}" -h sha256 \
    -n "$APP_TITLE" -ts "${WINDOWS_SIGN_TS:-http://timestamp.digicert.com}" -in "$1" -out "$1.signed"
  mv "$1.signed" "$1"
}

# name : rust target : C toolchain prefix
for spec in x64:x86_64-pc-windows-gnu:x86_64-w64-mingw32 arm64:aarch64-pc-windows-gnullvm:aarch64-w64-mingw32; do
  IFS=: read -r arch target prefix <<<"$spec"
  w="$WORK/$arch"
  rm -rf "$w" && mkdir -p "$w"

  # Icon and version information, linked into the executable.
  v4="$(echo "$APP_VERSION" | tr . ,),0"
  sed -e "s|@ICON@|$ROOT/packaging/icons/bxplore.ico|" -e "s/@V4@/$v4/g" -e "s/@VERSION@/$APP_VERSION/g" \
    -e "s/@TITLE@/$APP_TITLE/g" -e "s/@NAME@/$APP_NAME/g" -e "s/@PUBLISHER@/$APP_PUBLISHER/g" \
    "$ROOT/packaging/windows/bxplore.rc.in" > "$w/bxplore.rc"
  if [ "$arch" = x64 ]; then
    cc=$prefix-gcc-posix; command -v $cc >/dev/null || cc=$prefix-gcc
    x86_64-w64-mingw32-windres "$w/bxplore.rc" -O coff -o "$w/bxplore.res.o"
  else
    cc=$prefix-clang
    $prefix-windres "$w/bxplore.rc" -O coff -o "$w/bxplore.res.o"
  fi

  tu="$(echo "$target" | tr a-z- A-Z_)"
  export "CARGO_TARGET_${tu}_LINKER=$cc"
  export "CC_$(echo "$target" | tr - _)=$cc"
  export "AR_$(echo "$target" | tr - _)=$([ "$arch" = x64 ] && echo $prefix-ar || echo llvm-ar)"
  # The C runtime goes into the executable; only DLLs that ship with Windows remain.
  export "CARGO_TARGET_${tu}_RUSTFLAGS=-C target-feature=+crt-static -C link-arg=$w/bxplore.res.o"
  (cd "$ROOT" && cargo build --locked --profile standalone --target "$target" --bin "$APP_NAME")

  exe="$w/$APP_NAME.exe"
  cp "$CARGO_TARGET_DIR/$target/standalone/$APP_NAME.exe" "$exe"
  sign "$exe"

  cp "$ROOT/README.md" "$w/README.md"
  zip="$DIST/$APP_NAME-$APP_VERSION-windows-$arch-portable.zip"
  rm -f "$zip" && (cd "$w" && zip -q -9 "$zip" "$APP_NAME.exe" README.md)

  setup="$DIST/$APP_NAME-$APP_VERSION-windows-$arch-setup.exe"
  makensis -V2 -DVERSION="$APP_VERSION" -DARCH="$arch" -DEXE="$exe" -DICON="$ROOT/packaging/icons/bxplore.ico" \
    -DOUT="$setup" -DTITLE="$APP_TITLE" -DNAME="$APP_NAME" -DPUBLISHER="$APP_PUBLISHER" "$ROOT/packaging/windows/bxplore.nsi"
  sign "$setup"
  echo "built $zip and $setup"
done
