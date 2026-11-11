#!/usr/bin/env bash
# Tests the packages in dist/. Runs inside the packaging VM (packaging/vm.sh test).
# The VM is arm64; x86_64 Linux code runs through Rosetta, in containers and
# in the Flatpak sandbox. Windows packages are inspected, not run.
set -uo pipefail
. "$(cd "$(dirname "$0")" && pwd)/common.sh"
DIST="${DIST:-$ROOT/dist}"
V="$APP_VERSION"
fail=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }
check() { local name="$1"; shift; if "$@" >/tmp/check.log 2>&1; then ok "$name"; else bad "$name"; sed 's/^/      /' /tmp/check.log | head -8; fi; }
# The dump is written to a file first: a reader that stops early would
# break the pipe and fail the program.
dumps() { "$@" >/tmp/dump.txt 2>/dev/null; grep -q "^\[File\]" /tmp/dump.txt; }
# gui <name> <command...>: the program must still be running after a while
# (xvfb-run ends as soon as the program does).
gui() {
  local name="$1"; shift
  xvfb-run -a -s "-screen 0 1280x800x24" "$@" >/tmp/gui.log 2>&1 &
  local pid=$!
  sleep 10
  if kill -0 $pid 2>/dev/null; then ok "$name"; else bad "$name"; head -5 /tmp/gui.log; fi
  flatpak kill "$APP_ID" 2>/dev/null; sudo pkill -x bxplore 2>/dev/null; pkill -P $pid 2>/dev/null; kill $pid 2>/dev/null; wait $pid 2>/dev/null
}
cp /usr/bin/ls "$HOME/sample-elf"

echo "== standalone executables"
for arch in x86_64 aarch64; do
  bin="$DIST/$APP_NAME-$V-linux-$arch"
  newest="$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"
  [ "$newest" = GLIBC_2.17 ] && ok "$arch needs at most $newest" || bad "$arch needs $newest"
  check "$arch tarball holds the executable" sh -c "tar -tzf '$bin.tar.gz' | grep -q '/bxplore$'"
  # Old and new distributions, each on its own architecture.
  platform=$([ "$arch" = x86_64 ] && echo amd64 || echo arm64)
  for image in centos:7 debian:11 ubuntu:26.04 fedora:latest; do
    check "$arch runs on $image" sh -c "nerdctl run --rm --platform $platform -v '$DIST':/dist:ro $image /dist/$APP_NAME-$V-linux-$arch --dump /bin/ls > /tmp/dump.txt; grep -q '^\[File\]' /tmp/dump.txt"
  done
done
check "aarch64 runs here" dumps "$DIST/$APP_NAME-$V-linux-aarch64" --dump "$HOME/sample-elf"
gui "aarch64 window opens" "$DIST/$APP_NAME-$V-linux-aarch64" "$HOME/sample-elf"

echo "== flatpak"
for arch in aarch64 x86_64; do
  flatpak uninstall --user -y "$APP_ID" >/dev/null 2>&1
  check "$arch flatpak installs" flatpak install --user -y --noninteractive "$DIST/$APP_NAME-$V-linux-$arch.flatpak"
  check "$arch flatpak runs" dumps flatpak run --arch="$arch" "$APP_ID" --dump "$HOME/sample-elf"
  gui "$arch flatpak window opens" flatpak run --arch="$arch" "$APP_ID" "$HOME/sample-elf"
done

echo "== snap"
check "arm64 snap installs" sudo snap install --dangerous "$DIST/${APP_NAME}_${V}_arm64.snap"
check "arm64 snap runs" dumps snap run bxplore --dump "$HOME/sample-elf"
gui "arm64 snap window opens" snap run bxplore "$HOME/sample-elf"
# The amd64 snap cannot be installed on this machine; look inside instead.
check "amd64 snap is for amd64" sh -c "unsquashfs -cat '$DIST/${APP_NAME}_${V}_amd64.snap' meta/snap.yaml | grep -q amd64"
check "amd64 snap holds an x86-64 executable" sh -c "rm -rf /tmp/sq && unsquashfs -q -d /tmp/sq '$DIST/${APP_NAME}_${V}_amd64.snap' bin/bxplore && file /tmp/sq/bin/bxplore | grep -q x86-64"

echo "== windows (inspected, not run)"
tool="$DIST/$APP_NAME-$V-linux-aarch64"
for arch in x64 arm64; do
  w=/tmp/win-$arch; rm -rf $w; mkdir -p $w
  check "$arch zip unpacks" unzip -q "$DIST/$APP_NAME-$V-windows-$arch-portable.zip" -d $w
  machine=$([ "$arch" = x64 ] && echo "AMD64" || echo "ARM64")
  check "$arch executable is a $machine GUI program" sh -c "'$tool' --dump $w/bxplore.exe | grep -q 'File Type.*$machine' && '$tool' --dump $w/bxplore.exe | grep -q 'Windows GUI'"
  check "$arch executable has icon and version resources" sh -c "$HOME/llvm-mingw/bin/llvm-readobj --coff-resources $w/bxplore.exe | grep -c 'GROUP_ICON\|VERSIONINFO' | grep -qx 2"
  # Only DLLs that are part of Windows: no compiler runtime to ship.
  check "$arch executable needs no runtime DLLs" sh -c "! $HOME/llvm-mingw/bin/llvm-objdump -p $w/bxplore.exe | grep 'DLL Name' | grep -qi 'libgcc\|libstdc\|libwinpthread\|libc++\|libunwind\|vcruntime\|msvcp'"
  check "$arch installer is an NSIS archive" sh -c "file '$DIST/$APP_NAME-$V-windows-$arch-setup.exe' | grep -q Nullsoft"
done

echo "== nix flake"
if [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
  export NIX_CONFIG="experimental-features = nix-command flakes"
  rm -rf "$HOME/flake-src" && mkdir "$HOME/flake-src"
  (cd "$ROOT" && tar -cf - --exclude=./target --exclude=./dist --exclude=./.git --exclude=./fuzz . | tar -xf - -C "$HOME/flake-src")
  cd "$HOME/flake-src"
  check "flake builds" nix build .#bxplore
  check "flake check" nix flake check
  check "flake program runs" dumps ./result/bin/bxplore --dump "$HOME/sample-elf"
  # Outside NixOS a Nix program does not see the system's graphics drivers;
  # nixGL supplies Mesa. On NixOS the program runs as it is.
  if [ -e /etc/NIXOS ]; then
    gui "flake window opens" ./result/bin/bxplore "$HOME/sample-elf"
  else
    check "nixGL builds" nix build --impure github:nix-community/nixGL#nixGLIntel -o "$HOME/nixgl"
    gui "flake window opens (through nixGL)" "$HOME/nixgl/bin/nixGLIntel" ./result/bin/bxplore "$HOME/sample-elf"
  fi
else
  echo "skip  nix is not installed"
fi

[ $fail = 0 ] && echo "ALL PASSED" || echo "SOME TESTS FAILED"
exit $fail
