#!/usr/bin/env bash
# Installs the build and test tools inside the Ubuntu VM. Run by packaging/vm.sh.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -q
sudo apt-get install -y -q build-essential clang lld curl xz-utils zip unzip file \
  mingw-w64 nsis \
  flatpak flatpak-builder \
  xvfb xauth libgl1-mesa-dri libegl1 libgl1 libxkbcommon0 libxkbcommon-x11-0 libwayland-client0 libx11-6 libxcursor1 libxi6 libxrandr2 \
  librsvg2-bin icoutils squashfs-tools desktop-file-utils appstream

# Rust with the targets the packages are built for.
if ! command -v rustup >/dev/null && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
. "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
  x86_64-pc-windows-gnu aarch64-pc-windows-gnullvm

# Zig links the Linux builds against an old glibc, so they run on old and new
# distributions alike.
ZIG_VERSION=0.13.0
if [ ! -x "$HOME/zig/zig" ]; then
  curl -sSfL "https://ziglang.org/download/$ZIG_VERSION/zig-linux-$(uname -m)-$ZIG_VERSION.tar.xz" -o /tmp/zig.tar.xz
  mkdir -p "$HOME/zig" && tar -xf /tmp/zig.tar.xz -C "$HOME/zig" --strip-components=1
fi
command -v cargo-zigbuild >/dev/null || cargo install --locked cargo-zigbuild

# llvm-mingw: the linker and C compiler for Windows on ARM64.
LLVM_MINGW=20250114
if [ ! -d "$HOME/llvm-mingw" ]; then
  curl -sSfL "https://github.com/mstorsjo/llvm-mingw/releases/download/$LLVM_MINGW/llvm-mingw-$LLVM_MINGW-ucrt-ubuntu-20.04-$(uname -m).tar.xz" -o /tmp/llvm-mingw.tar.xz
  mkdir -p "$HOME/llvm-mingw" && tar -xf /tmp/llvm-mingw.tar.xz -C "$HOME/llvm-mingw" --strip-components=1
fi

# Flatpak runtime for both architectures (the x86_64 one runs through Rosetta).
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
for arch in aarch64 x86_64; do
  flatpak install --user -y --noninteractive --arch="$arch" flathub org.freedesktop.Platform//25.08 org.freedesktop.Sdk//25.08
done

# snapcraft builds inside an LXD container.
sudo snap install snapcraft --classic
sudo snap install lxd
sudo usermod -aG lxd "$USER"
sudo lxd init --auto
# Nix, for the flake.
if [ ! -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  curl -sSfL https://nixos.org/nix/install | sh -s -- --daemon --yes
fi
echo "VM setup done"
