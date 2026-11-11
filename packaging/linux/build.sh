#!/usr/bin/env bash
# Builds the Linux packages for x86_64 and aarch64 into dist/:
#   bxplore-<version>-linux-<arch>            the standalone executable
#   bxplore-<version>-linux-<arch>.tar.gz     the same with icon, desktop file and README
#   bxplore-<version>-linux-<arch>.flatpak
#   bxplore_<version>_<arch>.snap
# Runs inside the packaging VM (see packaging/vm.sh); the source tree may be
# read-only. Pick parts with: build.sh [bin] [flatpak] [snap]
# and architectures with ARCHS="x86_64 aarch64" (the default).
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/../common.sh"
[ ! -f "$HOME/.cargo/env" ] || . "$HOME/.cargo/env"
export PATH="$HOME/zig:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/target}"
DIST="${DIST:-$ROOT/dist}"
WORK="$HOME/work/linux"
# The oldest glibc the executable accepts: 2.17 is CentOS 7, from 2014.
GLIBC="${GLIBC:-2.17}"
parts="${*:-bin flatpak snap}"
ARCHS="${ARCHS:-x86_64 aarch64}"
mkdir -p "$DIST"

stage() { # stage <arch>: the files every package takes
  local arch="$1" s="$WORK/$1/stage"
  rm -rf "$s" && mkdir -p "$s"
  cp "$DIST/$APP_NAME-$APP_VERSION-linux-$arch" "$s/bxplore"
  chmod 755 "$s/bxplore"
  cp "$ROOT/packaging/icons/bxplore-256.png" "$s/icon-256.png"
  cp "$ROOT/packaging/icons/bxplore-512.png" "$s/icon-512.png"
  cp "$ROOT/packaging/icons/bxplore.svg" "$s/icon.svg"
  sed -e "s/@VERSION@/$APP_VERSION/" -e "s/@DATE@/$(date -u +%F)/" "$ROOT/packaging/linux/metainfo.xml" > "$s/metainfo.xml"
}

for arch in $ARCHS; do
  bin="$DIST/$APP_NAME-$APP_VERSION-linux-$arch"
  if [[ " $parts " == *" bin "* ]]; then
    (cd "$ROOT" && cargo zigbuild --locked --profile standalone --target "$arch-unknown-linux-gnu.$GLIBC")
    cp "$CARGO_TARGET_DIR/$arch-unknown-linux-gnu/standalone/$APP_NAME" "$bin"
    t="$WORK/$arch/tar/$APP_NAME-$APP_VERSION"
    rm -rf "$WORK/$arch/tar" && mkdir -p "$t"
    cp "$bin" "$t/bxplore"
    cp "$ROOT/packaging/linux/bxplore.desktop" "$ROOT/README.md" "$t/"
    sed -i "s/^Icon=.*/Icon=bxplore/" "$t/bxplore.desktop"
    cp "$ROOT/packaging/icons/bxplore-256.png" "$t/bxplore.png"
    tar -C "$WORK/$arch/tar" -czf "$bin.tar.gz" "$APP_NAME-$APP_VERSION"
    echo "built $bin and $bin.tar.gz"
  fi

  if [[ " $parts " == *" flatpak "* ]]; then
    stage "$arch"
    cp "$ROOT/packaging/linux/bxplore.desktop" "$WORK/$arch/stage/bxplore.desktop"
    sed "s/@ID@/$APP_ID/g" "$ROOT/packaging/linux/flatpak.yml.in" > "$WORK/$arch/$APP_ID.yml"
    (cd "$WORK/$arch" && flatpak-builder --user --force-clean --disable-rofiles-fuse --arch="$arch" --repo=repo build "$APP_ID.yml" \
      && flatpak build-bundle --arch="$arch" repo "$DIST/$APP_NAME-$APP_VERSION-linux-$arch.flatpak" "$APP_ID")
    echo "built $DIST/$APP_NAME-$APP_VERSION-linux-$arch.flatpak"
  fi

  if [[ " $parts " == *" snap "* ]]; then
    stage "$arch"
    sarch=$([ "$arch" = x86_64 ] && echo amd64 || echo arm64)
    sed -e "s/^Icon=.*/Icon=\${SNAP}\/meta\/gui\/icon.png/" "$ROOT/packaging/linux/bxplore.desktop" > "$WORK/$arch/stage/bxplore.desktop"
    mkdir -p "$WORK/$arch/snap"
    sed -e "s/@VERSION@/$APP_VERSION/g" -e "s/@SNAP_ARCH@/$sarch/g" "$ROOT/packaging/linux/snapcraft.yaml.in" > "$WORK/$arch/snap/snapcraft.yaml"
    # `sg` picks up the lxd group without a new login.
    (cd "$WORK/$arch" && rm -f ./*.snap && sg lxd -c "snapcraft pack --build-for $sarch")
    cp "$WORK/$arch/${APP_NAME}_${APP_VERSION}_$sarch.snap" "$DIST/"
    echo "built $DIST/${APP_NAME}_${APP_VERSION}_$sarch.snap"
  fi
done
