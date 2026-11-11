#!/usr/bin/env bash
# Regenerates the PNG and ICO icons from bxplore.svg. Needs rsvg-convert and
# icotool (both are in the packaging VM). The macOS .icns is made from the
# PNGs by packaging/macos/build.sh with iconutil.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here}"
for s in 16 32 48 64 128 256 512 1024; do
  rsvg-convert -w "$s" -h "$s" "$here/bxplore.svg" -o "$out/bxplore-$s.png"
done
icotool -c -o "$out/bxplore.ico" "$out"/bxplore-{16,32,48,64,256}.png
