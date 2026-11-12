#!/usr/bin/env bash
# Assembles the landing page into _site/ (or the directory given as $1).
#
# The page itself lives in site/. The screenshots and the icon are not copied
# into site/: they are taken from docs/screenshots/ and packaging/icons/ at
# build time, so the README and the page always show the same images.
#
#   site/build.sh                        # build into ./_site
#   python3 -m http.server -d _site      # preview at http://localhost:8000
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$repo/_site}"

rm -rf "$out"
mkdir -p "$out/assets/screenshots"

cp "$repo/site/index.html" "$repo/site/style.css" "$repo/site/main.js" "$out/"
cp "$repo"/docs/screenshots/*.png "$out/assets/screenshots/"
cp "$repo/packaging/icons/bxplore.svg" "$out/assets/icon.svg"
touch "$out/.nojekyll"

# Fail when the page references an asset the build did not produce.
missing=0
for ref in $(grep -oE '(src|href)="assets/[^"]+"' "$out/index.html" | sed -E 's/^[a-z]+="//; s/"$//' | sort -u); do
  if [ ! -f "$out/$ref" ]; then echo "missing asset: $ref" >&2; missing=1; fi
done
for f in $(grep -oE '"[a-z-]+\.png"' "$out/main.js" | tr -d '"' | sort -u); do
  if [ ! -f "$out/assets/screenshots/$f" ]; then echo "missing screenshot: $f" >&2; missing=1; fi
done
[ "$missing" -eq 0 ]

echo "site built in $out"
