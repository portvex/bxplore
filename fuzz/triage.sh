#!/bin/sh
# Replays every saved crash input and prints the distinct failure locations.
cd "$(dirname "$0")/.."
bin=fuzz/target/$(rustc -vV | sed -n 's/^host: //p')/release
for t in parse_any parse_each pe_edit resource_previews elf_edit macho_edit queries decoders; do
    for f in fuzz/artifacts/$t/*; do
        [ -f "$f" ] || continue
        "$bin/$t" -rss_limit_mb=2048 -timeout=10 "$f" 2>&1 | grep -E "panicked at|ERROR: " -A1 | head -2 | paste - - | sed -E "s/thread '[^']*' \([0-9]+\) //; s/==[0-9]+==//; s|$PWD/||"
    done | sort | uniq -c | sort -rn | sed "s|^|$t: |"
done
