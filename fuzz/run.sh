#!/bin/sh
# Runs one libFuzzer target, or all of them, for a limited time.
#   fuzz/run.sh [target|all] [seconds]
# cargo-fuzz needs a nightly toolchain (rustup toolchain install nightly) and
# cargo-fuzz itself (cargo install cargo-fuzz). The nightly tools are put first
# on PATH so this also works when another cargo shadows the rustup proxy.
set -e
cd "$(dirname "$0")/.."
target=${1:-all}
seconds=${2:-60}
nightly=$(rustup run nightly rustc --print sysroot)/bin
PATH="$nightly:$PATH"
export PATH
[ "$target" = all ] && target="parse_any parse_each pe_edit resource_previews elf_edit macho_edit queries decoders"
status=0
for t in $target; do
    echo "=== $t (${seconds}s)"
    mkdir -p "fuzz/corpus/$t" "fuzz/seeds/$t"
    cargo fuzz run "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- -max_total_time="$seconds" -max_len=16384 -timeout=10 || status=1
done
[ $status -eq 0 ] || echo "A target crashed. The input is in fuzz/artifacts; move it to fuzz/regressions once fixed."
exit $status
