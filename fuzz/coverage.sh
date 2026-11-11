#!/bin/sh
# Line coverage of the library reached by the fuzz corpus and seeds.
#   fuzz/coverage.sh [target|all]
# Writes fuzz/coverage/<target>.txt (per file summary) and prints the totals.
# Needs: rustup component add llvm-tools-preview --toolchain nightly
set -e
cd "$(dirname "$0")/.."
target=${1:-all}
sysroot=$(rustup run nightly rustc --print sysroot)
PATH="$sysroot/bin:$PATH"
export PATH
host=$(rustc -vV | sed -n 's/^host: //p')
cov="$sysroot/lib/rustlib/$host/bin/llvm-cov"
if [ ! -x "$cov" ]; then
    echo "llvm-cov is missing; run: rustup component add llvm-tools-preview --toolchain nightly" >&2
    exit 2
fi
[ "$target" = all ] && target="parse_any parse_each pe_edit resource_previews elf_edit macho_edit queries decoders structured differential"
mkdir -p fuzz/coverage
for t in $target; do
    mkdir -p "fuzz/corpus/$t" "fuzz/seeds/$t"
    # One directory only: cargo-fuzz writes the profile of each directory it is
    # given to the same file, so the last one (often the few seeds) would win.
    all=$(mktemp -d)
    cp fuzz/corpus/$t/* fuzz/seeds/$t/* "$all/" 2>/dev/null || true
    rm -rf "fuzz/coverage/$t"
    if ! cargo fuzz coverage "$t" "$all" > "fuzz/coverage/$t.log" 2>&1; then
        echo "$t: cargo fuzz coverage failed, see fuzz/coverage/$t.log" >&2
        rm -rf "$all"
        continue
    fi
    rm -rf "$all"
    # cargo-fuzz versions differ in where they put the instrumented binary.
    bin="target/$host/coverage/$host/release/$t"
    [ -x "$bin" ] || bin="fuzz/target/$host/coverage/$host/release/$t"
    "$cov" report "$bin" \
        -instr-profile="fuzz/coverage/$t/coverage.profdata" \
        -ignore-filename-regex='(\.cargo|rustc|fuzz_targets)' > "fuzz/coverage/$t.txt"
    printf '%-18s %s\n' "$t" "$(awk '/^TOTAL/ {print "lines " $10 ", regions " $4 ", functions " $7}' "fuzz/coverage/$t.txt")"
done
echo "Per file numbers are in fuzz/coverage/<target>.txt"
