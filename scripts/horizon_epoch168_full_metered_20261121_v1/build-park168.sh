#!/usr/bin/env bash
# Compile the copy-only operator against the same sealed replay inputs as recover166.
set -euo pipefail
umask 077
case "${2:-original}" in
    original) profile=() ;;
    retry4) profile=(--cfg park168_retry4) ;;
    *) exit 2 ;;
esac
test "$#" -ge 1 && test "$#" -le 2
out=$1
mkdir -p -- "$out/tmp"
export TMPDIR="$out/tmp"
rust=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu
deps=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/current-nodes-136-169-20261120-g2/target/release/deps
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
args=("${profile[@]}" --edition=2024 --cfg epoch166_retry11 --cfg epoch166_after170 -C opt-level=1 -C strip=symbols -C codegen-units=4 -C linker=clang -C "link-arg=-fuse-ld=$rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld" -C link-arg=-Wl,--threads=1 -L "dependency=$deps")
for lib in anyhow-fcfd55939853d71f serde-8c11d906d3ff8a0b serde_json-c069c0f2e8c082ee libc-298e6c33c74760e9 sha2-917ab732b7d88cc0 tempfile-20415c3ecef1c5dd; do
    args+=(--extern "${lib%-*}=$deps/lib$lib.rlib")
done
"$rust/bin/rustc" "${args[@]}" --test "$src/park168.rs" -o "$out/park168-tests"
"$out/park168-tests" --test-threads=1 holding_entry
"$rust/bin/rustc" "${args[@]}" "$src/park168.rs" -o "$out/park168"
