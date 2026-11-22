#!/bin/bash
set -euo pipefail
umask 077
src=/home/sol/.jetstreamer-private/public-method-20261120/status-retry-source
work=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/current-nodes-136-169-20261120-g2
base=/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-recovery-20261121-v1
scratch=$work
cfg=epoch166_recovery
epoch=166
extra_cfg=()
if [[ $# == 1 && ( $1 == epoch166-retry11 || $1 == epoch170-retry11 || $1 == epoch170-retry12 || $1 == epoch170-retry13 || $1 == epoch166-after170 ) ]]; then
    if [[ $1 == epoch170-* ]]; then epoch=170; fi
    retry=${1#*-}
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    if [[ $retry == after170 ]]; then
        retry=retry11
        extra_cfg=(--cfg epoch166_after170)
    fi
    base="/var/lib/jetstreamer/horizon_runtime_data/epoch${epoch}-$retry-rebook-20261122-v1"
    scratch=/home/sol/.jetstreamer-private/epoch168-extractor-build-20261120-v1/work
    test "$(findmnt -n -T "$scratch" -o SOURCE)" = /dev/loop3
    cfg="epoch${epoch}_$retry"
else
    test $# == 0
fi
stage="$base/session-build-$INVOCATION_ID"
out="$scratch/tmp/incident-${epoch}-session-$INVOCATION_ID"
group="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
test "$(cat "$group/cpu.max")" = '100000 100000'
test "$(cat "$group/memory.max")" = '536870912'
test "$(cat "$group/memory.swap.max")" = '0'
test "$(findmnt -n -T "$work" -o SOURCE)" = /dev/loop4
test "$(df -B1 --output=avail "$scratch" | tail -1)" -gt 50331648
mkdir -m0700 "$stage" "$out" "$out/tmp"
exec > "$stage/build.log" 2>&1
deps="$work/target/release/deps"
export TMPDIR="$out/tmp"
export PATH=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin
cd "$src"
shared=scripts/horizon_epoch167_source_index_recovery_20261121_v1
own=scripts/horizon_epoch166_guard_recovery_20261121_v1
cp --parents "$shared"/*.rs "$own/source166.rs" "$own/build-session.sh" "$out"
if [[ $cfg == epoch166_retry11 || $epoch == 170 ]]; then
    cp --parents "$own/retry11.rs" "$out"
fi
if [[ $epoch == 170 ]]; then
    cp --parents scripts/horizon_epoch170_guard_recovery_20261121_v1/*.rs "$out"
fi
cd "$out"
find scripts -type f -print0 | sort -z | xargs -0 sha256sum > "$stage/sources"
args=(--edition=2024 -C opt-level=1 -C codegen-units=4 -C strip=symbols -C linker=clang -C link-arg=-fuse-ld=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld -C link-arg=-Wl,--threads=1 -L "dependency=$deps")
for lib in anyhow-fcfd55939853d71f serde-8c11d906d3ff8a0b serde_json-c069c0f2e8c082ee libc-298e6c33c74760e9 sha2-917ab732b7d88cc0 tempfile-20415c3ecef1c5dd; do args+=(--extern "${lib%-*}=$deps/lib$lib.rlib"); done
ulimit -c 0
rustc "${args[@]}" "${extra_cfg[@]}" --cfg "$cfg" --test "$shared/main.rs" -o "$out/tests$epoch"
"$out/tests$epoch" --test-threads=1
if [[ ${#extra_cfg[@]} -gt 0 ]]; then
    rustc "${args[@]}" --cfg epoch166_retry11 --test "$shared/main.rs" -o "$out/tests166-prior"
    "$out/tests166-prior" --test-threads=1
fi
if [[ $cfg == epoch170_retry13 ]]; then
    rustc "${args[@]}" --cfg epoch170_retry12 --test "$shared/main.rs" -o "$out/tests170-retry12"
    "$out/tests170-retry12" --test-threads=1
fi
if [[ $cfg == epoch170_retry12 || $cfg == epoch170_retry13 ]]; then
    rustc "${args[@]}" --cfg epoch170_retry11 --test "$shared/main.rs" -o "$out/tests170-prior"
    "$out/tests170-prior" --test-threads=1
fi
if [[ $epoch == 170 ]]; then
    rustc "${args[@]}" --cfg epoch166_retry11 --test "$shared/main.rs" -o "$out/tests166"
    "$out/tests166" --test-threads=1
fi
if [[ $cfg == epoch166_recovery ]]; then
    rustc "${args[@]}" --test "$shared/main.rs" -o "$out/tests167"
    "$out/tests167" --test-threads=1
fi
rustc "${args[@]}" "${extra_cfg[@]}" --cfg "$cfg" "$shared/main.rs" -o "$out/recover$epoch"
sha256sum "$out"/recover"$epoch" "$out"/tests1* > "$stage/artifacts"
printf '%s\n' "$out" > "$stage/build-dir"
if [[ $cfg == epoch166_recovery ]]; then "$out/recover166" prepare; fi
