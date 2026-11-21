#!/bin/bash
set -euo pipefail
umask 077
src=/home/sol/.jetstreamer-private/public-method-20261120/status-retry-source
work=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/current-nodes-136-169-20261120-g2
base=/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-recovery-20261121-v1
stage="$base/session-build-$INVOCATION_ID"
out="$work/tmp/incident-166-session-$INVOCATION_ID"
group="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
test "$(cat "$group/cpu.max")" = '100000 100000'
test "$(cat "$group/memory.max")" = '536870912'
test "$(cat "$group/memory.swap.max")" = '0'
test "$(findmnt -n -T "$work" -o SOURCE)" = /dev/loop4
test "$(df -B1 --output=avail "$work" | tail -1)" -gt 50331648
mkdir -m0700 "$stage" "$out" "$out/tmp"
exec > "$stage/build.log" 2>&1
deps="$work/target/release/deps"
export TMPDIR="$out/tmp"
export PATH=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin
cd "$src"
shared=scripts/horizon_epoch167_source_index_recovery_20261121_v1
own=scripts/horizon_epoch166_guard_recovery_20261121_v1
cp --parents "$shared"/*.rs "$own/source166.rs" "$own/build-session.sh" "$out"
cd "$out"
find scripts -type f -print0 | sort -z | xargs -0 sha256sum > "$stage/sources"
args=(--edition=2024 -C opt-level=1 -C codegen-units=4 -C strip=symbols -C linker=clang -C link-arg=-fuse-ld=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld -C link-arg=-Wl,--threads=1 -L "dependency=$deps")
for lib in anyhow-fcfd55939853d71f serde-8c11d906d3ff8a0b serde_json-c069c0f2e8c082ee libc-298e6c33c74760e9 sha2-917ab732b7d88cc0 tempfile-20415c3ecef1c5dd; do args+=(--extern "${lib%-*}=$deps/lib$lib.rlib"); done
ulimit -c 0
rustc "${args[@]}" --cfg epoch166_recovery --test "$shared/main.rs" -o "$out/tests166"
"$out/tests166" --test-threads=1
rustc "${args[@]}" --test "$shared/main.rs" -o "$out/tests167"
"$out/tests167" --test-threads=1
rustc "${args[@]}" --cfg epoch166_recovery "$shared/main.rs" -o "$out/recover166"
sha256sum "$out"/{recover166,tests166,tests167} > "$stage/artifacts"
printf '%s\n' "$out" > "$stage/build-dir"
"$out/recover166" prepare
