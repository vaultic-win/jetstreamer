#!/bin/bash
set -euo pipefail
umask 077
src=/home/sol/.jetstreamer-private/public-method-20261120/status-retry-source
work=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/current-nodes-136-169-20261120-g2
base=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-guard-20261121-v1
stage=$base/build-$INVOCATION_ID
out=$work/tmp/incident-guard-$INVOCATION_ID
group=/sys/fs/cgroup/system.slice/horizon-incident-native-guard-build-v2.service
test "$(cat "$group/cpu.max")" = '100000 100000'
test "$(cat "$group/memory.max")" = '1073741824'
test "$(cat "$group/memory.swap.max")" = '0'
test "$(findmnt -n -T "$work" -o SOURCE)" = /dev/loop4
test "$(df -B1 --output=avail "$work" | tail -1)" -gt 100663296
mkdir -p -m0700 "$base"
mkdir -m0700 "$stage" "$out" "$out/tmp"
exec > "$stage/build.log" 2>&1
deps=$work/target/release/deps
export TMPDIR=$out/tmp
export PATH=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin
cd "$src"
g=scripts/horizon_cold166_20261120_v1/guard
f=scripts/horizon_retry8_166_20261119_v1/guard/external
cp --parents "$g"/{guard_main.rs,data_fulfillment.rs,Cargo.toml,Cargo.lock} "$f"/* scripts/horizon_epoch166_guard_recovery_20261121_v1/incident_guard.rs "$out"
cd "$out"
find scripts -type f -print0 | sort -z | xargs -0 sha256sum > "$stage/sources"
args=(--edition=2024 --cfg 'feature="incident-recovery"' -C opt-level=0 -C codegen-units=4 -C strip=symbols -C linker=clang -C link-arg=-fuse-ld=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld -C link-arg=-Wl,--threads=1 -L "dependency=$deps")
for lib in anyhow-fcfd55939853d71f serde-8c11d906d3ff8a0b serde_json-c069c0f2e8c082ee libc-298e6c33c74760e9 sha2-917ab732b7d88cc0 tempfile-20415c3ecef1c5dd; do args+=(--extern "${lib%-*}=$deps/lib$lib.rlib"); done
ulimit -c 0
rustc "${args[@]}" --test "$g/guard_main.rs" -o "$out/tests"
"$out/tests" --test-threads=1
"$out/tests" --ignored --exact data_fulfillment::incident::tests::original_namespace_receipts_and_all_precreated_roots --test-threads=1
rustc "${args[@]}" -C opt-level=2 "$g/guard_main.rs" -o "$out/guard"
sha256sum "$out"/{guard,tests} > "$stage/artifacts"
cat /proc/sys/kernel/random/boot_id > "$stage/boot-id"
printf '%s\n' "$out" > "$stage/build-dir"
