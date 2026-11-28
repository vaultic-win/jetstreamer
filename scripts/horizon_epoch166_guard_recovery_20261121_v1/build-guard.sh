#!/bin/bash
set -euo pipefail
umask 077
src=/home/sol/.jetstreamer-private/public-method-20261120/status-retry-source
work=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/current-nodes-136-169-20261120-g2
base=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-guard-20261121-v1
group=/sys/fs/cgroup/system.slice/horizon-incident-native-guard-build-v2.service
features=(--cfg 'feature="incident-recovery"')
if [[ ${1:-} == epoch167-cold-v3 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch167-cold-guard-20261122-v3
    group=/sys/fs/cgroup/system.slice/horizon-167-cold-guard-v3-build.service
    features+=(--cfg 'feature="epoch167-cold-v3"')
elif [[ ${1:-} == epoch168-cold-v2 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261122-v2
    group=/sys/fs/cgroup/system.slice/horizon-168-cold-guard-v2-build.service
    features+=(--cfg 'feature="epoch168-cold-v2"')
elif [[ ${1:-} == epoch168-cold-v3 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261123-v3
    group=/sys/fs/cgroup/system.slice/horizon-168-cold-guard-v3-build.service
    features+=(--cfg 'feature="epoch168-cold-v3"')
elif [[ ${1:-} == epoch168-cold-v4 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261123-v4
    group=/sys/fs/cgroup/system.slice/horizon-168-cold-guard-v4-build.service
    features+=(--cfg 'feature="epoch168-cold-v4"')
elif [[ ${1:-} == epoch168-cold-v5 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261125-v5
    group=/sys/fs/cgroup/system.slice/horizon-168-cold-guard-v5-build.service
    features+=(--cfg 'feature="epoch168-cold-v5"')
elif [[ ${1:-} == epoch168-cold-v6 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261126-v6
    group=/sys/fs/cgroup/system.slice/horizon-168-cold-guard-v6-build.service
    features+=(--cfg 'feature="epoch168-cold-v6"' --cfg 'feature="root-budget-fd"')
elif [[ ${1:-} == epoch166-retry11 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry11-guard-20261122-v1
    group=/sys/fs/cgroup/system.slice/horizon-166-retry11-guard-build.service
    features+=(--cfg 'feature="epoch166-retry11"')
elif [[ ${1:-} == epoch170-retry11 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry11-guard-20261122-v1
    group=/sys/fs/cgroup/system.slice/horizon-170-retry11-guard-build.service
    features+=(--cfg 'feature="epoch170-retry11"')
elif [[ ${1:-} == epoch170-retry12 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry12-guard-20261122-v1
    group=/sys/fs/cgroup/system.slice/horizon-170-retry12-guard-build.service
    features+=(--cfg 'feature="epoch170-retry12"')
elif [[ ${1:-} == epoch170-retry13 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry13-guard-20261122-v1
    group=/sys/fs/cgroup/system.slice/horizon-170-retry13-guard-build.service
    features+=(--cfg 'feature="epoch170-retry13"')
elif [[ ${1:-} == epoch170-384 && $# == 1 ]]; then
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    base=/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry10-guard384-20261121-v1
    group=/sys/fs/cgroup/system.slice/horizon-170-retry10-guard384-build.service
    features+=(--cfg 'feature="epoch170-384"')
else
    test $# == 0
fi
stage=$base/build-$INVOCATION_ID
out=$work/tmp/incident-guard-$INVOCATION_ID
test "$(cat "$group/cpu.max")" = '100000 100000'
test "$(cat "$group/memory.max")" = '1073741824'
test "$(cat "$group/memory.swap.max")" = '0'
test "$(findmnt -n -T "$work" -o SOURCE)" = /dev/loop4
if [[ ${1:-} == epoch168-cold-v6 || ${1:-} == epoch168-cold-v5 || ${1:-} == epoch168-cold-v4 || ${1:-} == epoch168-cold-v3 || ${1:-} == epoch168-cold-v2 || ${1:-} == epoch167-cold-v3 || ${1:-} == epoch166-retry11 || ${1:-} == epoch170-retry11 || ${1:-} == epoch170-retry12 || ${1:-} == epoch170-retry13 ]]; then
    # Reuse the already allocated compiler filesystem for intermediates. Leave the
    # older read-only dependency filesystem and its remaining free space alone.
    scratch=/home/sol/.jetstreamer-private/epoch168-extractor-build-20261120-v1/work
    test "$(findmnt -n -T "$scratch" -o SOURCE | sort -u)" = /dev/loop3
    out=$scratch/$1-guard-$INVOCATION_ID
else
    scratch=$work
fi
test "$(df -B1 --output=avail "$scratch" | tail -1)" -gt 100663296
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
if [[ ${1:-} == epoch168-cold-v6 ]]; then
    cp --parents "$g/root_budget_fd.rs" "$out"
fi
cd "$out"
find scripts -type f -print0 | sort -z | xargs -0 sha256sum > "$stage/sources"
args=(--edition=2024 "${features[@]}" -C opt-level=0 -C codegen-units=4 -C strip=symbols -C linker=clang -C link-arg=-fuse-ld=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld -C link-arg=-Wl,--threads=1 -L "dependency=$deps")
for lib in anyhow-fcfd55939853d71f serde-8c11d906d3ff8a0b serde_json-c069c0f2e8c082ee libc-298e6c33c74760e9 sha2-917ab732b7d88cc0 tempfile-20415c3ecef1c5dd; do args+=(--extern "${lib%-*}=$deps/lib$lib.rlib"); done
ulimit -c 0
rustc "${args[@]}" --test "$g/guard_main.rs" -o "$out/tests"
"$out/tests" --test-threads=1
"$out/tests" --ignored --exact data_fulfillment::incident::tests::original_namespace_receipts_and_all_precreated_roots --test-threads=1
rustc "${args[@]}" -C opt-level=2 "$g/guard_main.rs" -o "$out/guard"
sha256sum "$out"/{guard,tests} > "$stage/artifacts"
cat /proc/sys/kernel/random/boot_id > "$stage/boot-id"
printf '%s\n' "$out" > "$stage/build-dir"
