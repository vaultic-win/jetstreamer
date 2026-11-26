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
if [[ $# == 1 && ( $1 == epoch166-retry11 || $1 == epoch170-retry11 || $1 == epoch170-retry12 || $1 == epoch170-retry13 || $1 == epoch166-after170 || $1 == epoch166-after168 || $1 == epoch166-after168-retry3 || $1 == epoch166-after168-closed || $1 == epoch166-after168-retry4 || $1 == epoch168-cold-rebook || $1 == epoch168-cold-retry3 || $1 == epoch168-cold-retry4 || $1 == epoch168-cold-retry5 || $1 == epoch168-cold-retry5-v13 || $1 == epoch168-cold-retry5-v10 ) ]]; then
    if [[ $1 == epoch170-* ]]; then epoch=170; fi
    retry=${1#*-}
    src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
    if [[ $retry == after168-retry4 ]]; then
        extra_cfg=(--cfg epoch166_after170 --cfg epoch166_after168 --cfg epoch166_after168_retry3 --cfg epoch166_after168_retry4)
        retry=retry11
    elif [[ $retry == after168-closed ]]; then
        extra_cfg=(--cfg epoch166_after170 --cfg epoch166_after168 --cfg epoch166_after168_retry3 --cfg epoch166_after168_closed)
        retry=retry11
    elif [[ $retry == after168-retry3 ]]; then
        extra_cfg=(--cfg epoch166_after170 --cfg epoch166_after168 --cfg epoch166_after168_retry3)
        retry=retry11
    elif [[ $retry == after168 ]]; then
        extra_cfg=(--cfg epoch166_after170 --cfg epoch166_after168)
        retry=retry11
    elif [[ $retry == after170 ]]; then
        retry=retry11
        extra_cfg=(--cfg epoch166_after170)
    fi
    date=20261122
    if [[ $retry == cold-retry5 || $retry == cold-retry5-v13 || $retry == cold-retry5-v10 ]]; then
        epoch=168
        date=20261125
        extra_cfg=(--cfg epoch168_cold_retry3 --cfg epoch168_cold_retry4 --cfg epoch168_cold_retry5)
        if [[ $retry == cold-retry5-v13 ]]; then extra_cfg+=(--cfg epoch168_cold_retry5_v13); fi
        if [[ $retry == cold-retry5-v10 ]]; then extra_cfg+=(--cfg epoch168_cold_retry5_v10); fi
        retry=retry5
    elif [[ $retry == cold-retry4 ]]; then
        epoch=168
        retry=retry4
        date=20261123
        extra_cfg=(--cfg epoch168_cold_retry3 --cfg epoch168_cold_retry4)
    elif [[ $retry == cold-retry3 ]]; then
        epoch=168
        retry=retry3
        date=20261123
        extra_cfg=(--cfg epoch168_cold_retry3)
    elif [[ $retry == cold-rebook ]]; then
        epoch=168
        retry=retry2
    fi
    base="/var/lib/jetstreamer/horizon_runtime_data/epoch${epoch}-$retry-rebook-${date}-v1"
    scratch=/home/sol/.jetstreamer-private/epoch168-extractor-build-20261120-v1/work
    test "$(findmnt -n -T "$scratch" -o SOURCE | sort -u)" = /dev/loop3
    cfg="epoch${epoch}_$retry"
    if [[ $epoch == 168 ]]; then cfg=epoch168_cold_rebook; fi
else
    test $# == 0
fi
stage="$base/session-build-$INVOCATION_ID"
out="$scratch/tmp/incident-${epoch}-session-$INVOCATION_ID"
group="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
test "$(cat "$group/cpu.max")" = '100000 100000'
memory_max=536870912
if [[ $epoch == 168 ]]; then memory_max=1073741824; fi
test "$(cat "$group/memory.max")" = "$memory_max"
test "$(cat "$group/memory.swap.max")" = '0'
test "$(findmnt -n -T "$work" -o SOURCE | sort -u)" = /dev/loop4
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
if [[ ${1:-} == epoch166-after168* ]]; then
    cp --parents "$own/after168.rs" "$out"
fi
if [[ $cfg == epoch166_retry11 || $epoch == 170 ]]; then
    cp --parents "$own/retry11.rs" "$out"
fi
if [[ $epoch == 168 ]]; then
    cp --parents scripts/horizon_epoch168_full_metered_20261121_v1/{cold168.rs,gate.py} "$out"
fi
if [[ $epoch == 170 ]]; then
    cp --parents scripts/horizon_epoch170_guard_recovery_20261121_v1/*.rs "$out"
fi
cd "$out"
find scripts -type f -print0 | sort -z | xargs -0 sha256sum > "$stage/sources"
args=(--edition=2024 -C opt-level=1 -C codegen-units=4 -C strip=symbols -C linker=clang -C link-arg=-fuse-ld=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld -C link-arg=-Wl,--threads=1 -L "dependency=$deps")
for lib in anyhow-fcfd55939853d71f serde-8c11d906d3ff8a0b serde_json-c069c0f2e8c082ee libc-298e6c33c74760e9 sha2-917ab732b7d88cc0 tempfile-20415c3ecef1c5dd; do args+=(--extern "${lib%-*}=$deps/lib$lib.rlib"); done
if [[ ${1:-} == epoch166-after168-retry3 || ${1:-} == epoch166-after168-closed || ${1:-} == epoch166-after168-retry4 ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry3-v1/deployment-seal-receipt.json
    if [[ $1 == epoch166-after168-closed ]]; then
        provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-closed168-retry3-v1/deployment-seal-receipt.json
    fi
    writer=/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry3-v1/deployment-seal-receipt.json
    deployments=retry3-deployments
    if [[ $1 == epoch166-after168-retry4 ]]; then
        provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry4-v1/deployment-seal-receipt.json
        writer=/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry4-v1/deployment-seal-receipt.json
        deployments=retry4-deployments
    fi
    sha256sum "$provider" "$writer" > "$stage/$deployments"
    RETRY3_FIT_SEAL=$(sha256sum "$provider" | cut -d' ' -f1)
    RETRY3_WRITER_SEAL=$(sha256sum "$writer" | cut -d' ' -f1)
    export RETRY3_FIT_SEAL RETRY3_WRITER_SEAL
fi
ulimit -c 0
rustc "${args[@]}" "${extra_cfg[@]}" --cfg "$cfg" --test "$shared/main.rs" -o "$out/tests$epoch"
"$out/tests$epoch" --test-threads=1
if [[ ${1:-} == epoch166-after168* ]]; then
    rustc "${args[@]}" --cfg epoch166_retry11 --cfg epoch166_after170 --test "$shared/main.rs" -o "$out/tests166-after170"
    "$out/tests166-after170" --test-threads=1
fi
if [[ ${1:-} == epoch168-cold-retry5 || ${1:-} == epoch168-cold-retry5-v13 || ${1:-} == epoch168-cold-retry5-v10 ]]; then
    rustc "${args[@]}" --cfg epoch168_cold_rebook --cfg epoch168_cold_retry3 --cfg epoch168_cold_retry4 --test "$shared/main.rs" -o "$out/tests168-prior"
    "$out/tests168-prior" --test-threads=1
elif [[ ${1:-} == epoch168-cold-retry4 ]]; then
    rustc "${args[@]}" --cfg epoch168_cold_rebook --cfg epoch168_cold_retry3 --test "$shared/main.rs" -o "$out/tests168-prior"
    "$out/tests168-prior" --test-threads=1
elif [[ ${1:-} == epoch168-cold-retry3 ]]; then
    rustc "${args[@]}" --cfg epoch168_cold_rebook --test "$shared/main.rs" -o "$out/tests168-prior"
    "$out/tests168-prior" --test-threads=1
elif [[ ${#extra_cfg[@]} -gt 0 ]]; then
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
