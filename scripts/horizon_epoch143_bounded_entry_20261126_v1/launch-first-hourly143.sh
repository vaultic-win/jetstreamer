#!/usr/bin/env bash
set -euo pipefail
umask 077

a=/var/lib/jetstreamer/horizon_runtime_data/epoch143-first-hourly-20261127-v1
run=/home/sol/.jetstreamer-private/epoch143-first-hourly-20261127-v1
view=/run/horizon143-first-hourly
unit=horizon-qualify-143-first-hourly-20261127-v1.service
guard_unit=horizon-guard-143-first-hourly-20261127-v1
writer=horizon-archive-status-cadence-after172-20261120-v1.service
contract="$a/contract-v1/LAUNCH_PROFILE.json"
contract_sha=84e2846e7c33a1a6b7793861f918344be2af10d8132dc380450345f59903a19f
source="$a/inputs-v1/SOURCE_REFERENCE.json"
guard="$a/tools-v1/guard"
guard_sha=dfea30dafc769c5af59cce61137fb73b70665de2abab05c747dbc32de641dc96
gate="$a/tools-v1/hold-143"
b=${1:?Pass the writer booking}
bsha=${2:?Pass its verified SHA-256}

sha() { sha256sum "$1" | cut -d ' ' -f1; }
value() { systemctl show "$1" -p "$2" --value; }

publish() {
    local out=$1 temp
    temp=$(mktemp "${out%/*}/.pending-XXXXXX")
    cat > "$temp"
    chmod 0444 "$temp"
    sync "$temp"
    mv -nT "$temp" "$out"
    test ! -e "$temp"
    python3 - "${out%/*}" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

writer_live() {
    test "$(value "$writer" InvocationID)" = "$writer_iid"
    test "$(value "$writer" ActiveState)" = active
    test "$(value "$timer" InvocationID)" = "$timer_iid"
    test "$(value "$timer" SubState)" = waiting
    test "$(sha "$fleet")" = "$fleet_sha"
}

screen() {
    local output=$1
    shift
    "$price" "$fleet" "$fleet_sha" "$@" | publish "$output"
    jq -e --arg fleet "$fleet" --arg sha "$fleet_sha" '
        .fleet=={path:$fleet,sha256:$sha} and .disk_fits and .memory_fits
        and .resource_credit_bytes==0 and .candidate_home_bytes==68786585600
        and .candidate_ram_bytes==44023414784 and .candidate_cpu_quota_micros==3000000
        and .available_home_bytes>=.retained_required_home_bytes+.candidate_home_bytes
        and .available_ram_bytes>=.retained_required_ram_bytes+.candidate_ram_bytes' "$output" >/dev/null
}

test "$(id -u)" = 0
exec 9<>/run/horizon-epoch171-to136-g1.operation.lock
flock -n -x 9
test "$(realpath "$b")" = "$b"
test "${b%/*}" = "$a"
[[ $(stat -c %u:%g:%a:%h "$b") =~ ^0:0:4(00|44):1$ ]]
test "$(sha "$b")" = "$bsha"
test "$(sha "$contract")" = "$contract_sha"
test "$(sha "$source")" = "$(jq -er '.source_reference.sha256' "$contract")"
operator=$(realpath "$0")
jq -e --arg path "$contract" --arg digest "$contract_sha" --arg op "$operator" --arg ops "$(sha "$operator")" \
    --arg unit "$unit" --arg writer "$writer" '
    .schema == "horizon-epoch143-first-hourly-booking-v1"
    and .contract=={path:$path,sha256:$digest} and .sealed_operator=={path:$op,sha256:$ops}
    and .unit==$unit and .writer.unit==$writer and .native_census_enrolled==true
    and .recording_authorized==true and .archive_publication_authorized==false
    and .HOME_bytes==68786585600 and .RAM_bytes==44023414784 and .cpu_quota_micros==3000000
    and .resource_credit_bytes==0
    and (.runtime_max_seconds|type=="number" and .>0 and floor==.)
    and (.latest_start_unix_seconds|type=="number" and floor==.)
    and (.must_drain_by_unix_seconds|type=="number" and floor==.)' "$b" >/dev/null
fleet=$(jq -er '.fleet.path' "$b")
fleet_sha=$(jq -er '.fleet.sha256' "$b")
writer_iid=$(jq -er '.writer.invocation_id' "$b")
timer=$(jq -er '.sole_next_timer.unit' "$b")
timer_iid=$(jq -er '.sole_next_timer.invocation_id' "$b")
price=$(jq -er '.sealed_price.path' "$b")
reader=$(jq -er '.sealed_reader.path' "$b")
test "$(sha "$price")" = "$(jq -er '.sealed_price.sha256' "$b")"
test "$(sha "$reader")" = "$(jq -er '.sealed_reader.sha256' "$b")"
runtime=$(jq -er '.runtime_max_seconds' "$b")
latest=$(jq -er '.latest_start_unix_seconds' "$b")
drain=$(jq -er '.must_drain_by_unix_seconds' "$b")
(( $(date +%s) <= latest && latest + runtime + 20 <= drain ))
for target in "$unit" "$guard_unit.timer" "$guard_unit.service"; do
    test "$(value "$target" LoadState)" = not-found
done
for target in "$run" "$a/barrier" "$a/guard-receipts" "$a/PRESTART_SCREEN.json"; do
    test ! -e "$target"
done
test "$(sha "$guard")" = "$guard_sha"
test "$(sha "$gate")" = 5c5f37185fcf617a01e3a323632847f34c70f3e513b0fece4ccb49e7c98d033c
test "$(sha "$a/inputs-v1/canonical-hashes.txt")" = "$(jq -er '.hash_list_sha256' "$source")"
while IFS=$'\t' read -r path digest; do
    test "$(sha "$path")" = "$digest"
done < <(jq -r '.images_and_genesis[]|[.path,.sha256]|@tsv' "$source")
snapshot=$(jq -er '.bootstrap.path' "$source")
test "$(stat -c '%d %i %s' "$snapshot")" = '64512 118554661 3714834246'
test "$(sha "$snapshot")" = "$(jq -er '.bootstrap.sha256' "$source")"
genesis=$(jq -er '.ledger_genesis.path' "$contract")
writer_live
screen "$a/PRESTART_SCREEN.json"
floor=$(jq -er '
    (.available_home_bytes-.retained_required_home_bytes-.candidate_home_bytes) as $surplus
    | .retained_required_home_bytes+([4294967296,($surplus/2|floor)]|min)' "$a/PRESTART_SCREEN.json")
test "$floor" -ge 9470567509909

released=0
started=0
guard_started=0
cleanup() {
    if (( released == 0 )); then
        if (( guard_started )); then systemctl stop "$guard_unit.timer" "$guard_unit.service" || true; fi
        if (( started )); then systemctl stop "$unit" || true; fi
    fi
}
trap cleanup EXIT

install -d -m 0700 -o sol -g horizon "$run" "$run/ledger" "$run/private" "$run/scratch"
install -m 0600 -o sol -g horizon /dev/null "$run/ledger/genesis.tar.bz2"
install -d -m 0755 "$a/barrier"
install -d -m 0700 "$a/guard-receipts"
mapfile -t bindings < <(jq -r '.read_only_bind_map|to_entries[]|.key+":"+.value' "$contract")
bindings+=("$genesis:$run/ledger/genesis.tar.bz2")
env_args=("--setenv=TMPDIR=$run")
while IFS= read -r setting; do env_args+=("--setenv=$setting"); done < <(
    jq -r '.producer_env|to_entries[]|.key+"="+.value' "$contract"
)
test "$(value "$unit" LoadState)" = not-found
(( $(date +%s) <= latest ))
systemd-run --unit "$unit" --property=Type=exec --property=User=sol --property=Group=horizon \
    --property=Restart=no --property=KillMode=control-group --property=TimeoutStopSec=20s \
    "--property=RuntimeMaxSec=$runtime" --property=Delegate=no --property=TasksMax=512 \
    --property=CPUQuota=200% --property=MemoryHigh=38654705664 --property=MemoryMax=42949672960 \
    --property=MemorySwapMax=0 --property=LimitCORE=0 --property=ProtectHome=read-only \
    --property=ProtectSystem=strict --property=PrivateTmp=yes --property=PrivateDevices=yes \
    --property=ProtectControlGroups=yes --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
    "--property=WorkingDirectory=$run" "--property=ReadWritePaths=$run" \
    "--property=BindReadOnlyPaths=${bindings[*]}" --property=StandardOutput=journal \
    --property=StandardError=journal "${env_args[@]}" -- /usr/bin/env "$view/hold-143"
started=1
iid=$(value "$unit" InvocationID)
pid=$(value "$unit" MainPID)
[[ $iid =~ ^[0-9a-f]{32}$ && $pid -gt 1 ]]
inode=$(stat -Lc %d:%i "$gate")
for attempt in {1..30}; do
    [[ $(stat -Lc %d:%i "/proc/$pid/exe" 2>/dev/null || true) == "$inode" ]] && break
    sleep .1
done
test "$(stat -Lc %d:%i "/proc/$pid/exe")" = "$inode"
test "$(cat "/proc/$pid/cgroup")" = "0::/system.slice/$unit"
test "$(value "$unit" MemoryMax)" = 42949672960
test "$(value "$unit" MemorySwapMax)" = 0
test "$(value "$unit" CPUQuotaPerSecUSec)" = 2s
for binding in "${bindings[@]}"; do
    input=${binding%:*}
    destination=${binding##*:}
    test "$(stat -Lc '%d:%i:%s' "$input")" = "$(stat -Lc '%d:%i:%s' "/proc/$pid/root$destination")"
done

plan="$a/ACTUAL_GUARD_PLAN.json"
jq -n --arg iid "$iid" --arg unit "$unit" --arg run "$run" --argjson floor "$floor" \
    --arg receipts "$a/guard-receipts" '{
    schema:"jetstreamer-horizon-standalone-guard-plan-v1",unit:$unit,invocation_id:$iid,
    filesystem:"/home/sol",minimum_free_bytes:$floor,worker_root:$run,maximum_worker_vmas:3500000,
    maximum_root_physical_bytes:68719476736,receipt_directory:$receipts}' | publish "$plan"
plan_sha=$(sha "$plan")
guard_args=("$guard" "$plan" --plan-sha256 "$plan_sha" --self-sha256 "$guard_sha")
"${guard_args[@]}" --validate-plan-only
systemd-run --unit "$guard_unit" --on-active=1s --timer-property=AccuracySec=1s \
    --timer-property=OnUnitActiveSec=10s "--timer-property=BindsTo=$unit" "--timer-property=After=$unit" \
    --property=CPUQuota=100% --property=MemoryMax=1073741824 --property=MemorySwapMax=0 \
    --property=TasksMax=64 --property=TimeoutStopSec=10s --property=Restart=no \
    --property=ProtectHome=read-only --property=ProtectSystem=strict --property=PrivateNetwork=yes \
    "--property=ReadWritePaths=$a/guard-receipts" -- "${guard_args[@]}"
guard_started=1
first=
for attempt in {1..40}; do
    first=$(find "$a/guard-receipts" -maxdepth 1 -type f -name 'sample-*.json' -print -quit)
    [[ -n $first ]] && break
    sleep .25
done
test -n "$first"
jq -e --arg iid "$iid" --argjson pid "$pid" --arg digest "$plan_sha" '
    .producer_invocation_id==$iid and .producer.pid==$pid and .producer_stop_enabled
    and .plan_sha256==$digest and .trip_reason==null and .root_physical_observation_error==null
    and .worker_observation_error==null and .maximum_root_physical_bytes==68719476736
    and .root_physical_observation.exceeds_budget==false and .workers==[]' "$first" >/dev/null
screen "$a/POST_GUARD_SCREEN.json" "$iid"
jq -e --argjson floor "$floor" '
    .retained_required_home_bytes<=$floor
    and .available_home_bytes>=($floor+.candidate_home_bytes)' "$a/POST_GUARD_SCREEN.json" >/dev/null
writer_live
test "$(sha "$b")" = "$bsha"
test "$(value "$unit" InvocationID)" = "$iid"
test "$(value "$unit" MainPID)" = "$pid"
test "$(value "$guard_unit.timer" ActiveState)" = active
test "$(value "$guard_unit.timer" BindsTo)" = "$unit"
test "$(value "$guard_unit.service" CPUQuotaPerSecUSec)" = 1s
test "$(value "$guard_unit.service" MemoryMax)" = 1073741824
test "$(value "$guard_unit.service" MemorySwapMax)" = 0
gid=$(value "$guard_unit.timer" InvocationID)
ticks=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text().rsplit(") ",1)[1].split()[19])' "/proc/$pid/stat")
jq -n --arg iid "$iid" --arg unit "$unit" --argjson pid "$pid" --argjson ticks "$ticks" \
    --arg boot "$(cat /proc/sys/kernel/random/boot_id)" --arg guard_iid "$gid" \
    --arg plan "$plan" --arg ps "$plan_sha" --arg first "$first" --arg first_sha "$(sha "$first")" \
    --arg contract "$contract" --arg cs "$contract_sha" --arg booking "$b" --arg bs "$bsha" \
    --arg post "$a/POST_GUARD_SCREEN.json" --arg post_sha "$(sha "$a/POST_GUARD_SCREEN.json")" \
    --argjson now "$(date +%s)" '{
    schema:"horizon-epoch143-first-hourly-held-owner-v1",unit:$unit,producer_invocation_id:$iid,
    producer_pid:$pid,start_ticks:$ticks,boot_id:$boot,guard_timer_invocation_id:$guard_iid,
    guard_plan:{path:$plan,sha256:$ps},first_guard:{path:$first,sha256:$first_sha},
    contract:{path:$contract,sha256:$cs},booking:{path:$booking,sha256:$bs},
    post_guard_fit:{path:$post,sha256:$post_sha},recorded_unix_seconds:$now,
    archive_publication_authorized:false}' | publish "$a/HELD_OWNER.json"
printf '%s' "$iid" | publish "$a/barrier/allow"
released=1
printf 'Epoch 143 guarded release %s pid %s\n' "$iid" "$pid"
