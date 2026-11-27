#!/usr/bin/env bash
set -euo pipefail
umask 077

# The deployment name selects one immutable contract. Existing 143 deployments
# use the same entry point and booking arguments.
case ${0##*/} in
    launch-first-hourly143.sh)
        epoch=143
        contract_sha=84e2846e7c33a1a6b7793861f918344be2af10d8132dc380450345f59903a19f
        guard_sha=dfea30dafc769c5af59cce61137fb73b70665de2abab05c747dbc32de641dc96
        gate_sha=5c5f37185fcf617a01e3a323632847f34c70f3e513b0fece4ccb49e7c98d033c
        high=38654705664
        ;;
    launch-first-hourly141.sh)
        epoch=141
        contract_sha=73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131
        guard_sha=e7425f07894dd8161cef7817f462aed7415478678d0df8aa6cfc265806d8c0cc
        gate_sha=b8f8a7321750c014fa2eb66e182f191451147785985ee2b950a9b540054c06ec
        high=30064771072
        ;;
    *) exit 2 ;;
esac
a=/var/lib/jetstreamer/horizon_runtime_data/epoch${epoch}-first-hourly-20261127-v1
run=/home/sol/.jetstreamer-private/epoch${epoch}-first-hourly-20261127-v1
view=/run/horizon${epoch}-first-hourly
unit=horizon-qualify-${epoch}-first-hourly-20261127-v1.service
guard_unit=horizon-guard-${epoch}-first-hourly-20261127-v1
writer=horizon-archive-status-cadence-after172-20261120-v1.service
contract="$a/contract-v1/LAUNCH_PROFILE.json"
guard="$a/tools-v1/guard"
gate="$a/tools-v1/hold-$epoch"

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
    local quote
    quote=$("$price" "$fleet" "$fleet_sha" "$@")
    jq -e --argjson home "$home_charge" --argjson ram "$ram_charge" --arg fleet "$fleet" --arg sha "$fleet_sha" '
        .fleet=={path:$fleet,sha256:$sha} and .disk_fits and .memory_fits
        and .resource_credit_bytes==0 and .candidate_home_bytes==$home
        and .candidate_ram_bytes==$ram and .candidate_cpu_quota_micros==3000000
        and .available_home_bytes>=.retained_required_home_bytes+.candidate_home_bytes
        and .available_ram_bytes>=.retained_required_ram_bytes+.candidate_ram_bytes' <<<"$quote" >/dev/null
    if [[ $epoch == 143 ]]; then
        jq -e --arg iid "${1:-}" --arg path "$contract" --arg sha "$contract_sha" '
            .schema=="horizon-epoch143-first-hourly-replacement-fit-v1" and .projection_only==false
            and .contract=={path:$path,sha256:$sha} and (.closed141.sha256|length)==64
            and (.held_invocation // "")==$iid and (.held_invocation==null or (.candidate_guard_sample.sha256|length)==64)' <<<"$quote" >/dev/null
    fi
    printf '%s\n' "$quote" | publish "$output"
}

check_staged_141() {
    # Preflight already staged these private directories and the verified genesis.
    # Ensure no old producer output, release permit or guard receipt can be reused.
    for dir in "$run" "$run/private" "$run/ledger" "$run/scratch"; do
        test "$(realpath -e "$dir")" = "$dir"
        test "$(stat -c '%U:%G:%a' "$dir")" = sol:horizon:700
    done
    test "$(find "$run" -mindepth 1 -printf '%P\n' | sort)" = $'ledger\nledger/genesis.tar.bz2\nprivate\nscratch'
    test "$(stat -c '%U:%G:%a' "$a/barrier")" = root:root:755
    test "$(stat -c '%U:%G:%a' "$a/guard-receipts")" = root:root:700
    test -z "$(find "$a/barrier" "$a/guard-receipts" -mindepth 1 -print -quit)"
    test "$(stat -c '%u:%g:%a:%h' "$run/ledger/genesis.tar.bz2")" = 0:0:444:1
    test "$(sha "$run/ledger/genesis.tar.bz2")" = "$(jq -er '.ledger_genesis.sha256' "$contract")"
    # The large data file is root-sealed. Match every projected input to the
    # native preflight inode, then let the native adapter verify the full digest.
    test "$(sha "$a/contract-v1/MOUNT_PREFLIGHT.log")" = 7fb38e2aba67a0ae92c81610084f58c6f5eb22fe56661781ce705b9fcab3549f
    local destination inode access input snapshot
    while read -r destination inode access; do
        [[ $destination == /* ]] || continue
        input=$(jq -er --arg dest "$destination" '.read_only_bind_map|to_entries[]|select(.value==$dest)|.key' "$contract")
        test "$access" = ro
        test "$(stat -Lc '%d:%i' "$input")" = "$inode"
    done < "$a/contract-v1/MOUNT_PREFLIGHT.log"
    test "$(jq -er '.read_only_bind_map|length' "$contract")" = 10
    snapshot=$(jq -er '.local_projection.bootstrap.path' "$source")
    test "$(stat -c '%d:%i:%s' "$snapshot")" = "$(jq -er '.local_projection.bootstrap|.device_inode+":"+(.bytes|tostring)' "$source")"
    test "$(sha "$snapshot")" = "$(jq -er '.local_projection.bootstrap.sha256' "$source")"
}

check_staged_143() {
    local receipt path digest snapshot map mode sourcepath destination checked
    for path in "$run" "$a/barrier" "$a/guard-receipts"; do test ! -e "$path"; done
    test "$(sha "$gate")" = "$gate_sha"
    test "$(sha "$guard")" = "$guard_sha"
    test "$(sha "$a/inputs-v1/canonical-hashes.txt")" = "$(jq -er '.hash_list_sha256' "$source")"
    receipt=$(jq -er '.bootstrap.custody.path' "$source")
    test "$(sha "$receipt")" = "$(jq -er '.bootstrap.custody.sha256' "$source")"
    jq -en --slurpfile ref "$source" --slurpfile found "$receipt" '
      $ref[0].bootstrap as $b | $found[0] as $c |
      $c.epoch==143 and $c.slot==$b.slot and $c.object.sha256==$b.sha256
      and $c.object.generation==$b.generation and $c.object.bytes==$b.size and $c.local_input.path==$b.path' >/dev/null
    while IFS=$'\t' read -r path digest; do
        test "$(sha "$path")" = "$digest"
    done < <(jq -r '.images_and_genesis[]|[.path,.sha256]|@tsv' "$source")
    map="$a/projection-v1/visible-inodes.txt"
    test "$(sha "$map")" = c07d230f057a7b9d2f7ed220661082c501e85efc8f5ec90e0cb0ac0ddb2a2af9
    checked=0
    while read -r mode destination; do
        if [[ $destination == "$view"/* ]]; then
            sourcepath=$(jq -er --arg d "$destination" '.read_only_bind_map|to_entries[]|select(.value==$d)|.key' "$contract")
        else
            sourcepath=$(jq -er --arg d "$destination" '.images_and_genesis[]|select(.path==$d)|.path' "$source")
        fi
        test "$(stat -Lc '%d:%i:%s:%a' "$sourcepath")" = "$mode"
        checked=$((checked+1))
    done < "$map"
    test "$checked" = 6
    snapshot=$(jq -er '.bootstrap.path' "$source")
    if [[ ${1:-} == full ]]; then
        test "$(sha "$snapshot")" = "$(jq -er '.bootstrap.sha256' "$source")"
    fi
}

window_ok() {
    local latest=$1 runtime=$2 drain=$3 now=$4
    (( runtime > 0 && now <= latest && latest + runtime + 20 <= drain ))
}

test "$(id -u)" = 0
test "$(sha "$contract")" = "$contract_sha"
source=$(jq -er '.source_reference.path' "$contract")
tree=$(jq -er '.guarded_HOME_bytes' "$contract")
memory=$(jq -er '.producer_RAM_bytes' "$contract")
home_charge=$(jq -er '.guarded_HOME_bytes+.separate_evidence_HOME_bytes' "$contract")
ram_charge=$(jq -er '.producer_RAM_bytes+.guard_RAM_bytes' "$contract")
test "$(sha "$source")" = "$(jq -er '.source_reference.sha256' "$contract")"
if [[ ${1:-} == --check-staged && $# == 1 ]]; then
    if [[ $epoch == 141 ]]; then check_staged_141; else check_staged_143; fi
    exit 0
fi
if [[ $epoch == 143 && ${1:-} == --check-booking-window && $# == 5 ]]; then
    for arg in "${@:2}"; do [[ $arg =~ ^[0-9]{1,11}$ ]]; done
    window_ok "${@:2}"
    exit 0
fi
b=${1:?Pass the writer booking}
bsha=${2:?Pass its verified SHA-256}
exec 9<>/run/horizon-epoch171-to136-g1.operation.lock
flock -n -x 9
test "$(realpath "$b")" = "$b"
test "${b%/*}" = "$a"
[[ $(stat -c %u:%g:%a:%h "$b") =~ ^0:0:4(00|44):1$ ]]
test "$(sha "$b")" = "$bsha"
operator=$(realpath "$0")
jq -e --arg schema "horizon-epoch${epoch}-first-hourly-booking-v1" --argjson home "$home_charge" --argjson ram "$ram_charge" --arg path "$contract" --arg digest "$contract_sha" --arg op "$operator" --arg ops "$(sha "$operator")" \
    --arg unit "$unit" --arg writer "$writer" '
    .schema == $schema
    and .contract=={path:$path,sha256:$digest} and .sealed_operator=={path:$op,sha256:$ops}
    and .unit==$unit and .writer.unit==$writer and .native_census_enrolled==true
    and .recording_authorized==true and .archive_publication_authorized==false
    and .HOME_bytes==$home and .RAM_bytes==$ram and .cpu_quota_micros==3000000
    and .resource_credit_bytes==0
    and (.runtime_max_seconds|type=="number" and .>0 and floor==.)
    and (.latest_start_unix_seconds|type=="number" and floor==.)
    and (.must_drain_by_unix_seconds|type=="number" and floor==.)' "$b" >/dev/null
if [[ $epoch == 143 ]]; then
    test "$(jq -er '.native_stop_grace_seconds' "$b")" = 20
    acceptance=$(jq -er '.closed_141.path' "$b")
    test "$acceptance" = /var/lib/jetstreamer/horizon_runtime_data/epoch141-first-hourly-20261127-v1/terminal-capture-v1/PRIVATE_FIRST_HOURLY_ACCEPTANCE.json
    test "$(sha "$acceptance")" = "$(jq -er '.closed_141.sha256' "$b")"
fi
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
# Bound service runtime and its StopSec grace by the booked drain deadline.
if [[ $epoch == 141 ]]; then
    runtime=$(( runtime < drain-latest-20 ? runtime : drain-latest-20 ))
fi
window_ok "$latest" "$runtime" "$drain" "$(date +%s)"
for target in "$unit" "$guard_unit.timer" "$guard_unit.service"; do
    test "$(value "$target" LoadState)" = not-found
done
test ! -e "$a/PRESTART_SCREEN.json"
test "$(sha "$guard")" = "$guard_sha"
test "$(sha "$gate")" = "$gate_sha"
genesis=$(jq -er '.ledger_genesis.path' "$contract")
if [[ $epoch == 141 ]]; then
    check_staged_141
else
    check_staged_143 full
fi
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

if [[ $epoch == 143 ]]; then
    install -d -m 0700 -o sol -g horizon "$run" "$run/ledger" "$run/private" "$run/scratch"
    install -m 0600 -o sol -g horizon /dev/null "$run/ledger/genesis.tar.bz2"
    install -d -m 0755 "$a/barrier"
    install -d -m 0700 "$a/guard-receipts"
fi
mapfile -t bindings < <(jq -r '.read_only_bind_map|to_entries[]|.key+":"+.value' "$contract")
if [[ $epoch == 143 ]]; then bindings+=("$genesis:$run/ledger/genesis.tar.bz2"); fi
env_args=("--setenv=TMPDIR=$run")
while IFS= read -r setting; do env_args+=("--setenv=$setting"); done < <(
    jq -r '.producer_env|to_entries[]|.key+"="+.value' "$contract"
)
test "$(value "$unit" LoadState)" = not-found
(( $(date +%s) <= latest ))
systemd-run --unit "$unit" --property=Type=exec --property=User=sol --property=Group=horizon \
    --property=Restart=no --property=KillMode=control-group --property=TimeoutStopSec=20s \
    "--property=RuntimeMaxSec=$runtime" --property=Delegate=no --property=TasksMax=512 \
    --property=CPUQuota=200% "--property=MemoryHigh=$high" "--property=MemoryMax=$memory" \
    --property=MemorySwapMax=0 --property=LimitCORE=0 --property=ProtectHome=read-only \
    --property=ProtectSystem=strict --property=PrivateTmp=yes --property=PrivateDevices=yes \
    --property=ProtectControlGroups=yes --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
    "--property=WorkingDirectory=$run" "--property=ReadWritePaths=$run" \
    "--property=BindReadOnlyPaths=${bindings[*]}" --property=StandardOutput=journal \
    --property=StandardError=journal "${env_args[@]}" -- /usr/bin/env "$view/hold-$epoch"
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
test "$(value "$unit" MemoryMax)" = "$memory"
test "$(value "$unit" MemorySwapMax)" = 0
test "$(value "$unit" CPUQuotaPerSecUSec)" = 2s
for binding in "${bindings[@]}"; do
    input=${binding%:*}
    destination=${binding##*:}
    test "$(stat -Lc '%d:%i:%s' "$input")" = "$(stat -Lc '%d:%i:%s' "/proc/$pid/root$destination")"
    awk -v dest="$destination" '$5==dest && $6 ~ /(^|,)ro(,|$)/ {found=1} END {exit !found}' "/proc/$pid/mountinfo"
done

plan="$a/ACTUAL_GUARD_PLAN.json"
jq -n --argjson tree "$tree" --arg iid "$iid" --arg unit "$unit" --arg run "$run" --argjson floor "$floor" \
    --arg receipts "$a/guard-receipts" '{
    schema:"jetstreamer-horizon-standalone-guard-plan-v1",unit:$unit,invocation_id:$iid,
    filesystem:"/home/sol",minimum_free_bytes:$floor,worker_root:$run,maximum_worker_vmas:3500000,
    maximum_root_physical_bytes:$tree,receipt_directory:$receipts}' | publish "$plan"
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
jq -e --argjson tree "$tree" --arg iid "$iid" --argjson pid "$pid" --arg digest "$plan_sha" '
    .producer_invocation_id==$iid and .producer.pid==$pid and .producer_stop_enabled
    and .plan_sha256==$digest and .trip_reason==null and .root_physical_observation_error==null
    and .worker_observation_error==null and .maximum_root_physical_bytes==$tree
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
jq -n --arg schema "horizon-epoch${epoch}-first-hourly-held-owner-v1" --arg iid "$iid" --arg unit "$unit" --argjson pid "$pid" --argjson ticks "$ticks" \
    --arg boot "$(cat /proc/sys/kernel/random/boot_id)" --arg guard_iid "$gid" \
    --arg plan "$plan" --arg ps "$plan_sha" --arg first "$first" --arg first_sha "$(sha "$first")" \
    --arg contract "$contract" --arg cs "$contract_sha" --arg booking "$b" --arg bs "$bsha" \
    --arg post "$a/POST_GUARD_SCREEN.json" --arg post_sha "$(sha "$a/POST_GUARD_SCREEN.json")" \
    --argjson now "$(date +%s)" '{
    schema:$schema,unit:$unit,producer_invocation_id:$iid,
    producer_pid:$pid,start_ticks:$ticks,boot_id:$boot,guard_timer_invocation_id:$guard_iid,
    guard_plan:{path:$plan,sha256:$ps},first_guard:{path:$first,sha256:$first_sha},
    contract:{path:$contract,sha256:$cs},booking:{path:$booking,sha256:$bs},
    post_guard_fit:{path:$post,sha256:$post_sha},recorded_unix_seconds:$now,
    archive_publication_authorized:false}' | publish "$a/HELD_OWNER.json"
printf '%s' "$iid" | publish "$a/barrier/allow"
released=1
printf 'Epoch %s guarded release %s pid %s\n' "$epoch" "$iid" "$pid"
