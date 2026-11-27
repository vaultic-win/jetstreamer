#!/usr/bin/env bash
set -euo pipefail
umask 077
profile=${HORIZON140_PROFILE:-initial}
case "$profile" in
    initial) suffix=v1; tree_cap=25769803776; price_mode=() ;;
    retry1) suffix=retry1; tree_cap=60129542144; price_mode=(--retry1) ;;
    retry2) suffix=retry2; tree_cap=$((44 << 30)); price_mode=(--retry2) ;;
    *) exit 2 ;;
esac
a="/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-recording-20261127-$suffix"
run="/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-$suffix"
u=horizon-epoch140-suffix-recording.service
g="horizon-guard-epoch140-suffix-recording-20261127-$suffix"
home_charge=$((tree_cap + 67108864))
original=horizon-qualify-170-full-metered-20261124-v1.service
fence_dir="/run/systemd/system/$original.d"
fence="$fence_dir/95-epoch140-cpu-loan.conf"
marker=/run/horizon-epoch140-epoch170-cpu-loan.active
original_bus_path=/org/freedesktop/systemd1/unit/horizon_2dqualify_2d170_2dfull_2dmetered_2d20261124_2dv1_2eservice
guard="$a/static/guard"
price="$a/pricing-v2/price-epoch140"
case "$profile" in
    retry1) price="$a/pricing-v5/price-epoch140" ;;
    retry2) price="$a/pricing-v6/price-epoch140" ;;
esac
render="$(dirname "$0")/epoch140-producer-argv.sh"
sealer=/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment
self_sha=e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3
fleet=${1:?Pass the current accepted fleet}
fsha=${2:?Pass its independently verified digest}
booking=${3:?Pass the writer-owned CPU and cadence booking}
bsha=${4:?Pass its independently verified digest}

sha() { sha256sum "$1" | cut -d ' ' -f1; }
test "$(id -u)" = 0
test "$(stat -c %u:%g:%a:%h "$guard")" = 0:0:555:1
guard_sha=$(sha "$guard")
test "$(sha "$fleet")" = "$fsha"
test "$(sha "$booking")" = "$bsha"
[[ $(stat -c %u:%g:%a:%h "$booking") =~ ^0:0:4(00|44):1$ ]]
if jq -e '.sealed_operator != null' "$booking" >/dev/null; then
    operator=$(realpath "$0")
    jq -e --arg path "$operator" --arg sha "$(sha "$operator")" '
      .sealed_operator=={path:$path,sha256:$sha}' "$booking" >/dev/null
fi
jq -e --arg f "$fleet" --arg s "$fsha" --arg unit "$u" --argjson home "$home_charge" '
  .schema=="horizon-epoch140-private-recording-booking-v1" and .fleet=={path:$f,sha256:$s}
  and .unit==$unit and .cpu_quota_micros==3000000
  and .HOME_bytes==$home and .RAM_bytes==28991029248
  and (.runtime_max_seconds|type=="number" and .>0 and .<=1800)
  and (.must_drain_by_unix_seconds|type=="number" and floor==.)
  and .recording_authorized==true and .archive_publication_authorized==false' "$booking" >/dev/null
cache_retirement_sha=$(jq -r '.local_cache_retirement.sha256 // empty' "$booking")
if [[ -n $cache_retirement_sha ]]; then
    [[ $profile != initial && $cache_retirement_sha =~ ^[0-9a-f]{64}$ ]]
    price_mode+=(--cache-retirement-sha "$cache_retirement_sha")
fi

cpu_donor_exact() {
    local bridge=horizon-qualify-170-checkpoint-suffix-20261127-v1.service
    local donor_guard=horizon-guard-170-checkpoint-suffix-20261127-v1.timer
    test "$(systemctl show "$donor_guard" -p InvocationID --value)" = 84f40c559d6b4c2eaa36e99138518948
    test "$(systemctl show "$donor_guard" -p ActiveState --value)" = active
    [[ $(systemctl show "$original" -p ActiveState --value) =~ ^(inactive|failed)$ ]]
    test "$(systemctl show "$original" -p ControlPID --value)" = 0
    test "$(systemctl show "$original" -p MainPID --value)" = 0
    local original_events="/sys/fs/cgroup/system.slice/$original/cgroup.events"
    if [[ -e $original_events ]]; then grep -qx 'populated 0' "$original_events"; fi
    test "$(systemctl show "$original" -p Job --value)" = ''
    test "$(systemctl show "$bridge" -p ActiveState --value)" = active
    test "$(systemctl show "$bridge" -p InvocationID --value)" = 3a5e311489834552ab5fda89379f9481
    test "$(systemctl show "$bridge" -p CPUQuotaPerSecUSec --value)" = 6s
}

verify_fence() {
    local conditions
    test "$(stat -c %u:%g:%a:%h "$marker")" = 0:0:444:1
    test "$(systemctl show "$original" -p DropInPaths --value)" = "$fence"
    conditions=$(busctl get-property org.freedesktop.systemd1 "$original_bus_path" org.freedesktop.systemd1.Unit Conditions)
    [[ $conditions == *"\"ConditionPathExists\" false true \"$marker\""* ]]
    cpu_donor_exact
}

screen() {
    local result=$1
    "$price" "$fleet" "$fsha" "${price_mode[@]}" > "$result"
    jq -e --argjson home "$home_charge" '
      .disk_fits and .memory_fits and .candidate_home_bytes==$home
      and .incumbent_167_cap_bytes==85899345920' "$result" >/dev/null
}

publish() {
    local dest=$1 tmp
    tmp=$(mktemp "${dest%/*}/.pending-XXXXXX")
    cat > "$tmp"
    chmod 0444 "$tmp"
    sync "$tmp"
    mv -nT "$tmp" "$dest"
    test ! -e "$tmp"
    python3 - "${dest%/*}" <<'PY'
import os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
PY
}

drain_by=$(jq -er '.must_drain_by_unix_seconds' "$booking")
booked_runtime=$(jq -er '.runtime_max_seconds' "$booking")
test "$booked_runtime" -le 1600
test "$((drain_by - $(date +%s)))" -ge 150
if [[ $profile == retry2 ]] && (( booked_runtime != 1600 || drain_by - $(date +%s) < 1655 )); then
    printf 'Epoch 140 retry2 requires the full 1600-second native window\n' >&2
    exit 1
fi

exec 9<>/run/horizon-epoch171-to136-g1.operation.lock
flock -n -x 9
if [[ $(systemctl show "$u" -p LoadState --value) != not-found ]]; then
    printf 'Epoch 140 recorder unit still has a loaded definition; clear the verified terminal before booking\n' >&2
    exit 1
fi
test ! -e "$run"
test ! -e "$a/barrier"
test ! -e "$a/plan"
cpu_donor_exact
screen "$a/PRESTART_SCREEN.json"
test ! -e "$fence_dir"
test ! -e "$marker"
released=0
fence_owned=0
launch_attempted=0
stop_failed_hold() {
    local result=$?
    if (( released == 0 && fence_owned == 1 )); then
        if (( launch_attempted == 1 )); then
            systemctl stop "$g.timer" 2>/dev/null || true
            systemctl stop "$u" 2>/dev/null || true
            systemctl stop "$g.service" 2>/dev/null || true
        fi
        if [[ $(systemctl show "$u" -p ActiveState --value) =~ ^(inactive|failed)$ &&
              $(systemctl show "$g.timer" -p ActiveState --value) =~ ^(inactive|failed)$ &&
              $(systemctl show "$g.service" -p ActiveState --value) =~ ^(inactive|failed)$ ]]; then
            rm -f -- "$fence" "$marker"
            rmdir -- "$fence_dir"
            systemctl daemon-reload
        fi
    fi
    return "$result"
}
trap stop_failed_hold EXIT
mkdir -m 0755 "$fence_dir"
fence_owned=1
printf '[Unit]\nConditionPathExists=!%s\n' "$marker" | publish "$fence"
printf '%s\n' "$bsha" | publish "$marker"
systemctl daemon-reload
verify_fence
# The incumbent floor is live and can increase while the guard is being armed.
# Use part of the verified surplus to fit a stricter guard without changing reservations.
guard_floor=$(jq -er '
  (.available_home_bytes-.retained_required_home_bytes-.candidate_home_bytes) as $surplus
  | .retained_required_home_bytes+([4294967296,($surplus/2|floor)]|min)' "$a/PRESTART_SCREEN.json")
node_floor=$((guard_floor + $(jq -er '.candidate_home_bytes' "$a/PRESTART_SCREEN.json")))
install -d -m 0700 -o sol -g horizon "$run"
install -d -m 0700 "$a/guard-receipts"
install -d -m 0755 "$a/barrier"
snap=snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst
jq -n --arg run "$run" --arg snap "/run/horizon140-suffix-snapshot/$snap" --argjson floor "$node_floor" '{
 schema:"jetstreamer-private-epoch140-suffix-recording-plan-v1",
 node_sha256:"f209b010dc9ceb5f6e55a274a36a7865eea9125b11dc81e3a49e640f6e79ab99",
 run_root:$run,prefix_audit:{path:"/run/horizon140-suffix-plan/prefix-audit.json",sha256:"263fb573bc3854cae1db6c66ac5da1f8f8af88cb06afa740980b1b138f44bb5f"},
 snapshot:$snap,genesis:"/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-inputs-20261020-v1/genesis.tar.bz2",
 minimum_free_bytes:$floor}' | publish "$a/PLAN_SOURCE.json"
plan_sha=$(sha "$a/PLAN_SOURCE.json")
jq -n --arg dest "$a/plan" --arg path "$a/PLAN_SOURCE.json" --arg sha "$plan_sha" '{
 schema:"jetstreamer-sealed-deployment-plan-v1",destination:$dest,
 members:[{name:"plan.json",source:$path,sha256:$sha,mode:292}]}' | publish "$a/PLAN_SEAL.json"
"$sealer" "$a/PLAN_SEAL.json" --plan-sha256 "$(sha "$a/PLAN_SEAL.json")" --self-sha256 "$self_sha"
bound_runtime=$((drain_by - $(date +%s) - 55))
if (( bound_runtime > booked_runtime )); then bound_runtime=$booked_runtime; fi
(( bound_runtime >= 120 ))
if [[ $profile == retry2 ]] && (( bound_runtime != booked_runtime )); then
    printf 'Epoch 140 retry2 setup consumed part of the native window\n' >&2
    exit 1
fi
mapfile -t launch_args < <(bash "$render" "$plan_sha" "$suffix" | jq -r --arg bound "$bound_runtime" 'map(if startswith("--property=RuntimeMaxSec=") then "--property=RuntimeMaxSec="+$bound else . end)[]')
launch_attempted=1
"${launch_args[@]}"
iid=$(systemctl show "$u" -p InvocationID --value)
pid=$(systemctl show "$u" -p MainPID --value)
[[ $iid =~ ^[0-9a-f]{32}$ && $pid -gt 1 ]]
gate_inode=$(stat -Lc %d:%i "$a/static/hold-entry140")
for attempt in {1..30}; do
    if [[ $(stat -Lc %d:%i "/proc/$pid/exe" 2>/dev/null || true) == "$gate_inode" ]]; then break; fi
    sleep .1
done
test "$(stat -Lc %d:%i "/proc/$pid/exe")" = "$gate_inode"
test "$(cat "/proc/$pid/cgroup")" = "0::/system.slice/$u"
test "$(cat "/sys/fs/cgroup/system.slice/$u/memory.max")" = 27917287424
test "$(cat "/sys/fs/cgroup/system.slice/$u/memory.swap.max")" = 0
test "$(systemctl show "$u" -p CPUQuotaPerSecUSec --value)" = 2s
jq -n --arg iid "$iid" --arg u "$u" --arg run "$run" --arg receipts "$a/guard-receipts" --argjson floor "$guard_floor" --argjson cap "$tree_cap" '{
 schema:"jetstreamer-horizon-standalone-guard-plan-v1",unit:$u,invocation_id:$iid,filesystem:"/home/sol",
 minimum_free_bytes:$floor,worker_root:$run,maximum_worker_vmas:3500000,maximum_root_physical_bytes:$cap,
 receipt_directory:$receipts}' | publish "$a/ACTUAL_GUARD_PLAN.json"
plan="$a/ACTUAL_GUARD_PLAN.json"
guard_args=("$guard" "$plan" --plan-sha256 "$(sha "$plan")" --self-sha256 "$guard_sha")
"${guard_args[@]}" --validate-plan-only
systemd-run --unit "$g" --on-active=1s --timer-property=AccuracySec=1s --timer-property=OnUnitActiveSec=10s \
  "--timer-property=BindsTo=$u" "--timer-property=After=$u" \
  --property=CPUQuota=100% --property=MemoryMax=1073741824 --property=MemorySwapMax=0 --property=TasksMax=64 --property=TimeoutStopSec=10s --property=Restart=no --property=ProtectHome=read-only --property=ProtectSystem=strict --property=PrivateNetwork=yes   "--property=ReadWritePaths=$a/guard-receipts" -- "${guard_args[@]}"
first=
for attempt in {1..30}; do
    first=$(find "$a/guard-receipts" -maxdepth 1 -type f -name 'sample-*.json' -print -quit)
    if [[ -n $first ]]; then break; fi
    sleep .3
done
test -n "$first"
jq -e --arg iid "$iid" --arg plan_sha "$(sha "$plan")" --argjson pid "$pid" --argjson cap "$tree_cap" '
  .producer_invocation_id==$iid and .producer.pid==$pid and .plan_sha256==$plan_sha
  and .producer_stop_enabled==true and .trip_reason==null
  and .root_physical_observation_error==null and .worker_observation_error==null
  and .maximum_root_physical_bytes==$cap
  and .root_physical_observation.exceeds_budget==false and .workers==[]' "$first" >/dev/null
screen "$a/HELD_POST_GUARD_SCREEN.json"
jq -e --argjson floor "$guard_floor" '
  .retained_required_home_bytes<=$floor and .available_home_bytes>=($floor+.candidate_home_bytes)'   "$a/HELD_POST_GUARD_SCREEN.json" >/dev/null
verify_fence
test "$(sha "$booking")" = "$bsha"
test "$(systemctl show "$u" -p InvocationID --value)" = "$iid"
test "$(systemctl show "$u" -p MainPID --value)" = "$pid"
test "$(systemctl show "$g.timer" -p ActiveState --value)" = active
test "$(systemctl show "$g.timer" -p BindsTo --value)" = "$u"
test "$(systemctl show "$g.service" -p CPUQuotaPerSecUSec --value)" = 1s
test "$(systemctl show "$g.service" -p MemoryMax --value)" = 1073741824
test "$(systemctl show "$g.service" -p MemorySwapMax --value)" = 0
timer_iid=$(systemctl show "$g.timer" -p InvocationID --value)
ticks=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text().rsplit(") ",1)[1].split()[19])' "/proc/$pid/stat")
held_owner=$(jq -n --arg iid "$iid" --argjson pid "$pid" --argjson ticks "$ticks"   --arg boot "$(cat /proc/sys/kernel/random/boot_id)" --arg unit "$u"   --arg timer "$g.timer" --arg timer_iid "$timer_iid"   --arg plan "$plan" --arg plan_sha "$(sha "$plan")" --arg sample "$first" --arg sample_sha "$(sha "$first")"   --arg fleet "$fleet" --arg fleet_sha "$fsha" --arg booking "$booking" --arg booking_sha "$bsha"   --arg nodeplan "$a/plan/plan.json" --arg nodeplan_sha "$plan_sha" --argjson cap "$tree_cap" --argjson now "$(date +%s)" '{
 schema:"horizon-epoch140-guarded-held-owner-v1",epoch:140,unit:$unit,invocation_id:$iid,pid:$pid,start_ticks:$ticks,
 boot_id:$boot,guard_timer:$timer,guard_timer_invocation_id:$timer_iid,
 guard_plan:{path:$plan,sha256:$plan_sha},first_guard:{path:$sample,sha256:$sample_sha},
 inherited_fleet:{path:$fleet,sha256:$fleet_sha},booking:{path:$booking,sha256:$booking_sha},
 node_plan:{path:$nodeplan,sha256:$nodeplan_sha},recorded_unix_seconds:$now,
 cpu_quota_micros:3000000,producer_RAM_bytes:27917287424,guard_RAM_bytes:1073741824,
 guarded_HOME_bytes:$cap,archive_publication_authorized:false}')
printf '%s\n' "$held_owner" | publish "$a/HELD_OWNER.json"
jq -n --arg iid "$iid" --argjson pid "$pid" --arg path "$booking" --arg sha "$bsha"   --argjson now "$(date +%s)" --argjson duration "$bound_runtime" --argjson deadline "$drain_by" --arg fence "$fence" --arg fence_sha "$(sha "$fence")" '{
    schema:"horizon-epoch140-epoch170-cpu-loan-v1",candidate_invocation:$iid,candidate_pid:$pid,
    booking:{path:$path,sha256:$sha},recorded_unix_seconds:$now,
    outer_runtime_cap_seconds:$duration,must_drain_by_unix_seconds:$deadline,overlap_fence:{path:$fence,sha256:$fence_sha},original_epoch170_producer_quota_micros:9000000,
    live_bridge_invocation:"3a5e311489834552ab5fda89379f9481",bridge_cpu_quota_micros:6000000,
    retained_bridge_guard_timer_invocation:"84f40c559d6b4c2eaa36e99138518948",
    producer_cpu_quota_micros:2000000,guard_cpu_quota_micros:1000000,
    return_requires_drained_candidate_and_guard:true,canonical_publication_authorized:false}'     | publish "$a/CPU_LOAN_ACTIVE.json"
printf '%s' "$iid" | publish "$a/barrier/allow"
released=1
flock -u 9
exec 9>&-
printf 'Epoch 140 release issued for %s\n' "$iid"
