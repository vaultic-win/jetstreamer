#!/usr/bin/env bash
set -euo pipefail
umask 077
a=/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-recording-20261127-v1
run=/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-v1
u=horizon-epoch140-suffix-recording.service
g=horizon-guard-epoch140-suffix-recording-20261127-v1
original=horizon-qualify-170-full-metered-20261124-v1.service
fence_dir="/run/systemd/system/$original.d"
fence="$fence_dir/95-epoch140-cpu-loan.conf"
marker=/run/horizon-epoch140-epoch170-cpu-loan.active
original_bus_path=/org/freedesktop/systemd1/unit/horizon_2dqualify_2d170_2dfull_2dmetered_2d20261124_2dv1_2eservice
guard="$a/static/guard"
price="$a/pricing-v2/price-epoch140"
guard_sha=f91ce8931e8c8485206e5db0d6ad30d10cab4ea96bb72b4ebbfb6cb932359bfa
render="$(dirname "$0")/epoch140-producer-argv.sh"
sealer=/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment
self_sha=e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3
fleet=${1:?Pass the current accepted fleet}
fsha=${2:?Pass its independently verified digest}
booking=${3:?Pass the writer-owned CPU and cadence booking}
bsha=${4:?Pass its independently verified digest}

sha() { sha256sum "$1" | cut -d ' ' -f1; }
test "$(id -u)" = 0
test "$(sha "$fleet")" = "$fsha"
test "$(sha "$booking")" = "$bsha"
test "$(stat -c %u:%g:%a:%h "$booking")" = 0:0:444:1
jq -e --arg f "$fleet" --arg s "$fsha" --arg unit "$u" '
  .schema=="horizon-epoch140-private-recording-booking-v1" and .fleet=={path:$f,sha256:$s}
  and .unit==$unit and .cpu_quota_micros==3000000
  and .HOME_bytes==25836912640 and .RAM_bytes==28991029248
  and (.runtime_max_seconds|type=="number" and .>0 and .<=1800)
  and (.must_drain_by_unix_seconds|type=="number" and floor==.)
  and .recording_authorized==true and .archive_publication_authorized==false' "$booking" >/dev/null

cpu_donor_exact() {
    local bridge=horizon-qualify-170-checkpoint-suffix-20261127-v1.service
    local donor_guard=horizon-guard-170-checkpoint-suffix-20261127-v1.timer
    test "$(systemctl show "$donor_guard" -p InvocationID --value)" = 84f40c559d6b4c2eaa36e99138518948
    test "$(systemctl show "$donor_guard" -p ActiveState --value)" = active
    test "$(systemctl show "$original" -p MainPID --value)" = 0
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
    "$price" "$fleet" "$fsha" > "$result"
    jq -e '.disk_fits and .memory_fits and .incumbent_167_cap_bytes==85899345920' "$result" >/dev/null
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

exec 9<>/run/horizon-epoch171-to136-g1.operation.lock
flock -n -x 9
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
guard_floor=$(jq -er '.retained_required_home_bytes' "$a/PRESTART_SCREEN.json")
node_floor=$(jq -er '.retained_required_home_bytes+.candidate_home_bytes' "$a/PRESTART_SCREEN.json")
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
mapfile -t launch_args < <(bash "$render" "$plan_sha" | jq -r --arg bound "$bound_runtime" 'map(if startswith("--property=RuntimeMaxSec=") then "--property=RuntimeMaxSec="+$bound else . end)[]')
launch_attempted=1
"${launch_args[@]}"
iid=$(systemctl show "$u" -p InvocationID --value)
pid=$(systemctl show "$u" -p MainPID --value)
[[ $iid =~ ^[0-9a-f]{32}$ && $pid -gt 1 ]]
test "$(stat -Lc %d:%i "/proc/$pid/exe")" = "$(stat -Lc %d:%i "$a/static/hold-entry140")"
test "$(cat "/proc/$pid/cgroup")" = "0::/system.slice/$u"
test "$(cat "/sys/fs/cgroup/system.slice/$u/memory.max")" = 27917287424
test "$(cat "/sys/fs/cgroup/system.slice/$u/memory.swap.max")" = 0
test "$(systemctl show "$u" -p CPUQuotaPerSecUSec --value)" = 2s
jq -n --arg iid "$iid" --arg u "$u" --arg run "$run" --arg receipts "$a/guard-receipts" --argjson floor "$guard_floor" '{
 schema:"jetstreamer-horizon-standalone-guard-plan-v1",unit:$u,invocation_id:$iid,filesystem:"/home/sol",
 minimum_free_bytes:$floor,worker_root:$run,maximum_worker_vmas:3500000,maximum_root_physical_bytes:25769803776,
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
jq -e --arg iid "$iid" --arg plan_sha "$(sha "$plan")" --argjson pid "$pid" '
  .producer_invocation_id==$iid and .producer.pid==$pid and .plan_sha256==$plan_sha
  and .producer_stop_enabled==true and .trip_reason==null
  and .root_physical_observation_error==null and .worker_observation_error==null
  and .maximum_root_physical_bytes==25769803776
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
jq -n --arg iid "$iid" --argjson pid "$pid" --argjson ticks "$ticks"   --arg boot "$(cat /proc/sys/kernel/random/boot_id)" --arg unit "$u"   --arg timer "$g.timer" --arg timer_iid "$timer_iid"   --arg plan "$plan" --arg plan_sha "$(sha "$plan")" --arg sample "$first" --arg sample_sha "$(sha "$first")"   --arg fleet "$fleet" --arg fleet_sha "$fsha" --arg booking "$booking" --arg booking_sha "$bsha"   --arg nodeplan "$a/plan/plan.json" --arg nodeplan_sha "$plan_sha" --argjson now "$(date +%s)" '{
 schema:"horizon-epoch140-guarded-held-owner-v1",epoch:140,unit:$unit,invocation_id:$iid,pid:$pid,start_ticks:$ticks,
 boot_id:$boot,guard_timer:$timer,guard_timer_invocation_id:$timer_iid,
 guard_plan:{path:$plan,sha256:$plan_sha},first_guard:{path:$sample,sha256:$sample_sha},
 inherited_fleet:{path:$fleet,sha256:$fleet_sha},booking:{path:$booking,sha256:$booking_sha},
 node_plan:{path:$nodeplan,sha256:$nodeplan_sha},recorded_unix_seconds:$now,
 cpu_quota_micros:3000000,producer_RAM_bytes:27917287424,guard_RAM_bytes:1073741824,
 guarded_HOME_bytes:25769803776,archive_publication_authorized:false}' | publish "$a/HELD_OWNER.json"
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
