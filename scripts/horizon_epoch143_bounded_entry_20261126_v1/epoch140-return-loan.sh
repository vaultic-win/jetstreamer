#!/usr/bin/env bash
set -euo pipefail
umask 077

suffix=${1:-v1}
[[ $suffix == v1 || $suffix == retry1 ]]
authority="/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-recording-20261127-$suffix"
producer=horizon-epoch140-suffix-recording.service
guard="horizon-guard-epoch140-suffix-recording-20261127-$suffix"
original=horizon-qualify-170-full-metered-20261124-v1.service
marker=/run/horizon-epoch140-epoch170-cpu-loan.active
loan="$authority/CPU_LOAN_ACTIVE.json"

sha() { sha256sum "$1" | cut -d ' ' -f1; }
prop() { systemctl show "$1" -p "$2" --value; }

test "$(id -u)" = 0
exec 9<>/run/horizon-epoch171-to136-g1.operation.lock
flock -n -x 9
test "$(stat -c %u:%g:%a:%h "$loan")" = 0:0:444:1
iid=$(jq -er '.candidate_invocation | select(test("^[0-9a-f]{32}$"))' "$loan")
fence=$(jq -er '.overlap_fence.path' "$loan")
test "$fence" = "/run/systemd/system/$original.d/95-epoch140-cpu-loan.conf"
test "$(sha "$fence")" = "$(jq -er '.overlap_fence.sha256' "$loan")"
test "$(stat -c %u:%g:%a:%h "$marker")" = 0:0:444:1
test "$(cat "$marker")" = "$(jq -er '.booking.sha256' "$loan")"

drained() {
    local unit=$1 cg
    [[ $(prop "$unit" ActiveState) =~ ^(inactive|failed)$ ]] || return 1
    test "$(prop "$unit" MainPID)" = 0 || return 1
    test "$(prop "$unit" ControlPID)" = 0 || return 1
    test -z "$(prop "$unit" Job)" || return 1
    cg="/sys/fs/cgroup/system.slice/$unit"
    if [[ -e $cg/cgroup.events ]]; then
        grep -qx 'populated 0' "$cg/cgroup.events"
    fi
}

drained "$producer"
live_bid=$(prop "$producer" InvocationID)
[[ -z $live_bid || $live_bid == "$iid" ]]
if [[ $(prop "$guard.timer" ActiveState) != inactive ]]; then systemctl stop "$guard.timer"; fi
if ! drained "$guard.service"; then systemctl stop "$guard.service"; fi
test "$(prop "$guard.timer" ActiveState)" = inactive
test -z "$(prop "$guard.timer" Job)"
drained "$guard.service"
drained "$producer"
drained "$original"

out="$authority/CPU_LOAN_RETURN.json"
test ! -e "$out"
staged=$(mktemp "$authority/.loan-return-XXXXXX")
jq -n --arg iid "$iid" --arg old "$original" --arg prod "$producer" --arg g "$guard" \
  --arg loan "$loan" --arg loan_sha "$(sha "$loan")" --arg result "$(prop "$producer" Result)" \
  --argjson end_ns "$(date +%s%N)" '{
  schema:"horizon-epoch140-epoch170-cpu-loan-return-v1",candidate_invocation:$iid,
  candidate_unit:$prod,candidate_result:$result,guard_unit:($g+".service"),guard_timer:($g+".timer"),
  loan:{path:$loan,sha256:$loan_sha},drained_utc_unix_nanoseconds:$end_ns,original_170_unit:$old,
  producer_and_guard_drained:true,reusable_cpu_quota_micros:3000000}' > "$staged"
chmod 0444 "$staged"
sync "$staged"
rm -- "$fence"
rmdir -- "${fence%/*}"
systemctl daemon-reload
test -z "$(prop "$original" DropInPaths)"
rm -- "$marker"
mv -nT -- "$staged" "$out"
test ! -e "$staged"
python3 - "$authority" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
sha256sum "$out"
