#!/bin/bash
set -euo pipefail
umask 077
src=/home/sol/.jetstreamer-private/public-method-20261120/status-retry-source
base=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work
current="$base/current-nodes-136-169-20261120-g2"
old="$current/tmp/early145-f3c1e61202f340f8a43902eb27fea7fc/source"
d="$current/target/release"
flavor="${2:-recovery}"
focused=false
if [[ $flavor == timer-rejoin || $flavor == focused-rejoin || $flavor == focused-post || $flavor == retry-post || $flavor == timer-post ]]; then
  focused=true
  src=/home/sol/.jetstreamer-private/paid145-focused169-recovery-20261121-v1
fi
registered=false
fixture_recovery=false
fixture_post=false
audit_turnover=false
if [[ $flavor == audit-turnover-rejoin ]]; then
  audit_turnover=true
  flavor=status-owner-rejoin
fi
status_owner=false
if [[ $flavor == status-owner-rejoin ]]; then
  status_owner=true
  flavor=donor-pressure-rejoin
fi
donor_pressure=false
if [[ $flavor == donor-pressure-rejoin ]]; then
  donor_pressure=true
  flavor=guard-walk-rejoin
fi
guard_walk=false
if [[ $flavor == guard-walk-rejoin ]]; then
  guard_walk=true
  flavor=missed-rejoin
fi
missed_rejoin=false
if [[ $flavor == missed-rejoin ]]; then
  missed_rejoin=true
  flavor=lease-rejoin
fi
lease_rejoin=false
if [[ $flavor == lease-rejoin ]]; then
  lease_rejoin=true
  flavor=retry4-rejoin
fi
retry4_rejoin=false
if [[ $flavor == retry4-rejoin ]]; then
  retry4_rejoin=true
  flavor=retry3-rejoin
fi
retry3_rejoin=false
if [[ $flavor == retry3-rejoin ]]; then
  retry3_rejoin=true
  flavor=five-lane-rejoin
fi
five_lane_rejoin=false
if [[ $flavor == five-lane-rejoin ]]; then
  five_lane_rejoin=true
  flavor=homefloor-rejoin
fi
homefloor_rejoin=false
if [[ $flavor == homefloor-rejoin ]]; then
  homefloor_rejoin=true
  flavor=fixture-rejoin
fi
v5q_136_post=false
if [[ $flavor == v5q-136-post ]]; then
  v5q_136_post=true
  flavor=v5n-post
fi
v5o_136_post=false
if [[ $flavor == v5o-136-post ]]; then
  v5o_136_post=true
  flavor=v5n-post
fi
v5n_136_post=false
if [[ $flavor == v5n-136-post ]]; then
  v5n_136_post=true
  flavor=v5n-post
fi
v5n_post=false
if [[ $flavor == v5n-post ]]; then
  v5n_post=true
  flavor=v5m-post
fi
v5m_post=false
if [[ $flavor == v5m-post ]]; then
  v5m_post=true
  flavor=v5k-post
fi
v5k_post=false
if [[ $flavor == v5k-post ]]; then
  v5k_post=true
  flavor=v5j-retry1-post
fi
v5j_retry_post=false
if [[ $flavor == v5j-retry1-post ]]; then
  v5j_retry_post=true
  flavor=v5j-post
fi
v5j_post=false
if [[ $flavor == v5j-post ]]; then
  v5j_post=true
  flavor=fixture-post
fi
registered_v7b=false
registered_v7c=false
if [[ $flavor == fixture-post-v7c ]]; then
  registered_v7c=true
  flavor=fixture-post
fi
if [[ $flavor == fixture-post-v7b ]]; then
  registered_v7b=true
  flavor=fixture-post
fi
if [[ $flavor == registered-post || $flavor == fixture-rejoin || $flavor == fixture-post ]]; then
  if [[ $flavor == fixture-post ]]; then
    fixture_post=true
    registered=true
    flavor=timer-post
  elif [[ $flavor == registered-post ]]; then
    registered=true
    flavor=timer-post
  else
    fixture_recovery=true
    flavor=timer-rejoin
  fi
  focused=true
  src=$(cd -- "$(dirname "$(realpath -e "$0")")/../.." && pwd -P)
  exec 9>>/run/lock/horizon-epoch140-suffix-compiler.lock
  flock -n 9
  ps -eo comm | awk '$1=="cargo" || $1=="rustc" || $1=="ld.lld" {busy=1} END{exit busy}'
fi
extra=()
fixture=(incident145::tests::failed_145_pass_keeps_the_original_leased_objects_and_requires_restart materialized::tests::paid_inode_native_projection)
case "$flavor" in
recovery) sources=(incident-phase.py run-incident.sh) ;;
rejoin) sources=(incident-phase.py run-incident.sh)
        extra=(--cfg incident_rejoin145_only)
        ;;
timeout-rejoin|focused-rejoin|timer-rejoin) sources=(incident-phase.py run-incident.sh)
        extra=(--cfg incident_rejoin145_only --cfg incident_timeout145_only)
        if $focused; then extra+=(--cfg incident_focused145_only); fixture+=(incident145::preserves_the_actual_cadence_failure_and_frozen_inode); fi
        if [[ $flavor == timer-rejoin ]]; then extra+=(--cfg incident_timer145_only); fixture+=(incident145::proves_retirement_timeout_and_rejects_other_commands); fi
        fixture+=(incident145::tests::distinguishes_native_query_timeout_from_foreign_or_malformed_failures)
        ;;
post|current-post|timeout-post|focused-post|retry-post|timer-post) sources=(incident-post-phase.py run-incident-post.sh post-phase-test.py)
      extra=(--cfg incident_post145_only)
      if [[ $flavor == timeout-post || $flavor == focused-post || $flavor == retry-post || $flavor == timer-post ]]; then extra+=(--cfg incident_timeout_post145_only); fi
      if $focused; then extra+=(--cfg incident_focused_post145_only); fi
      if [[ $flavor == retry-post || $flavor == timer-post ]]; then extra+=(--cfg incident_retry_post145_only); fi
      if [[ $flavor == timer-post ]]; then extra+=(--cfg incident_timer_post145_only); fi
      fixture=(publication_tree::tests::freezer_covers_uploader_and_grandchild post::tests::current_full_and_plugin_use_the_same_qualified_plan_as_delivery)
      ;;
*) exit 2 ;;
esac
if $fixture_recovery; then
  extra+=(--cfg incident_fixture145_only)
  sources+=(registered-build-fit.py)
  fixture+=(incident145::authenticates_the_failed_fixture_census_and_frozen_inode)
fi
if $homefloor_rejoin; then
  extra+=(--cfg incident_homefloor145_only)
  sources+=(homefloor-phase-test.py)
  fixture+=(incident145::accepts_only_the_actual_stopped_retry1_and_retained_candidate)
fi
if $five_lane_rejoin; then
  extra+=(--cfg incident_five_lane145_only)
  fixture+=(incident_fit::tests::both_exact_park_terminals_and_retirements_precede_handoff)
fi
if $retry3_rejoin; then extra+=(--cfg incident_retry3_145_only); fi
if $retry4_rejoin; then extra+=(--cfg incident_retry4_145_only); fi
if $lease_rejoin; then
  test -s "$src/scripts/horizon_epoch145_guarded_export_20261121_v1/lease_startup.rs"
  extra+=(--cfg incident_lease_start145_only)
  if $missed_rejoin; then
    extra+=(--cfg incident_missed_clock145_only)
    sources+=(missed_clock.py test_missed_clock.py build_159_price.py)
  fi
fi
if $guard_walk; then
  test -s "$src/scripts/horizon_epoch145_guarded_export_20261121_v1/guard_walk.rs"
  extra+=(--cfg incident_guard_walk145_only)
  sources+=(v5n_feature_cover.py test_v5n_feature_cover.py)
fi
if $donor_pressure; then
  extra+=(--cfg incident_donor_pressure145_only)
  sources+=(v5n_stopped.py test_v5n_stopped.py)
fi
if $status_owner; then
  extra+=(--cfg incident_status_owner145_only)
  sources+=(v5o_stopped.py test_v5o_stopped.py)
fi
if $audit_turnover; then
  extra+=(--cfg incident_audit_turnover145_only)
  sources+=(v5p_stopped.py test_v5p_stopped.py)
fi
if $fixture_post; then extra+=(--cfg incident_fixture_post145_only); fi
if $v5j_post; then extra+=(--cfg incident_v5j_post145_only); sources+=(post_inputs.py test_post_inputs.py); fi
if $v5k_post; then extra+=(--cfg incident_v5k_post145_only); fi
if $v5m_post; then
  extra+=(--cfg incident_v5m_post145_only)
  sources+=(build_159_price.py)
fi
if $v5n_post; then extra+=(--cfg incident_v5n_post145_only); fi
if $v5n_136_post; then extra+=(--cfg incident_v5n_136_post145_only); fi
if $v5o_136_post; then extra+=(--cfg incident_v5o_136_post145_only); fi
if $v5q_136_post; then extra+=(--cfg incident_v5q_136_post145_only); fi
if $v5j_retry_post; then extra+=(--cfg incident_v5j_retry1_post145_only); fi
if $registered_v7c; then extra+=(--cfg incident_v7c_post145_only); fi
if $registered_v7b; then extra+=(--cfg incident_v7b_post145_only); fi
if $registered; then extra+=(--cfg incident_registered136_post145_only); sources+=(registered-build-fit.py); fi
q=/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/incident-build-$INVOCATION_ID
out="$current/tmp/incident145-$INVOCATION_ID"
cg="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
test "$(cat "$cg/cpu.max")" = '100000 100000'
memory=1073741824
if [[ $flavor == timeout-rejoin || $flavor == timeout-post ]] || $focused; then memory=805306368; fi
test "$(cat "$cg/memory.max")" = "$memory"
test "$(cat "$cg/memory.swap.max")" = '0'
test "$(cat "$cg/pids.max")" = '128'
test "$(findmnt -n -T "$current" -o SOURCE)" = /dev/loop4
if [[ $flavor == rejoin || $flavor == current-post || $flavor == timeout-rejoin || $flavor == timeout-post ]] || $focused; then
  # Keep the historical compiler/dependency cache immutable. Pay a new bounded
  # image on HOME for this generation and retain its exact products for sealing.
  provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v5/post-stop-fit
  signature=c5491d6f0e96c50cbe914db9956f6eff620d99db436897750e3eaf44d2b9e2b2
  if [[ $flavor == current-post ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v6/post-stop-fit
    signature=f16e961612d5c74727fb62a9be280dbb298ebe937cc6c57e50c93839e603609f
  fi
  if [[ $flavor == timeout-rejoin ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v9/post-stop-fit
    signature=57e2f4666f62efe9f65abde6bb3b9fc3e4280f8641c1ee730fad22e906f978aa
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == a3c04e5f662aaca041398496a609bb9a7072177cbc180fa6e1dac32fd1ab0b9c ]]
  fi
  if [[ $flavor == timeout-post ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v10/post-stop-fit
    signature=d5ed981b98ad6fc2c54843667852e9d3c3567c764398b644afac00231cd2940d
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == d32722386d1511d8db85801e349dd645107b2f3c0043a7debebb22c9eae60085 ]]
  fi
  if $focused && ! $homefloor_rejoin; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v14-bootstrap/post-stop-fit
    signature=63538fb9ff385f34b9b7b592c6b61b296e649f7eb3a70de017d9edeb0326ad50
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == 54083064203f8e64629ccfaf0b5411181bc90b0489028493795804ea757d27fe ]]
  fi
  if [[ $flavor == retry-post ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v14b-prestart/post-stop-fit
    signature=7caf7d7eb81ac5c0972649666e6d22273926c841640b537cd7fe336706514cd3
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == db71be720088b97a5fe0db694d0f863b77273cd7963112b61ac673b23213fda8 ]]
  fi
  if [[ $flavor == timer-rejoin ]] && ! $fixture_recovery; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v15b-prestart/post-stop-fit
    signature=350295e25c3404b9e23f60969a378061e780ad5a580fdf71c8c29861722d953b
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == 6222a205645ea6a2bf34b4b2c4085d30a0fda7349e4243524a2c52089fc19931 ]]
  fi
  if [[ $flavor == timer-post ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v16/post-stop-fit
    signature=5829fb668122a391d61672598e82967e5299a9d84909d2ee6fc6ffd5563d1ee4
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == b11e6366a6fc0cf3ed91d2584314851b628f2589d60b70d41b922cb1170d0cb5 ]]
  fi
  if $registered; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v18-registered136/post-stop-fit
    signature=c651d4d2b8d1c32a83ca7b6cfc77d711f19b0b97a78fd489fb11a399a00b7802
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == 428442272e7b2d68c66533636b22600dba8daf3decc44ced6d3075d517acfd47 ]]
  fi
  if $fixture_post || $fixture_recovery; then
    native_package=tools-v20-prestart
    if $v5j_post; then
      native_package=tools-homefloor-145-rejoin-v4
      if $v5k_post; then native_package=tools-homefloor-145-lease-rejoin-v1; fi
      if $v5m_post; then native_package=tools-homefloor-145-missed-rejoin-v1; fi
      if $v5n_post; then native_package=tools-homefloor-145-guard-walk-rejoin-v1; fi
      if $v5o_136_post; then native_package=tools-homefloor-145-donor-pressure-rejoin-v1; fi
      if $v5q_136_post; then native_package=tools-homefloor-145-audit-turnover-rejoin-v1; fi
      [[ ${5:?expected original build price generation} == "$native_package" ]]
    elif $fixture_post; then
      native_package=${5:?expected build price generation}
      [[ $native_package == tools-v20-prestart || $native_package == tools-v20 ]]
    elif $homefloor_rejoin; then
      native_package=${5:?expected sealed HOME provider directory}
      [[ $native_package == tools-homefloor-* && $native_package =~ ^[a-z0-9-]+$ ]]
    fi
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/$native_package/post-stop-fit
    signature=${3:?expected qualified terminal price digest}
    seal_digest=${4:?expected qualified terminal deployment digest}
    [[ $signature =~ ^[a-f0-9]{64}$ && $seal_digest =~ ^[a-f0-9]{64}$ ]]
    if $audit_turnover; then
      [[ $native_package == tools-homefloor-145-v5p-stopped-v1 &&
         $signature == 45b5f5371c6ef23ea900cb550c83406d12f4a32fe11edb268d617f50141502b3 &&
         $seal_digest == b2febb131aa5c7e1ae42644a241311a8c0d30b82b4ecfb5946b884230d1ea888 ]]
    elif $status_owner; then
      [[ $native_package == tools-homefloor-145-v5o-stopped-v1 &&
         $signature == 8c80997fccb17c1b10481c6a60f902078a5c9ae179d39dcfb03217f5c09dac27 &&
         $seal_digest == 48e7fbef4140b01a9ea80d2710b21f488f0ed1e8b0ab4f428a9c47a65581ed34 ]]
    fi
    [[ $(sha256sum "${provider%/*}/deployment-seal-receipt.json" | cut -d' ' -f1) == "$seal_digest" ]]
    jq -e --arg hash "$signature" --arg dir "${provider%/*}" '
      .destination == $dir and .remote_mutations == false
      and .sealer_sha256 == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
      and ([.members[] | select(.name == "post-stop-fit" and .mode == "0555" and .sha256 == $hash)] | length == 1)
    ' "${provider%/*}/deployment-seal-receipt.json" >/dev/null
  fi
  [[ $(sha256sum "$provider" | cut -d' ' -f1) == "$signature" ]]
  mkdir -m0700 "$q"
  fleet_sha=$(sha256sum "$1" | cut -d' ' -f1)
  maximum_attempts=5
  if [[ $flavor == retry-post || $flavor == timer-post ]]; then maximum_attempts=10; fi
  if $guard_walk; then
    feature_cover="$src/scripts/horizon_epoch145_guarded_export_20261121_v1/v5n_feature_cover.py"
    feature_snapshot() {
      /usr/bin/python3 -IB -c '
import json, runpy, sys
print(json.dumps(runpy.run_path(sys.argv[1])["snapshot"](runpy.run_path(sys.argv[2])), sort_keys=True))
' "$feature_cover" "$src/scripts/horizon_epoch145_guarded_export_20261121_v1/build_159_price.py"
    }
    feature_snapshot > "$q/feature159-before.json"
  fi
  for ((probe=1;probe<=maximum_attempts;probe++)); do
    if $missed_rejoin || $v5m_post; then
      donor="$src/scripts/horizon_epoch145_guarded_export_20261121_v1/build_159_price.py"
      if $v5m_post; then
        [[ $(sha256sum "$donor" | cut -d' ' -f1) == 2e69123264b8709259aa9c8aec1f2a0c4f5cce10dece303f751f628bc1f2fe24 ]]
      fi
      /usr/bin/python3 -IB "$donor" snapshot > "$q/donor-before.json"
    fi
    if $fixture_post && ! $v5j_post; then
      # Capture the 136 mirrors and public reader commitments in the same native observation.
      quote=${6:?expected full mirror price executable}
      quote_digest=${7:?expected qualification hash for mirror price}
      [[ $(realpath -e -- "$quote") == "$quote" ]]
      quote_mode=444
      quote_args=("$1" "$fleet_sha")
      if $registered_v7c; then
        [[ $native_package == tools-v20 ]]
        wrapper=${provider%/*/*}/tools-v22-active-mirrors
        [[ $quote == "$wrapper/price-mirrors" && $quote_digest == a4d32f83e4d5ddf857fa0d0770690bafd765b05893fe7621b71586f16072d0d2 ]]
        [[ $(sha256sum "$wrapper/deployment-seal-receipt.json" | cut -d' ' -f1) == 5085510c3899e1cb82846c99ad6f4bb05ee43ba6a54a23b5743b5f75942fe411 ]]
        quote_mode=555
        worker=${q%/*}/V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json
        quote_args+=("$worker" 1b16ce2d061e2ec97ab8c1ba81cd2dbcff9d0a759f317fbaf53b64e731a19501)
      elif [[ $native_package == tools-v20 ]]; then
        quote_args+=("$seal_digest")
        [[ $quote == "${provider%/*}/price_recovery_mirrors.py" ]]
        jq -e --arg hash "$quote_digest" '
          [.members[] | select(.name == "price_recovery_mirrors.py" and .mode == "0444" and .sha256 == $hash)] | length == 1
        ' "${provider%/*}/deployment-seal-receipt.json" >/dev/null
      else
        [[ $quote == "${provider%/*/*}/PRICE_V20_PRESTART_MIRRORS.py" ]]
      fi
      [[ $(stat -c '%u %g %a %h' -- "$quote") == "0 0 $quote_mode 1" && $quote_digest =~ ^[a-f0-9]{64}$ ]]
      [[ $(sha256sum -- "$quote" | cut -d' ' -f1) == "$quote_digest" ]]
      if /usr/bin/python3 -IB "$quote" "${quote_args[@]}" > "$q/mirrors-$probe.json" 2> "$q/fit-$probe.stderr"; then
        jq -e --arg seal "$seal_digest" --arg path "${provider%/*}/deployment-seal-receipt.json" '
           .mirrors_fit and .admission_granted == false and .resource_credit_bytes == 0
           and .provider == {path:$path,sha256:$seal} and .native.fleet == .fleet
        ' "$q/mirrors-$probe.json" >/dev/null
        cp "$q/mirrors-$probe.json" "$q/build-mirrors.json"
        jq -e '.native' "$q/build-mirrors.json" > "$q/before.json"
        break
      fi
    elif "$provider" 145 "$1" "$fleet_sha" > "$q/fit-$probe.json" 2> "$q/fit-$probe.stderr"; then
      cp "$q/fit-$probe.json" "$q/before.json"
      break
    fi
    # A different provider is never excluded from the live 145 cgroup. Wait
    # out the read-only observer overlap and repeat the entire original fit.
    last=$(tail -1 "$q/fit-$probe.stderr")
    manager_timeout=false
    if [[ ( $flavor == retry-post || $flavor == timer-post ) && $last == "subprocess.TimeoutExpired: Command '['/usr/bin/systemctl', 'show', '-p', "*" 'horizon-qualify-168-full-metered-20261121-v1.service']' timed out after 10 seconds" ]]; then
      manager_timeout=true
    fi
    expired_probe=false
    if $fixture_post && [[ $native_package == tools-v20 &&
         $last == "FileNotFoundError: [Errno 2] No such file or directory: '/proc/4011654/stat'" ]]; then
      # The historical publication adapter consults its V5C PID only after a full native
      # price reports a transient verifier descendant. Discard the failed price in full.
      if grep -Fq 'capacity-tools-bounded/publication-fit", line 129, in wait_for_145_probe' "$q/fit-$probe.stderr" &&
         grep -Fq 'tools-v20/price_recovery_mirrors.py", line 73, in capture' "$q/fit-$probe.stderr"; then
        expired_probe=true
      fi
    fi
    audit_probe=false
    if { $audit_turnover || $v5q_136_post; } && [[ ! -s "$q/fit-$probe.json" &&
         "$last" == 'public audit workers changed during capacity capture' ]]; then
      audit_probe=true
    fi
    [[ ( $flavor == current-post || $flavor == timeout-post || $focused == true ) && $probe -lt $maximum_attempts &&
       ( "$last" == 'ValueError: foreign 145 descendants' || "$last" == 'ValueError: foreign recovery worker' || $manager_timeout == true || $expired_probe == true || $audit_probe == true ) ]] ||
       { cat "$q/fit-$probe.stderr" >&2; exit 1; }
    sleep "$((2+probe))"
  done
  disk=117440512
  if $homefloor_rejoin || $v5j_post; then disk=$((92274688 + 16777216)); fi
  python3 -IB -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["fits"] and v["resource_credit_bytes"]==0 and v["available_HOME_bytes"]-v["complete_required_HOME_bytes"]>=int(sys.argv[3]) and v["available_memory_bytes"]-v["required_available_memory_bytes"]>=int(sys.argv[2])' "$q/before.json" "$memory" "$disk"
  if $homefloor_rejoin || $v5j_post; then
    slice=/sys/fs/cgroup/horizonaudit.slice
    build_unit=horizon-145-homefloor-rejoin-build-v1.service
    if $v5j_post; then build_unit=horizon-145-v5j-post-build-v1.service; fi
    if $lease_rejoin; then build_unit=horizon-145-lease-rejoin-build-v1.service; fi
    if $missed_rejoin; then build_unit=horizon-145-missed-rejoin-build-v1.service; fi
    if $v5j_retry_post; then build_unit=horizon-145-v5j-post-build-v2.service; fi
    if $v5k_post; then build_unit=horizon-145-v5k-post-build-v1.service; fi
    if $v5m_post; then build_unit=horizon-145-v5m-post-build-v1.service; fi
    if $guard_walk; then build_unit=horizon-145-guard-walk-rejoin-build-v1.service; fi
    if $donor_pressure; then build_unit=horizon-145-donor-pressure-rejoin-build-v1.service; fi
    if $status_owner; then build_unit=horizon-145-status-owner-rejoin-build-v1.service; fi
    if $audit_turnover; then build_unit=horizon-145-audit-turnover-rejoin-build-v1.service; fi
    if $v5n_post; then build_unit=horizon-145-v5n-post-build-v1.service; fi
    if $v5n_136_post; then build_unit=horizon-145-v5n-136-post-build-v1.service; fi
    if $v5o_136_post; then build_unit=horizon-145-v5o-136-post-build-v1.service; fi
    if $v5q_136_post; then build_unit=horizon-145-v5q-136-post-build-v1.service; fi
    [[ $cg == "$slice/$build_unit" ]]
    [[ $(cat "$slice/cpu.max") == '1200000 100000' && $(cat "$slice/cpu.idle") == 1 ]]
    [[ $(cat "$slice/memory.high") == 21474836480 && $(cat "$slice/memory.max") == 25769803776 ]]
    (( $(cat "$slice/memory.current") + memory <= $(cat "$slice/memory.high") ))
    (( $(cat "$slice/pids.current") + 128 <= $(cat "$slice/pids.max") ))
    jq -e --arg fleet "$1" --arg hash "$fleet_sha" '
        .fleet == {path:$fleet,sha256:$hash} and now-.recorded_unix_seconds >= 0
        and now-.recorded_unix_seconds <= 120' "$q/before.json" >/dev/null
    if $guard_walk; then
      feature_snapshot > "$q/feature159-after.json"
      cmp "$q/feature159-before.json" "$q/feature159-after.json"
      /usr/bin/python3 -IB "$donor" build "$q/donor-before.json" "$q/before.json" > "$q/donor-combined-price.json"
    fi
    if $audit_turnover; then
      jq -e '.phase145.InvocationID == "c01dc3ba08b74e3aa0d4b531601e9fda"
             and .phase145.failure.sha256 == "fa6fb641253e22525916d591a39589c75b4d01aeda7bc04f58da7c5bf2936a67"
             and .phase145.recovery.sha256 == "49b5c68ca1217ecd89af0a11f1ea96f9abe1dbec454b52783c7a541b9fa7e3fc"
             and .phase145.public_audit_terminal.sha256 == "abda107d59f55823a92d3609cbc142dec21e7e63337d9b495f6f070dfe04de24"
             and .phase145.candidate.inode == 103237059 and .phase145.candidate.bytes == 105610995833
             and .phase145.retry_worker == null and .phase145.source_checkpoint_exists == false
             and .status_registration.invocation_id == "d6d40746a4974ca186acd7f2d5a5cac4"
             and .status_registration.consumer_seal.sha256 == "a608208cd09681d366f0994dfc43406b4f8430330e13919a88b3af031efaf160"
             and .epoch159_donor_cover.credited_retirement_bytes == 0' "$q/before.json" >/dev/null
    elif $status_owner; then
      jq -e '.phase145.InvocationID == "f3474dfad55f4a05a64431421881db29"
             and .phase145.failure.sha256 == "8b5c1b7024fec2fadbfedc14b59bd80bad97d3f3e98ee30f405f78d8c1798d27"
             and .phase145.recovery.sha256 == "e4b9e72a6481ea4f38b8fe7b49986463e2f93d37bc1dcb7f2156049930fd744b"
             and .phase145.status_owner_terminal.sha256 == "95fc24c89db925ca86fa1f918a6f61e665d3c124a7e4687ecf8ee44816b01f6f"
             and .phase145.candidate.inode == 103237059 and .phase145.candidate.bytes == 105610995833
             and .phase145.retry_worker == null and .phase145.source_checkpoint_exists == false
             and .status_registration.invocation_id == "d6d40746a4974ca186acd7f2d5a5cac4"
             and .status_registration.consumer_seal.sha256 == "a608208cd09681d366f0994dfc43406b4f8430330e13919a88b3af031efaf160"
             and .epoch159_donor_cover.credited_retirement_bytes == 0' "$q/before.json" >/dev/null
    elif $donor_pressure; then
      [[ $native_package == tools-homefloor-145-v5n-stopped-v1 && $seal_digest == a43da5f9618b8a5af9750e4201c67447a2fe50aa830d1445e6a896ad37e88dbf ]]
      jq -e '.phase145.InvocationID == "f86e7e61f4b34dc7aedc4e08a128e713"
             and .phase145.failure.sha256 == "553c2d9be55bf4688dd1c8b42bc497ba2f6ea985305e42b7fb7db951f400bd36"
             and .phase145.recovery.sha256 == "dad6a11f67b7717668c0189c607142ac89a64fc7fde8971b28b4e3c8622619ed"
             and .phase145.candidate.inode == 103237059 and .phase145.candidate.bytes == 105610995833
             and .phase145.retry_worker == null and .phase145.source_checkpoint_exists == false
             and .epoch159_donor_cover.credited_retirement_bytes == 0' "$q/before.json" >/dev/null
    elif $guard_walk; then
      [[ $native_package == tools-homefloor-145-v5m-stopped-v1 && $seal_digest == b066013b8e25ae95d43b2e0984ad7df55c47e9a68a32c685e54d1f71667151d7 ]]
      jq -e '.phase145.InvocationID == "dba04d40f1b046b4875d7e27e0ff224a"
             and .phase145.failure.sha256 == "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"
             and .phase145.recovery.sha256 == "06d2a4fa77bebe110f4d1c218bc91ec3066dc2e86f07575332d8725c1cf4e9b7"
             and .phase145.rejected_guard.sha256 == "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"
             and .phase145.candidate.inode == 103237059 and .phase145.candidate.bytes == 105610995833
             and .phase145.retry_worker == null and .phase145.source_checkpoint_exists == false
             and .epoch159_donor_cover.credited_retirement_bytes == 0' "$q/before.json" >/dev/null
    elif $missed_rejoin; then
      /usr/bin/python3 -IB "$donor" build "$q/donor-before.json" "$q/before.json" > "$q/donor-combined-price.json"
      [[ $native_package == tools-homefloor-145-v5k-stopped-v1 && $seal_digest == ea8e6bd7138cc8eb241c3b39f12e69fc65844505cb60a0d29be966adf56f05c6 ]]
      jq -e '.phase145.InvocationID == "ff597d64ad37400ea5c6836336fb6706"
             and .phase145.failure.sha256 == "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"
             and .phase145.recovery.sha256 == "706b0986b8a3979caa083d08ac007d93905919819b50126486e738cee6977e48"
             and .phase145.candidate.inode == 103237059 and .phase145.retry_worker == null
             and .phase145.source_checkpoint_exists == false' "$q/before.json" >/dev/null
    elif $lease_rejoin; then
      [[ $native_package == tools-homefloor-145-lease-build-v1 && $seal_digest == ba47dd7987accfbb8471b845425dd56a9b9c2e3e2231601e277889e6444a30b5 ]]
      jq -e '.phase145.InvocationID == "f2afc696a63a4e6aa6812451cf3559e5"
             and .phase145.failure.sha256 == "eff2c5c0da6cb103890f6ced5cb11920959f637234567d7fd2382a2fca2fbcc7"
             and .phase145.recovery.sha256 == "adb40073fd977545227b6eaf1cd0999f8769a5a992999561eab7ca382d3c139e"
             and .phase145.candidate.inode == 103237059 and .phase145.retry_worker == null
             and .phase145.source_checkpoint_exists == false' "$q/before.json" >/dev/null
    elif $v5j_retry_post; then
      selector=--retry1
      if $v5k_post; then selector=--lease-ready; fi
      if $v5m_post; then
        if $v5q_136_post; then
          selector=--audit-turnover
          [[ $seal_digest == f553f7a4f7d4b061f637b0a83e936e6dd6a9a33d4dcae56b15e492f74339b679 ]]
        elif $v5o_136_post; then
          selector=--donor-pressure
          [[ $seal_digest == 1618a2ec8613292dbaa45b1c34e8fa9ea8a2866fb7c6a0b4d1e575099577a069 ]]
        elif $v5n_post; then
          selector=--guard-walk
          handoff=${provider%/*/*}/tools-homefloor-145-handoff-v5
          jq -e --arg path "${provider%/*}/deployment-seal-receipt.json" --arg digest "$seal_digest" '
              .provider == {path:$path,sha256:$digest} and .failed_phase.InvocationID == "dba04d40f1b046b4875d7e27e0ff224a"
            ' "$handoff/admission-review.json" >/dev/null
          handoff_hash=$(sha256sum "$handoff/admission-review.json" | cut -d' ' -f1)
          jq -e --arg hash "$handoff_hash" --arg dir "$handoff" '
              .destination == $dir and .sealer_sha256 == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
              and ([.members[] | select(.name == "admission-review.json" and .sha256 == $hash and .mode == "0444")] | length == 1)
            ' "$handoff/deployment-seal-receipt.json" >/dev/null
        else
          selector=--missed-clock
          [[ $seal_digest == b2e28f51da8e428c106a23b3e5d73a6d92b1aca84043e82d1e662387d2c18b96 ]]
        fi
        /usr/bin/python3 -IB "$donor" build "$q/donor-before.json" "$q/before.json" > "$q/donor-combined-price.json"
      fi
      /usr/bin/python3 -IB "$src/scripts/horizon_epoch145_guarded_export_20261121_v1/post_inputs.py" "$selector" verify-build-price "$q/before.json"
    else
      jq -e '.phase145.InvocationID == "afcf6cdd1ec0400ea2757f81472987b3"
             and .phase145.failure.sha256 == "5e001f59750a67f2cdce6aa43fb11b7d55e648a40d52e3fbee26ed3ead66a366"
             and .phase145.candidate.inode == 103237059
             and .phase145.source_checkpoint_exists == false' "$q/before.json" >/dev/null
    fi
    jq -e '.epoch == 145 and .fits and .candidate == null and .replay_launch_authorized == false
           and .recovery_obligations.public_storage.remaining_archive_growth_bytes == 0
           and .recovery_obligations.prefix.maximum_HOME_allocation_bytes == 16777216
           and .recovery_obligations.missing_mirror_bytes >= 0 and .candidate136.cap == 77309411328' "$q/before.json" >/dev/null
    [[ $(sha256sum "$1" | cut -d' ' -f1) == "$fleet_sha" ]]
    jq -e '.retry9_auxiliary_commitments | .build_and_native_qualification_serial and
           .holding_and_build_may_overlap and .build_cpu_quota_micros >= 1000000 and
           .build_memory_bytes >= 805306368 and .build_fixed_image_bytes >= 92274688 and
           .build_outside_allowance_bytes >= 16777216' "$1" >/dev/null
  elif $registered || $fixture_recovery; then
    python3 -IB "$src/scripts/horizon_epoch145_guarded_export_20261121_v1/registered-build-fit.py" "$q" "$provider" "$cg"
  fi
  image="$q/cache.ext4"
  fallocate -l 92274688 "$image"
  /usr/sbin/mke2fs -q -t ext4 -F -m0 -E nodiscard,lazy_itable_init=0,lazy_journal_init=0 "$image"
  [[ $(stat -c %s "$image") == 92274688 ]]
  blocks=$(stat -c %b "$image"); ((blocks >= 180224 && blocks <= 182272))
  stat -c '%d:%i:%h:%s:%u:%g:%a' "$image" > "$q/cache-identity"
  out="$q/cache"
  mkdir -m0700 "$out"
  mount --make-rprivate /
  mount -o loop,noatime,nodiscard,nodev,nosuid "$image" "$out"
  test "$(df -B1 --output=avail "$out" | tail -1)" -gt 73400320
  mkdir -m0700 "$out/tmp"
else
  test "$(df -B1 --output=avail "$current" | tail -1)" -gt 73400320
  mkdir -m0700 "$q" "$out" "$out/tmp"
fi
exec > "$q/build.log" 2>&1
cp -R "$old" "$out/source"
if [[ $flavor == timeout-rejoin || $flavor == timeout-post ]] || $focused; then
  # The historical source layout also contains files from the epoch 166 fixture.
  # Take the entire small staged source tree from the same current checkout.
  revision=$(git -c safe.directory="$src" -C "$src" rev-parse --verify HEAD^{commit})
  while IFS= read -r -d '' prior; do
    rel=${prior#"$out/source/"}
    git -c safe.directory="$src" -C "$src" show "$revision:$rel" > "$prior"
  done < <(find "$out/source" -type f -print0)
fi
s=scripts/horizon_epoch145_guarded_export_20261121_v1
cp "$src/$s"/*.rs "$src/$s/build-incident.sh" "$out/source/$s/"
for file in "${sources[@]}"; do cp "$src/$s/$file" "$out/source/$s/"; done
cd "$out/source"
find . -type f -print0 | sort -z | xargs -0 sha256sum > "$q/sources"
export TMPDIR="$out/tmp"
export PATH=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin
export INCIDENT_FLEET="$1"
if $homefloor_rejoin || $v5j_post; then export INCIDENT_HOMEFLOOR_PRICE="$q/before.json"; fi
args=("${extra[@]}" --cfg incident145_only --cfg continuity145_only --cfg materialized145_only --cfg partial145_only -Adead_code -L "dependency=$d/deps" -Copt-level=2 -Cstrip=symbols -Ccodegen-units=1 -Clink-arg=-Wl,--threads=1 -Clink-arg=-lstdc++)
for o in "$d"/build/*/out; do args+=(-L "native=$o"); done
ulimit -c 0
args+=(@"$base/epoch145-aligned-prefix-integration-20261120-g1/rustc.args")
if $missed_rejoin; then /usr/bin/python3 -IB "$s/test_missed_clock.py"; fi
if $guard_walk; then /usr/bin/python3 -IB "$s/test_v5n_feature_cover.py"; fi
if $donor_pressure; then /usr/bin/python3 -IB "$s/test_v5n_stopped.py"; fi
if $homefloor_rejoin; then
  if $audit_turnover; then
    /usr/bin/python3 -IB "$s/test_v5p_stopped.py" -v
    /usr/bin/python3 -IB "$s/homefloor-phase-test.py" -v
  elif $status_owner; then
    /usr/bin/python3 -IB "$s/test_v5o_stopped.py" -v
    /usr/bin/python3 -IB "$s/homefloor-phase-test.py" -v
  else
    /usr/bin/python3 -IB "$s/homefloor-phase-test.py"
  fi
  # Both the real source inode and its read-only test mounts are inside this build's own image.
  projection="$out/tmp/paid-projection"
  mkdir -m0700 "$projection" "$projection/view"
  export RECOVERY_FIXTURE_SOURCE="$projection/source" RECOVERY_FIXTURE_VIEW="$projection/view/fixture"
  echo paid-fixture > "$RECOVERY_FIXTURE_SOURCE"
  touch "$RECOVERY_FIXTURE_VIEW"
  mount --bind "$projection/view" "$projection/view"
  mount --bind "$RECOVERY_FIXTURE_SOURCE" "$RECOVERY_FIXTURE_VIEW"
  mount -o remount,bind,ro "$RECOVERY_FIXTURE_VIEW"
  mount -o remount,bind,ro "$projection/view"
fi
rustc --edition=2024 --test "${args[@]}" "$s/main.rs" -o "$out/tests"
"$out/tests" --test-threads=1
for name in "${fixture[@]}"; do "$out/tests" --ignored --exact "$name"; done
"$out/tests" --ignored --exact incident_fit::tests::authenticates_the_actual_fleet_and_disallows_missing_members
if [[ $flavor == timeout-post || $flavor == focused-post || $flavor == retry-post || $flavor == timer-post ]]; then
  phase_package=tools-v8
  if $focused; then phase_package=tools-v9; fi
  if [[ $flavor == retry-post ]]; then phase_package=tools-v10; fi
  if [[ $flavor == timer-post ]]; then phase_package=tools-v11; fi
  if $registered; then phase_package=tools-v12; fi
  if $fixture_post; then phase_package=tools-v13; fi
  if $registered_v7b; then phase_package=tools-v13b; fi
  if $registered_v7c; then phase_package=tools-v13c; fi
  if $v5j_post; then phase_package=tools-v13d; fi
  if $v5j_retry_post; then phase_package=tools-v13e; fi
  if $v5k_post; then phase_package=tools-v13f; fi
  if $v5m_post; then phase_package=tools-v13g; fi
  if $v5n_post; then phase_package=tools-v13h; fi
  if $v5n_136_post; then phase_package=tools-v13i; fi
  if $v5o_136_post; then phase_package=tools-v13j; fi
  if $v5q_136_post; then phase_package=tools-v13k; fi
  mkdir "$out/tmp/$phase_package"
  cp "$s/incident-post-phase.py" "$out/tmp/$phase_package/"
  if $v5j_post; then
    /usr/bin/python3 -IB "$s/test_post_inputs.py"
    POST_PHASE_UNDER_TEST="$out/tmp/$phase_package/incident-post-phase.py" /usr/bin/python3 -IB "$s/post-phase-test.py" \
      PostPhaseTest.test_full_native_read_and_foreign_command PostPhaseTest.test_unregistered_controller_and_phase_members
  else
    POST_PHASE_UNDER_TEST="$out/tmp/$phase_package/incident-post-phase.py" /usr/bin/python3 -IB "$s/post-phase-test.py"
  fi
elif [[ $flavor == post || $flavor == current-post ]]; then
  /usr/bin/python3 -IB "$s/post-phase-test.py"
fi
rustc --edition=2024 "${args[@]}" "$s/main.rs" -o "$out/export145"
sha256sum "$out/tests" "$out/export145" > "$q/artifacts"
cat "$cg/memory.peak" > "$q/memory.peak"
du -s -B1 "$out" > "$q/scratch-bytes"
test "$(cut -f1 "$q/scratch-bytes")" -le 73400320
if [[ $flavor == rejoin || $flavor == current-post || $flavor == timeout-rejoin || $flavor == timeout-post ]] || $focused; then
  mkdir -m0700 "$q/products"
  if $homefloor_rejoin || $v5j_post; then
    # Keep the test binary inside the paid image. The 16 MiB outside allocation covers the retained source, binary and deployment image.
    cp -R "$out/source" "$out/export145" "$q/products/"
    test "$(du -s -B1 "$q/products" | cut -f1)" -le 7340032
  else
    cp -R "$out/source" "$out/tests" "$out/export145" "$q/products/"
  fi
  test "$(du -s -B1 "$q/products" | cut -f1)" -le 24117248
fi
