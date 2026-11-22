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
if [[ $flavor == registered-post || $flavor == fixture-rejoin ]]; then
  if [[ $flavor == registered-post ]]; then
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
  if $focused; then
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
  if $fixture_recovery; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v20-prestart/post-stop-fit
    signature=${3:?expected qualified terminal price digest}
    seal_digest=${4:?expected qualified terminal deployment digest}
    [[ $signature =~ ^[a-f0-9]{64}$ && $seal_digest =~ ^[a-f0-9]{64}$ ]]
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
  for ((probe=1;probe<=maximum_attempts;probe++)); do
    if "$provider" 145 "$1" "$fleet_sha" > "$q/fit-$probe.json" 2> "$q/fit-$probe.stderr"; then
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
    [[ ( $flavor == current-post || $flavor == timeout-post || $focused == true ) && $probe -lt $maximum_attempts &&
       ( "$last" == 'ValueError: foreign 145 descendants' || "$last" == 'ValueError: foreign recovery worker' || $manager_timeout == true ) ]] ||
       { cat "$q/fit-$probe.stderr" >&2; exit 1; }
    sleep "$((2+probe))"
  done
  python3 -IB -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["fits"] and v["resource_credit_bytes"]==0 and v["available_HOME_bytes"]-v["complete_required_HOME_bytes"]>=117440512 and v["available_memory_bytes"]-v["required_available_memory_bytes"]>=int(sys.argv[2])' "$q/before.json" "$memory"
  if $registered || $fixture_recovery; then
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
args=("${extra[@]}" --cfg incident145_only --cfg continuity145_only --cfg materialized145_only --cfg partial145_only -Adead_code -L "dependency=$d/deps" -Copt-level=2 -Cstrip=symbols -Ccodegen-units=1 -Clink-arg=-Wl,--threads=1 -Clink-arg=-lstdc++)
for o in "$d"/build/*/out; do args+=(-L "native=$o"); done
ulimit -c 0
args+=(@"$base/epoch145-aligned-prefix-integration-20261120-g1/rustc.args")
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
  mkdir "$out/tmp/$phase_package"
  cp "$s/incident-post-phase.py" "$out/tmp/$phase_package/"
  POST_PHASE_UNDER_TEST="$out/tmp/$phase_package/incident-post-phase.py" /usr/bin/python3 -IB "$s/post-phase-test.py"
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
  cp -R "$out/source" "$out/tests" "$out/export145" "$q/products/"
  test "$(du -s -B1 "$q/products" | cut -f1)" -le 24117248
fi
