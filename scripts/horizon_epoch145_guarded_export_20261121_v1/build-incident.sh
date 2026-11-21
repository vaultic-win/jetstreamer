#!/bin/bash
set -euo pipefail
umask 077
src=/home/sol/.jetstreamer-private/public-method-20261120/status-retry-source
base=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work
current="$base/current-nodes-136-169-20261120-g2"
old="$current/tmp/early145-f3c1e61202f340f8a43902eb27fea7fc/source"
d="$current/target/release"
flavor="${2:-recovery}"
extra=()
fixture=(incident145::tests::failed_145_pass_keeps_the_original_leased_objects_and_requires_restart materialized::tests::paid_inode_native_projection)
case "$flavor" in
recovery) sources=(incident-phase.py run-incident.sh) ;;
rejoin) sources=(incident-phase.py run-incident.sh)
        extra=(--cfg incident_rejoin145_only)
        ;;
post|current-post) sources=(incident-post-phase.py run-incident-post.sh post-phase-test.py)
      extra=(--cfg incident_post145_only)
      fixture=(publication_tree::tests::freezer_covers_uploader_and_grandchild post::tests::current_full_and_plugin_use_the_same_qualified_plan_as_delivery)
      ;;
*) exit 2 ;;
esac
q=/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/incident-build-$INVOCATION_ID
out="$current/tmp/incident145-$INVOCATION_ID"
cg="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
test "$(cat "$cg/cpu.max")" = '100000 100000'
test "$(cat "$cg/memory.max")" = '1073741824'
test "$(cat "$cg/memory.swap.max")" = '0'
test "$(cat "$cg/pids.max")" = '128'
test "$(findmnt -n -T "$current" -o SOURCE)" = /dev/loop4
if [[ $flavor == rejoin || $flavor == current-post ]]; then
  # Keep the historical compiler/dependency cache immutable. Pay a new bounded
  # image on HOME for this generation and retain its exact products for sealing.
  provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v5/post-stop-fit
  signature=c5491d6f0e96c50cbe914db9956f6eff620d99db436897750e3eaf44d2b9e2b2
  if [[ $flavor == current-post ]]; then
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v6/post-stop-fit
    signature=f16e961612d5c74727fb62a9be280dbb298ebe937cc6c57e50c93839e603609f
  fi
  [[ $(sha256sum "$provider" | cut -d' ' -f1) == "$signature" ]]
  mkdir -m0700 "$q"
  fleet_sha=$(sha256sum "$1" | cut -d' ' -f1)
  for probe in 1 2 3 4 5; do
    if "$provider" 145 "$1" "$fleet_sha" > "$q/fit-$probe.json" 2> "$q/fit-$probe.stderr"; then
      cp "$q/fit-$probe.json" "$q/before.json"
      break
    fi
    # A different provider is never excluded from the live 145 cgroup. Wait
    # out the read-only observer overlap and repeat the entire original fit.
    last=$(tail -1 "$q/fit-$probe.stderr")
    [[ $flavor == current-post && $probe -lt 5 &&
       ( "$last" == 'ValueError: foreign 145 descendants' || "$last" == 'ValueError: foreign recovery worker' ) ]] ||
       { cat "$q/fit-$probe.stderr" >&2; exit 1; }
    sleep "$((2+probe))"
  done
  python3 -IB -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["fits"] and v["resource_credit_bytes"]==0 and v["available_HOME_bytes"]-v["complete_required_HOME_bytes"]>=117440512 and v["available_memory_bytes"]-v["required_available_memory_bytes"]>=1073741824' "$q/before.json"
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
if [[ "$flavor" == post || "$flavor" == current-post ]]; then /usr/bin/python3 -IB "$s/post-phase-test.py"; fi
rustc --edition=2024 "${args[@]}" "$s/main.rs" -o "$out/export145"
sha256sum "$out/tests" "$out/export145" > "$q/artifacts"
cat "$cg/memory.peak" > "$q/memory.peak"
du -s -B1 "$out" > "$q/scratch-bytes"
test "$(cut -f1 "$q/scratch-bytes")" -le 73400320
if [[ $flavor == rejoin || $flavor == current-post ]]; then
  mkdir -m0700 "$q/products"
  cp -R "$out/source" "$out/tests" "$out/export145" "$q/products/"
  test "$(du -s -B1 "$q/products" | cut -f1)" -le 24117248
fi
