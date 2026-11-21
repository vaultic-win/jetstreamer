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
post) sources=(incident-post-phase.py run-incident-post.sh post-phase-test.py)
      extra=(--cfg incident_post145_only)
      fixture=(publication_tree::tests::freezer_covers_uploader_and_grandchild)
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
test "$(df -B1 --output=avail "$current" | tail -1)" -gt 73400320
mkdir -m0700 "$q" "$out" "$out/tmp"
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
if [[ "$flavor" == post ]]; then /usr/bin/python3 -IB "$s/post-phase-test.py"; fi
rustc --edition=2024 "${args[@]}" "$s/main.rs" -o "$out/export145"
sha256sum "$out/tests" "$out/export145" > "$q/artifacts"
cat "$cg/memory.peak" > "$q/memory.peak"
du -s -B1 "$out" > "$q/scratch-bytes"
test "$(cut -f1 "$q/scratch-bytes")" -le 73400320
