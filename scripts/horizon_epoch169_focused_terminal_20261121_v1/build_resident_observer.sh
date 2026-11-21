#!/usr/bin/env bash
set -euo pipefail
umask 077
r=/var/lib/jetstreamer/horizon_runtime_data
old=/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1
freeze=/home/sol/.jetstreamer-private/observer-exit-census-20261107-v1/source-freeze.tar.gz
dest="$r/resident-observer-20261121-v1"
run="$dest/$INVOCATION_ID"
mkdir -m 700 "$run"
work=/home/sol/.jetstreamer-private/resident-observer-build-mount-20261121-v1
test -d "$work" && test ! -L "$work" && ! mountpoint -q "$work"
test -z "$(ls -A "$work")"
exec >"$run/build.log" 2>&1
provider="$r/incident-replay-fit-20261121-v1/tools-v14/post-stop-fit"
test "$(sha256sum "$provider" | cut -d' ' -f1)" = 63538fb9ff385f34b9b7b592c6b61b296e649f7eb3a70de017d9edeb0326ad50
"$provider" 145 "$1" "$2" > "$run/fit.json"
jq -e '.fits and .available_HOME_bytes - .complete_required_HOME_bytes >= 822083584 and .available_memory_bytes - .required_available_memory_bytes >= 1073741824' "$run/fit.json" > /dev/null
(cd "$old" && sha256sum --check --status SHA256SUMS)
test "$(sha256sum "$freeze" | cut -d' ' -f1)" = 4fe9c556a1dc272f04bf1f856ecb9bbf1c7e128909dddf56e487951b614e343b
fallocate -l 768M "$run/work.ext4"
mkfs.ext4 -q -F -m 0 "$run/work.ext4"
mount -o loop,nosuid,nodev "$run/work.ext4" "$work"
release() {
    cd /
    umount "$work"
    test -z "$(losetup -j "$run/work.ext4")"
    rm "$run/work.ext4"
}
trap release EXIT
tar --no-same-owner -xzf "$freeze" -C "$work"
cd "$work/source"
python3 -I -B - "$old/source-manifest.json" <<'PY'
import hashlib,json,sys
from pathlib import Path
for row in json.loads(Path(sys.argv[1]).read_bytes()):
    path=Path(row['path'])
    assert not path.is_absolute() and '..' not in path.parts and not path.is_symlink()
    data=path.read_bytes()
    assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
PY
git apply --check "$dest/pf-exiting.patch"
git apply "$dest/pf-exiting.patch"
rss=jetstreamer-horizon-observe/src/rss.rs
rg -F 'const MAX_ATTEMPTS: usize = 5;' "$rss"
rg -F 'flags & 0x0000_0004 != 0' "$rss"
sha256sum "$rss" > "$run/rss.sha256"
export CARGO_HOME=/home/sol/.cargo
export PATH=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0
export TMPDIR="$work/tmp"
mkdir -m 1777 "$TMPDIR"
# The predecessor separates ordinary parser tests (unprivileged) and log custody tests (root).
# Give the build identity its own cgroup-local mount point and the exact frozen source.
chown -R sol:sol "$work/source" "$TMPDIR"
options=(--offline --locked -p jetstreamer-horizon-observe --bin jetstreamer-horizon-observe)
runuser -u sol --preserve-environment -- cargo test "${options[@]}" -- --test-threads=1 > "$run/tests.log" 2>&1 || { tail -60 "$run/tests.log"; exit 1; }
rg -F 'exiting_flag_retries_complete_host_census_before_zombie_state ... ok' "$run/tests.log"
test_bin=$(find target/debug/deps -type f -perm /111 -name 'jetstreamer_horizon_observe-*')
test "$(wc -l <<< "$test_bin")" = 1
"$test_bin" --ignored root_log_policy_rejects_inode_fd_append_symlink_and_hardlink_substitutions --test-threads=1 > "$run/root-tests.log"
rg -F "3 passed; 0 failed" "$run/root-tests.log"
runuser -u sol --preserve-environment -- cargo clippy "${options[@]}" -- -D warnings
runuser -u sol --preserve-environment -- cargo build "${options[@]}" --release
bin=target/release/jetstreamer-horizon-observe
install -m 0555 "$bin" "$run/jetstreamer-horizon-observe"
cfg=$(jq -r .sole_next_observer.path "$1")
"$old/jetstreamer-horizon-observe" "$cfg" --check-config > "$run/before-check.json"
"$run/jetstreamer-horizon-observe" "$cfg" --check-config > "$run/after-check.json"
cmp "$run/before-check.json" "$run/after-check.json"
if "$run/jetstreamer-horizon-observe" "$cfg" --unexpected-mode; then exit 1; fi
sha256sum "$run/jetstreamer-horizon-observe" "$run/tests.log" "$run/after-check.json" > "$run/passed"
