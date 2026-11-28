#!/bin/bash
set -euo pipefail
stage=/run/horizon261-native-build-v1
result="$stage/result"
cd "$stage/src"
unit=/sys/fs/cgroup/system.slice/horizon261-native-build-v1.service
test "$(cat "$unit/memory.max")" = 2147483648
test "$(cat "$unit/memory.swap.max")" = 0
test "$(cat "$unit/cpu.max")" = '100000 100000'
test "$(cat "$unit/pids.max")" = 96
test "$(stat -f -c %T /tmp)" = tmpfs
test "$(stat -f -c %T "$result")" = tmpfs
test ! -w "$stage/src"
test -z "$(ls -A "$result")"
export PATH=/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin
export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/tmp/target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true TMPDIR=/tmp
mkdir "$CARGO_HOME"
ln -s /home/ubuntu/.cargo/registry "$CARGO_HOME/registry"
sha256sum --check "$stage/source.sha256"
rustc -vV
for role in input guard; do
    package="horizon261-native-$role"
    manifest="tools/$package/Cargo.toml"
    cargo test --manifest-path "$manifest" --release --offline --locked -- --include-ignored --test-threads=1
    cargo clippy --manifest-path "$manifest" --release --offline --locked --all-targets -- -D warnings
    cargo build --manifest-path "$manifest" --release --offline --locked --message-format=json -vv > "$result/$role-build.jsonl"
    install -m 0555 "$CARGO_TARGET_DIR/release/$package" "$result/$package"
    sha256sum "$result/$package"
    if [ "$role" = input ]; then
        "$CARGO_TARGET_DIR/release/$package" --validate-inputs > "$result/validated-inputs.json"
        HORIZON261_NATIVE_HARNESS_SHA256="$(sha256sum "$result/$package" | cut -d' ' -f1)"
        export HORIZON261_NATIVE_HARNESS_SHA256
    fi
done
cp -r "$CARGO_TARGET_DIR/release/.fingerprint" "$result/fingerprints"
(cd "$CARGO_TARGET_DIR" && find release -name '*.d' -exec cp --parents {} "$result" \;)
sha256sum --check "$stage/source.sha256"
