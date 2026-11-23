#!/bin/bash
# Run inside the campaign owner's admitted compiler. Writable output belongs on HOME scratch.
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(git -C "$source_dir" rev-parse --show-toplevel)
output=${1:?supply a fresh absolute output under the admitted HOME scratch mount}
cache=${2:?supply the absolute path of the original offline Cargo cache}
toolchain=${3:?supply the path of the exact Rust 1.49.0 toolchain}
case "$output" in /home/sol/*);; *) echo 'expected charged HOME path' >&2; exit 1;; esac
test ! -e "$output"
test "$(id -u)" = 1001
awk '/^NoNewPrivs:/ { good = $2 == 1 } END { exit !good }' /proc/self/status
# Use the original native compiler's systemd mount namespace and unprivileged identity.
# Git and Cargo may write their own private locks under the new output.
for input in "$repo" "$cache/registry/index" "$cache/registry/cache" "$cache/git/db" "$toolchain"; do
  options=$(findmnt -n -o VFS-OPTIONS -T "$input")
  case ",$options," in *,ro,*);; *) echo "compiler input mount must be read-only: $input" >&2; exit 1;; esac
done
mkdir -m 0700 -- "$output"
env -i LANG=C PATH="$toolchain/bin:/usr/bin:/bin" HOME="$output" TMPDIR="$output" GIT_CONFIG_NOSYSTEM=1 \
  /bin/bash -eu -o pipefail -c '
    src=$1 repo=$2 slot=$3 cache=$4 toolchain=$5
    dst=$slot/prepared
    /usr/bin/python3 -IB "$src/backport_source.py" prepare --repo "$repo" --cache "$cache" --output "$dst"
    export CARGO_HOME="$dst/cargo" CARGO_TARGET_DIR="$dst/target" TMPDIR="$dst/tmp"
    export CARGO_BUILD_JOBS=1 CARGO_NET_OFFLINE=true RUSTC="$toolchain/bin/rustc"
    cd "$dst/workspace"
    "$RUSTC" -vV | tee "$slot/rustc.txt"
    head -1 "$slot/rustc.txt" | grep -Fxq "rustc 1.49.0 (e1884a8e3 2020-12-29)"
    cargo -V | tee "$slot/cargo.txt"
    opts=(--locked --offline --manifest-path worker/Cargo.toml)
    cargo metadata --format-version 1 "${opts[@]}" > "$dst/metadata.json"
    /usr/bin/python3 -IB "$src/backport_source.py" check-graph --output "$dst"
    cargo build -j1 --release --message-format=json "${opts[@]}" > "$slot/release.jsonl"
    /usr/bin/python3 -IB "$src/backport_source.py" check-build --output "$dst"
    mkdir -p worker/tests
    cp -- "$src/vote_feature_candidate.rs" worker/tests/vote_feature_candidate.rs
    cargo test -j1 --release "${opts[@]}" --test vote_feature_candidate -- --nocapture | tee "$slot/native-test.txt"
    sha256sum "$dst/target/release/jetstreamer-historical-worker-v1-5-6" > "$slot/candidate.sha256"
  ' compiler "$source_dir" "$repo" "$output" "$cache" "$toolchain"
