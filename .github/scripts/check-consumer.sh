#!/bin/sh
set -eu

workspace_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
consumer=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/jetstreamer-consumer.XXXXXX")
trap 'rm -rf -- "$consumer"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Reuse compiled dependencies without inheriting the workspace lockfile or patches.
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$workspace_dir/target"}
case "$CARGO_TARGET_DIR" in
    /*) ;;
    *) CARGO_TARGET_DIR="$(pwd)/$CARGO_TARGET_DIR" ;;
esac
export CARGO_TARGET_DIR

mkdir "$consumer/src"
cp "$workspace_dir/rust-toolchain.toml" "$consumer/rust-toolchain.toml"
python3 - "$workspace_dir" > "$consumer/Cargo.toml" <<'PY'
import json
import sys

print('[package]\nname = "jetstreamer-consumer-check"\nversion = "0.0.0"\nedition = "2024"')
print('\n[workspace]\n\n[dependencies]')
print(f'jetstreamer = {{ path = {json.dumps(sys.argv[1])} }}')
PY
cat > "$consumer/src/main.rs" <<'RS'
fn main() {
    let _: Option<jetstreamer::firehose::TransactionData> = None;
}
RS

cd "$consumer"
cargo generate-lockfile
cargo tree --locked --target all --edges normal,build --prefix none --format '{p}' > dependency-tree.txt
if grep -E '^(solana-ledger|rocksdb|librocksdb-sys) v' dependency-tree.txt; then
    echo "The default library consumer must not build ledger or RocksDB dependencies." >&2
    exit 1
fi
cargo check --locked
