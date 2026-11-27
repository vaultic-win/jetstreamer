#!/usr/bin/env python3
"""Emit a read-only source packet for any bounded epoch 141 interval after the first."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
INVENTORY = RUNTIME / (
    "epoch140-suffix-recording-20261127-retry1/downstream-hourly-intervals-v1/"
    "HOURLY_SOURCE_INTERVALS.json"
)
COMMON = RUNTIME / "epoch141-hourly-original-build-20261127-v1/first-interval-capped-inputs/FIRST_INTERVAL.json"
INVENTORY_SHA = "a1643ab0cdc8bd0ebfce4243d4be15723f93e7802797f765fe41169d2cf0af0d"
NATIVE_SHA = "516d6282ac650930b869b7793d9a56d4e11106c52a6257a5139a72b02e99ab45"
RESTORE_OPERATOR = Path(
    "/home/sol/.jetstreamer-private/epoch141-foundation-second-bootstrap-20261127.Om5kzmEJ/"
    "restore_bound_gcs_snapshot.py"
)
RESTORE_OPERATOR_SHA = "38a2b4bf9d3e854694e114caaf04ca92599dc131ce2db4d407962c190d7c325a"
COMMON_SHA = "e256a49f49c1ad0bf2b3530695d5ef24c2992fbfc39df42785ac7e1da726b05c"
OUTPUT_SAMPLE_SHA = "d6594a4f1cb5be36f30651fda8e8b01b3a5613be6463d04a7772b81ccc2f9cd0"
BASE58 = r"[1-9A-HJ-NP-Za-km-z]{32,44}"
CHECKPOINT = re.compile(rf'\s*\((\d+), "({BASE58})", (\d+)\),\s*')
SHA256 = re.compile(r"[0-9a-f]{64}")
GIB = 1 << 30
MIB = 1 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bound_bytes(path, expected=None):
    path = path.resolve(strict=True)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(expected is None or expected == digest, f"digest mismatch for {path}")
    return data, {"path": str(path), "bytes": len(data), "sha256": digest}


def bound_json(path, expected=None):
    data, reference = bound_bytes(path, expected)
    return json.loads(data), reference


def registered(native, inventory):
    table = native.decode().split("const CHECKPOINTS: &[Checkpoint] = &[\n", 1)[1].split("];", 1)[0]
    rows = []
    for line in table.splitlines():
        match = CHECKPOINT.fullmatch(line)
        require(match is not None, f"unrecognized native checkpoint row {line!r}")
        slot, accounts_hash, cumulative = match.groups()
        rows.append((int(slot), accounts_hash, int(cumulative)))
    expected = [
        (row["slot"], row["accounts_hash"], row["cumulative_target_count"])
        for row in inventory["checkpoints"]
    ]
    require(rows == expected and len(rows) == len(inventory["intervals"]) + 1,
            "native checkpoint sequence differs from the frozen inventory")
    return expected


def select_interval(inventory, index, ordinal):
    require(2 <= ordinal <= len(inventory["intervals"]), "interval is outside the sequential profile")
    bootstrap, terminal = inventory["checkpoints"][ordinal - 1:ordinal + 1]
    interval = inventory["intervals"][ordinal - 1]
    start, end = bootstrap["slot"], terminal["slot"]
    require((start, end, end - start) == (interval["bootstrap"], interval["endpoint"], interval["positions"])
            and interval["positions"] == interval["epoch141_output_positions"], "interval coverage differs")
    rows = index["slots"]
    require(all(a["slot"] < b["slot"] for a, b in zip(rows, rows[1:])), "original index is not ordered")
    targets = rows[bootstrap["cumulative_target_count"]:terminal["cumulative_target_count"]]
    require(targets == [r for r in rows if start < r["slot"] <= end], "cumulative target bounds differ")
    require(len(targets) == interval["original_targets"]
            and sum(row["length"] for row in targets) == interval["original_target_bytes"]
            and (targets[0]["slot"], targets[-1]["slot"]) == (interval["first_target"], interval["last_target"]),
            "original targets differ from the inventory")
    return bootstrap, terminal, interval, targets


def snapshot_name(row):
    return f'snapshot-{row["slot"]}-{row["accounts_hash"]}.tar.zst'


def validate_metadata(metadata_dir, row):
    uri = row["versioned_uri"]
    object_uri = f'gs://mainnet-beta-ledger-us-ny5/60911751/hourly/{snapshot_name(row)}#{row["generation"]}'
    require(uri == object_uri, "foreign checkpoint object or generation")
    if metadata_dir is None:
        return None
    metadata, reference = bound_json(metadata_dir / f'metadata-{row["slot"]}.json')
    expected = {
        "bucket": "mainnet-beta-ledger-us-ny5",
        "name": f"60911751/hourly/{snapshot_name(row)}",
        "generation": str(row["generation"]),
        "size": row["size"],
        "crc32c_hash": row["crc32c"],
        "md5_hash": row["md5"],
        "etag": row["etag"],
        "storage_url": uri,
    }
    require({key: metadata.get(key) for key in expected} == expected,
            f'GCS object metadata changed at slot {row["slot"]}')
    return reference


def file_identity(metadata):
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def verify_target_bytes(path, index, targets):
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == index["data_bytes"], "original data length differs")
        for row in targets:
            offset, size = row["offset"], row["length"]
            require(0 <= offset < offset + size <= before.st_size, "original data range is invalid")
            stream.seek(offset)
            payload = stream.read(size)
            require(len(payload) == size and hashlib.sha256(payload).hexdigest() == row["sha256"],
                    f'original data digest differs at slot {row["slot"]}')
        require(file_identity(before) == file_identity(os.fstat(stream.fileno())) == file_identity(path.stat()),
                "original data changed during target verification")


def custody(custody_path, row):
    if custody_path is None:
        return None
    receipt, reference = bound_json(custody_path)
    require(receipt["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1"
            and receipt["snapshot_slot"] == row["slot"] and receipt["generation"] == row["generation"]
            and receipt["versioned_uri"] == row["versioned_uri"] and not receipt["remote_mutations"],
            "restore receipt is for a different generation")
    path = Path(receipt["destination"])
    readback = receipt["file"]
    m = path.lstat()
    identity = {"device": m.st_dev, "inode": m.st_ino, "size": m.st_size,
                "mtime_ns": m.st_mtime_ns, "mode": stat.S_IMODE(m.st_mode), "uid": m.st_uid}
    require(path.resolve() == path and stat.S_ISREG(m.st_mode) and m.st_nlink == 1
            and not m.st_mode & 0o077 and all(readback.get(k) == v for k, v in identity.items())
            and m.st_size == row["size"] and readback["crc32c_base64"] == row["crc32c"]
            and readback["md5_base64"] == row["md5"] and SHA256.fullmatch(readback["sha256"]),
            "private bootstrap identity differs from its bound restore receipt")
    return {"receipt": reference, "path": str(path), "bytes": m.st_size, "sha256": readback["sha256"],
            "file_identity": identity, "payload_rehashed_in_this_packet": False}


def sizing(interval, bootstrap, common_bytes, checkpoint_bytes, sample_path):
    basis = None
    estimated = None
    if sample_path is not None:
        sample, reference = bound_json(sample_path, OUTPUT_SAMPLE_SHA)
        positions = sample["last_bucket_last_slot"] - sample["first_slot"] + 1
        estimate = sample["bytes_through_last_bucket"] * interval["epoch141_output_positions"]
        estimated = (estimate + positions - 1) // positions
        basis = {"reference": reference, "source_stored_bytes": sample["bytes_through_last_bucket"],
                 "source_output_positions": positions, "format_version": sample["archive_format"]}
    single = bootstrap["size"]
    return {
        "bootstrap_exact_bytes": single,
        "terminal_payload_required_bytes": 0,
        "shared_installation_exact_bytes": common_bytes,
        "new_interval_input_exact_bytes": single + checkpoint_bytes,
        "immutable_bytes_if_no_shared_installation": single + common_bytes + checkpoint_bytes,
        "output_estimated_bytes": estimated,
        "output_estimate_basis": basis,
        "prior_comparable_lane": {"working_tree_cap_bytes": 44 * GIB, "output_custody_cap_bytes": 4 * GIB,
                                  "producer_ram_bytes": 74 * GIB, "guard_ram_bytes": GIB},
        "bootstrap_plus_prior_output_custody_cap_bytes": single + 4 * GIB,
        "bootstrap_with_64_mib_minimum_free_bytes": single + 64 * MIB,
    }


def packet(args):
    inventory, inv_ref = bound_json(args.inventory, INVENTORY_SHA)
    native, native_ref = bound_bytes(args.native_source, NATIVE_SHA)
    registered(native, inventory)
    index, index_ref = bound_json(Path(inventory["original_input_index"]["path"]),
                                  inventory["original_input_index"]["sha256"])
    common, common_ref = bound_json(args.common, COMMON_SHA)
    boot, end, declaration, targets = select_interval(inventory, index, args.interval)
    require(index["data_sha256"] == inventory["original_input_data_sha256"], "original data SHA-256 differs")
    projection = common["local_projection"]
    if args.verify_target_bytes:
        verify_target_bytes(Path(projection["data"]), index, targets)
    metadata = {"bootstrap": validate_metadata(args.metadata_dir, boot),
                "terminal": validate_metadata(args.metadata_dir, end)}
    lines = [snapshot_name(boot), snapshot_name(end)]
    checkpoint_text = ("\n".join(lines) + "\n").encode()
    target_text = json.dumps(targets, sort_keys=True, separators=(",", ":")).encode()
    by_name = {Path(row["path"]).name: row for row in common["members"]}
    names = ("index.json", "original-entries.data", "genesis.tar.bz2", "manifest.json",
             "epoch-141-slot-ranges.raw", "jetstreamer-historical-worker-v1-4-25", "jetstreamer-node")
    members = [by_name[name] for name in names]
    common_bytes = sum(row["bytes"] for row in members)
    local_bootstrap = custody(args.bootstrap_custody, boot)
    restore = None
    if local_bootstrap is None:
        _, operator = bound_bytes(args.restore_operator, RESTORE_OPERATOR_SHA)
        restore = {"program": operator, "versioned_uri": boot["versioned_uri"],
                   "expected_size": boot["size"], "expected_crc32c": boot["crc32c"],
                   "expected_md5": boot["md5"]}
    return {
        "schema": "horizon-epoch141-sequential-hourly-source-packet-v1",
        "epoch": 141, "interval_ordinal": args.interval, "interval": declaration,
        "first_output_slot": boot["slot"] + 1,
        "bootstrap": boot, "terminal": end,
        "metadata": metadata,
        "source_inventory": inv_ref, "native_checkpoint_source": native_ref,
        "existing_common_packet": common_ref, "node_qualification": common["node_qualification"],
        "native_compiled_commit": common["compiled"], "native_equivalent_merged_commit": common["merged"],
        "common_artifacts": members, "local_projection": {k: projection[k] for k in
            ("node", "worker", "genesis", "index", "data", "slot_range_manifest", "slot_range_raw",
             "slot_range_raw_absolute_alias")},
        "original_entry_index": index_ref,
        "original_targets": targets, "original_targets_canonical_json_sha256": hashlib.sha256(target_text).hexdigest(),
        "original_target_bytes_rehashed": declaration["original_target_bytes"] if args.verify_target_bytes else 0,
        "epoch_hashes": {"lines": lines, "encoding": "UTF-8 records with LF including the final line",
                         "bytes": len(checkpoint_text), "sha256": hashlib.sha256(checkpoint_text).hexdigest()},
        "bootstrap_custody": local_bootstrap,
        "budget": sizing(declaration, boot, common_bytes, len(checkpoint_text), args.output_sample),
        "next_input_operator": restore,
        "terminal_payload_required": False, "replay_executed": False, "archive_publication_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=int, required=True, help="one-based sequential interval number, starting at 2")
    parser.add_argument("--inventory", type=Path, default=INVENTORY)
    parser.add_argument("--native-source", type=Path,
                        default=Path(__file__).resolve().parents[1] / "jetstreamer-node/src/epoch141_hourly.rs")
    parser.add_argument("--common", type=Path, default=COMMON)
    parser.add_argument("--restore-operator", type=Path, default=RESTORE_OPERATOR)
    parser.add_argument("--metadata-dir", type=Path, help="require pinned metadata-<slot>.json for both endpoints")
    parser.add_argument("--bootstrap-custody", type=Path, help="verify an existing bound local GCS restore receipt")
    parser.add_argument("--verify-target-bytes", action="store_true", help="rehash only the selected original data ranges")
    parser.add_argument("--output-sample", type=Path, help="bind the recorded prior archive byte measurement")
    args = parser.parse_args()
    try:
        print(json.dumps(packet(args), indent=2))
    except (KeyError, ValueError, OSError, IndexError) as error:
        print(f"source packet refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
