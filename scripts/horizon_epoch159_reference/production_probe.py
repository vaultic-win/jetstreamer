"""Bind the successful bounded replay to a private jetstreamer-node probe recipe."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import feature156

REFERENCE = Path("/var/lib/jetstreamer/horizon_runtime_data") / feature156.RUNTIME
INVOCATION = "663b7b2c5d354301879d2ebad31396b2"
OUTCOME_SHA = "fbcc5dfd2e3bdb5f41a91d90e3800952ad78548c7780f20fb7aac9493868589f"
SUCCESS_SHA = "13c38c31c15c4de3950581740e06f3be8a40e61734a42cf4933fd72d0720a006"
DRIVER_EXIT_SHA = "573b5f2496fd63b1df46a9e0e1f820dfdb5636afb654bbb1a88b23ba918f948c"
HELLO_SHA = "0e2fd07f3b01067080452aa44c485229593bde38406cf6c23014385a6467c469"
BUILD_SHA = "cec51e151db338fd5e5526b108b20ac013c3a2001448586f8089b1c8c4e3fa85"
WORKER_SHA = "a26b0e0eb6ba118eb8e5fa669797742b70237755227e4552fe63ae28ae39a2b7"


def read_bound(path, expected):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"reference evidence digest changed at {path}")
    return json.loads(raw)


def build_recipe(reference):
    attempt = reference / "attempt-v1"
    success = read_bound(attempt / "success.json", SUCCESS_SHA)
    driver = read_bound(attempt / "driver-exit.json", DRIVER_EXIT_SHA)
    outcome = read_bound(attempt / "retained/outcome.json", OUTCOME_SHA)
    hello = read_bound(attempt / "retained/hello.json", HELLO_SHA)
    build = read_bound(reference / "package-v1/v156-build.json", BUILD_SHA)
    spec = feature156.spec()
    source = json.loads((HERE / "inputs.json").read_bytes())
    if (success["iid"] != INVOCATION or driver["iid"] != INVOCATION or driver["code"] != 0
            or success["outcome"] != OUTCOME_SHA or outcome["complete"] is not True
            or outcome["canonical_checks_passed"] is not True or outcome["signed_mismatches"]
            or outcome["source_windows"] != source["car_windows"]
            or any(outcome[key] != value for key, value in source["source_counters"].items())
            or outcome["canonical_transactions"] != dict.fromkeys(spec["canonical_transaction_outcomes"], True)):
        raise ValueError("reference did not reproduce the authenticated bounded replay")
    vote = outcome["vote"]
    expected_vote = source["failing_vote"]
    if (vote["accepted"] is not True or vote["status"] is not None
            or any(vote[key] != expected_vote[key] for key in
                   ("slot", "ordinal", "signature", "entry_index", "transaction_in_entry"))):
        raise ValueError("reference did not reproduce the historical vote")
    for state in outcome["states"].values():
        feature156.check_checkpoint(state)
    worker = reference / "package-v1" / feature156.WORKER.name
    with worker.open("rb") as executable:
        info = os.fstat(executable.fileno())
        worker_sha = hashlib.file_digest(executable, "sha256").hexdigest()
    feature_spec_sha = hashlib.sha256((HERE / "v156-backport.json").read_bytes()).hexdigest()
    if (hello["invocation_id"] != INVOCATION or hello["protocol"] != 5
            or (info.st_dev, info.st_ino) != (hello["worker"]["dev"], hello["worker"]["ino"])
            or build["worker"]["sha256"] != WORKER_SHA or worker_sha != WORKER_SHA
            or info.st_size != build["worker"]["length"]
            or build["native_build_succeeded"] is not True or build["patch_sha256"] != spec["patch_sha256"]
            or build["source_manifest_sha256"] != feature_spec_sha):
        raise ValueError("unexpected native worker artifact")
    bootstrap = source["bootstrap"]
    terminal = outcome["states"][str(vote["slot"])]
    return {
        "reference_invocation": INVOCATION,
        "reference_outcome_sha256": OUTCOME_SHA,
        "worker_environment": {"JETSTREAMER_HISTORICAL_WORKER_V1_5_6": str(worker)},
        "worker_sha256": WORKER_SHA,
        "checkpoint_filenames": [
            Path(bootstrap["path"]).name,
            *(f"snapshot-{state['slot']}-{state['accounts_hash']}.tar.zst"
              for _, state in sorted(outcome["states"].items())),
        ],
        "snapshot": bootstrap["path"],
        "snapshot_sha256": bootstrap["sha256"],
        "replay_slots": [bootstrap["checkpoint"]["slot"] + 1, terminal["slot"]],
        "record_slots": [68_688_000, terminal["slot"]],
        "terminal": terminal,
        "vote": vote,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-root", type=Path, default=REFERENCE)
    args = parser.parse_args()
    if not args.reference_root.is_absolute():
        parser.error("reference root must be absolute")
    print(json.dumps(build_recipe(args.reference_root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
