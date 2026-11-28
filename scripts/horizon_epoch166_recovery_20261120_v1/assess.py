"""Inspect the three stopped lanes and measure the immediate retry9 capacity gap."""

import hashlib
import json
import subprocess
from pathlib import Path


HOME = Path("/home/sol")
PRIVATE = HOME / ".jetstreamer-private"
STATE = Path("/var/lib/jetstreamer")
STOPS = (
    (166, 8, "retry8-preparation-20261119-v1", "guard-state-recovery-v2",
     "b99e26a6836609dc68b4c646eb19ce2b2c0edd0d7547c80b1e0b517be4875b08",
     "f663f933ec2ceba6ed27c9d863a126a23027b16f9bd2d40c4074cae2a61e496c"),
    (167, 7, "retry3-preparation-20261113-v1", "guard-state",
     "5b51b01a57f5c717ef6397cad6bcc6b01ac72336e84d02d2b9354c99ee3fd5aa",
     "dd5f515167b27bc1541c73d57e98c2bfab975ee0e1b6ca051be28a4b79f8f946"),
    (170, 6, "retry6-170-preparation-20261118-v1", "guard-state",
     "3601e2dabb55f7c3ca9ed8f91c253588f301b51a87c42ba9ece18f73fab48264",
     "22344407c7f7f034eae858791636fc0275c7b12c2bee1a5326e18dd1560700fb"),
)


def verified_json(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Unexpected receipt digest for {path}")
    return json.loads(data)


def main():
    predecessors = []
    successor_roots = []
    lane166 = PRIVATE / "epoch166-standard-lane-20261109-v1"
    for epoch, attempt, package, guard, completion_sha, intent_sha in STOPS:
        base = STATE / package / f"epoch{epoch}" / f"local3retry{attempt}"
        receipts = base / guard / "receipts"
        completion = verified_json(receipts / "stop-completion.json", completion_sha)
        intent = verified_json(receipts / "stop-intent.json", intent_sha)
        predecessors.append({
            "epoch": epoch,
            "attempt": attempt,
            "invocation": completion["producer_invocation_id"],
            "terminal": completion["terminal"]["active"],
            "guard_error": intent["sample"]["DATA_fulfillment_observation_error"],
        })
        root = PRIVATE / f"epoch{epoch}-standard-lane-20261109-v1" / (
            f"replacement-local3retry{attempt + 1}-20261110-v1")
        metadata = root.lstat()
        successor_roots.append({
            "path": str(root), "device": metadata.st_dev, "inode": metadata.st_ino,
            "on_home": metadata.st_dev == HOME.stat().st_dev,
        })

    package = STATE / STOPS[0][2] / "epoch166/local3retry8"
    prepared = verified_json(package / "prepared.json",
                             "03e46b79dfe8845e116a13370e8b60c1184855492689fc8114d3c94c2fdbccce")
    review = verified_json(Path(prepared["review"]["path"]), prepared["review"]["sha256"])
    completion_dir = package / STOPS[0][3] / "receipts"
    stop = verified_json(completion_dir / "stop-intent.json", STOPS[0][5])
    cap = stop["sample"]["maximum_root_physical_bytes"]
    # Count the entire lane on one filesystem, including retained earlier attempts.
    # This single pass supports diagnosis only. Admission requires the native ledger.
    usage = subprocess.check_output(
        ["/usr/bin/du", "--one-file-system", "--summarize", "--block-size=1", "--", lane166],
        text=True,
    )
    used = int(usage.split("\t", 1)[0])
    historical_growth = review["proposed_fresh_working_maximum_bytes"]
    print(json.dumps({
        "predecessors": predecessors,
        "successor_roots": successor_roots,
        "whole_lane_cap_bytes": cap,
        "whole_lane_measured_bytes": used,
        "remaining_under_cap_bytes": cap - used,
        "previous_growth_budget_bytes": historical_growth,
        "deficit_even_at_previous_growth_budget_bytes": max(0, used + historical_growth - cap),
    }, indent=2))


if __name__ == "__main__":
    main()
