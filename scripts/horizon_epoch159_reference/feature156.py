"""Independent native worker binding and canonical replay gates for the v1.5.6 vote backport."""
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
RUNTIME = "epoch159-v156-vote-feature-reference-20261123-v1"
UNIT = "horizon-epoch159-v156-vote-feature-reference-20261123-v1.service"
WORKER = Path("/opt/epoch159/jetstreamer-historical-worker-v1-5-6")
PREVIOUS_INVOCATION = "cbf90e9daf634f5cb6fa3dc4b3e81ccd"
PREVIOUS_ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch159-vote-feature-reference-20261123-v1")
SETTLEMENT = PREVIOUS_ROOT / "attempt-v1/scratch-retired.json"
SETTLEMENT_SHA = "9a535f97cea4ef7a0a0e4c08745d3ca6828e2a5df007f9e7219e8d5850f78192"
DONOR_UNITS = PREVIOUS_ROOT / "ADMISSION.json"
DONOR_UNITS_SHA = "edba2dc20f03aaf508d5ea94c348aba9722d2cd5cdfb984dab379c1207c0e353"


def spec():
    return json.loads((HERE / "v156-backport.json").read_bytes())


def worker_row():
    original = spec()
    seal = json.loads((HERE / "v156-build.json").read_bytes())
    row = seal["worker"]
    if not (
        seal["source_manifest_sha256"] == hashlib.sha256((HERE / "v156-backport.json").read_bytes()).hexdigest()
        and seal["patch_sha256"] == original["patch_sha256"] and seal["native_build_succeeded"] is True
        and re.fullmatch(r"[0-9a-f]{64}", seal["native_build_evidence_sha256"])
        and row["path"] == str(WORKER) and row["length"] > 0
        and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
        and row["sha256"] != original["original_worker_sha256"]
    ):
        raise ValueError("unbound native v1.5.6 backport")
    return row


def check_checkpoint(state):
    conf = spec()
    slot = state["slot"]
    if state["bank_hash"] != conf["signed_checkpoints"][str(slot)]:
        raise ValueError(f"v1.5.6 backport missed signed Bank at {slot}")
    if slot == 68_687_999 and state != conf["original_last_158_checkpoint"]:
        raise ValueError("v1.5.6 backport changed final epoch 158 native checkpoint")


def transaction_digest(rows):
    sha = hashlib.sha256()
    for signature, status, fee in rows:
        sha.update(bytes.fromhex(signature))
        sha.update(bytes([status is None]))
        sha.update(fee.to_bytes(8, "little"))
    return sha.hexdigest()
