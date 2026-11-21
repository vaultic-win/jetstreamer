#!/usr/bin/env python3
"""Render the epoch 167 successor or rollback producer argv for native admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
PREVIOUS = RUNTIME / "epoch167-retry8-recovery-20261120-v1"
SUCCESSOR = RUNTIME / "epoch167-local-index-successor-20261121-v1/deployment"
ORIGINAL = Path("/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1")
INPUTS = Path("/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1")
QUALIFIED = Path("/home/sol/.jetstreamer-private/public-method-20261120/167-source-index/qualified-v1")
LANE = Path("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1")
OLD_ATTEMPT = LANE / "replacement-local3retry8-20261110-v1"
OLD_UNIT = "horizon-qualify-167-replacement-local3retry8-20261110-v1.service"
NODE = "jetstreamer-node"
WORKER = "jetstreamer-historical-worker-v1-5-6"
MANIFEST_ENV = "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST"
INDEX = "379692ca3092bcbdd29c968606dc72cf6703a7e41a8c4a774ee4540ba51d9cf7"
MANIFEST = "8d0bb4e330a3d6d9c3c014e63df99069856af6298de43a319ef710021b88a7b2"


def checked(path, expected):
    with open(path, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != expected:
            raise ValueError(f"digest mismatch for {path}")
    return {"path": str(path), "sha256": expected}


def render(successor):
    state = PREVIOUS / "launch-state/epoch167"
    parent = checked(state / "ORIGINAL_PRODUCER_ARGV.json", "914ece3f9e09519df0363d303bc6b9529b02381a44404119d0241f018246f8a7")
    body = Path(parent["path"]).read_bytes()
    if hashlib.sha256(body).hexdigest() != parent["sha256"]:
        raise ValueError("predecessor argv changed during render")
    args = json.loads(body)
    marker = "source-index-v1" if successor else "source-index-rollback-v1"
    fresh = LANE / f"replacement-{marker}-20261121"
    unit = f"horizon-qualify-167-{marker}-20261121.service"
    timer = f"horizon-guard-167-{marker}-20261121.timer"
    package = SUCCESSOR if successor else ORIGINAL
    # systemd-run resolves the executable before constructing the service mount namespace.
    view = ORIGINAL
    node_sha = "6b0f3089c1c1108dbbbea76a06625d3b285de647f83b50791ead121e1af81699" if successor else "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
    seal_sha = "f78d66c9d4a12f58d4f6551ef8d1bce330bbb2c35b89beb2b80c98ad750a9410" if successor else "c6c34bf0e5aec1e04a6ee0439e6335a9ca8a5bb54f6055cf6f442f041a59ceee"
    bindings = [
        parent,
        checked(package / "deployment-seal-receipt.json", seal_sha),
        checked(package / NODE, node_sha),
        checked(package / WORKER, "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"),
        checked(package / "preflight-167-v4.json", "125424a7fe2a84119a690e9e14a9ff1b0a7b32a5e32b3f3d896f95c0816940d5"),
        checked(INPUTS / "deployment-seal-receipt.json", "a8ca0ff1a91c77cbbc9b3c7c48a2369c62b773fd5143e6a84f1bd2af5b8215f2"),
        checked(INPUTS / "genesis.tar.bz2", "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"),
        checked(state / "ORIGINAL_GUARD_ARGV.json", "4fbff52bb7cf7f7443cd7466289494b23c1b32c8c433e6ecf196356f6f8fc76f"),
        checked(state / "ACTUAL_GUARD_PLAN.json", "c52363638f3f965c5641c073e9883a56abd4d437de64652999d6ae827e5bfa5d"),
    ]
    if successor:
        bindings.extend([checked(QUALIFIED / "manifest.json", MANIFEST),
                         checked(QUALIFIED / "epoch-167-slot-ranges.raw", INDEX)])
    result = []
    for arg in args:
        if arg == f"--property=ReadWritePaths={LANE}":
            result.append(f"--property=ReadWritePaths={fresh}")
        elif arg.startswith("--property=ExecPaths="):
            result.append(f"--property=ExecPaths={view/NODE} {view/WORKER} {fresh}")
        elif arg.startswith("--property=BindReadOnlyPaths="):
            result.append(f"--property=BindReadOnlyPaths={package}:{view}:rbind")
        elif arg.startswith("--setenv=XDG_CONFIG_HOME="):
            result.append(f"--setenv=XDG_CONFIG_HOME={fresh}/config")
        elif arg.startswith("--setenv=CLOUDSDK_CONFIG="):
            result.append(f"--setenv=CLOUDSDK_CONFIG={fresh}/config/gcloud")
        elif arg == str(ORIGINAL / NODE):
            result.append("--property=UnsetEnvironment=JETSTREAMER_FORCE_LEGACY_INDEX"
                          + ("" if successor else f" {MANIFEST_ENV} {MANIFEST_ENV}_SHA256"))
            if successor:
                result.extend([
                    f"--property=BindReadOnlyPaths={QUALIFIED}:{QUALIFIED}:rbind",
                    f"--setenv={MANIFEST_ENV}={QUALIFIED}/manifest.json",
                    f"--setenv={MANIFEST_ENV}_SHA256={MANIFEST}",
                ])
            result.append(str(view / NODE))
        else:
            result.append(arg.replace(str(OLD_ATTEMPT), str(fresh)).replace(OLD_UNIT, unit)
                          .replace(str(ORIGINAL), str(view)))
    if successor:
        result.append("--require-local-slot-ranges=167")
    return {"kind": "epoch167-producer-profile-for-native-admission", "mode": marker,
            "producer_unit": unit, "guard_timer": timer, "producer_argv": result,
            "fresh_attempt": str(fresh), "stage_genesis_to": str(fresh/"output/genesis.tar.bz2"),
            "guard_worker_root": str(LANE), "bindings": bindings,
            "guard_binary_sha256": "7f3b53a6a316a91ea868fdb9fb17cb4e8585cfd32c91afc7122a91ce86db94fe",
            "previous_guard_proof": str(state / "ACTUAL_GUARD_PROTECTION.json"),
            "source_snapshot_sha256": "948ca3ec94f7c9c7bc970fa21fef5e388ba2c3357e7d39589de402257ab5b81f",
            "source_snapshot_generation": 1634787403577062,
            "replay_launch_authorized": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("successor", "rollback"))
    print(json.dumps(render(parser.parse_args().mode == "successor"), indent=2))
