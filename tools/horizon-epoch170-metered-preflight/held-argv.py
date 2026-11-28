"""Print the held systemd-run command for a reviewed epoch 170 profile."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-full-metered-rebook-20261124-v1")
ALIAS = Path("/run/horizon-epoch170-full-metered")
UNIT = "horizon-qualify-170-full-metered-20261124-v1.service"
HOLD = RUNTIME / "tools-preflight-879447ca/preflight"
HOLD_SEAL = "2a4ab5d56a9f5b8328050b6d0bb218bdc04eacc125c1e63d0b1ff76e73850842"
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def pinned(path, digest=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, f"foreign path {path}")
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and (meta.st_uid, meta.st_gid, meta.st_nlink) == (0, 0, 1)
         and not meta.st_mode & 0o222, f"unsealed file {path}")
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    need(digest is None or actual == digest, f"changed file {path}")
    return data, actual, stat.S_IMODE(meta.st_mode)


def sealed_member(path, seal_digest, mode):
    seal, _, _ = pinned(path.with_name("deployment-seal-receipt.json"), seal_digest)
    seal = json.loads(seal)
    need(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
         and seal["sealer_sha256"] == SEALER and seal["destination"] == str(path.parent)
         and seal["replay_launch_authorized"] is seal["r2_mutations"] is False,
         f"foreign deployment for {path}")
    member, = (row for row in seal["members"] if row["name"] == path.name)
    data, digest, actual_mode = pinned(path, member["sha256"])
    need(int(member["mode"], 8) == actual_mode == mode and member["bytes"] == len(data),
         f"foreign member mode or length for {path}")
    return data, digest


def held_argv(profile, payload, digest):
    actor = profile["actor"]
    argv = actor["producer_argv_after_protection"]
    node = profile["source"]["node"]["reference"]["path"]
    need(actor["unit"] == UNIT and actor["requires_held_before_useful_work"] is True
         and argv[:2] == ["/usr/bin/systemd-run", "--unit=" + UNIT]
         and argv.count(node) == 1, "foreign epoch 170 producer command")
    command = argv[:argv.index(node)]
    for prop, projection in (
        ("ExecPaths", str(ALIAS / "preflight")),
        ("BindReadOnlyPaths", " ".join((
            f"{HOLD}:{ALIAS / 'preflight'}",
            f"{payload}:{ALIAS / 'payload.json'}",
            f"{RUNTIME / 'barrier'}:{ALIAS / 'barrier'}",
        ))),
    ):
        prefix = f"--property={prop}="
        index, = (i for i, arg in enumerate(command) if arg.startswith(prefix))
        need(str(ALIAS / "preflight") not in command[index]
             and str(ALIAS / "payload.json") not in command[index]
             and str(ALIAS / "barrier") not in command[index], f"held binding already present in {prop}")
        command[index] += " " + projection
    # systemd-run checks its initial executable before mounting the service
    # namespace. Resolve the read-only alias after that namespace is active.
    return [*command, "/usr/bin/env", str(ALIAS / "preflight"), "hold", digest]


def review_command(review_path, review_sha, payload_seal):
    raw, _, _ = pinned(review_path, review_sha)
    review = json.loads(raw)
    need(review["schema"] == "horizon-epoch170-metered-preflight-review-v1"
         and review["replay_launch_authorized"] is review["archive_publication_authorized"] is False,
         "native epoch 170 preflight review required")
    profile = review["profile"]
    fleet = profile["observer"]["active_fleet"]["fleet"]["sha256"]
    need(re.fullmatch(r"[0-9a-f]{64}", fleet), "foreign fleet digest")
    payload = RUNTIME / f"payload-{fleet}/payload.json"
    raw, payload_sha = sealed_member(payload, payload_seal, 0o444)
    need(json.loads(raw) == profile, "held payload differs from the native reviewed profile")
    sealed_member(HOLD, HOLD_SEAL, 0o555)
    barrier = RUNTIME / "barrier"
    meta = barrier.lstat()
    need((meta.st_uid, meta.st_gid, meta.st_mode) == (0, 0, stat.S_IFDIR | 0o755)
         and not os.path.lexists(barrier / "allow"), "occupied or unsafe epoch 170 release barrier")
    return held_argv(profile, payload, payload_sha)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("review", type=Path)
    cli.add_argument("review_sha256")
    cli.add_argument("payload_seal_sha256")
    args = cli.parse_args()
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
             "run the held command generator as root with python3 -IB")
        print(json.dumps(review_command(args.review, args.review_sha256, args.payload_seal_sha256)))
    except (KeyError, OSError, ValueError) as exc:
        cli.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
