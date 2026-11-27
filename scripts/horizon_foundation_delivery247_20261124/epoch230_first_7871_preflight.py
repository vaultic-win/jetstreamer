"""Qualify the exact small epoch 230 window with the site's ordinary namespace and guard."""

import fcntl
import json
import os
from pathlib import Path
import subprocess

from epoch230_hourly_second_preflight import (
    BASE, bound, check_readonly_bindings, qualify_namespace, reference, seal,
)


PREPARED = BASE / "horizon230-first-7871-preflight-v1"
STATE = BASE / "horizon230-first-7871-runtime-v1"
SOURCE = {"path": str(PREPARED / "source.json"),
          "sha256": "f50254b3f3938d0dde7e6ba4414d5527234d789d5c9c5cda36eb30bcaaa25e0a"}
PROFILE_SHA = "7d3a7c8bad8d3b257622800874a92a278d287a6b1cd6d377f729c2e139e9f4fd"
SCHEMA = "foundation-epoch230-first-7871-runtime-preflight-v1"


def private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    st = path.lstat()
    assert path.resolve() == path and path.is_dir() and st.st_uid == 0 and st.st_mode & 0o777 == 0o700


def qualify():
    profile_dir = bound(SOURCE)
    profile = bound(profile_dir["profile"])
    assert profile_dir["profile"]["sha256"] == PROFILE_SHA
    assert (profile_dir["epoch"], profile_dir["first_slot"], profile_dir["last_slot"]) == (230, 99437434, 99445304)
    assert not profile["admitted"] and not profile["publication_authorized"]
    for ref in (profile_dir["epoch_hashes"], profile_dir["terminal_generation"],
                profile_dir["terminal_finalized"], *profile_dir["fixtures"]):
        assert reference(Path(ref["path"])) == ref
    fixture = bound(profile_dir["fixtures"][0])
    assert all(fixture[key]["exit_code"] == 1 and fixture[key]["log_sha256"] == ref["sha256"]
               for key, ref in zip(("positive", "negative"), profile_dir["fixtures"][1:], strict=True))
    sizing = bound(profile_dir["sizing"])
    for item in sizing["evidence"].values():
        assert reference(Path(item["path"])) == item
    for key in ("node", "worker", "guard"):
        image = profile[key]
        assert reference(Path(image["path"]))["sha256"] == image["sha256"]
    terminal = bound(profile["prior_drained_window"])
    assert terminal["guard_drained"] and terminal["state"] == "local-segment-committed"
    assert terminal["invocation_id"] == "a0a94d2d42984804877c1a80fc934585"
    assert reference(Path(profile["compact_index_checksum_manifest"]["path"])) == profile["compact_index_checksum_manifest"]
    for name in ("admission.json", "cadence-registration.json", "guard-plan.json", "terminal.json"):
        assert not (STATE / name).exists()
    guards = STATE / "guard-receipts"
    private_directory(guards)
    assert not any(guards.iterdir())
    bindings = profile["readonly_bindings"]
    first = bindings[0]
    assert first["path"] == profile["bootstrap"]["path"] and len(bindings) == 4
    measured = check_readonly_bindings(profile, bindings)
    assert qualify_namespace(profile, bindings, "foundation-230-first-7871-namespace-v1") == measured
    assert all(Path(row["destination"]).stat().st_size == 0 for row in bindings)
    plan = seal("static-guard-plan.json", bound(profile_dir["plan"]), STATE)
    assert plan == profile["static_guard_plan"]
    guard = profile["guard"]
    check = json.loads(subprocess.check_output([
        guard["path"], plan["path"], "--plan-sha256", plan["sha256"], "--self-sha256",
        guard["sha256"], "--validate-plan-only",
    ], timeout=25))
    assert check["validated"] and bound(profile_dir["guard_static"]) == check
    validation = seal("static-guard-validation.json", check, STATE)
    assert validation == profile["static_guard_validation"]
    profile_ref = seal("profile.json", profile, STATE)
    namespace = seal("namespace.json", {"profile": profile_ref, "mounted_device_inode_size": measured,
                                        "host_guard_sees_empty_placeholders": True}, STATE)
    snapshot = Path(first["path"]).stat()
    bootstrap = seal("bootstrap-recheck.json", {"bootstrap": {
        "path": first["path"], "sha256": first["sha256"],
        "identity": (f"{snapshot.st_dev}:{snapshot.st_ino}:{snapshot.st_size}:"
                     f"{int(snapshot.st_mtime)}:{int(snapshot.st_ctime)}"),
    }}, STATE)
    receipt = seal("preflight.json", {
        "schema": SCHEMA, "epoch": 230, "first_slot": 99437434, "last_slot": 99445304,
        "evidence": [SOURCE, profile_ref, namespace, bootstrap, validation,
                     profile_dir["epoch_hashes"], profile["prior_drained_window"]],
        "snapshot_sha256_rechecked": True, "private_namespace_validated": True,
        "static_guard_validated": True, "writable_private_state_validated": True,
        "publication_authorized": False,
    }, STATE)
    print(json.dumps({"profile": profile_ref, "preflight": receipt}))


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    os.umask(0o077)
    private_directory(STATE)
    directory_fd = os.open(STATE, os.O_DIRECTORY | os.O_RDONLY)
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        qualify()
    finally:
        os.close(directory_fd)
