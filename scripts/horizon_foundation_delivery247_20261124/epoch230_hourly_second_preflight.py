"""Seal the existing second hourly epoch 230 preflight for guarded admission."""

import hashlib
import json
import os
from pathlib import Path
import subprocess


BASE = Path("/var/lib/jetstreamer")
PREPARED = BASE / "horizon230-middle-hourly-second-preflight-v1"
STATE = BASE / "horizon230-middle-hourly-second-runtime-v1"
CPUS = "48-55"


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def reference(path):
    with path.open("rb") as source:
        before = identity(os.fstat(source.fileno()))
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        assert before == identity(os.fstat(source.fileno())) == identity(path.stat())
    return {"path": str(path), "sha256": digest}


def bound(document):
    path = Path(document["path"])
    assert path.resolve() == path
    assert reference(path) == {"path": str(path), "sha256": document["sha256"]}
    return json.loads(path.read_bytes())


def seal(name, value, state=STATE):
    path = state / name
    data = (json.dumps(value, indent=2) + "\n").encode()
    if path.exists():
        assert path.read_bytes() == data and path.stat().st_mode & 0o777 == 0o400
    else:
        pending = path.with_suffix(".pending")
        with pending.open("xb") as target:
            target.write(data)
            os.fchmod(target.fileno(), 0o400)
            target.flush()
            os.fsync(target.fileno())
        pending.rename(path)
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return reference(path)


def qualify_namespace(profile, bindings, unit="foundation-230-hourly-second-namespace-v1"):
    properties = {
        **profile["properties"],
        "BindReadOnlyPaths": " ".join(f'{row["path"]}:{row["destination"]}' for row in bindings),
        "PrivateNetwork": "yes",
        "RuntimeMaxSec": "30s",
    }
    probe = """
import os
import sys
from pathlib import Path
for destination in sys.argv[2:]:
    p = Path(destination)
    assert os.statvfs(p).f_flag & os.ST_RDONLY
    with p.open('rb') as source:
        info = os.fstat(source.fileno())
        assert source.read(1)
        print(f'{info.st_dev}:{info.st_ino}:{info.st_size}')
probe = Path(sys.argv[1]) / '.second-hourly-namespace-probe'
with probe.open('xb') as target:
    target.write(b'ok')
probe.unlink()
"""
    result = subprocess.check_output([
        "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={unit}",
        *(f"--property={key}={value}" for key, value in properties.items()),
        "/usr/bin/python3", "-c", probe, profile["environment"]["JETSTREAMER_PRIVATE_RUN_ROOT"],
        *(row["destination"] for row in bindings),
    ], text=True, timeout=40)
    return result.splitlines()


def check_readonly_bindings(profile, bindings):
    root = Path(profile["run_root"])
    measurements = []
    for row in bindings:
        path, dest = Path(row["path"]), Path(row["destination"])
        assert path.resolve() == path and dest.resolve() == dest and dest.is_relative_to(root)
        expected = tuple(row[key] for key in ("device", "inode", "bytes", "mtime_ns", "ctime_ns"))
        assert identity(path.stat()) == expected and dest.stat().st_size == 0
        assert reference(path)["sha256"] == row["sha256"] and identity(path.stat()) == expected
        measurements.append(":".join(str(value) for value in expected[:3]))
    return measurements


def main():
    assert __debug__ and os.geteuid() == 0
    os.umask(0o077)
    source = reference(PREPARED / "preflight.json")
    assert source["sha256"] == "38665f7a41bd35595addbfdd38ed98966496a31db716b59c0c2beecef7a4a066"
    prior = bound(source)
    assert prior["readonly_namespace_qualified"] and prior["snapshot_expectations_parsed"]
    assert prior["worker_started"] is False and prior["canonical_publication_authorized"] is False
    profile = bound(prior["profile"])
    assert (profile["epoch"], prior["first_slot"], prior["last_slot"]) == (230, 99_476_783, 99_516_304)
    assert profile["admitted"] is False and profile["publication_authorized"] is False
    profile["properties"]["AllowedCPUs"] = CPUS
    profile["source_preflight"] = source
    bindings = profile["readonly_bindings"] = profile.pop("read_only_bindings")
    measurements = check_readonly_bindings(profile, bindings)
    snapshot = Path(profile["bootstrap"]["path"]).stat()
    assert bindings[0]["path"] == profile["bootstrap"]["path"]
    assert reference(Path(prior["cli_log"]["path"])) == prior["cli_log"]
    assert bound(prior["guard_validation"])["validated"]
    assert qualify_namespace(profile, bindings) == measurements
    assert all(Path(row["destination"]).stat().st_size == 0 for row in bindings)
    STATE.mkdir(mode=0o700, exist_ok=True)
    assert STATE.resolve() == STATE and STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o777 == 0o700
    guard_receipts = STATE / "guard-receipts"
    guard_receipts.mkdir(mode=0o700, exist_ok=True)
    assert guard_receipts.resolve() == guard_receipts and guard_receipts.stat().st_uid == 0
    assert guard_receipts.stat().st_mode & 0o777 == 0o700 and not any(guard_receipts.iterdir())
    guard_plan = dict(bound(profile["static_guard_plan"]), receipt_directory=str(guard_receipts))
    profile["static_guard_plan"] = seal("static-guard-plan.json", guard_plan)
    plan = profile["static_guard_plan"]
    guard = profile["guard"]
    assert reference(Path(guard["path"])) == guard
    check = json.loads(subprocess.check_output([
        guard["path"], plan["path"], "--plan-sha256", plan["sha256"],
        "--self-sha256", guard["sha256"], "--validate-plan-only",
    ], timeout=25))
    assert check["validated"] and check["plan_sha256"] == plan["sha256"]
    profile["static_guard_validation"] = seal("static-guard-validation.json", check)
    profile_ref = seal("profile.json", profile)
    namespace = seal("namespace.json", {
        "profile": profile_ref, "mounted_device_inode_size": measurements,
        "host_guard_sees_empty_placeholders": True,
    })
    bootstrap = seal("bootstrap-recheck.json", {
        "bootstrap": {
            "path": profile["bootstrap"]["path"], "sha256": profile["bootstrap"]["sha256"],
            "identity": (f"{snapshot.st_dev}:{snapshot.st_ino}:{snapshot.st_size}:"
                         f"{int(snapshot.st_mtime)}:{int(snapshot.st_ctime)}"),
        },
    })
    receipt = seal("preflight.json", {
        "schema": "foundation-epoch230-middle-hourly-second-runtime-preflight-v1",
        "epoch": 230, "first_slot": prior["first_slot"], "last_slot": prior["last_slot"],
        "evidence": [source, profile_ref, namespace, bootstrap, profile["static_guard_validation"],
                     prior["cli_log"], reference(PREPARED / "epoch-hashes.txt")],
        "snapshot_sha256_rechecked": True, "private_namespace_validated": True,
        "static_guard_validated": True, "writable_private_state_validated": True,
        "publication_authorized": False,
    })
    print(json.dumps({"profile": profile_ref, "preflight": receipt}))


if __name__ == "__main__":
    main()
