#!/usr/bin/python3
"""Freeze the retirement plan only after exact private park completion."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1")
STATE = Path("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1")
PARK = "horizon-closed185-lanek-park-20261127-v1.service"
IID = "cd7e3722016c43528f47608092b4e313"
MANIFEST = "c62a2eec03efacb86947eac6c8c123b0d51476dad3cc019cb277b5643924c5e7"
BLOB = "91e8053f4aeecc44555bffd3b4581e6dbed5e60e18a7b6535de4c76524777a15"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, expected=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, "aliased evidence")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as file:
        identity = os.fstat(file.fileno())
        need(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1 and identity.st_uid == 0
             and not (identity.st_mode & 0o222) and identity.st_size <= 1 << 20, "unsealed evidence")
        body = file.read((1 << 20) + 1)
        after = path.lstat()
        need((identity.st_dev, identity.st_ino, identity.st_ctime_ns, identity.st_size) ==
             (after.st_dev, after.st_ino, after.st_ctime_ns, len(body)), "evidence changed")
    digest = hashlib.sha256(body).hexdigest()
    need(expected is None or digest == expected, "evidence digest changed")
    return {"path": str(path), "sha256": digest}, json.loads(body)


def persist(path, value):
    body = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    if path.exists():
        ref, recorded = read(path)
        need(recorded == value, "conflicting retained post-park evidence")
        return ref
    fd, temp = tempfile.mkstemp(prefix=".postpark-", dir=ROOT)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o400)
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(temp), -100, os.fsencode(path), 1) != 0:
            error = ctypes.get_errno()
            if error != errno.EEXIST:
                raise OSError(error, os.strerror(error), path)
        dir_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        ref, recorded = read(path)
        need(recorded == value, "post-park output differs")
        return ref
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    start_ref, start = read(ROOT / "PARK_START.json", "75cb59704be9c9007b03a82553bbc69689139c046400bfafcb9339fa3da4e5fd")
    adm_ref, admission = read(ROOT / "PARK_ADMISSION.json", "e30f1a6ee45a024163bf2cecbbd4d125e0322151e6536c15849c993367d83204")
    plan_ref, park = read(ROOT / "package/plan.json", "929fd063b6776b525699f504dd6e83835a34ce6a08f8e690b3c6ff407dd9ea95")
    need(start["admission"] == adm_ref and admission["plan"] == plan_ref and admission["unit"] == PARK,
         "park admission changed")
    fields = ("Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,TriggeredBy,"
              "Restart,NRestarts,Type,RemainAfterExit,Result,ExecMainStatus,ExecMainPID,ExecMainStartTimestampMonotonic")
    result = subprocess.check_output(["/usr/bin/systemctl", "show", PARK, "-p", fields], text=True)
    native = dict(line.split("=", 1) for line in result.splitlines())
    expected = dict(Id=PARK, LoadState="loaded", ActiveState="active", SubState="exited", InvocationID=IID,
                    MainPID="0", ControlPID="0", Job="", TriggeredBy="", Restart="no", NRestarts="0",
                    Type="oneshot", RemainAfterExit="yes", Result="success", ExecMainStatus="0")
    need(all(native.get(k) == v for k, v in expected.items()), "private park has no clean exact exit")
    need(all(native[k] == start["native"][k] for k in ("Id", "InvocationID", "ExecMainPID", "ExecMainStartTimestampMonotonic")),
         "different completed park process")
    custody_ref, custody = read(STATE / "receipts" / ("custody-" + MANIFEST + ".json"))
    need(custody["schema"] == "jetstreamer-horizon-holding-custody-v2" and custody["host"] == "dev-samjohnson"
         and custody["bucket"] == "solana-archive-with-accounts-data" and custody["prefix"] == "node_02/"
         and custody["sha256"] == BLOB and custody["length"] == 66_545_963_870
         and custody["object_key"] == "node_02/objects/" + BLOB + ".blob"
         and custody["manifest_key"] == "node_02/manifests/" + MANIFEST + ".json"
         and custody["manifest_sha256"] == MANIFEST and custody["object_etag"]
         and custody["local_source_revalidated"] is True and custody["remote_sha256_readback"] is True
         and custody["local_retirement_authorized"] is False and custody["canonical_publication_authorized"] is False
         and all(custody[k] == park[k] for k in ("source", "mapping", "eligibility", "sha256", "length")),
         "holding custody scope or readback changed")
    retire_plan = {"schema": "jetstreamer-horizon-holding-retire185-lanek-plan-v1", "mapping": park["mapping"],
                   "custody": custody_ref, "park_start": start_ref}
    ref = persist(ROOT / "RETIREMENT_PLAN_AFTER_CUSTODY.json", retire_plan)
    event = {"schema": "horizon-185-lanek-post-park-handoff-v1", "plan": ref, "native": native,
             "park_start": start_ref, "admission": adm_ref, "custody": custody_ref,
             "resource_credit_bytes": 0, "source_retired": False, "next": "fresh check and execution price"}
    print(json.dumps(persist(ROOT / "RETIREMENT_READY_AFTER_PARK.json", event)))


if __name__ == "__main__":
    main()
