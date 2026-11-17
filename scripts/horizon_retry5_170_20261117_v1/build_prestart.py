"""Wait for a sealed, invocation-bound first build-guard success before rustc runs."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path


IID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA = "horizon-epoch170-retry5-build-prestart-plan-v1"
TOKEN = "horizon-epoch170-retry5-build-prestart-token-v1"
BASE = Path("/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/build-v1")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum, modes):
    assert path.is_absolute() and path.resolve(strict=True) == path
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_uid == 0
    assert stat.S_IMODE(before.st_mode) in modes and before.st_nlink == 1
    assert 0 < before.st_size <= maximum
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        assert (opened.st_dev, opened.st_ino, opened.st_size) == (
            before.st_dev, before.st_ino, before.st_size
        )
        raw = os.read(fd, maximum + 1)
    finally:
        os.close(fd)
    after = path.lstat()
    assert len(raw) == before.st_size
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    )
    return raw


def native(unit):
    assert re.fullmatch(r"[A-Za-z0-9_.-]+\.service|[A-Za-z0-9_.-]+\.timer", unit)
    fields = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus"
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "-p", fields, "--no-pager"],
        capture_output=True,
        text=True,
        timeout=5,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        check=True,
    )
    assert result.stderr == "" and len(result.stdout) < 65536
    pairs = [line.split("=", 1) for line in result.stdout.splitlines()]
    assert all(len(pair) == 2 for pair in pairs)
    out = dict(pairs)
    assert len(out) == len(pairs) and out.get("Id") == unit
    return out


def actor_start_pre(plan, iid):
    actor = native(plan["actor_unit"])
    assert actor["ActiveState"] == "activating" and actor["SubState"] == "start-pre"
    assert actor["InvocationID"] == iid and actor["MainPID"] == "0"
    assert actor["ControlPID"] == str(os.getpid()) and actor["NRestarts"] == "0"
    return actor


def check_token(plan, plan_hash, iid):
    directory = Path(plan["gates_root"]) / iid
    if not directory.exists():
        return False
    metadata = directory.lstat()
    assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
    # The deployment sealer makes its destination read-only after publication.
    assert stat.S_IMODE(metadata.st_mode) == 0o555
    token_path = directory / "token.json"
    seal_path = directory / "deployment-seal-receipt.json"
    if not token_path.exists() or not seal_path.exists():
        return False
    token_raw = read_regular(token_path, 32768, {0o444})
    seal = json.loads(read_regular(seal_path, 32768, {0o444}))
    assert seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
    assert seal["destination"] == str(directory)
    assert seal["replay_launch_authorized"] is False
    assert seal["remote_mutations"] is False
    assert len(seal["members"]) == 1
    member = seal["members"][0]
    assert member["name"] == "token.json" and member["mode"] == "0444"
    assert member["sha256"] == digest(token_raw)
    token = json.loads(token_raw)
    assert token["schema"] == TOKEN and token["plan_sha256"] == plan_hash
    assert token["actor_unit"] == plan["actor_unit"]
    assert token["actor_invocation_id"] == iid
    assert token["guard_unit"] == plan["guard_unit"]
    assert token["replay_launch_authorized"] is False
    assert token["remote_mutations"] is False
    guard_iid = token["guard_invocation_id"]
    assert isinstance(guard_iid, str) and IID.fullmatch(guard_iid)
    bound = token["guard_receipt"]
    receipt_path = Path(bound["path"])
    assert receipt_path == Path(plan["guard_receipt_directory"]) / f"sample-{guard_iid}.json"
    receipt_raw = read_regular(receipt_path, 65536, {0o600, 0o640, 0o644})
    assert bound["sha256"] == digest(receipt_raw)
    receipt = json.loads(receipt_raw)
    assert receipt["schema"] == "jetstreamer-horizon-build-guard-sample-v1"
    assert receipt["unit"] == plan["actor_unit"]
    assert receipt["actor_invocation_id"] == iid
    assert receipt["guard_invocation_id"] == guard_iid
    assert receipt["self_sha256"] == plan["guard_sha256"]
    assert receipt["trip"] is False and receipt["native_owner_stable"] is True
    assert receipt["minimum_free_bytes"] == plan["minimum_free_bytes"]
    assert receipt["maximum_root_bytes"] == plan["maximum_root_bytes"]
    assert receipt["remote_mutations"] is False
    guard = native(plan["guard_unit"])
    assert guard["InvocationID"] == guard_iid
    assert guard["ActiveState"] == "inactive" and guard["Result"] == "success"
    assert guard["ExecMainStatus"] == "0"
    timer = native(plan["guard_timer"])
    assert timer["ActiveState"] == "active" and timer["SubState"] == "waiting"
    actor_start_pre(plan, iid)
    return True


def main():
    if not __debug__:
        raise RuntimeError("optimized Python disables the gate assertions")
    assert os.geteuid() == 0 and len(sys.argv) == 6
    assert sys.argv[2] == "--plan-sha256" and sys.argv[4] == "--self-sha256"
    plan_hash, self_hash = sys.argv[3], sys.argv[5]
    assert SHA.fullmatch(plan_hash) and SHA.fullmatch(self_hash)
    self_path = Path(__file__)
    assert digest(read_regular(self_path, 65536, {0o555})) == self_hash
    plan_path = Path(sys.argv[1])
    assert plan_path.parent == BASE and plan_path.name.endswith(".json")
    plan_raw = read_regular(plan_path, 65536, {0o600, 0o640, 0o644})
    assert digest(plan_raw) == plan_hash
    plan = json.loads(plan_raw)
    assert plan["schema"] == SCHEMA and plan["owner"] == "/root"
    assert plan["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
    assert plan["replay_launch_authorized"] is False
    assert plan["remote_mutations"] is False
    assert plan["gates_root"] == str(BASE / "gates")
    assert plan["guard_receipt_directory"] == str(BASE / "guard-receipts")
    assert plan["guard_unit"] == plan["actor_unit"].replace("horizon-qualify-", "horizon-guard-", 1)
    assert plan["guard_timer"] == plan["guard_unit"].removesuffix(".service") + ".timer"
    assert 0 < plan["minimum_free_bytes"] < 10**13
    assert 0 < plan["maximum_root_bytes"] <= 4 << 30
    assert SHA.fullmatch(plan["guard_sha256"])
    iid = os.environ.get("INVOCATION_ID", "")
    assert IID.fullmatch(iid)
    actor_start_pre(plan, iid)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        actor_start_pre(plan, iid)
        if check_token(plan, plan_hash, iid):
            print(json.dumps({"gate": "accepted", "actor_invocation_id": iid}))
            return
        time.sleep(0.2)
    raise TimeoutError("first guarded build proof was not sealed before setup deadline")


if __name__ == "__main__":
    main()
