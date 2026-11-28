"""Admit the previously qualified single-copy receiver for the fourth bootstrap."""

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import fcntl
import json
import os
import subprocess
import sys
import time


ROOT = Path("/var/lib/jetstreamer/horizon141-foundation-interval4-runtime-v1")
PRIOR = Path("/var/lib/jetstreamer/horizon141-foundation-interval3-runtime-v1")
LOCK = Path("/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock")
UNIT = "foundation-141-interval4-payload-intake-v1.service"
TIMER = "foundation-publication-cadence-v222.timer"
CPU = 30
RAM = 2 << 30
RUNTIME = 240
SIZE = 2_201_713_062
HOME = 6_832_226_304
PAYLOAD = "9944c752006ccd77def013750035b90cbb5c1cd0ef96f8ae4548436323d98d57"
MANIFEST = "19086d7d15039c4b064442caf9a09f6b3e64292a0afabe9e0f352d2ca501d6be"
ASSIGNMENT = "f56969445eb933d4ff9ea3eb3ec8a218d999ce9a63c1d1c2da063c154cebbf8e"
RECEIVER = "be55dc34f80cb957b788c2919d28869321eb8c62ba7f76b6f1d660bcadcdc512"


def reference(path):
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}


def record(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        os.fchmod(stream.fileno(), 0o400)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return reference(path)


def document(path, value):
    return record(path, (json.dumps(value, indent=2) + "\n").encode())


def properties(unit, fields):
    lines = subprocess.check_output(
        ["/usr/bin/systemctl", "show", unit, "-p", ",".join(fields)], text=True)
    return dict(row.split("=", 1) for row in lines.splitlines())


def cpus(raw):
    values = set()
    for item in raw.strip().split(","):
        if item:
            ends = list(map(int, item.split("-")))
            values.update(range(ends[0], ends[-1] + 1))
    return values


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 4
    os.umask(0o077)
    roster_path, exact_binding = map(Path, sys.argv[1:3])
    custody_raw = exact_binding.read_bytes()
    assert sha256(custody_raw).hexdigest() == sys.argv[3]
    custody = json.loads(custody_raw)
    assert custody["bytes"] == SIZE and custody["sha256"] == PAYLOAD
    assert custody["object_key"] == f"node_02/objects/{PAYLOAD}.blob"
    assert custody["manifest_sha256"] == MANIFEST
    assert custody["manifest_key"] == f"node_02/manifests/{MANIFEST}.json"
    assert custody["authenticated_post_readback"]["authenticated"] is True
    assert custody["authenticated_post_readback"]["conditional_final_identity"] is True
    assignment = reference(ROOT / "inputs/foundation-assignment.json")
    receiver = reference(ROOT / "conditional-receiver.py")
    assert assignment["sha256"] == ASSIGNMENT and receiver["sha256"] == RECEIVER
    prior_done = json.loads((PRIOR / "transfer-completion.json").read_bytes())
    assert json.loads((PRIOR / "transfer-admission.json").read_bytes())["receiver"]["sha256"] == reference(PRIOR / "conditional-receiver.py")["sha256"]
    assert prior_done["schema"] == "foundation-epoch141-interval3-intake-completion-v1"
    roster = json.loads(roster_path.read_bytes())
    assert roster["schema"] == "foundation-epoch226-suffix-roster-binding-v1"
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert 0 <= time.time() - roster["recorded_unix_seconds"] <= 120
        listing = subprocess.check_output(
            ["/usr/bin/systemctl", "list-timers", TIMER, "--no-legend", "--no-pager"], text=True)
        next_tick = datetime.strptime(listing.splitlines()[0][:27], "%a %Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        assert next_tick.timestamp() - time.time() > RUNTIME + 30
        assert properties(UNIT, ["LoadState"])["LoadState"] == "not-found"
        assert not (ROOT / "transfer-admission.json").exists()
        siblings = cpus(Path(f"/sys/devices/system/cpu/cpu{CPU}/topology/thread_siblings_list").read_text())
        assert siblings.isdisjoint(set(range(24, 30)))
        check = ["ActiveState", "InvocationID", "MainPID", "ControlGroup", "AllowedCPUs"]
        for owner, expected in roster["owners"].items():
            live = properties(owner, check)
            assert all(live[field] == expected["systemd"][field] for field in check)
            assert siblings.isdisjoint(cpus(live["AllowedCPUs"]))
        for guard in roster["periodic_guards"].values():
            assert siblings.isdisjoint(cpus(properties(guard["unit"], ["AllowedCPUs"])["AllowedCPUs"]))
        cap = roster["capacity"]
        fs = os.statvfs(ROOT)
        headroom = min(cap["available_disk_bytes"], fs.f_bavail * fs.f_frsize)
        retired_candidate = cap["candidate_total_memory_bytes"]
        assert ROOT.stat().st_dev == roster["filesystem_device"]
        assert headroom >= cap["protected_existing_disk_bytes"] + HOME
        assert cap["host_total_memory_bytes"] >= cap["required_hard_memory_bytes"] - retired_candidate + RAM
        assert cap["available_memory_bytes"] >= cap["required_remaining_memory_bytes"] - retired_candidate + RAM
        pinned = record(ROOT / "inputs/bootstrap-r2-custody.json", custody_raw)
        (ROOT / "payloads").mkdir(mode=0o700)
        props = {
            "Type": "exec", "UMask": "0077", "PrivateTmp": "yes", "NoNewPrivileges": "yes",
            "ProtectHome": "read-only", "ProtectSystem": "strict", "ReadWritePaths": str(ROOT),
            "AllowedCPUs": str(CPU), "CPUAffinity": str(CPU), "CPUQuota": "100%",
            "MemoryMax": str(RAM), "MemorySwapMax": "0", "LimitFSIZE": str(SIZE), "TasksMax": "96",
            "Restart": "no", "KillMode": "control-group", "RuntimeMaxSec": f"{RUNTIME}s",
            "TimeoutStopSec": "15s", "Nice": "5",
        }
        approval = document(ROOT / "transfer-admission.json", {
            "schema": "foundation-epoch141-interval4-transfer-admission-v1",
            "roster": reference(roster_path), "handoff": assignment, "receiver": receiver,
            "bootstrap_custody": pinned, "protected_disk_bytes": cap["protected_existing_disk_bytes"],
            "reserved_incremental_home_bytes": HOME, "received_bytes": SIZE, "next_cadence": next_tick.isoformat(),
            "properties": props, "reused_original": prior_done["reused_original"],
            "runtime_launch_authorized": False, "canonical_publication_authorized": False,
        })
        subprocess.run([
            "/usr/bin/systemd-run", "--quiet", f"--unit={UNIT}",
            "-pEnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env",
            *[f"-p{key}={value}" for key, value in props.items()],
            "/usr/bin/python3", "-B", receiver["path"],
        ], check=True)
        live = properties(UNIT, ["Id", "InvocationID", "ActiveState", "MainPID", "AllowedCPUs", "MemoryMax", "MemorySwapMax"])
        assert live["Id"] == UNIT and len(live["InvocationID"]) == 32 and int(live["MainPID"]) > 0
        assert live["ActiveState"] == "active" and live["AllowedCPUs"] == str(CPU)
        assert int(live["MemoryMax"]) == RAM and live["MemorySwapMax"] == "0"
        print(json.dumps(document(ROOT / "transfer-launch.json", {
            "schema": "foundation-epoch141-interval4-transfer-launch-v1",
            "admission": approval, "actual": live, "canonical_publication_authorized": False,
        })))


if __name__ == "__main__":
    main()
