"""Exact producer transport and evidence shared by the half-core full-epoch session."""
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
INPUT = RUNTIME / "epoch172-full-replay-20261120-v1"
BASE = RUNTIME / "epoch172-full-half-core-20261120-v1"
PACKAGE = BASE / "controller"
LANE = Path("/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1")
RUN = LANE / "full-metered-20261120-v1"
LOG = RUN / "producer.log"
UNIT = "horizon-qualify-172-full-half-core-20261120-v1.service"
GUARD_UNIT = "horizon-guard-172-full-half-core-20261120-v1.service"
TIMER = GUARD_UNIT.removesuffix("service") + "timer"
ALIAS = Path("/run/horizon-full172-half-core")
GUARD = RUNTIME / "epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
GUARD_SHA = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
PAYLOAD_SHA = "c573f9f54962f1d489ca8208414d51aafe98e9b59483b52d79f4ffa43f0d0eca"
ORIGINAL_SHA = "29f151c971041b45fe1dbda9dafe0ec6328add8c8040641c4344ec1cd0ef1dc0"
AUDIT_SHA = "73bcc3f40270116c828e9eda204049993e545c2290c5ce7f1f8ebb961e27a0b8"
ACTOR_BYTES = 68 << 30
GUARD_BYTES = 1 << 30
CAP = 288 << 30
VMA = 3_500_000
GIB = 1 << 30


def need(value, message):
    if not value:
        raise ValueError(message)


def run(*args, timeout=30):
    return subprocess.run([str(v) for v in args], check=True, capture_output=True,
                          text=True, stdin=subprocess.DEVNULL, timeout=timeout).stdout


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def reference(path):
    return {"path": str(path), "sha256": digest(path)}


def checked(path, expected):
    p = Path(path)
    with p.open("rb") as f:
        st = os.fstat(f.fileno())
        need(p.resolve() == p and stat.S_ISREG(st.st_mode) and st.st_uid == 0
             and st.st_nlink == 1 and st.st_mode & 0o022 == 0 and st.st_size <= 128 << 20,
             f"untrusted root evidence {p}")
        b = f.read()
    need(hashlib.sha256(b).hexdigest() == expected, f"changed evidence {p}")
    return json.loads(b)


def bound(ref):
    return checked(ref["path"], ref["sha256"])


def native(unit):
    fields = "Id,LoadState,ActiveState,SubState,ControlGroup,MainPID,ControlPID,Job,InvocationID,NRestarts,Result,ExecMainStatus,Description,Triggers,TriggeredBy,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Restart"
    result = dict(s.split("=", 1) for s in run("/usr/bin/systemctl", "show", unit,
                                               "--property=" + fields).splitlines())
    need(result["Id"] == unit, f"different native unit {unit}")
    return result


def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def iid(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{32}", value) and value != "0" * 32


def payload():
    value = checked(INPUT / "FULL_PAYLOAD.json", PAYLOAD_SHA)
    need(value["run_root"] == str(RUN) and value["worker_scope"] == "full canonical archive"
         and value["canonical_epoch_range"] == [74304000, 74735999]
         and value["terminal_checkpoint_slot"] == 74735808, "wrong epoch or checkpoint")
    return value


def producer_argv(v, original, token):
    need(original[0] == "/usr/bin/systemd-run" and v["original_normal_producer"]["sha256"] == ORIGINAL_SHA,
         "source producer contract")
    node = str(v["package_target"]) + "/jetstreamer-node"
    # Reuse all original hardening, network, task and memory settings. Only the new
    # worker root is writable. The prior files and package appear read-only inside it.
    props = dict(s.removeprefix("--property=").split("=", 1) for s in original if s.startswith("--property="))
    need(props["CPUQuota"] == "900%" and int(props["MemoryMax"]) == ACTOR_BYTES
         and props["MemorySwapMax"] == "0" and props["User"] == "sol" and props["Group"] == "horizon"
         and props["Restart"] == "no" and props["ReadWritePaths"] == str(LANE)
         and props["RuntimeMaxSec"] == "604800", "original producer limits differ")
    props.update(CPUQuota="50%", ReadWritePaths=str(RUN), WorkingDirectory=str(v["package_target"]),
                 StandardOutput=f"append:{LOG}", StandardError=f"append:{LOG}",
                 ExecPaths=f"{RUN} {ALIAS}/gate {ALIAS}/jetstreamer-node", RuntimeMaxSec="1209600")
    binds = [f'{v["package_source"]}:{v["package_target"]}:rbind',
             f'{v["package_source"]}/jetstreamer-node:{ALIAS}/jetstreamer-node',
             f'{PACKAGE}/gate:{ALIAS}/gate', f'{BASE}/barrier:{ALIAS}/barrier']
    for child in v["file_binds"]:
        source, target = Path(child["source"]), Path(child["target"])
        need(target.is_relative_to(RUN) and source.is_relative_to(LANE)
             and not source.is_relative_to(RUN), "unexpected input projection")
        binds.append(f"{source}:{target}")
    props["BindReadOnlyPaths"] = " ".join(binds)
    need(v["normal_node_argv"][0] == node and v["normal_node_argv"][1] == "172"
         and v["normal_node_argv"][3:5] == ["--verify", "--root-checkpoint-cohort"]
         and v["environment"]["JETSTREAMER_VERIFY_SNAPSHOTS"] == "1", "normal verification disabled")
    return ["/usr/bin/systemd-run", f"--unit={UNIT}", f"--description={token}",
            *[f"--property={k}={v}" for k, v in props.items()],
            *[f"--setenv={k}={v}" for k, v in v["environment"].items()],
            "/usr/bin/env", str(ALIAS / "gate"), *v["normal_node_argv"]]


def guard_plan(invocation, floor):
    need(iid(invocation) and floor >= 8515329790544, "bad protected floor or invocation")
    return {"schema":"jetstreamer-horizon-standalone-guard-plan-v1", "unit":UNIT,
            "invocation_id":invocation, "filesystem":"/home/sol", "minimum_free_bytes":floor,
            "worker_root":str(LANE), "maximum_worker_vmas":VMA, "maximum_root_physical_bytes":CAP,
            "receipt_directory":str(BASE / "guard-receipts")}


def guard_argv(plan, plan_hash):
    args = ["/usr/bin/systemd-run", "--on-active=1s", "--on-unit-inactive=5s",
            "--timer-property=AccuracySec=1s", "--service-type=oneshot"]
    for prop in ["User=root","Group=root","UMask=0077","Restart=no","MemoryMax=1G","MemorySwapMax=0",
                 "CPUQuota=25%","TasksMax=256","TimeoutStartSec=120","TimeoutStopSec=15",
                 "PrivateNetwork=yes","ProtectSystem=strict","ProtectHome=read-only","PrivateTmp=yes",
                 "NoNewPrivileges=yes","CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
                 "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
                 f"ReadWritePaths={BASE}/guard-receipts",
                 f"StandardOutput=append:{BASE}/guard.stdout",f"StandardError=append:{BASE}/guard.stderr"]:
        args.append("--property=" + prop)
    return args + ["--unit=" + GUARD_UNIT.removesuffix(".service"), "--timer-property=Requisite=" + UNIT,
                   "--timer-property=After=" + UNIT, "--timer-property=StopPropagatedFrom=" + UNIT,
                   str(GUARD), str(plan), "--plan-sha256", plan_hash, "--self-sha256", GUARD_SHA]


def atomic_file(path, data, mode=0o444):
    # Link exposes only complete contents and fails if a concurrent writer won.
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temp = Path(f.name)
        try:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
            os.link(temp, path)
        finally:
            temp.unlink(missing_ok=True)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record(path, value):
    atomic_file(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
    return reference(path)
