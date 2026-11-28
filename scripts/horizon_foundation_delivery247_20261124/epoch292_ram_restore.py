"""Fit and run the closed epoch 292 custody check in a private RAM volume."""

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

from epoch226_layered_capacity import RESTAGING, staging_cost, toolkit


STATE = Path("/var/lib/jetstreamer")
HOLDING = STATE / "horizon-foundation-closed-private-holding-v1"
RUN = STATE / "horizon292-appendvec-ram-restore-v308"
CONTROL = STATE / "horizon-seven-publication-controller-v222/cycle.lock"
ISSUER = Path("/run/horizon292-300-finite-v205-a1/issuer.lock")
MAPPING = STATE / "horizon-r2-holding-foundation-node-01-user-mapping-v1/mapping.json"
UNIT = "horizon-restore-292-appendvec-ram-v308.service"
PARK = "foundation-292-appendvec-custody-v308.service"
EXTRACT = "horizon-qualify-226-checkpoint-continuation-extract-v3.service"
BROKER = "foundation-226-original225-broker-v3.service"
SUFFIX = "horizon-qualify-226-checkpoint-continuation-suffix-v1.service"
MOUNT = "/tmp/epoch292-appendvec-restore"
MEMORY = 72 << 30
VOLUME = 69 << 30
ACTION = "holding-foundation-292-appendvec-restore-compare-ram"


def command(*argv):
    return subprocess.check_output(argv, text=True, timeout=20)


def reference(path):
    assert path.resolve(strict=True) == path
    detail = path.stat()
    assert stat.S_ISREG(detail.st_mode) and detail.st_uid == 0 and not detail.st_mode & 0o222
    with path.open("rb") as stream:
        return dict(path=str(path), sha256=hashlib.file_digest(stream, "sha256").hexdigest())


def record(name, value):
    path = RUN / name
    with tempfile.NamedTemporaryFile(dir=RUN) as out:
        out.write((json.dumps(value, indent=2) + "\n").encode())
        out.flush()
        os.fchmod(out.fileno(), 0o400)
        os.fsync(out.fileno())
        os.link(out.name, path)
    descriptor = os.open(RUN, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return reference(path)


def running_units():
    words = command(
        "systemctl", "list-units", "--type=service", "--state=running,activating",
        "--plain", "--no-legend", "--no-pager",
        "horizon-qualify-*", "horizon-perf-*", "horizon-publish-*",
        "horizon-upload-*", "horizon-restore-*", "foundation-*-broker-*",
        "foundation-292-closed-appendvec-staging-v308.service", PARK,
    )
    return {line.split()[0] for line in words.splitlines() if line.strip()}


def fit(require_closed=False):
    previous, kit = toolkit()
    completion, fleet_ref, fleet = previous.latest_accepted_fleet(kit)
    ops = kit.ops
    helper = kit.measure.source.helper
    phase = next(row for row in fleet["inventory"]["entries"] if row["epoch"] == 292)
    assert phase["state"] == "missing"
    owners, growth = {}, {}
    for row in fleet["active"]:
        epoch, producer = row["epoch"], row["producer"]
        unit = producer["Id"]
        owner = helper.active_props(unit, producer["InvocationID"])
        assert owner["MainPID"] == producer["MainPID"] and unit not in owners
        owners[unit] = owner
        if epoch == 226:
            if unit == EXTRACT:
                guards = STATE / "horizon226-extract-v3/guard-receipts"
                broker = row["capacity_owners"]["broker"]
                assert broker["unit"] == BROKER
                booking = helper.active_props(BROKER, broker["invocation_id"])
                assert int(booking["MainPID"]) == broker["pid"]
                owners[BROKER] = booking
            else:
                assert unit == SUFFIX
                guards = STATE / "horizon226-suffix-v1/guard-receipts"
        else:
            guards = previous.GUARDS[epoch]
        growth[unit] = kit.measure.source.growth_for(epoch, owner, guards)
    fs = os.statvfs(HOLDING)
    root = Path("/").stat().st_dev
    assert HOLDING.stat().st_dev == root
    staged_ref, stage, stage_disk, stage_memory = staging_cost(ops, root, fs.f_frsize)
    staged_live = stage["ActiveState"] == "active"
    if require_closed:
        assert stage["ActiveState"] == "inactive" and stage_disk == stage_memory == 0
    expected = set(owners) | ({stage["Id"]} if staged_live else set())
    assert running_units() == expected, "live Horizon services differ from the booked roster"
    assert all(not ({90, 91} & helper.cpus(owner["AllowedCPUs"])) for owner in owners.values())
    for row in growth.values():
        sample = ops.bound(row["sample"])
        plan = ops.bound(dict(path=sample["plan"], sha256=sample["plan_sha256"]))
        assert Path(plan["filesystem"]).stat().st_dev == root
    floor = max(row["floor_bytes"] for row in growth.values())
    disk_required = (floor + helper.PUBLICATION_SCRATCH + stage_disk
                     + sum(row["remaining_growth_bytes"] for row in growth.values()))
    disk_margin = fs.f_bavail * fs.f_frsize - disk_required
    for unit, owner in owners.items():
        current = helper.active_props(unit, owner["InvocationID"])
        assert all(current[field] == owner[field] for field in
                   ("MainPID", "ControlGroup", "AllowedCPUs", "MemoryMax"))
        owner["MemoryCurrent"] = str(min(int(owner["MemoryCurrent"]), int(current["MemoryCurrent"])))
    mem = {name: int(value.split()[0]) * 1024
           for line in Path("/proc/meminfo").read_text().splitlines()
           if ":" in line
           for name, value in [line.split(":", 1)]
           if name in ("MemAvailable", "MemTotal")}
    memory_required = mem["MemTotal"] // 10 + stage_memory + sum(
        max(0, int(owner["MemoryMax"]) - int(owner["MemoryCurrent"]))
        for owner in owners.values()
    )
    assert running_units() == expected
    assert disk_margin >= 64 << 20, "restore receipt writes exceed disk headroom"
    assert mem["MemAvailable"] >= memory_required + MEMORY, "RAM restore does not fit"
    return dict(
        schema="foundation-epoch292-appendvec-ram-restore-fit-v1", unit=UNIT, epoch=292,
        recorded_unix_seconds=int(time.time()), boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        fleet=fleet_ref, fleet_completion=completion, staging_owner=staged_ref, staging_live=staged_live,
        owners=owners, growth=growth, all_live_owners_and_growth_bound=True,
        host_memory_protected_bytes=memory_required, host_mem_available_bytes=mem["MemAvailable"],
        restore_memory_max_bytes=MEMORY, same_device_disk_margin_bytes=disk_margin,
        local_retirement_authorized=False, publication_authorized=False,
    )


def launch(qualification_path, qualification_sha, custody_path):
    ops = toolkit()[1].ops
    qualification = reference(qualification_path)
    assert qualification["sha256"] == qualification_sha
    release = ops.bound(qualification)
    assert release["schema"] == "foundation-epoch292-ram-restore-release-v1"
    executable = release["artifact"]
    binary = Path(executable["path"])
    assert binary.parent == qualification_path.parent
    assert reference(binary) == {key: executable[key] for key in ("path", "sha256")}
    assert binary.stat().st_size == executable["bytes"]
    park_start = ops.bound(reference(RESTAGING / "custody-start.json"))
    park_owner = park_start["owner"]
    assert park_owner["Id"] == PARK
    assert ops.props(PARK, ["ActiveState", "MainPID", "ControlGroup"]) == {
        "ActiveState": "inactive", "MainPID": "0", "ControlGroup": "",
    }
    log = [json.loads(line) for line in command(
        "journalctl", "-q", "--no-pager", "-o", "json",
        "_PID=1", f"UNIT={PARK}", f"INVOCATION_ID={park_owner['InvocationID']}",
    ).splitlines()]
    terminal, = [row for row in log if row["MESSAGE"] == f"{PARK}: Deactivated successfully."]
    custody_ref = reference(custody_path)
    assert custody_path.parent == HOLDING / "receipts"
    custody = ops.bound(custody_ref)
    intent = ops.bound(park_start["intent"])
    assert custody["park_spec"] == intent["spec"] and custody["epoch"] == 292
    assert custody["remote_sha256_readback"] and custody["local_source_revalidated"]
    assert not custody["local_retirement_authorized"] and not custody["publication_authorized"]
    source = Path(custody["manifest"]["restore_metadata"]["source"])
    assert source.name == "accounts-state" and source.resolve(strict=True) == source
    assert not any(ch.isspace() for ch in str(source))
    assert ops.props(UNIT, ["LoadState"]) == {"LoadState": "not-found"}

    review = fit(require_closed=True)
    RUN.mkdir(mode=0o700)
    fit_ref = record("fit.json", review)
    admission = record("admission.json", dict(
        schema="foundation-epoch292-appendvec-ram-restore-admission-v1",
        unit=UNIT, custody=custody_ref, boot_id=review["boot_id"], fit=fit_ref,
        recorded_unix_seconds=review["recorded_unix_seconds"],
        memory_max_bytes=MEMORY, tmpfs_bytes=VOLUME,
    ))
    spec = record("plan.json", dict(
        schema="foundation-epoch292-appendvec-ram-restore-plan-v1",
        mapping=reference(MAPPING), custody=custody_ref, admission=admission,
    ))
    record("intent.json", dict(
        unit=UNIT, qualification=qualification, plan=spec,
        park_custody_start=park_start["intent"], park_terminal_cursor=terminal["__CURSOR"],
        changes_local_source=False, remote_mutations=False,
    ))
    command(
        "systemd-run", "--quiet", f"--unit={UNIT}",
        "--property=Type=exec", "--property=User=root", "--property=UMask=0077",
        "--property=AllowedCPUs=90-91", "--property=CPUQuota=200%",
        f"--property=MemoryMax={MEMORY}", "--property=MemorySwapMax=0", "--property=TasksMax=128",
        "--property=RuntimeMaxSec=12h", "--property=LimitCORE=0", "--property=Restart=no",
        "--property=KillMode=control-group", "--property=OOMPolicy=stop",
        "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
        "--property=PrivateMounts=yes", "--property=PrivateTmp=yes",
        "--property=NoNewPrivileges=yes", f"--property=ReadOnlyPaths={source}",
        f"--property=ReadWritePaths={HOLDING / 'receipts'} {HOLDING / 'transition.lock'}",
        f"--property=TemporaryFileSystem={MOUNT}:rw,size={VOLUME},mode=0700,nosuid,nodev,noexec,noswap",
        "--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env",
        str(binary), ACTION, spec["path"], "--spec-sha256", spec["sha256"],
        "--self-sha256", executable["sha256"],
    )
    owner = ops.props(UNIT, ["Id", "ActiveState", "InvocationID", "MainPID", "ControlGroup"])
    assert owner["ActiveState"] == "active"
    assert Path(f"/proc/{int(owner['MainPID'])}/exe").resolve(strict=True) == binary
    return record("start.json", dict(owner=owner, plan=spec, qualification=qualification))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_subparsers(dest="mode", required=True)
    mode.add_parser("check")
    action = mode.add_parser("launch")
    action.add_argument("qualification", type=Path)
    action.add_argument("qualification_sha256")
    action.add_argument("custody", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    if args.mode == "check":
        value = fit()
    else:
        with ExitStack() as locks:
            for path in (ISSUER, CONTROL):
                handle = locks.enter_context(path.open("rb"))
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            value = launch(args.qualification, args.qualification_sha256, args.custody)
    print(json.dumps(value))


if __name__ == "__main__":
    main()
