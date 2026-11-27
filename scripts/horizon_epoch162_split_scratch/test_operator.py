"""Exercise the production layout and enrollment decisions using a disposable held unit."""

import copy
import importlib.util
import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refuses(fn, *args):
    try:
        fn(*args)
    except (ValueError, FileNotFoundError):
        return
    raise ValueError("incorrect fixture accepted")


def run(root):
    l = load("layout")
    launch = load("launch")
    l.need(
        os.geteuid() == 0
        and root.resolve() == root
        and root.parent.parent == l.PRIVATE
        and root.parent.name.startswith("epoch162-split-scratch-")
        and not root.exists(),
        "wrong fixture root",
    )
    root.mkdir(mode=0o755)
    p = l.profile(36)
    packet = l.scope()
    bindings = l.sources()
    l.need(
        p["combined_ram"] == 63 * l.G
        and p["home_image"] + p["control"] == 8657043456
        and p["producer_memory_max"] == 62 * l.G
        and len(bindings) == 14,
        "wrong issued layout",
    )
    refuses(l.profile, 35)
    fleet = max(l.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    _, fleet_ref = l.pinned(fleet)
    test_enrollment = {"path": str(root / "fake-enrollment"), "sha256": "1" * 64}
    quote = dict(
        schema="horizon-162-split-fleet-price-v1",
        phase="prestart",
        fits=True,
        unit=l.UNIT,
        scratch_gib=36,
        profile=p,
        held_invocation=None,
        donor={"path": str(l.DONOR), "sha256": l.DONOR_SHA},
        enrollment=test_enrollment,
        guard_floor=l.MIN_FLOOR,
        home_margin=1,
        ram_margin=1,
        exclusive_166_lease=True,
        peers={"169": {"phase": "precharged"}},
        fleet=fleet_ref,
        boot_id=l.BOOT.read_text().strip(),
    )
    launch.validate_quote(quote, "prestart", None, test_enrollment)
    bad_quotes = [
        dict(quote, ram_margin=-1),
        dict(quote, exclusive_166_lease=False),
        dict(quote, held_invocation="1" * 32),
        dict(quote, scratch_gib=32),
        dict(quote, peers={}),
        dict(quote, enrollment={}),
    ]
    for q in bad_quotes:
        try:
            launch.validate_quote(q, "prestart", None, test_enrollment)
        except (ValueError, KeyError):
            continue
        raise ValueError("unregistered 162 quote accepted")
    l.RUN = root / "tree"
    l.IMAGE = l.RUN / "mutable.ext4"
    l.RUN.mkdir(mode=0o755)
    old_tree = Path(packet["profile"]["scope"])
    private_view = root / "bind"
    private_view.mkdir(mode=0o755)
    for r in bindings:
        dest = Path(r["readonly_view"])
        if dest.is_relative_to(old_tree):
            r["readonly_view"] = str(l.RUN / dest.relative_to(old_tree))
        else:
            r["readonly_view"] = str(private_view / dest.name)
        if r.get("role"):
            b = root / "barrier"
            b.mkdir(mode=0o755)
            r["source"] = str(b)
    ii = l.prepare_image(
        l.RUN,
        l.IMAGE,
        [
            Path(r["readonly_view"]).relative_to(l.RUN)
            for r in bindings
            if Path(r["readonly_view"]).is_relative_to(l.RUN)
        ],
    )
    unit = "horizon-162-split-operator-fixture-" + str(time.time_ns()) + ".service"
    argv = l.producer_argv(36, packet, bindings)
    argv[1] = "--unit=" + unit
    argv = [x for x in argv if not x.startswith("--setenv=")]
    # The fixture keeps the production filesystem geometry but caps actual process use.
    argv = [
        "--property=MemoryMax=536870912"
        if a.startswith("--property=MemoryMax=")
        else "--property=MemoryHigh=469762048"
        if a.startswith("--property=MemoryHigh=")
        else "--property=CPUQuota=25%"
        if a.startswith("--property=CPUQuota=")
        else "--property=RuntimeMaxSec=60"
        if a.startswith("--property=RuntimeMaxSec=")
        else a
        for a in argv
    ]
    argv[argv.index("--") + 1 :] = ["/usr/bin/sleep", "40"]
    subprocess.run(argv, check=True)
    try:
        props = l.manager(unit)
        pid = int(props["MainPID"])
        mounts = l.verify_mounts(pid, 36, ii, bindings)
        altered = copy.deepcopy(bindings)
        altered[0]["source"] = altered[1]["source"]
        refuses(l.verify_mounts, pid, 36, ii, altered)
        refuses(l.verify_mounts, pid, 32, ii, bindings)
        refuses(l.verify_mounts, pid, 36, [*ii[:2], 123], bindings)
        # Create a disk marker in the actual private namespace. Read back after exit.
        marker = Path(f"/proc/{pid}/root") / str(l.RUN / "ledger/marker").lstrip("/")
        marker.write_bytes(b"retained epoch 162 fixture\n")
        with marker.open("rb") as f:
            os.fsync(f.fileno())
        l.need(not (l.RUN / "ledger/marker").exists(), "private mounted output escaped")
        actual = os.statvfs(l.RUN)
        floor = actual.f_bavail * actual.f_frsize - (8 * l.G + 64 * l.M)
        l.need(floor > l.MIN_FLOOR, "wrong HOME floor")
        plan = l.guard_plan(props["InvocationID"], floor)
        plan_file = root / "plan.json"
        plan["worker_root"] = str(old_tree)
        p_ref = l.save(plan_file, plan)
        proc = subprocess.run(
            [
                str(l.GUARD),
                str(plan_file),
                "--plan-sha256",
                p_ref["sha256"],
                "--self-sha256",
                l.GUARD_SHA,
                "--validate-plan-only",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        guard = json.loads(proc.stdout)
        l.need(
            guard["validated"] and not guard["producer_signaled"] and guard["unit"] == l.UNIT, "different native guard"
        )
    finally:
        subprocess.run(["systemctl", "stop", unit], check=True)
    read_cmd = [
        "systemd-run",
        "--quiet",
        "--collect",
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--unit=" + unit.replace("-fixture-", "-readback-fixture-"),
        "--property=User=sol",
        "--property=Group=horizon",
        "--property=MemoryMax=128M",
        "--property=MemorySwapMax=0",
        "--property=CPUQuota=25%",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=PrivateNetwork=yes",
        f"--property=MountImages={l.IMAGE}:{l.RUN}:ro,noload,nosuid,nodev",
        "--",
        "/usr/bin/cat",
        str(l.RUN / "ledger/marker"),
    ]
    result = subprocess.check_output(read_cmd)
    l.need(result == b"retained epoch 162 fixture\n", "missing post-exit custody marker")
    ref = l.save(
        root / "OPERATOR_FIXTURE.json",
        dict(
            utc=time.time(),
            none_released=True,
            profile=l.profile(36),
            native_guard=guard,
            quote_negative_cases=len(bad_quotes),
            native_mount_negatives=3,
            guarded_production_entries=0,
            source_projections=mounts,
            readback=result.decode(),
            argv=argv,
            producer_invocation=props["InvocationID"],
            source=l.digest(HERE / "layout.py"),
        ),
    )
    print(json.dumps(ref), flush=True)


if __name__ == "__main__":
    with Path("/run/lock/horizon-epoch140-suffix-compiler.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(Path(sys.argv[1]))
