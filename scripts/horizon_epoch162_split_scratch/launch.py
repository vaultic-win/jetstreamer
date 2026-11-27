"""Hold, guard and release the enrolled private epoch 162 interval under one fleet lock."""

import argparse
import fcntl
import json
import os
import re
import runpy
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
l = SimpleNamespace(**runpy.run_path(str(HERE / "layout.py")))
status = SimpleNamespace(**runpy.run_path(str(HERE / "status162.py")))
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
WRITER = l.RT / "survivor172-cadence-20261122-v1"
SEAL = l.PKG / "deployment-seal-receipt.json"
ENROLL = l.BASE / "SPLIT162_ENROLLMENT.json"
LEASE = l.DATA / "LEASE.json"
PROFILE = l.profile(36)


def file_ref(p):
    return {"path": str(p), "sha256": l.digest(p)}


def sealed_program(ref):
    p = Path(ref["path"])
    st = p.lstat()
    l.need(
        p.resolve(strict=True) == p
        and stat.S_ISREG(st.st_mode)
        and st.st_uid == 0
        and not st.st_mode & 0o222
        and st.st_nlink == 1
        and file_ref(p) == ref,
        "unsealed program " + str(p),
    )
    return p


def enrollment():
    l.need(os.geteuid() == 0 and __debug__ and HERE == l.PKG, "operator must run from the sealed package")
    spec, spec_ref = l.pinned(ENROLL)
    _, pkg = l.pinned(SEAL)
    members = l.bound(pkg)["members"]
    for m in members:
        sealed_program({"path": str(l.PKG / m["name"]), "sha256": m["sha256"]})
    active = l.bound(spec["writer_active"])
    writer_path = Path(spec["writer_active"]["path"])
    l.need(
        writer_path.parent == WRITER
        and re.fullmatch(r"FAILED166_CADENCE_V[0-9]+_ACTIVE\.json", writer_path.name)
        and spec["operator"] == pkg
        and spec["donor"] == {"path": str(l.DONOR), "sha256": l.DONOR_SHA},
        "different operator, writer or 166 donor",
    )
    l.bound(spec["donor"])
    ready = l.bound(active["ready"])
    who = active["new"]
    program = Path(who["program"])
    reader = program.parent / "status162.py"
    l.need(
        ready["split162_provider"] == pkg
        and ready["split162_reader"] == file_ref(reader)
        and l.digest(reader) == l.digest(HERE / "status162.py")
        and json.loads((reader.parent / "split162_provider.json").read_bytes()) == pkg,
        "writer did not enroll this exact operator",
    )
    props = l.manager(who["unit"])
    pid = int(who["pid"])
    live = Path("/proc") / str(pid)
    lock = (live / "fd" / str(who["lock"]["fd"])).stat()
    l.need(
        props["ActiveState"] == "active"
        and not props["Job"]
        and props["InvocationID"] == who["invocation_id"]
        and int(props["MainPID"]) == pid
        and l.ticks(pid) == who["start_ticks"]
        and os.fsencode(program) in (live / "cmdline").read_bytes().split(b"\0")
        and (lock.st_dev, lock.st_ino) == (who["lock"]["device"], who["lock"]["inode"]),
        "foreign cadence writer",
    )
    sealed_program(spec["capacity"])
    return spec, spec_ref


def validate_quote(q, phase, held, enrollment_ref, profile=PROFILE):
    l.need(
        q.get("schema") == "horizon-162-split-fleet-price-v1"
        and q.get("phase") == phase
        and q["fits"] is True
        and q["unit"] == l.UNIT
        and q["scratch_gib"] == 36
        and q["profile"] == profile
        and q["held_invocation"] == held
        and q["donor"] == {"path": str(l.DONOR), "sha256": l.DONOR_SHA}
        and q["enrollment"] == enrollment_ref
        and q["guard_floor"] >= l.MIN_FLOOR
        and type(q["home_margin"]) is int
        and type(q["ram_margin"]) is int
        and min(q["home_margin"], q["ram_margin"]) >= 0
        and q["exclusive_166_lease"] is True
        and "169" in q["peers"]
        and q["peers"]["169"]["phase"] in ("precharged", "held", "bootstrap", "worker", "terminal")
        and q["boot_id"] == l.BOOT.read_text().strip(),
        "no current positive 162 fleet, donor and 169 booking",
    )
    fleet = l.bound(q["fleet"])
    current = max(l.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    l.need(
        q["fleet"]["path"] == str(current) and fleet["resource_credit_bytes"] == 0,
        "162 quote refers to a superseded fleet",
    )
    return q


def check_169(spec, q):
    ready = l.bound(l.bound(spec["writer_active"])["ready"])
    seal = ready["split169_provider"]
    directory = l.RT / "epoch169-hourly-admission-20261123-v1/issued-split-v1"
    l.need(seal["path"] == str(directory / "deployment-seal-receipt.json"), "unknown 169 provider")
    receipt = l.bound(seal)
    l.need(receipt["destination"] == str(directory), "different 169 destination")
    for member in receipt["members"]:
        path = directory / member["name"]
        sealed_program({"path": str(path), "sha256": member["sha256"]})
    peer = runpy.run_path(str(directory / "split_actor.py"))
    fleet = l.bound(q["fleet"])
    actual = peer["current"](fleet)
    reported = q["peers"]["169"]
    expected = "precharged" if actual is None else actual["phase"]
    l.need(reported["phase"] == expected, "actual 169 phase differs from the price")
    if actual is not None:
        iid = actual["invocation_id"] if expected == "terminal" else actual["unit"]["InvocationID"]
        l.need(reported.get("invocation_id") == iid, "price omitted current 169 invocation")
        if expected != "terminal":
            l.need(
                reported.get("start_intent") == actual["hourly169_start_intent"]
                and reported.get("guard_floor", 0) >= actual["disk"]["floor"]
                and reported.get("remaining_home_and_control", -1)
                >= actual["disk"]["remaining"] + actual["disk"]["fixed_control"],
                "price omitted protected 169 HOME or guard floor",
            )
    peer["recheck"](fleet, actual)


def price(phase, held):
    spec, ref = enrollment()
    provider = runpy.run_path(str(sealed_program(spec["capacity"])))
    q = provider["quote"](phase=phase, held_invocation=held, profile=PROFILE, enrollment=ref)
    validate_quote(q, phase, held, ref)
    check_169(spec, q)
    return q


def new_dir(p, mode):
    l.need(not os.path.lexists(p), "previous or foreign state " + str(p))
    p.mkdir(mode=mode)
    p.chmod(mode)


def start_guard(iid, floor):
    plan_path = l.DATA / "GUARD_PLAN.json"
    plan = l.save(plan_path, l.guard_plan(iid, floor))
    args = [str(l.GUARD), str(plan_path), "--plan-sha256", plan["sha256"], "--self-sha256", l.GUARD_SHA]
    subprocess.run([*args, "--validate-plan-only"], check=True)
    cmd = [
        "/usr/bin/systemd-run",
        "--unit=" + l.TIMER.removesuffix(".timer"),
        "--on-active=1s",
        "--timer-property=AccuracySec=1s",
        "--timer-property=OnUnitActiveSec=10s",
        "--timer-property=BindsTo=" + l.UNIT,
        "--timer-property=After=" + l.UNIT,
        "--property=CPUQuota=100%",
        "--property=MemoryMax=1073741824",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=64",
        "--property=Restart=no",
        "--property=ProtectHome=read-only",
        "--property=ProtectSystem=strict",
        "--property=PrivateNetwork=yes",
        "--property=ReadWritePaths=" + str(l.GUARDS),
    ]
    subprocess.run([*cmd, "--", *args], check=True)
    return plan


def launch():
    q = price("prestart", None)
    for name in (l.UNIT, l.TIMER, l.TIMER.replace(".timer", ".service")):
        props = l.manager(name)
        l.need(
            props["ActiveState"] in ("inactive", "failed")
            and props.get("MainPID", "0") == "0"
            and props.get("ControlPID", "0") == "0"
            and not props["Job"]
            and not props.get("ControlGroup"),
            "occupied 162 unit",
        )
    packet = l.scope()
    bindings = l.sources()
    for p in (l.DATA, l.RUN, l.GUARDS, l.ALLOW.parent):
        l.need(not os.path.lexists(p), "previous 162 state " + str(p))
    new_dir(l.DATA, 0o700)
    pre = l.save(l.DATA / "PRESTART.json", q)
    lease = l.save(
        LEASE,
        dict(
            unit=l.UNIT,
            donor=q["donor"],
            profile=PROFILE,
            owner_enrollment=q["enrollment"],
            prestart=pre,
            boot_id=q["boot_id"],
        ),
    )
    new_dir(l.GUARDS, 0o700)
    new_dir(l.ALLOW.parent, 0o755)
    new_dir(l.RUN, 0o755)
    image = l.prepare_image(
        l.RUN,
        l.IMAGE,
        [
            Path(r["readonly_view"]).relative_to(l.RUN)
            for r in bindings
            if Path(r["readonly_view"]).is_relative_to(l.RUN)
        ],
    )
    argv = l.producer_argv(36, packet, bindings)
    intent = l.save(
        l.DATA / "INTENT.json",
        dict(
            unit=l.UNIT,
            profile=PROFILE,
            prestart=pre,
            lease=lease,
            image=image,
            argv=argv,
            canonical_publication_authorized=False,
        ),
    )
    subprocess.run(argv, check=True)
    who = l.manager(l.UNIT)
    iid, pid = who["InvocationID"], int(who["MainPID"])
    released = False
    timer_iid = None
    try:
        l.need(
            re.fullmatch(r"[a-f0-9]{32}", iid)
            and int(iid, 16)
            and pid > 1
            and who["ActiveState"] == "active"
            and Path(f"/proc/{pid}/exe").samefile(l.GATE),
            "162 gate did not hold",
        )
        mounts = l.verify_mounts(pid, 36, image, bindings)
        plan = start_guard(iid, q["guard_floor"])
        timer_iid = l.manager(l.TIMER)["InvocationID"]
        held = dict(
            producer_unit=l.UNIT,
            producer_invocation_id=iid,
            producer_pid=pid,
            start_ticks=l.ticks(pid),
            boot_id=q["boot_id"],
            guard_timer_invocation_id=timer_iid,
            guard_plan=plan,
            intent=intent,
            mounts=mounts,
        )
        status.owner(PROFILE, l.manager(l.UNIT), held, l)
        deadline = time.monotonic() + 45
        while not any(l.GUARDS.glob("sample-*.json")):
            l.need(time.monotonic() < deadline, "162 guard did not emit its first sample")
            time.sleep(0.15)
        g, first, _ = status.last_guard(l, held)
        l.need(not g["workers"] and g["producer"]["pid"] == pid, "162 executed before first guard")
        l.need(
            all(
                w["physical_bytes"] >= l.IMAGE.stat().st_blocks * 512
                for w in (g["root_physical_observation"]["first"], g["root_physical_observation"]["second"])
            ),
            "guard omitted the 162 backing image",
        )
        held.update(first_guard=first)
        hr = l.save(l.DATA / "HELD_OWNER.json", held)
        post = price("postguard", iid)
        l.need(
            post["guard_floor"] <= q["guard_floor"]
            and post["fleet"] == q["fleet"]
            and post["enrollment"] == q["enrollment"],
            "162 protection or enrollment changed at release",
        )
        post_ref = l.save(l.DATA / "POST_GUARD.json", post)
        status.owner(PROFILE, l.manager(l.UNIT), held, l)
        status.last_guard(l, held)
        l.need(
            l.verify_mounts(pid, 36, image, bindings) == mounts
            and Path(f"/proc/{pid}/exe").samefile(l.GATE)
            and l.bound(hr) == held,
            "162 gate changed during capacity check",
        )
        grant = l.save(
            l.DATA / "GRANT.json",
            dict(
                held=hr,
                postguard=post_ref,
                iid=iid,
                profile=PROFILE,
                writer=q["enrollment"],
                canonical_publication_authorized=False,
            ),
        )
        l.save(l.ALLOW, iid.encode())
        released = True
        return dict(grant=grant, invocation_id=iid, unit=l.UNIT)
    finally:
        # Only abort the producer/timer created by this call. An uncertain
        # release is reconciled from its durable marker and native gate identity.
        if not released and not l.ALLOW.exists():
            if timer_iid and l.manager(l.TIMER)["InvocationID"] == timer_iid:
                subprocess.run(["systemctl", "stop", l.TIMER], check=True)
            if l.manager(l.UNIT)["InvocationID"] == iid and int(l.manager(l.UNIT)["MainPID"]) == pid:
                subprocess.run(["systemctl", "stop", l.UNIT], check=True)


if __name__ == "__main__":
    args = argparse.ArgumentParser(__doc__)
    args.add_argument("stage", choices=["price", "launch"])
    command = args.parse_args().stage
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(json.dumps(price("prestart", None) if command == "price" else launch(), sort_keys=True, indent=2))
