"""Use the funded serial slot for closed lane N after M returns custody."""

from datetime import datetime
from pathlib import Path
import argparse
import json
import os
import re
import runpy
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rotation as op

QUALIFIED = "b7d1925a8c9828b061fd8440814e3d8395ce80a2613556e487eac8e5f9c57023"
M_RETURN = "4178b19beaa79dbe5c13678d6728ba473697ce5426f18311d582985c12cfdc00"
FLEET = "6344b45ca39d7bff5e7718988b67c2d2be2fdc322dcb075b61669d759b3ac051"
PAID = "f8e45c96f33686d57834398c4a1f331faea0a54439359840f45ddc349df9faeb"
PROVIDER_SHA = "1f53927d594917f5b59f61b9edee1e2495717d5950c4b4a64145ecd16a421458"
DASHBOARD_RAM = 512 * op.M


def m_return():
    handoff = op.bound(op.fixed(op.OUT / "QUALIFIED_HANDOFF.json", QUALIFIED))
    n = handoff["sources"]["n"]
    plan = op.bound(n["plan"])
    expected = op.bound(n["expected"])
    for name in ("profile", "plan", "expected"):
        op.need(
            n[name] == op.ref(op.OUT / "n" / (name + ".json")), "different N " + name
        )
    op.need(
        plan["eligibility"] == op.ref(op.OUT / "n/eligibility.json")
        and handoff["fixture"] == op.ref(op.OUT / "RESTORE_FIXTURE_ACCEPTED.json")
        and expected["single_copy_peak"] == n["single_copy_restore"] == 28579274897
        and expected["retained_shared_serial_slot"] == op.SLOT,
        "lane N restore evidence changed",
    )
    receipt = op.fixed(op.OUT / "M_SERIAL_HANDBACK.json", M_RETURN)
    prior = op.bound(receipt)
    terminal = op.bound(prior["retirement"])
    park = op.bound(prior["park"])
    custody = op.bound(park["native_custody"])
    op.need(
        prior["source_lane"] == "m"
        and prior["return_to"] == "campaign controller"
        and prior["park"] == op.ref(op.OUT / "m/PARK_ACCEPTED.json")
        and prior["retirement"] == op.ref(op.OUT / "m/RETIRED.json")
        and prior["allocated_bytes_removed"]
        == terminal["allocated_bytes_removed"]
        == 42990256128
        and park["success"]
        and terminal["success"]
        and terminal["native_terminal"]["success"]
        and custody["remote_sha256_readback"]
        and custody["local_source_revalidated"]
        and custody["sha256"] == terminal["sha256"] == op.PINNED["m"][2]
        and custody["source"] == terminal["source"] == op.source("m")["source"]
        and not os.path.lexists(terminal["source"]),
        "lane M retirement did not return the serial slot",
    )
    return receipt


def accepted_fleet(ref):
    latest = max(
        op.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
        key=lambda p: p.stat().st_mtime_ns,
    )
    op.need(ref["path"] == str(latest), "superseded fleet")
    fleet = op.bound(ref)
    sampled = datetime.fromisoformat(fleet["sampled_at_utc"]).timestamp()
    op.need(
        0 <= time.time() - sampled <= 1900
        and fleet["resource_credit_bytes"] == 0
        and fleet["all_reservation_ending_bytes"] == 0
        and fleet["all_active_status_reports_authenticated_readback"],
        "stale or incomplete fleet",
    )
    row, cursor = fleet, ref
    while cursor["sha256"] != FLEET:
        prev = row["previous_Root_operational_review"]
        predecessor = op.bound(prev)
        op.need(
            datetime.fromisoformat(predecessor["sampled_at_utc"])
            < datetime.fromisoformat(row["sampled_at_utc"]),
            "fleet does not descend from the accepted four-owner census",
        )
        row, cursor = predecessor, prev
    return fleet


def active_units(*patterns):
    text = op.consumers.system(
        "list-units",
        "--plain",
        "--no-legend",
        "--type=service",
        "--state=running,activating,deactivating,reloading",
        *patterns,
    )
    return {line.split()[0] for line in text.splitlines() if line.split()}


def owners(quote):
    fleet = accepted_fleet(quote["fleet"])
    rows = (
        fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"]
    )
    op.need(
        len(rows) == 4 and {r["epoch"] for r in rows} == {146, 167, 170, 172},
        "changed replay roster",
    )
    op.need(
        active_units("horizon-qualify-*") == {r["unit"]["Id"] for r in rows},
        "different active replay units",
    )
    for row in rows:
        recorded = row["unit"]
        props = op.consumers.system(
            "show",
            "--all",
            "-p",
            "Id,InvocationID,MainPID,ControlGroup,ActiveState,Job",
            recorded["Id"],
        )
        now = dict(line.split("=", 1) for line in props.splitlines())
        op.need(
            all(now[k] == recorded[k] for k in now)
            and now["ActiveState"] == "active"
            and not now["Job"]
            and re.fullmatch("[0-9a-f]{32}", now["InvocationID"])
            and now["ControlGroup"] == "/system.slice/" + now["Id"],
            "native replay actor differs from fleet",
        )
        p = Path("/proc") / now["MainPID"]
        ticks = int((p / "stat").read_text().rsplit(") ", 1)[1].split()[19])
        start = row["start_ticks"] if "start_ticks" in row else row["processes"][0][1]
        op.need(
            ticks == start
            and (p / "cgroup").read_text().strip() == "0::" + now["ControlGroup"],
            "reused replay pid",
        )


def serial_owner():
    active = active_units(
        "horizon-*park*",
        "horizon-*holding*",
        "horizon-*retire*",
        "horizon-*restore*",
        "horizon-closed186-*",
    )
    own = Path(Path("/proc/self/cgroup").read_text().strip().removeprefix("0::")).name
    if re.fullmatch(r"horizon-closed186-(park|retire|restore)-n-[0-9]+\.service", own):
        active.discard(own)
    op.need(not active, "other serial holding owner: " + str(sorted(active)))
    # Detect the native transition even when a caller used a nonstandard unit name.
    path = op.HOLD / "transition.lock"
    st = path.lstat()
    op.need(
        (st.st_dev, st.st_ino, st.st_nlink, st.st_uid) == (64512, 95818311, 1, 0),
        "holding lock changed",
    )
    ident = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
    for line in Path("/proc/locks").read_text().splitlines():
        fields = line.split()
        if ident in fields:
            op.need(
                fields[1:6] == ["FLOCK", "ADVISORY", "WRITE", str(os.getpid()), ident],
                "native holding slot occupied",
            )


def compiler_reservation():
    directory = op.BASE / "epoch168-anza-reader-build-20261127.jMydZnTw"
    launch_ref = op.fixed(
        directory / "PAIR_BUILD_LAUNCH.json",
        "eb28c90cc4285e40815b1eee2182bf29c7fa45d13edae0db84f1aaad1e008dc9",
    )
    launch = op.bound(launch_ref)
    intent, fit = op.bound(launch["intent"]), op.bound(launch["fit"])
    native, unit = launch["native"], launch["unit"]
    iid = native["InvocationID"]
    op.need(
        unit == "horizon-168-current-anza-reader-build-20261127-v1.service"
        and native["Id"] == unit
        and iid == "b0c51472c443489bac4367144fb5d85c"
        and intent["fit"] == launch["fit"]
        and fit["fits"]
        and fit["mode"] == "launch"
        and fit["new_build_image"] == 4 * op.G
        and fit["new_builder_evidence"] == fit["new_holding_evidence"] == op.META
        and fit["serial_compiler_memory"] == fit["serial_holding_memory"] == 2 * op.G
        and fit["dashboard_rotation_memory"] == DASHBOARD_RAM
        and fit["raw_holding_restore"] == op.SLOT,
        "compiler is outside the jointly funded booking",
    )
    op.fixed(
        op.PROVIDER, "a8d2139c524f06d38329cb9c7ab00ab036f26f1adbba3b3b501b365511fed471"
    )
    provider = runpy.run_path(str(op.PROVIDER))
    now = provider["props"](unit)
    terminal = None
    if now["ActiveState"] == "active":
        op.need(
            not now["Job"]
            and now["ControlPID"] == "0"
            and now["InvocationID"] == iid
            and now["MainPID"] == native["MainPID"]
            and now["ControlGroup"] == native["ControlGroup"]
            and now["MemoryMax"] == str(2 * op.G)
            and now["MemorySwapMax"] == "0"
            and now["CPUQuotaPerSecUSec"] == "1s",
            "compiler invocation, cgroup or hard limits changed",
        )
        proc = Path("/proc") / now["MainPID"]
        group = Path("/sys/fs/cgroup" + native["ControlGroup"])
        op.need(
            (proc / "cgroup").read_text().strip() == "0::" + native["ControlGroup"]
            and now["MainPID"] in (group / "cgroup.procs").read_text().split()
            and (group / "memory.max").read_text().strip() == str(2 * op.G)
            and (group / "memory.swap.max").read_text().strip() == "0"
            and (group / "cpu.max").read_text().split() == ["100000", "100000"],
            "compiler kernel reservation changed",
        )
    else:
        op.need(
            now["ActiveState"] in ("inactive", "failed")
            and not now["Job"]
            and now["MainPID"] == now["ControlPID"] == "0"
            and not now["ControlGroup"],
            "compiler did not drain",
        )
        terminal = provider["terminal"](unit, iid)
        op.need(
            terminal["invocation_id"] == iid and terminal["unit"] == unit,
            "different compiler terminal",
        )
    image = directory / "compiler.ext4"
    allocated = 0
    if os.path.lexists(image):
        st = image.lstat()
        op.need(
            image.resolve(strict=True) == image
            and (st.st_dev, st.st_ino) == (64512, 97854169)
            and (st.st_uid, st.st_gid, st.st_nlink, st.st_size) == (0, 0, 1, 4 * op.G)
            and stat.S_ISREG(st.st_mode)
            and stat.S_IMODE(st.st_mode) == 0o600,
            "compiler fixed image was replaced",
        )
        allocated = min(st.st_blocks * 512, st.st_size)
    op.need(
        terminal is not None or allocated == 4 * op.G,
        "active compiler image is not completely provisioned",
    )
    op.need(provider["props"](unit) == now, "compiler changed during price")
    return dict(
        launch=launch_ref,
        intent=launch["intent"],
        fit=launch["fit"],
        unit=unit,
        invocation=iid,
        kernel=now,
        terminal=terminal,
        image_path=str(image),
        image_inode=97854169,
        image_physically_funded_bytes=allocated,
    )


def margins(base, funded, image_allocated=0):
    op.need(
        funded["build_and_native_qualification_serial"]
        and funded["holding_and_build_may_overlap"]
        and funded["holding_serial"]
        and funded["holding_staging_bytes"] == 0
        and funded["holding_cpu_quota_micros"] == 2_000_000
        and funded["holding_memory_bytes"] == 2 * op.G
        and funded["build_cpu_quota_micros"] == 1_000_000
        and funded["build_fixed_image_bytes"] == 4 * op.G
        and funded["build_outside_allowance_bytes"] == op.META
        and funded["build_memory_bytes"] == 2 * op.G,
        "changed shared holding and build reserves",
    )
    disk = min(
        base["available_home"] - base["required_home"], base["historical_home_margin"]
    )
    op.need(
        disk == base["home_margin"]
        and base["ram_margin"] == base["available_ram"] - base["required_ram"],
        "inconsistent fleet margins",
    )
    # The live price includes both distinct 2 GiB slots. Only the dashboard is new RAM.
    # The build image and its separate evidence allowance still require disk.
    extra_home = (
        funded["build_fixed_image_bytes"] + funded["build_outside_allowance_bytes"]
    )
    ram_margin = base["ram_margin"] - DASHBOARD_RAM
    op.need(
        0 <= image_allocated <= funded["build_fixed_image_bytes"],
        "compiler image outside its fixed cap",
    )
    live_home = (
        base["available_home"] - base["required_home"] - extra_home + image_allocated
    )
    historical_home = base["historical_home_margin"] - extra_home
    return dict(
        remaining_home=min(live_home, historical_home),
        remaining_ram=0
        if ram_margin < 0
        else funded["holding_memory_bytes"] + ram_margin,
        post_reservation_ram_margin=ram_margin,
        build_home=extra_home,
        build_ram=funded["build_memory_bytes"],
        independent_control_ram=DASHBOARD_RAM,
        holding_ram_available_from_serial=funded["holding_memory_bytes"],
    )


def price():
    qualified = op.fixed(op.TOOLS / "live_price.py", PROVIDER_SHA)
    import live_price

    base = live_price.live_price()
    raw = base["raw"]
    fleet = accepted_fleet(raw["fleet"])
    aux = raw["auxiliary"]
    park = op.bound(op.fixed(op.PAID, PAID))
    op.need(
        0 <= time.time() - raw["observed"] <= 15
        and raw["phase170_first"]
        and raw["phase"] == "held"
        and raw["replacement143"] is None
        and raw["guarded_hourly_remaining"] == 64 * op.G
        and raw["joint"]["producer_allowance"] == 48 * op.G
        and raw["assembly168"]["state"] == "live"
        and base["required_home"]
        >= max(raw["assembly168"]["floor"], base["actual_170_floor"])
        + raw["assembly168_remaining_bytes"]
        + base["remaining_170_bytes"]
        and aux["park"] == op.ref(op.PAID)
        and park["serial_slot"] == fleet["active_serial_holding_authority"]
        and park["restore_overlap_bytes"]
        == aux["serial_restore_overlap_already_reserved"]
        == op.SLOT,
        "different guard floors, 143 booking, or unsupported serial slot",
    )
    build_ref = raw["joint"]["extra"]["141_build"]
    build = op.bound(build_ref)
    settlement = op.bound(raw["joint"]["extra"]["141_build_settlement"])
    op.need(
        build_ref["sha256"]
        == "a3f4f39a2a7e48b03e639932a84de59a4ed879ade4212af9d076bb85f031af65"
        and settlement["booking"] == build_ref
        and settlement["ram_reservation_release_bytes"] == 0
        and settlement["cpu_reservation_release_micros"] == 0
        and build["candidate_ram_bytes"] == 2 * op.G
        and build["candidate_cpu_quota_micros"] == 1_000_000,
        "the separately charged compiler slot is not retained",
    )
    serial_owner()
    compiler = compiler_reservation()
    rooms = margins(
        base,
        fleet["retry9_auxiliary_commitments"],
        compiler["image_physically_funded_bytes"],
    )
    return dict(
        basis=base,
        utc=time.time(),
        fleet=raw["fleet"],
        available_home=base["available_home"],
        floor=base["available_home"] - rooms["remaining_home"],
        serial_slot=op.SLOT,
        qualified_price=qualified,
        compiler=compiler,
        resource_credit_bytes=0,
        **rooms,
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=("park", "retire", "restore"))
    args = ap.parse_args()
    op.deployment(args.phase, "n")
    op.need(
        op.TOOLS == op.FOLLOWON and os.getuid() == 0 and not sys.flags.optimize,
        "use the deployed N quote",
    )
    with op.locked(op.OPLOCK):
        handback = op.serial_handoff()
        result = price()
        owners(result)
        memory = op.G if args.phase == "retire" else 2 * op.G
        disk = (
            op.bound(op.ref(op.OUT / "n/expected.json"))["single_copy_peak"]
            if args.phase == "restore"
            else op.META
        )
        fit = result["remaining_home"] >= disk and result["remaining_ram"] >= memory
        record = op.save(
            op.OUT / "n" / ("FIT_" + args.phase + "_" + str(time.time_ns()) + ".json"),
            dict(
                utc=time.time(),
                fit=fit,
                phase=args.phase,
                lane="n",
                price=result,
                prior=handback,
                disk=disk,
                ram=memory,
                swap=0,
                cpu_quota_micros=2_000_000 if args.phase == "park" else 1_000_000,
                post_phase_home=result["remaining_home"] - disk,
                post_phase_ram=result["post_reservation_ram_margin"],
                command=[
                    "/usr/bin/python3",
                    "-IB",
                    str(op.TOOLS / "dispatch.py"),
                    args.phase,
                    "n",
                ],
            ),
        )
    print(
        json.dumps(
            {
                "receipt": record,
                "fits": fit,
                "disk_margin": result["remaining_home"] - disk,
                "ram_margin": result["post_reservation_ram_margin"],
            }
        )
    )
    sys.exit(0 if fit else 3)
