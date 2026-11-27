"""Use the funded serial slot for closed lane N after M returns custody."""

from datetime import datetime
from pathlib import Path
import argparse
import json
import os
import re
import runpy
import stat
import subprocess
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


def compiler_terminal(directory, launch_ref, unit, iid, now):
    path = directory / "PAIR_BUILD_TERMINAL.json"
    terminal_ref = op.fixed(
        path, "16b0e10e77dbf48c442ca59e3bb993aab9c9cc7c38bf35a3b5ab8fc533981b20"
    )
    terminal = op.bound(terminal_ref)
    recorded = terminal["native"]
    op.need(
        terminal["launch_sha256"] == launch_ref["sha256"]
        and terminal["unit"] == unit
        and terminal["invocation"] == recorded["InvocationID"] == iid
        and recorded["Result"] == "oom-kill"
        and recorded["MainPID"] == recorded["ControlPID"] == "0"
        and not recorded["ControlGroup"]
        and terminal["image"]["path"] == str(directory / "compiler.ext4")
        and terminal["image"]["inode"] == 97854169
        and terminal["image"]["length"] == 4 * op.G
        and not terminal["remote_writes"],
        "different compiler exit",
    )
    events = subprocess.check_output(
        [
            "/usr/bin/journalctl",
            "-b",
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            "UNIT=" + unit,
            "INVOCATION_ID=" + iid,
            "MESSAGE_ID=d9b373ed55a64feb8242e02dbe79a49c",
        ],
        text=True,
        timeout=15,
    )
    matched = [json.loads(line) for line in events.splitlines()]
    op.need(
        len(matched) == 1
        and matched[0]["UNIT_RESULT"] == recorded["Result"]
        and now["InvocationID"] in ("", iid),
        "missing exact PID-1 compiler terminal",
    )
    return terminal_ref


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
        terminal = compiler_terminal(directory, launch_ref, unit, iid, now)
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


def recovery_reservation(compiler):
    # A check-only 3 GiB proposal cannot consume a second compiler slot. Once its
    # launch is issued, retain any incremental GiB even if the process has exited.
    base = Path(compiler["image_path"]).parent
    dest = base / "v2-20261127"
    unit = "horizon-168-anza-reader-recovery-v2-20261127.service"
    active = active_units("horizon-168-anza-reader-recovery-*")
    op.need(active <= {unit}, "unknown compiler recovery")
    path = dest / "BUILD_INTENT.json"
    if not path.exists():
        op.need(
            not active and not (dest / "BUILD_LAUNCH.json").exists(),
            "unregistered compiler recovery",
        )
        return dict(intent=None, native=None, maximum_memory=2 * op.G)
    intent_ref = op.ref(path)
    intent = op.bound(intent_ref)
    fit = op.bound(intent["receipt"])
    limit = fit["ram_limit"]
    op.need(
        compiler["terminal"] == intent["original"] == fit["prior"]
        and fit["phase"] == "launch"
        and fit["fits"]
        and fit["existing_fixed_image"]["inode"] == compiler["image_inode"]
        and fit["existing_fixed_image"]["length"] == 4 * op.G
        and fit["budgeted_evidence_and_holding"] == 2 * op.META
        and not fit["publication_authorized"]
        and limit in (2 * op.G, 3 * op.G, 4 * op.G)
        and intent["command"] == fit["argv"]
        and "--unit=" + unit in fit["argv"],
        "different compiler recovery reservation",
    )
    launch_path = dest / "BUILD_LAUNCH.json"
    launch_ref = op.ref(launch_path) if launch_path.exists() else None
    if active:
        op.need(launch_ref, "active compiler recovery without PID-1 launch binding")
        launch = op.bound(launch_ref)
        row = launch["native"]
        props = op.consumers.system(
            "show",
            "--all",
            "-p",
            "Id,InvocationID,MainPID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec",
            unit,
        )
        now = dict(line.split("=", 1) for line in props.splitlines())
        op.need(
            launch["intent"] == intent_ref
            and launch["fit"] == intent["receipt"]
            and now["Id"] == row["Id"] == unit
            and now["InvocationID"] == row["InvocationID"]
            and now["MainPID"] == row["MainPID"]
            and now["ControlGroup"] == row["ControlGroup"]
            and now["MemoryMax"] == str(limit)
            and now["MemorySwapMax"] == "0"
            and now["CPUQuotaPerSecUSec"] == "1s",
            "compiler recovery exceeds its secured reservation",
        )
    return dict(intent=intent_ref, native=launch_ref, maximum_memory=limit)


def repeated_serial_slot(raw, funded):
    # Recover the actual native peak inherited by 167. Its auxiliary phase peak
    # already contains the same 2 GiB holding reservation charged again by 170.
    ledger_ref = op.fixed(
        op.RT / "epoch172-full-half-core-20261120-v1/POST_GUARD_CAPACITY.json",
        "e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb",
    )
    ledger = op.bound(ledger_ref)
    aux = ledger["native_inputs"]["auxiliary"]
    older = aux["retained_bookings"]
    original = op.bound(ledger["fleet"])
    serial = funded["receipt_bindings"]["PARK_SERIAL_ADMISSION"]
    op.need(
        older == original["retry9_auxiliary_commitments"]
        and older["holding_serial"]
        and older["holding_and_build_may_overlap"]
        and older["holding_memory_bytes"] == older["build_memory_bytes"] == 2 * op.G
        and older["receipt_bindings"]["PARK_SERIAL_ADMISSION"] == serial
        and serial == op.ref(op.SCOPE)
        and op.bound(serial)["additional_memory_bytes"] == 2 * op.G
        and aux["memory_bytes"] == 6576668672
        and ledger["native_inputs"]["temporary_memory"] == 0
        and original["complete_projected_memory_bytes"]
        + 16 * op.G
        + aux["memory_bytes"]
        + 24 * op.G
        == ledger["complete_memory_plus_reserve_bytes"]
        == 810658050048,
        "original native memory peak does not contain this serial reservation",
    )
    joint = raw["joint"]
    progress = op.bound(joint["charged_167"])
    release = op.bound(progress["release"])
    intent = op.bound(release["intent"])
    post = op.bound(release["post_guard_capacity"])
    prior = intent["quote"]["exact_native_fit"]
    inherited = post["required_ram_bytes"] + prior["resident_lower_bound_bytes"]
    builder = op.bound(joint["extra"]["141_build"])
    op.need(
        release["intent"] == progress["actor"]["intent"]
        and post["required_ram_bytes"] == prior["required_available_memory_bytes"]
        and intent["quote"]["producer_memory_bytes"] == 42 * op.G
        and prior["reserved_new_selector_RAM_bytes"] == 4 * op.G
        and inherited
        == ledger["complete_memory_plus_reserve_bytes"]
        - 68 * op.G
        + 42 * op.G
        + 6 * op.G
        + 4 * op.G
        + 200 * op.M
        and builder["candidate_ram_bytes"] == 2 * op.G
        and joint["required_ram"]
        == inherited
        - joint["resident_lower_bytes"]
        + 2 * op.G
        + op.G
        + 32 * op.M
        + builder["candidate_ram_bytes"]
        + joint["charged140_ram"]
        + 31 * op.G
        and raw["auxiliary"]["park"] == op.ref(op.PAID)
        and op.bound(raw["auxiliary"]["park"])["serial_slot"] == serial,
        "170 follow-on no longer repeats the inherited holding slot",
    )
    return dict(
        same_slot=serial,
        inherited_ledger=ledger_ref,
        basis167=release["post_guard_capacity"],
        charged_by_170=raw["auxiliary"]["park"],
        old_auxiliary_memory=aux["memory_bytes"],
        inherited_pre_residency_ram=inherited,
        repeated_serial_bytes=2 * op.G,
    )


def margins(base, funded, image_allocated=0, repeated=0):
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
    op.need(
        repeated in (0, funded["holding_memory_bytes"]), "invalid duplicate serial term"
    )
    ram_margin = base["ram_margin"] + repeated - DASHBOARD_RAM
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
    funded = fleet["retry9_auxiliary_commitments"]
    repeated = repeated_serial_slot(raw, funded)
    rooms = margins(
        base,
        funded,
        compiler["image_physically_funded_bytes"],
        repeated["repeated_serial_bytes"],
    )
    recovery = recovery_reservation(compiler)
    extra = recovery["maximum_memory"] - funded["build_memory_bytes"]
    rooms["post_reservation_ram_margin"] -= extra
    rooms["remaining_ram"] = (
        0
        if rooms["post_reservation_ram_margin"] < 0
        else funded["holding_memory_bytes"] + rooms["post_reservation_ram_margin"]
    )
    rooms["build_ram"] += extra
    return dict(
        basis=base,
        utc=time.time(),
        fleet=raw["fleet"],
        available_home=base["available_home"],
        floor=base["available_home"] - rooms["remaining_home"],
        serial_slot=op.SLOT,
        qualified_price=qualified,
        compiler=compiler,
        compiler_recovery=recovery,
        one_serial_slot=repeated,
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
