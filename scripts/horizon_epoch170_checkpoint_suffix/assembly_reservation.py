"""Account for the private 168 assembler in a replay quote under the shared host lock."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

GIB = 1 << 30
MIB = 1 << 20
HOME = Path("/home/sol")
PRIVATE = HOME / ".jetstreamer-private"
BOOKINGS = PRIVATE / "epoch168-assembly-operator-20261127-v1"
OUTPUT = PRIVATE / "epoch168-private-assembly-20261127-v1/output"
ASSEMBLER = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-joint-checkpoint-reduced-run-20261126-v1/private-assembly-tools-20261127-v2/horizon-168-source-views")
ASSEMBLER_SHA = "a42303fdb80321d670534dc02ea5d117ce591b892d2f730d7b84d80e5a164829"
UNIT = "horizon-assemble-168-private-20261127-v1.service"
ARCHIVE, EVIDENCE, RAM = 128 * GIB, 64 * MIB, 8 * GIB
PEAK = ARCHIVE + EVIDENCE


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def native(unit=UNIT):
    fields = "Id,LoadState,ActiveState,SubState,Job,MainPID,ControlPID,InvocationID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec"
    p = subprocess.run(["/usr/bin/systemctl", "show", "--all", "--property=" + fields, "--", unit],
                       capture_output=True, text=True, timeout=15)
    row = dict(line.split("=", 1) for line in p.stdout.splitlines())
    need(p.returncode in (0, 4) and row.get("Id") == unit and set(fields.split(",")) <= row.keys(), "cannot identify epoch 168")
    return row


def evidence(path, expected=None, *, owner_writable=False):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_mode & (0o022 if owner_writable and expected else 0o222) == 0 and st.st_nlink == 1 and st.st_size <= 32*MIB,
         "unsealed epoch 168 evidence: " + str(path))
    data = path.read_bytes()
    ref = {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    need(expected is None or expected == ref, "epoch 168 evidence binding changed: " + str(path))
    return json.loads(data), ref


def directory_on_home(path):
    meta = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0
         and not meta.st_mode & 0o022 and meta.st_dev == HOME.stat().st_dev,
         "unexpected 168 directory custody: " + str(path))


def native_command(row, intent, pin):
    tail = ["/bin/bash", "-o", "pipefail", "-c", '"$1" --assemble-private "$2" "$3" 2>&1 | /usr/bin/head -c 33554432',
            "epoch168", str(ASSEMBLER), pin["path"], pin["sha256"]]
    argv = intent["argv"]
    need(intent["plan"] == pin and not intent["publication_authorized"] and argv[0] == "/usr/bin/systemd-run"
         and argv[argv.index("--") + 1:] == tail and "--unit=" + UNIT in argv,
         "different native 168 launch command")
    # Compare full argv elements. The native wrapper may be represented as /usr/bin/bash in /proc/exe.
    proc = Path("/proc") / row["MainPID"]
    args = (proc / "cmdline").read_bytes().split(b"\0")
    need(args == [os.fsencode(arg) for arg in tail] + [b""] and (proc / "exe").samefile(tail[0])
         and (proc / "cgroup").read_text().strip() == "0::" + row["ControlGroup"], "unbound native 168 wrapper")
    group = Path("/sys/fs/cgroup" + row["ControlGroup"])
    need((group / "memory.max").read_text().strip() == str(RAM) and (group / "memory.swap.max").read_text().strip() == "0"
         and (group / "cpu.max").read_text().split() == ["100000", "100000"]
         and row["MainPID"] in (group / "cgroup.procs").read_text().split(), "changed 168 kernel limits")
    with ASSEMBLER.open("rb") as exe:
        need(hashlib.file_digest(exe, "sha256").hexdigest() == ASSEMBLER_SHA, "changed epoch 168 assembler")


def incremental_ram(fit):
    carried = fit["same_epoch_reused_memory_bytes"]
    incremental = fit["additional_assembly_memory_bytes"]
    need(carried in (4*GIB, 6*GIB) and carried + incremental == RAM, "unknown epoch 168 RAM funding")
    if carried == 4*GIB:
        return incremental
    ref = fit["drained_comparator"]
    need(ref["sha256"] == "74c0b5a1a5a6e76a5b9bca3149daa7b8f97c5cb00a3ef20b867982f5b0b5e993"
         and fit["carried_comparator_memory_bytes"] == 2*GIB,
         "168 does not own the extra 2 GiB comparator allowance")
    comparison, _ = evidence(Path(ref["path"]), ref)
    selector = fit["carried_selector_fit"]
    need(selector["sha256"] == "fd548b83f5b1ddd09f835eb3b2b65c7355ea46fa09dd61f48c128b578f3bc4c8",
         "different source of 168 selector funding")
    original, _ = evidence(Path(selector["path"]), selector)
    basis = original["bounded_native"]
    bounded, _ = evidence(Path(basis["path"]), basis, owner_writable=True)
    settled = bounded["terminal168_compute_settlement"]
    comparator = settled["comparator"]
    unit = comparison["unit"]
    iid = comparison["invocation_id"]
    event = comparator["terminal_event"]
    need(original["reused_same_epoch_selector_bytes"] == 4*GIB
         and original["old_selector"] == settled["active_selector"] and original["old_selector"]["memory_bytes"] == 4*GIB
         and settled["preserved_comparator_memory_bytes"] == comparator["memory_bytes"] == 2*GIB
         and not settled["other_operation_can_reuse"] and comparator["phase"] == "complete"
         and unit == comparator["unit"] == event["UNIT"] and iid == comparator["invocation_id"] == event["INVOCATION_ID"]
         and iid == "328366ba244949efb9c9725df7279051" and event == comparison["pid1_event"]
         and event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" and event["_PID"] == "1" and event["_UID"] == "0"
         and original["price"]["live_quote"]["joint"]["charged_167"] == fit["replay_price"]["joint"]["charged_167"],
         "168 comparator slot belongs to a different allocation")
    now = native(unit)
    need(now["Id"] == unit and now["ActiveState"] == "inactive" and now["MainPID"] == now["ControlPID"] == "0"
         and not now["ControlGroup"] and not now["Job"], "168 comparator slot is in use again")
    return incremental


def replay_envelope(fit):
    replay = fit["replay_price"]
    q = replay["source"]
    phase = replay["phase170"]
    hourly = replay["phase143"]
    need(phase in {"between", "successor"} and hourly in {"reserved", "held", "released"}
         and q["fleet"] == fit["fleet"] and q["resource_credit_bytes"] == 0
         and fit["minimum_home_free_bytes"] >= replay["required_home"] > 0,
         "168 fit lacks an admitted shared replay envelope")
    if hourly == "released":
        peer143 = q["replacement143"]["iid"]
        need(q["replacement143"]["cap"] == 64*GIB, "different hourly cap")
    else:
        peer143 = q["held_invocation"]
        need(q["phase170"] == phase and q["candidate_home_bytes"] == 64*GIB + EVIDENCE
             and q["candidate_ram_bytes"] == 41*GIB and q["candidate_cpu_quota_micros"] == 3000000
             and not q["projection_only"] and not q["archive_publication_authorized"],
             "168 fit excludes the full 143 booking")
        peer = q["protected170"]
        need((peer["iid"] if peer else None) == replay["producer_170_invocation"],
             "different 170 guard in the 168 fit")
    peer170 = replay["producer_170_invocation"]
    need((peer143 is None if hourly == "reserved" else bool(re.fullmatch("[0-9a-f]{32}", peer143 or "")))
         and (peer170 is None and replay["producer_170_unit"] is None if phase == "between" else
              replay["producer_170_unit"] == "horizon-qualify-170-from-73746882-20261127-v1.service"
              and bool(re.fullmatch("[0-9a-f]{32}", peer170 or "")))
         and 0 <= replay["protected_143_growth_bytes"] <= 64*GIB
         and 0 <= replay["protected_170_growth_bytes"] <= 384*GIB
         and (phase != "between" or replay["protected_170_growth_bytes"] == 36*GIB),
         "foreign 143/170 bindings in the 168 fit")
    return dict(phase143=hourly, phase170=phase, invocation143=peer143, invocation170=peer170)


def physical_output(group):
    # Only the native writer's output fd can reduce the remaining archive ceiling.
    # Its temporary file can be larger than evidence, but the evidence file cannot.
    accepted = set()
    pids = (group / "cgroup.procs").read_text().split()
    for pid in pids:
        proc = Path("/proc") / pid
        try:
            if not (proc / "exe").samefile(ASSEMBLER):
                continue
            for fd in (proc / "fd").iterdir():
                name = Path(os.readlink(fd))
                if name.parent != OUTPUT or not (name.name.startswith(".tmp") or name.name == "epoch-168.jet"):
                    continue
                st = fd.stat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_size <= EVIDENCE:
                    continue
                if not fd.samefile(name) or st.st_dev != HOME.stat().st_dev:
                    continue
                flags = next(line.split()[1] for line in (proc / "fdinfo" / fd.name).read_text().splitlines()
                             if line.startswith("flags:"))
                if int(flags, 8) & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                    accepted.add((st.st_dev, st.st_ino, min(st.st_size, st.st_blocks * 512, ARCHIVE)))
        except (FileNotFoundError, ProcessLookupError):
            # Unproven allocation simply retains the full reservation.
            continue
    need(len(accepted) <= 1, "more than one large 168 output inode")
    return min((entry[2] for entry in accepted), default=0)


def terminal(iid):
    args = ["/usr/bin/journalctl", "-q", "--no-pager", "-o", "json", "_PID=1", "_UID=0",
            "UNIT=" + UNIT, "INVOCATION_ID=" + iid]
    rows = (json.loads(line) for line in subprocess.check_output(args, text=True, timeout=20).splitlines())
    return any(r.get("MESSAGE_ID") in {"7ad2d189f7e94e70a38c781354912448", "98e322203f7a4ed290d09fe03c09fe15"}
               for r in rows)


def reservation():
    row = native()
    directory_on_home(BOOKINGS)
    dirs = sorted(p for p in BOOKINGS.iterdir() if p.name.startswith("launch-"))
    live = row["ActiveState"] in {"active", "activating", "deactivating", "reloading"} or bool(row["Job"])
    if not live:
        need(row["ActiveState"] in {"inactive", "failed"} and row["MainPID"] == row["ControlPID"] == "0"
             and not row["ControlGroup"], "indeterminate epoch 168 owner")
    pending = []
    for directory in dirs:
        directory_on_home(directory)
        audit = directory / "LAUNCH_NATIVE.json"
        if audit.exists():
            owner, _ = evidence(audit)
            iid = owner["InvocationID"]
            need(owner["Id"] == UNIT and re.fullmatch("[a-f0-9]{32}", iid), "foreign 168 native receipt")
            if not live or row["InvocationID"] != iid:
                need(terminal(iid), "unsettled prior 168 invocation " + iid)
                continue
        pending.append(directory)
    if not pending and not live:
        need(native() == row, "epoch 168 changed during idle check")
        return {"state": "queued-or-drained", "unit": UNIT, "incremental_home": 0, "incremental_ram": 0,
                "floor": 0, "native": row}
    need(len(pending) == 1, "live or pending 168 lacks one bound local booking")
    directory = pending[0]
    plan, pin = evidence(directory / "PLAN.json")
    admission, ar = evidence(directory / "ADMISSION.json", plan["admission"])
    fit, fr = evidence(directory / "FIT.json", admission["capacity_basis"])
    floor = plan["minimum_home_free_bytes"]
    need(plan["schema"] == "horizon-epoch168-private-assembly-plan-v1" and plan["unit"] == admission["unit"] == UNIT
         and plan["output_directory"] == admission["output_directory"] == str(OUTPUT)
         and plan["maximum_archive_bytes"] == admission["maximum_archive_bytes"] == ARCHIVE
         and plan["evidence_allowance_bytes"] == admission["evidence_allowance_bytes"] == EVIDENCE
         and plan["memory_max_bytes"] == admission["memory_max_bytes"] == RAM
         and plan["cpu_quota_micros"] == admission["cpu_quota_micros"] == 1000000
         and 0 < floor == admission["minimum_home_free_bytes"] == fit["minimum_home_free_bytes"]
         and fit["schema"] == "horizon-epoch168-private-assembly-complete-fit-v1"
         and admission["schema"] == "horizon-epoch168-private-v4-assembly-admission-v1" and admission["epoch"] == 168
         and fit["inputs"]["assembler"] == {"path": str(ASSEMBLER), "sha256": ASSEMBLER_SHA}
         and plan["admission_expires_unix_seconds"] == admission["admission_expires_unix_seconds"]
         and 0 < plan["admission_expires_unix_seconds"] - fit["observed_unix_seconds"] <= 600
         and plan["qualification"] == admission["qualification"] and admission["all_existing_commitments_retained"]
         and fit["resource_credit_bytes"] == admission["resource_credit_bytes"] == admission["swap_bytes"] == 0
         and all(not d["publication_authorized"] for d in (plan, admission, fit))
         and fit["fits"] and admission["fits"]
         and fit["required_available_home_bytes"] == admission["required_available_home_bytes"] == floor + PEAK
         and fit["available_home_bytes"] == admission["available_home_bytes"] >= floor + PEAK
         and fit["available_memory_bytes"] == admission["available_memory_bytes"] >= fit["required_available_memory_bytes"]
         and fit["required_available_memory_bytes"] == admission["required_available_memory_bytes"] >= RAM
         and fit["complete_cpu_quota_micros"] == admission["complete_cpu_quota_micros"] <= 64000000
         and fit["same_epoch_reused_cpu_quota_micros"] == 1000000
         and admission["booked_assembly_home_bytes"] == fit["booked_assembly_home_bytes"] == PEAK
         and fit["additional_cpu_quota_micros"] == 0,
         "epoch 168 plan or capacity basis differs from its reserved envelope")
    ram = incremental_ram(fit)
    replay = replay_envelope(fit)
    outstat = OUTPUT.lstat()
    need(OUTPUT.resolve(strict=True) == OUTPUT and stat.S_ISDIR(outstat.st_mode) and outstat.st_uid == 0
         and stat.S_IMODE(outstat.st_mode) == 0o700 and outstat.st_dev == HOME.stat().st_dev, "changed 168 output custody")
    filled = 0
    if live:
        need(re.fullmatch("[a-f0-9]{32}", row["InvocationID"]) and row["ControlGroup"] == "/system.slice/" + UNIT
             and int(row["MemoryMax"]) == RAM and row["MemorySwapMax"] == "0" and row["CPUQuotaPerSecUSec"] == "1s"
             and row["ActiveState"] == "active" and not row["Job"], "active 168 does not match its sealed plan")
        intent, _ = evidence(directory / "LAUNCH_INTENT.json")
        check, _ = evidence(directory / "PLAN_CHECK.json")
        need(check["plan_sha256"] == pin["sha256"] and check["archive_bytes_written"] == 0
             and not check["publication_authorized"], "168 preflight differs from the live plan")
        native_command(row, intent, pin)
        filled = physical_output(Path("/sys/fs/cgroup" + row["ControlGroup"]))
    else:
        need(time.time() <= plan["admission_expires_unix_seconds"], "expired 168 booking without terminal receipt")
    need(native() == row, "epoch 168 owner changed during pricing")
    return {"state": "live" if live else "launching", "unit": UNIT, "plan": pin, "admission": ar, "fit": fr,
            "native": row, "floor": floor, "replay": replay, "verified_occupied_archive_bytes": filled,
            "incremental_home": PEAK - filled, "incremental_ram": ram, "incremental_cpu_micros": 0}


def apply_170(base, assembly):
    growth = base["required_home"] - base["guard_floor"]
    if assembly["state"] != "queued-or-drained":
        admitted = assembly["replay"]
        peer = base["replacement143"]
        need(not admitted["invocation143"] or (peer and peer["iid"] == admitted["invocation143"]),
             "168 holds an unreconciled 143 invocation")
        need(not admitted["invocation170"] or admitted["invocation170"] == base["priced_170_invocation"],
             "168 holds an unreconciled 170 invocation")
    # 168 enforces its absolute free-space floor on every write. Keep that
    # floor available even if 143 and 170 use all their remaining growth.
    # The 170 base floor already carries 143: add its remaining growth only
    # on the separate 168 guard constraint, never again on the 170 side.
    live_floor = assembly["floor"] + base["guarded_hourly_remaining"] if assembly["floor"] else 0
    floor = max(base["guard_floor"], live_floor) + assembly["incremental_home"]
    historical = base["historical_home_margin"] - assembly["incremental_home"]
    required = floor + growth
    margin = min(base["available_home"] - required, historical)
    ram = base["required_ram"] + assembly["incremental_ram"]
    return dict(base, assembly168=assembly, guard_floor=floor, required_home=required,
                historical_home_margin=historical, home_margin=margin, required_ram=ram,
                ram_margin=base["available_ram"]-ram, fits=base["fits"] and margin >= 0 and base["available_ram"] >= ram)
