"""Bind the Anza epoch 168 verifier and the ready-audit commitments at the fourth 170 turnover."""
from hashlib import file_digest
import os
from pathlib import Path
import re
import stat

GIB = 1 << 30
MIB = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
V168 = RT / "epoch168-exact-private-verification-20261127-v1"
ARMED = "3c82735d07fdf42e292e4b803cb144b6af47de1beb2df7b61a1d04a667c68ed7"
CONTRACT = "689937a6805ab14a1d59c430c818ba98f463596dcdca483fca0a433980a1c53f"
LISTENER = "horizon-168-private-verification-listener.service"
SLICE = Path("/sys/fs/cgroup/horizonaudit.slice")
AUDIT_POOL = RT / "ready-range-audit-20261121-v1/pool/anza-149-156/jobs"
BASELINE = {
    "horizon-r2-ready-parallel-regions-20261121-v1.service": 7,
    "horizon-r2-ready-ranges-101-300-20261121-v1.service": 4,
}
AUDIT = re.compile(r"horizon-anza-ready-audit@(149|15[0-6])\.service")
SCAN = re.compile(r"horizon-168-private-archive-verify-([0-9]+)\.service")
SERIAL = Path("/run/lock/horizon-epoch140-suffix-compiler.lock")


def check_file(core, ref, expected):
    path = Path(ref["path"])
    props = path.lstat()
    with path.open("rb") as source:
        core.need(path == expected and path.resolve(strict=True) == path and stat.S_ISREG(props.st_mode)
                  and props.st_uid == 0 and not props.st_mode & 0o222
                  and file_digest(source, "sha256").hexdigest() == ref["sha256"],
                  "private verification program or unit changed")


def limits(core, state, group, cpu, ram, tasks):
    pid = state["MainPID"]
    core.need(state["ActiveState"] == "active" and not state["Job"] and int(pid) > 0
              and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"])
              and state["ControlGroup"] == "/" + str(group.relative_to("/sys/fs/cgroup"))
              and (Path("/proc")/pid/"cgroup").read_text().strip() == "0::"+state["ControlGroup"]
              and pid in (group/"cgroup.procs").read_text().split()
              and (group/"cpu.max").read_text().split() == [str(cpu), "100000"]
              and (group/"memory.max").read_text().strip() == state["MemoryMax"] == str(ram)
              and (group/"memory.swap.max").read_text().strip() == state["MemorySwapMax"] == "0"
              and (group/"pids.max").read_text().strip() == str(tasks),
              "private verifier cgroup or limits differ from its booking")


def listener(core, armed, deployment):
    row = core.state(LISTENER)
    check_file(core, armed["systemd"], Path("/etc/systemd/system") / LISTENER)
    program = V168 / "tools-v1/dispatch.py"
    check_file(core, deployment["source"]["dispatch.py"], program)
    if row["ActiveState"] == "active":
        limits(core, row, Path("/sys/fs/cgroup/system.slice") / LISTENER, 50_000, 128*MIB, 64)
        proc = Path("/proc") / row["MainPID"]
        core.need((proc/"cmdline").read_bytes().split(b"\0") == [b"/usr/bin/python3", b"-IB", os.fsencode(program), b"watch", b""]
                  and (proc/"exe").samefile("/usr/bin/python3"), "unexpected listener entry point")
    else:
        core.need(row["ActiveState"] in ("inactive", "failed") and not row["Job"] and not row["ControlGroup"]
                  and row["MainPID"] == row["ControlPID"] == "0", "private listener is in transition")
    return row


def scanner(core, name, deployment):
    scope = deployment["scope"]
    attempt = V168 / ("attempt-" + SCAN.fullmatch(name)[1])
    row = core.state(name)
    core.need(row["ActiveState"] == "active" and not row["Job"] and (attempt/"output/STARTED.json").is_file(),
              "private scanner is in transition")
    admitted, admission = core.read(attempt/"ADMISSION.json")
    entered, started = core.read(attempt/"output/STARTED.json")
    intent = core.read(attempt/"INTENT.json")[0]
    limits(core, row, SLICE / name, 100_000, 2*GIB, 96)
    pid = row["MainPID"]
    serial = SERIAL.lstat()
    lock_id = f"{os.major(serial.st_dev):02x}:{os.minor(serial.st_dev):02x}:{serial.st_ino}"
    rows = (line.split()[1:8] for line in Path("/proc/locks").read_text().splitlines())
    check_file(core, deployment["binary"], V168 / "tools-v1/private-archive-verify")
    core.need(intent["admission"] == entered["admission"] == admission and intent["scope"] == admitted["scope"] == entered["scope"] == scope
              and intent["unit"] == admitted["scan_unit"] == entered["scan_unit"] == name and admitted["fits"]
              and not admitted["canonical_writes"] and admitted["output"] == str(attempt/"output")
              and entered["ram_bytes"] == admitted["ram_bytes"] == 2*GIB and entered["exclusive_serial_lock"]
              and entered["invocation"] == row["InvocationID"] and entered["pid"] == int(pid)
              and intent["binary"] == deployment["binary"] and (Path("/proc")/pid/"exe").samefile(deployment["binary"]["path"])
              and stat.S_ISREG(serial.st_mode) and not serial.st_mode & 0o022 and serial.st_uid == 0 and serial.st_nlink == 1
              and ["FLOCK", "ADVISORY", "WRITE", pid, lock_id, "0", "EOF"] in rows,
              "private scanner is outside its funded serial slot")
    return dict(native=row, admission=admission, started=started, compiler_lock_inode=serial.st_ino)


def audit_roster(core, deployment):
    core.need((SLICE/"cpu.max").read_text().split() == ["1200000", "100000"]
              and (SLICE/"memory.swap.max").read_text().strip() == "0", "different audit slice")
    groups = {g.name for g in SLICE.iterdir() if g.is_dir() and (g/"cgroup.procs").read_text().strip()}
    pending = {epoch for epoch in range(149, 157) if (AUDIT_POOL / str(epoch) / "READY").is_file()}
    active = set()
    scan = None
    for name in sorted(groups):
        group = SLICE / name
        if name in BASELINE:
            core.need((group/"cpu.max").read_text().split() == [str(BASELINE[name]*100_000), "100000"],
                      "unexpected baseline audit quota")
        elif SCAN.fullmatch(name):
            core.need(scan is None, "multiple owners of the native verification slot")
            scan = scanner(core, name, deployment)
        else:
            match = AUDIT.fullmatch(name)
            core.need(match and (AUDIT_POOL/match[1]/"current/CONSUMED").is_file()
                      and (group/"cpu.max").read_text().split() == ["100000", "100000"]
                      and (group/"memory.max").read_text().strip() == str(2*GIB)
                      and (group/"memory.swap.max").read_text().strip() == "0",
                      "unrecognized audit slice owner " + name)
            active.add(int(match[1]))
    return dict(active=sorted(active), pending=sorted(pending), scanner=scan, groups=sorted(groups),
                additional_audit_ram=2*GIB*len(active | pending))


def reservation(core, funds):
    armed, armed_ref = core.read(V168 / "ARMED_1795817442140579941.json", ARMED)
    contract, contract_ref = core.read(V168 / "SCAN_CONTRACT.json", CONTRACT)
    deployment, fit = core.bound(armed["deployment"]), core.bound(armed["fit"])
    data = fit["data"]
    outside = data["room"]["extra_output_bytes"]
    extra_ram = fit["additional_listener_ram"]
    core.need(fit["fits"] and fit["private"] and data["fits"] and not armed["canonical_writes"]
              and not deployment["canonical_writes"] and not contract["publication_authorized"]
              and deployment["scope"]["sha256"] == contract["scope_sha256"] and armed["scope"]["scope"] == deployment["scope"]
              and contract["memory_max"] == funds["build_memory_bytes"] == 2*GIB
              and contract["cpu_quota_micros"] == funds["build_cpu_quota_micros"] == 1_000_000
              and contract["memory_swap_max"] == contract["working_tree_bytes"] == contract["archive_disk_growth"] == 0
              and contract["compiler_serial_lock"] == str(SERIAL) and funds["build_and_native_qualification_serial"]
              and fit["additional_disk"] == contract["evidence_limit"] == 16*MIB
              and outside == data["retained_packages"] + 128*MIB == 1_510_182_912
              and extra_ram == data["controller_ram"] == 128*MIB
              and armed["unit"]["Id"] == LISTENER and armed["unit"]["MemoryMax"] == str(extra_ram),
              "different private verification reservation")
    native = listener(core, armed, deployment)
    audits = audit_roster(core, deployment)
    core.need(core.state(LISTENER) == native, "private listener changed during the fourth-window quote")
    return dict(armed=armed_ref, fit=armed["fit"], contract=contract_ref, deployment=armed["deployment"],
                listener=native, audits=audits, retained_packages=data["retained_packages"],
                miscellaneous_home=128*MIB, listener_evidence_within_miscellaneous=fit["additional_disk"],
                additional_home=outside, additional_ram=extra_ram+audits["additional_audit_ram"],
                listener_ram=extra_ram, scanner_ram_from_serial=contract["memory_max"])


def apply(core, quote):
    fleet = core.bound(quote["fleet"])
    charge = reservation(core, fleet["retry9_auxiliary_commitments"])
    # The existing reader and producer prices fund 32 MiB of 170/holding records and
    # a separate 4 GiB compiler image. The 168 admission places its packages outside
    # those bookings. Its 16 MiB of evidence is inside its 128 MiB miscellaneous cap.
    home, ram = charge["additional_home"], charge["additional_ram"]
    core.need(quote["charged_control_evidence"] == 32*MIB and core.current_fleet()[1] == quote["fleet"],
              "complete commitments changed during the fourth-window quote")
    return dict(quote, fits=quote["fits"] and quote["home_margin"] >= home and quote["ram_margin"] >= ram,
                guard_floor=quote["guard_floor"]+home, required_home=quote["required_home"]+home,
                historical_home_margin=quote["historical_home_margin"]-home, home_margin=quote["home_margin"]-home,
                required_ram=quote["required_ram"]+ram, ram_margin=quote["ram_margin"]-ram, private_verification168=charge)
