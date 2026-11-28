"""Root-only staged handoff of the existing listener and writer on their original clocks."""

import fcntl
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cutover46 import (
    ACTOR_PROPS,
    ASSEMBLY,
    BASE,
    BOOKING_LOCK,
    WRITER,
    clock,
    command,
    listed,
    need,
    owner,
    private_write,
    state,
    systemctl,
)

OLD = BASE / "tools-cold168-retry5-failed166-v46-entry146-r2"
NEW = BASE / "tools-cold168-retry5-failed166-v47-entry146"
TARGET = BASE.parent / "epoch143-first-hourly-20261127-v1"
ORIGINAL_LISTENER = TARGET / "reentry-tools-v1/watch143_reentry.py"
LISTENER = "horizon-143-after168-reentry-20261127-v1.service"
LISTENER_RECEIPT = TARGET / "REENTRY_V47_REBOUND.json"
PROGRAM = NEW / "watch143_versions.py"
BOOKER = TARGET / "booking-price-v47"
READY = BASE / "FAILED166_CADENCE_V47_READY.json"
ACTIVE = BASE / "FAILED166_CADENCE_V47_ACTIVE.json"
OLD_ACTIVE = BASE / "FAILED166_CADENCE_V46_ACTIVE.json"
ORIGINAL_SEAL = "4bb23953781c66d9d221d36525f0daae6243d8d667b41bc4388b36be17bc9ea4"
OLD_OWNER = "657c9965f71dbff5478308c1c6a703bb4732855c6ac3d4b6daaa4dfa67907f4f"
ARMED = "accd593c5de9fbe4ad9dd061393678e36e51bff7ae96c4a1f825d3bcabffae64"
SYSTEMD_DIRECTORY = Path("/run/systemd/system")
NEXT = "horizon-qualify-170-from-73766969-20261127-v1.service"


def sha(path):
    import hashlib

    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def doc(path, digest=None):
    meta = path.lstat()
    need(
        path.resolve(strict=True) == path
        and meta.st_uid == 0
        and not meta.st_mode & 0o022
        and meta.st_nlink == 1
        and (not digest or sha(path) == digest),
        "changed receipt " + str(path),
    )
    return json.loads(path.read_bytes())


def ref(path):
    doc(path)
    return dict(path=str(path), sha256=sha(path))


def member(package, name):
    seal = package / "deployment-seal-receipt.json"
    value = doc(seal)
    path = package / name
    rows = [row for row in value["members"] if row["name"] == name]
    need(
        value["destination"] == str(package)
        and len(rows) == 1
        and path.resolve() == path
        and path.stat().st_uid == 0
        and not path.stat().st_mode & 0o222
        and sha(path) == rows[0]["sha256"],
        "member does not match the sealed package " + str(path),
    )
    return ref(seal)


def listener_state(program):
    props = state(
        LISTENER,
        *ACTOR_PROPS,
        "SubState",
        "ControlGroup",
        "CPUQuotaPerSecUSec",
        "MemoryMax",
        "MemorySwapMax",
        "Restart",
        "KillMode",
        "TasksMax",
    )
    need(
        props["ActiveState"] == "active"
        and props["SubState"] == "running"
        and not props["Job"]
        and props["ControlPID"] == "0"
        and props["ControlGroup"] == "/system.slice/" + LISTENER
        and (
            props["CPUQuotaPerSecUSec"],
            props["MemoryMax"],
            props["MemorySwapMax"],
            props["Restart"],
            props["KillMode"],
            props["TasksMax"],
        )
        == ("500ms", "268435456", "0", "no", "control-group", "64"),
        "143 listener lost its bounded native invocation",
    )
    pid = props["MainPID"]
    proc = Path("/proc") / pid
    need(
        (proc / "cmdline").read_bytes().split(b"\0")
        == [b"/usr/bin/python3", b"-IB", os.fsencode(program), b""]
        and (proc / "exe").samefile("/usr/bin/python3")
        and (proc / "cgroup").read_text().strip() == "0::" + props["ControlGroup"],
        "143 listener program changed",
    )
    pids = (
        (Path("/sys/fs/cgroup" + props["ControlGroup"]) / "cgroup.procs")
        .read_text()
        .split()
    )
    for child in pids:
        if child == pid:
            continue
        child_proc = Path("/proc") / child
        args = (child_proc / "cmdline").read_bytes().split(b"\0")
        need(
            (child_proc / "exe").samefile("/usr/bin/journalctl")
            and str(WRITER).encode() in args
            and ASSEMBLY.encode() in args
            and b"--follow" in args,
            "143 listener is already booking or launching",
        )
    return props


def released143():
    path = TARGET / "HELD_OWNER.json"
    if not path.exists():
        return None
    row = doc(path)
    scope = doc(TARGET / "REENTRY_WATCH_ARMED.json", ARMED)
    phase = doc(Path(scope["phase"]["path"]), scope["phase"]["sha256"])
    booking = doc(Path(row["booking"]["path"]), row["booking"]["sha256"])
    need(
        row["contract"] == phase["hourly143"]["contract"] == booking["contract"]
        and booking["native_census_enrolled"]
        and not booking["archive_publication_authorized"]
        and (TARGET / "barrier/allow").read_text() == row["producer_invocation_id"],
        "143 actor has a pending gate",
    )
    return ref(path)


def preserve143():
    actor = released143()
    if actor:
        return dict(assigned=actor)
    rebound = doc(LISTENER_RECEIPT)
    live = listener_state(PROGRAM)
    armed = doc(TARGET / "REENTRY_WATCH_ARMED.json", ARMED)
    need(
        rebound["original"]
        == dict(path=str(TARGET / "REENTRY_WATCH_ARMED.json"), sha256=ARMED)
        and rebound["phase"] == armed["phase"]
        and rebound["writer"] == dict(path=str(OLD_ACTIVE), sha256=OLD_OWNER)
        and rebound["new"]["InvocationID"] == live["InvocationID"]
        and rebound["new"]["MainPID"] == live["MainPID"]
        and rebound["writer_package"] == member(NEW, PROGRAM.name)
        and rebound["booker_package"] == member(BOOKER, "prepare143.py"),
        "V47 lost its 143 event receiver",
    )
    return dict(listener=live, handoff=ref(LISTENER_RECEIPT))


def rebind_listener():
    if released143() or LISTENER_RECEIPT.exists():
        return preserve143()
    active = doc(OLD_ACTIVE, OLD_OWNER)
    owner(active["new"], OLD)
    scope = doc(TARGET / "REENTRY_WATCH_ARMED.json", ARMED)
    phase = doc(Path(scope["phase"]["path"]), scope["phase"]["sha256"])
    need(
        phase["writer"] == ref(OLD_ACTIVE) and not ACTIVE.exists(),
        "wrong 143 authority before rebind",
    )
    pkg = member(NEW, PROGRAM.name)
    book = member(BOOKER, "prepare143.py")
    need(
        json.loads(command("/usr/bin/python3", "-IB", PROGRAM, "--check-entry"))[
            "writer"
        ]
        == ref(OLD_ACTIVE),
        "new listener cannot follow the original writer",
    )
    fit = max(
        TARGET.glob("WRITER_BOOKING_FIRST_HOURLY*.json"),
        key=lambda p: p.stat().st_mtime_ns,
    )
    need(doc(fit)["latest_start_unix_seconds"] < time.time(), "unconsumed 143 booking")
    dropin = SYSTEMD_DIRECTORY / (LISTENER + ".d") / "90-v46-v47-listener.conf"
    definition = (
        f"[Service]\nExecStart=\nExecStart=/usr/bin/python3 -IB {PROGRAM}\n".encode()
    )
    # The listener's durable source event is re-queried on each startup. A restart
    # adopts the same transient unit, with no second booking or listener scope.
    live = state(LISTENER, "ActiveState", "MainPID", "InvocationID")
    old = None
    if live["InvocationID"] == scope["listener"]["InvocationID"]:
        old = listener_state(ORIGINAL_LISTENER)
        need(
            old["MainPID"] == scope["listener"]["MainPID"]
            and scope["package"]
            == member(ORIGINAL_LISTENER.parent, ORIGINAL_LISTENER.name),
            "different V46 listener",
        )
    else:
        need(
            dropin.is_file() and dropin.read_bytes() == definition,
            "a different native 143 listener is running",
        )
    if dropin.exists():
        need(dropin.read_bytes() == definition, "foreign listener drop-in")
    else:
        dropin.parent.mkdir(mode=0o755, exist_ok=True)
        private_write(dropin, definition, 0o644)
    if old:
        try:
            systemctl("daemon-reload")
            need(
                str(PROGRAM) in state(LISTENER, "ExecStart")["ExecStart"]
                and listener_state(ORIGINAL_LISTENER) == old,
                "listener changed while loading its successor",
            )
        except Exception:
            dropin.unlink()
            systemctl("daemon-reload")
            raise
        systemctl("restart", LISTENER)
    elif live["ActiveState"] in ("inactive", "failed"):
        frozen = state(LISTENER, "MainPID", "ControlPID", "Job", "ExecStart")
        need(
            frozen["MainPID"] == frozen["ControlPID"] == "0"
            and not frozen["Job"]
            and str(PROGRAM) in frozen["ExecStart"],
            "143 listener did not drain through the staged rebind",
        )
        systemctl("start", LISTENER)
    new = listener_state(PROGRAM)
    need(
        new["InvocationID"] != scope["listener"]["InvocationID"],
        "listener failed to rebind",
    )
    report = dict(
        original=ref(TARGET / "REENTRY_WATCH_ARMED.json"),
        new=new,
        phase=scope["phase"],
        writer_package=pkg,
        booker_package=book,
        writer=ref(OLD_ACTIVE),
        producer_mutations=False,
    )
    private_write(
        LISTENER_RECEIPT, (json.dumps(report, sort_keys=True) + "\n").encode(), 0o400
    )
    return preserve143()


def endpoints(fleet):
    actual = listed("service", "running,activating,deactivating", "horizon-qualify-*")
    expected = {
        row["unit"]["Id"]: row["unit"]
        for row in fleet["actual_executing_replays"]
        + fleet["actual_active_private_diagnostics"]
    }
    need(
        actual == set(expected) and NEXT not in actual,
        "protected replay roster changed",
    )
    owners = {unit: state(unit, *ACTOR_PROPS) for unit in actual}
    for name, live in owners.items():
        need(
            all(
                live[k] == expected[name][k]
                for k in ("Id", "InvocationID", "MainPID", "ActiveState")
            )
            and not live["Job"],
            "protected owner changed " + name,
        )
    assembly = state(ASSEMBLY, *ACTOR_PROPS)
    phase = doc(TARGET / "PHASE_170_FIRST_168_LIVE.json")
    if assembly["ActiveState"] == "active":
        need(
            assembly["InvocationID"] == phase["assembly168"]["invocation_id"]
            and not assembly["Job"],
            "foreign active 168 assembly",
        )
    else:
        need(
            assembly["ActiveState"] == "inactive"
            and assembly["MainPID"] == assembly["ControlPID"] == "0"
            and not assembly["Job"],
            "168 assembly is changing",
        )
    guards = {
        u: state(u, "Id", "InvocationID", "ActiveState")
        for u in listed("timer", "active", "horizon-guard-*")
    }
    return dict(
        producers=owners, assembly=assembly, guards=guards, hourly143=preserve143()
    )


def old_process(old):
    """Compare the running executable and lock even after daemon-reload staged V47."""
    live = state(WRITER, *ACTOR_PROPS, "ExecStart", "SubState")
    if live["InvocationID"] != old["invocation_id"] or live["ActiveState"] != "active":
        return False
    pid = Path("/proc") / str(old["pid"])
    held = (pid / "fd" / str(old["lock"]["fd"])).stat()
    need(
        live["MainPID"] == str(old["pid"])
        and live["SubState"] == "running"
        and not live["Job"]
        and int((pid / "stat").read_text().rsplit(") ", 1)[1].split()[19])
        == old["start_ticks"]
        and (held.st_dev, held.st_ino) == (old["lock"]["device"], old["lock"]["inode"])
        and os.fsencode(old["program"]) in (pid / "cmdline").read_bytes().split(b"\0")
        and old["program"] == str(OLD / "status_cycle.py"),
        "incumbent writer changed during handoff",
    )
    return True


def recover_stopped(proposed, old, dropin, replacement):
    """Resume the same V47 start after the incumbent has drained; keep its sample or timer."""
    need(
        READY.exists()
        and doc(READY) == proposed
        and dropin.read_bytes() == replacement
        and str(NEW / "status_cycle.py") in state(WRITER, "ExecStart")["ExecStart"],
        "no exact staged V47 transition",
    )
    parent = Path("/proc") / str(old["pid"])
    need(
        not parent.exists()
        or int((parent / "stat").read_text().rsplit(") ", 1)[1].split()[19])
        != old["start_ticks"],
        "V46 writer still present",
    )
    records = command(
        "/usr/bin/journalctl",
        "-b",
        "-q",
        "--no-pager",
        "-o",
        "json",
        "_PID=1",
        "_UID=0",
        "UNIT=" + WRITER,
        "INVOCATION_ID=" + old["invocation_id"],
        "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
    )
    evs = [json.loads(line) for line in records.splitlines()]
    need(len(evs) == 1 and evs[0]["UNIT"] == WRITER, "missing exact clean V46 exit")
    st = state(WRITER, *ACTOR_PROPS, "ExecStart")
    if st["ActiveState"] == "active":
        pid = Path("/proc") / st["MainPID"]
        need(
            st["InvocationID"] != old["invocation_id"]
            and os.fsencode(str(NEW / "status_cycle.py"))
            in (pid / "cmdline").read_bytes().split(b"\0"),
            "unexpected live writer during recovery",
        )
    else:
        need(
            st["ActiveState"] in ("inactive", "failed")
            and st["MainPID"] == st["ControlPID"] == "0"
            and not st["Job"],
            "another writer is starting",
        )
        systemctl("start", WRITER)


def cutover(path):
    proposed = doc(path)
    if ACTIVE.exists():
        selected = doc(ACTIVE)["new"]
        owner(selected, NEW)
        need(
            doc(ACTIVE)["ready"] == ref(READY) and doc(READY) == proposed,
            "different installed V47 writer",
        )
        preserve143()
        return ref(ACTIVE)
    old = doc(OLD_ACTIVE, OLD_OWNER)["new"]
    still_old = old_process(old)
    raw = path.read_bytes()
    head = proposed["fleet"]
    check = json.loads(
        command(
            "/usr/bin/python3",
            "-IB",
            NEW / "status_cycle.py",
            "--check-v47-handoff",
            head["path"],
            head["sha256"],
        )
    )
    need(
        (
            check == proposed
            or not still_old
            and proposed["completed_sample"] is None
            and check["completed_sample"] is not None
            and dict(check, completed_sample=None) == proposed
        )
        and proposed["old_owner"] == ref(OLD_ACTIVE)
        and proposed["package"] == member(NEW, "status_cycle.py"),
        "V47 handoff needs the current armed clock",
    )
    fleet = doc(Path(head["path"]), head["sha256"])
    guards = endpoints(fleet)
    timer = proposed["timer"]
    observed = None if check["completed_sample"] else clock(timer)
    if still_old:
        need(
            observed is not None,
            "let the incumbent commit its existing sample before cutover",
        )
        due = int(
            command(
                "/usr/bin/date", "-u", "-d", observed["NextElapseUSecRealtime"], "+%s"
            )
        )
        need(
            due - time.time() > 120,
            "writer handoff requires time before the armed observation",
        )
    directory = SYSTEMD_DIRECTORY / (WRITER + ".d")
    predecessor = max(
        (p for p in directory.glob("*.conf") if "-v46-" in p.name), key=lambda p: p.name
    )
    original = predecessor.read_bytes()
    need(
        original.count(os.fsencode(OLD)) == 1
        and sha(OLD / "deployment-seal-receipt.json") == ORIGINAL_SEAL,
        "different original writer definition",
    )
    dropin = directory / ("z" + predecessor.name.replace("-v46-", "-v47-"))
    replacement = original.replace(os.fsencode(OLD), os.fsencode(NEW))
    if still_old:
        if dropin.exists():
            need(dropin.read_bytes() == replacement, "different V47 writer drop-in")
        else:
            private_write(dropin, replacement, 0o644)
        try:
            systemctl("daemon-reload")
            need(
                str(NEW / "status_cycle.py") in state(WRITER, "ExecStart")["ExecStart"]
                and endpoints(fleet) == guards
                and clock(timer) == observed
                and old_process(old),
                "staged V47 changed the old roster or clock",
            )
            if READY.exists() and READY.read_bytes() != raw:
                obsolete = doc(READY)
                need(
                    obsolete["old_owner"] == ref(OLD_ACTIVE)
                    and obsolete["package"] == proposed["package"]
                    and not ACTIVE.exists()
                    and old_process(old),
                    "different pending writer",
                )
                archive = READY.with_name(
                    "V47_UNCONSUMED_READY_" + sha(READY) + ".json"
                )
                if not archive.exists():
                    private_write(archive, READY.read_bytes(), 0o400)
                need(
                    archive.read_bytes() == READY.read_bytes(),
                    "unconsumed writer receipt changed",
                )
                READY.unlink()
            if not READY.exists():
                private_write(READY, raw, 0o400)
        except Exception:
            dropin.unlink()
            systemctl("daemon-reload")
            owner(old, OLD)
            raise
        systemctl("restart", WRITER)
    else:
        recover_stopped(proposed, old, dropin, replacement)
    deadline = time.monotonic() + 20
    while not ACTIVE.exists() and time.monotonic() < deadline:
        need(
            state(WRITER, "ActiveState")["ActiveState"] != "failed",
            "V47 writer failed after durable handoff",
        )
        time.sleep(0.15)
    record = doc(ACTIVE)
    selected = record["new"]
    owner(selected, NEW)
    need(
        record["old"] == old
        and record["ready"] == ref(READY)
        and all(
            selected["lock"][key] == old["lock"][key]
            for key in ("path", "device", "inode")
        )
        and endpoints(fleet) == guards,
        "V47 lost the existing controller lock or roster",
    )
    if observed is not None:
        need(clock(timer) == observed, "V47 changed the armed observer")
    else:
        need(
            ref(Path(check["completed_sample"]["path"])) == check["completed_sample"],
            "V47 lost the completed original observation",
        )
    return ref(ACTIVE)


if __name__ == "__main__":
    need(
        Path(__file__).resolve() == NEW / "cutover47.py" and os.geteuid() == 0,
        "use the sealed handoff operator",
    )
    with BOOKING_LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1:] == ["--rebind-listener"]:
            result = rebind_listener()
        elif len(sys.argv) == 3 and sys.argv[1] == "--cutover":
            result = cutover(Path(sys.argv[2]))
        else:
            raise ValueError("use --rebind-listener or --cutover READY.json")
        print(json.dumps(result, sort_keys=True))
