#!/usr/bin/python3 -IB
"""Submit the sealed v5j verifier once across release of its predecessor's fixed name."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import string
import subprocess
import sys
import tempfile
import time

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
PACKAGE = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v1"
SEMANTIC = RUNTIME / "epoch145-semantic-continuity-20261121-v1"
READER = SEMANTIC / "tools-v5j/export145"
STATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state"
HANDOFF = SEMANTIC / "v5j-name-handoff"
HOME = Path("/home/sol/.jetstreamer-private")
HOLD = HOME / "r2-holding-state-dev-samjohnson-v1"
UNIT = "horizon-holding-export145-20261121-v1.service"
OLD = "afcf6cdd1ec0400ea2757f81472987b3"
IMAGE_SHA = "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4"
REVIEW_SHA = "4b8963f5490bd9dba3d9d6db521b9e9e864a28108c7b79bbe420417eefaf82e6"
START = "39f53479d3a045ac8e11786248231fbf"
BOOT = Path("/proc/sys/kernel/random/boot_id")
PROPS = ("Id,Names,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,InvocationID,"
         "MainPID,ControlPID,ControlGroup,ExecMainStatus,NRestarts,Job,Result,UnitFileState,"
         "NeedDaemonReload,Transient,TriggeredBy,Description")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path, expected=None, limit=64 << 20):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, f"indirect file {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022
                and meta.st_nlink == 1 and meta.st_size <= limit, f"untrusted file {path}")
        data = stream.read(meta.st_size + 1)
        require(len(data) == meta.st_size and meta.st_ctime_ns == os.fstat(stream.fileno()).st_ctime_ns,
                f"changed file {path}")
        require(os.path.samestat(meta, path.lstat()), f"replaced file {path}")
    digest = hashlib.sha256(data).hexdigest()
    require(expected is None or expected == digest, f"hash changed {path}")
    return data, {"path": str(path), "sha256": digest}


def bound(ref):
    return json.loads(read(ref["path"], ref["sha256"])[0])


def record(path, value):
    """A crash before link leaves no visible partial receipt. Never replace an intent."""
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pending-", delete=False) as tmp:
        name = tmp.name
        try:
            tmp.write(encoded)
            tmp.flush()
            os.fchmod(tmp.fileno(), 0o400)
            os.fsync(tmp.fileno())
            # A rename is atomic. The exclusive dispatcher flock serializes all publishers.
            require(not os.path.lexists(path), f"receipt already exists {path}")
            os.rename(name, path)
            fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if os.path.lexists(name):
                os.unlink(name)


def out(argv, **kwargs):
    return subprocess.check_output(argv, text=True, timeout=185, **kwargs)


def successors(first):
    chain = [first]
    while True:
        fleet = bound(chain[-1])
        path = Path(chain[-1]["path"])
        require(path.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json" and path.parent.parent == RUNTIME
                and fleet["owner"] == "/root" and fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1",
                "foreign fleet")
        timer = fleet["sole_next_timer"]
        match = re.fullmatch(r"horizon-observer-(root[0-9]{6}[A-Za-z0-9-]+)\.timer",
                             timer if isinstance(timer, str) else timer["unit"])
        require(match is not None, "invalid fleet successor")
        next_path = RUNTIME / match[1] / path.name
        if not os.path.lexists(next_path):
            return chain
        data, ref = read(next_path)
        require(json.loads(data)["recorded_unix_seconds"] > fleet["recorded_unix_seconds"], "stale fleet chain")
        chain.append(ref)


def original_command(review, fleet):
    launcher = review["stock_launcher"]
    source = read(launcher["path"], launcher["sha256"])[0].decode()
    line, = [line for line in source.splitlines() if line.startswith("exec systemd-run ")]
    output = HOME / "epoch145-prefix-extract-funded-20261121-v1"
    values = dict(rt=str(STATE.parent), output=str(output), pkg=str(SEMANTIC),
                  view=str(HOME / "epoch145-prefix-extract-materialized-view-20261121-v1"),
                  leaf=str(output / ".tmp36MvkN"), holding=str(HOLD / "transition.lock"),
                  image=str(READER), image_sha=IMAGE_SHA, fleet=fleet["path"], fleet_sha=fleet["sha256"])
    argv = [string.Template(arg).substitute(values) for arg in shlex.split(line)[1:]]
    expected = [fleet["path"] if a == "CURRENT_COMPLETE_FLEET_PATH" else
                fleet["sha256"] if a == "CURRENT_COMPLETE_FLEET_SHA" else a for a in review["sealed_service_argv"]]
    require(argv == expected and argv[:3] == ["systemd-run", "--quiet", "--unit=" + UNIT[:-8]], "stock argv drift")
    return argv


def generations(exit_event):
    boot = BOOT.read_text().strip().replace("-", "")
    require(boot == exit_event["_BOOT_ID"], "original boot changed")
    rows = [json.loads(row) for row in out(["/usr/bin/journalctl", "--no-pager", "-o", "json",
            "_BOOT_ID=" + boot, "_PID=1", "UNIT=" + UNIT]).splitlines()]
    original, = [row for row in rows if row["__CURSOR"] == exit_event["__CURSOR"]]
    require(all(original.get(k) == v for k, v in exit_event.items()), "original PID1 exit changed")
    after = [row for row in rows if int(row["__MONOTONIC_TIMESTAMP"]) > int(original["__MONOTONIC_TIMESTAMP"])]
    return [row for row in after if row.get("INVOCATION_ID", "") not in ("", OLD)
            or row.get("JOB_TYPE") == "start"]


def inspect_unit():
    properties = dict(line.split("=", 1) for line in out(["/usr/bin/systemctl", "show", "-p", PROPS, UNIT]).splitlines())
    require(properties["Id"] == UNIT and properties["Names"] == UNIT, "different unit name")
    return properties


def check_empty(manager):
    require(manager["MainPID"] == manager["ControlPID"] == manager["NRestarts"] == "0"
            and all(not manager[k] for k in ["Job", "ControlGroup", "DropInPaths", "TriggeredBy"]),
            "145 unit still owns a task, job or trigger")
    cg = Path("/sys/fs/cgroup/system.slice") / UNIT
    require(not cg.exists() or (cg / "cgroup.events").read_text().splitlines().count("populated 0") == 1,
            "occupied 145 cgroup")


def retained(review):
    for saved in review["retained_inputs"]:
        path = Path(saved["path"])
        m = path.lstat()
        require(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode) and
                (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns, m.st_nlink,
                 m.st_uid, m.st_gid, oct(stat.S_IMODE(m.st_mode))) ==
                tuple(saved[k] for k in ("dev", "ino", "size", "mtime_ns", "ctime_ns", "links", "uid", "gid", "modes")),
                f"retained 145 input changed {path}")
    require(not os.path.lexists(Path(review["retained_inputs"][-1]["path"]).with_name("epoch-145.jet")),
            "145 output already promoted")
    for key in ["retained_manifest", "seal", "provider"]:
        bound(review[key])
    read(READER, IMAGE_SHA)


def handbacks(review, refs):
    require(len(refs) == 2, "expected both completed holdings")
    for (label, op), ref in zip(sorted(review["holding"].items()), refs, strict=True):
        require(ref["path"] == op["completion_path"], f"different completed holding {label}")
        end = bound(ref)
        terminal = bound(end["intent"]["park_terminal"])
        require(end["intent"]["park_terminal"]["path"] == op["terminal_path"]
                and terminal["invocation_id"] == op["registration"]["invocation_id"]
                and terminal["park_plan"] == op["plan"]
                and terminal["custody"] == end["intent"]["custody"]
                and end["intent"]["source"] == op["source"] and end["intent"]["quarantine"] == op["quarantine_path"]
                and end["authenticated_custody_revalidated"] is True and end["resource_credit_bytes"] == 0
                and end["source_absent"] is True and end["quarantine_absent"] is True
                and not any(os.path.lexists(op[k]) for k in ("source", "quarantine_path")),
                f"incomplete physical handback {label}")
        bound(terminal["custody"])


@contextmanager
def holding():
    path = HOLD / "transition.lock"
    with os.fdopen(os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK), "rb+") as stream:
        m = os.fstat(stream.fileno())
        require((m.st_dev, m.st_ino, m.st_mode, m.st_nlink, m.st_uid, m.st_gid) ==
                (64512, 95818311, stat.S_IFREG | 0o600, 1, 0, 0) and os.path.samestat(m, path.lstat()),
                "different transition lock")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        jobs = out(["/usr/bin/systemctl", "list-jobs", "--no-pager", "--no-legend", "--plain"])
        for line in jobs.splitlines():
            unit = line.split()[1]
            require(not (unit.startswith("horizon-") and any(k in unit for k in ("holding", "held141", "-park", "-census"))),
                    f"pending serial job {unit}")
        yield


def check_quote_parent(current):
    """A detached census is available only to the lock-holding dispatcher."""
    proc = Path("/proc") / str(os.getppid())
    argv = (proc / "cmdline").read_bytes().split(b"\0")
    require(len(argv) == 5 and argv[1:3] == [b"-IB", os.fsencode(PACKAGE / "run-recovery")]
            and os.path.samestat((proc / "exe").stat(), Path("/usr/bin/python3").stat()),
            "detached quote outside the deployed dispatcher")
    locks = [os.stat(path) for path in (HOLD / "transition.lock", HANDOFF / "dispatch.lock")]
    held = set()
    for fd in (proc / "fd").iterdir():
        try:
            meta = fd.stat()
            for i, target in enumerate(locks):
                if os.path.samestat(meta, target):
                    info = (proc / "fdinfo" / fd.name).read_text()
                    if any(" FLOCK " in line and " WRITE " in line for line in info.splitlines()):
                        held.add(i)
        except FileNotFoundError:
            continue
    require(held == {0, 1}, "detached quote lacks both original locks")
    intent = json.loads(read(HANDOFF / "submission-intent.json")[0])
    require(intent["review_sha256"] == REVIEW_SHA and successors(intent["fleet"])[-1] == current,
            "detached quote outside authenticated handoff chain")


def exact_price(price, current, review):
    phase = price["phase145"]
    require(price["schema"] == "horizon-incident-replay-fit-v1" and price["epoch"] == 145
            and price["fleet"] == current and price["fits"] is True and price["candidate"] is None
            and price["complete_cpu_quota_micros"] == 64_000_000
            and price["complete_memory_plus_reserve_bytes"] == 810_658_050_048
            and price["available_HOME_bytes"] >= price["complete_required_HOME_bytes"]
            and price["available_memory_bytes"] >= price["required_available_memory_bytes"]
            and price["resource_credit_bytes"] == 0 and price["replay_launch_authorized"] is False
            and 0 <= time.time() - price["recorded_unix_seconds"] <= 180, "failed fresh detached 145 fit")
    require((phase["Id"], phase["InvocationID"], phase["ActiveState"], phase["SubState"], phase["MainPID"])
            == (UNIT, "", "inactive", "dead", "0")
            and all(phase[k] == review["failed_phase"][k] for k in
                    ("candidate", "failure", "recovery", "retry_worker", "manager_exit", "source_checkpoint_exists", "resource_credit_bytes")),
            "different historical or live 145 price evidence")
    for k in ("registered_retry11_holding", "registered_cold168_holding"):
        require(price[k]["stage"] == "completed-copy" and price[k]["resource_credit_bytes"] == 0
                and price[k]["additional_reservation_bytes"] == 0, "holding still owns a phase")


class Host:
    def __init__(self, review, dispatch_fd):
        self.review = review
        self.fd = dispatch_fd

    def state(self):
        return inspect_unit(), generations(self.review["original_pid1_exit"])

    def original(self, manager):
        check_empty(manager)
        require(all(manager[k] == v for k, v in self.review["old_manager"].items()), "different original failed unit")
        bound_ref = self.review["original_fragment"]
        read(bound_ref["path"], bound_ref["sha256"])

    def absent(self, manager):
        check_empty(manager)
        require((manager["LoadState"], manager["ActiveState"], manager["SubState"], manager["InvocationID"],
                 manager["FragmentPath"]) == ("not-found", "inactive", "dead", "", "")
                and not os.path.lexists(self.review["original_fragment"]["path"]), "145 transient has not unloaded")

    def prepare(self, fleet):
        require(successors(fleet)[-1] == fleet, "initial fleet superseded")
        retained(self.review)
        argv = original_command(self.review, fleet)
        result = json.loads(out([str(READER), "check-serial-handback", fleet["path"], fleet["sha256"], IMAGE_SHA]))
        require(result["fleet"] == fleet and result["provider"] == self.review["provider"]
                and result["worker_started"] is False and 0 <= time.time() - result["recorded_unix_seconds"] <= 180,
                "unbound original handback")
        handbacks(self.review, result["serial_handback"])
        return dict(original=self.review["original_pid1_exit"], argv=argv, fleet=fleet, preflight=result,
                    state_directories=sorted(p.name for p in STATE.iterdir()), review_sha256=REVIEW_SHA)

    def check_intent(self, intent):
        require(intent["review_sha256"] == REVIEW_SHA and intent["original"] == self.review["original_pid1_exit"]
                and intent["argv"] == original_command(self.review, intent["fleet"])
                and intent["preflight"]["fleet"] == intent["fleet"]
                and intent["preflight"]["provider"] == self.review["provider"]
                and intent["preflight"]["worker_started"] is False, "changed submission identity")

    def validate(self, intent):
        self.check_intent(intent)
        require(sorted(p.name for p in STATE.iterdir()) == intent["state_directories"], "another verifier wrote evidence")
        retained(self.review)
        handbacks(self.review, intent["preflight"]["serial_handback"])

    def reset(self):
        out(["/usr/bin/systemctl", "reset-failed", UNIT], pass_fds=(self.fd,))
        for _ in range(30):
            manager, events = self.state()
            require(not events, "another 145 submission during reset")
            if manager["LoadState"] == "not-found":
                self.absent(manager)
                return
            time.sleep(0.1)
        raise RuntimeError("145 name has not unloaded")

    def quote(self, intent):
        current = successors(intent["fleet"])[-1]
        quote = json.loads(out([str(PACKAGE / "post-stop-fit"), "145", current["path"], current["sha256"]]))
        exact_price(quote, current, self.review)
        require(successors(current)[-1] == current, "fleet changed during detached price")
        return quote

    def preflight_current(self, intent):
        # Only the same, freshly priced fleet can use the original quote. A recovered
        # orphan with a superseding fleet needs the complete detached native census.
        proof = intent["preflight"]
        return (successors(intent["fleet"])[-1] == intent["fleet"]
                and 0 <= time.time() - proof["recorded_unix_seconds"] <= 180)

    def submit(self, argv):
        # A surviving systemd-run client retains the dispatcher flock after parent death.
        # The worker itself takes the independent holding flock and repeats the full native fit.
        subprocess.run(argv, executable="/usr/bin/systemd-run", check=True, pass_fds=(self.fd,))

    def accepted(self, manager, events, intent):
        argv = intent["argv"]
        command = argv[argv.index("--") + 1:]
        # PID1 records the complete default description as the exact ExecStart argument list.
        expected = "Started " + UNIT + " - " + " ".join(command) + "."
        starts = [r for r in events if r.get("MESSAGE_ID") == START and r.get("MESSAGE") == expected]
        require(len(starts) == 1, "other or uncertain verifier submission; reconcile existing owner")
        iid = starts[0]["INVOCATION_ID"]
        require(re.fullmatch(r"[0-9a-f]{32}", iid) and iid != OLD and
                all(r.get("INVOCATION_ID") == iid for r in events), "multiple verifier generations")
        require(manager["InvocationID"] in ("", iid), "another verifier holds the name")
        if manager["MainPID"] != "0":
            process = Path("/proc") / manager["MainPID"]
            require(manager["InvocationID"] == iid and manager["ControlGroup"] == "/system.slice/" + UNIT
                    and os.path.samestat((process / "exe").stat(), READER.stat())
                    and (process / "cmdline").read_bytes().split(b"\0") == [os.fsencode(a) for a in command] + [b""]
                    and ("INVOCATION_ID=" + iid).encode() in (process / "environ").read_bytes().split(b"\0"),
                    "different running 145 command")
        return {"invocation_id": iid, "manager_start_cursor": starts[0]["__CURSOR"], "argv": argv}


def advance(host, fleet, path, lease=holding):
    manager, events = host.state()
    intent_path = path / "submission-intent.json"
    fresh = None
    if not intent_path.exists():
        require(not events, "existing successor before original preflight")
        host.original(manager)
        intent = host.prepare(fleet)
        with lease():
            current, events = host.state()
            require(not events and current == manager, "original owner changed")
            host.original(current)
            host.validate(intent)
            record(intent_path, intent)
            fresh = intent
    intent = json.loads(read(intent_path)[0])
    host.check_intent(intent)
    require(fleet in successors(intent["fleet"]), "requested fleet outside original chain")
    manager, events = host.state()
    submitted = path / "submission-attempt.json"
    if events:
        require(submitted.exists() and json.loads(read(submitted)[0]) == intent["argv"],
                "another verifier started before this dispatcher submitted")
        return host.accepted(manager, events, intent)
    if fresh is None and manager["InvocationID"] == OLD:
        host.original(manager)
        fresh = host.prepare(successors(intent["fleet"])[-1])
        require(fresh["preflight"]["serial_handback"] == intent["preflight"]["serial_handback"],
                "different original handback on retry")
        record(path / f"original-price-{time.time_ns()}.json", fresh["preflight"])
    with lease():
        manager, events = host.state()
        require(not events, "another 145 submission")
        host.validate(intent)
        if manager["InvocationID"] == OLD:
            host.original(manager)
            host.reset()
        manager, events = host.state()
        require(not events, "another 145 submission after reset")
        host.absent(manager)
        if fresh is None or not host.preflight_current(fresh):
            quote = host.quote(intent)
            host.validate(intent)
            manager, events = host.state()
            require(not events, "another 145 submission during price")
            host.absent(manager)
            require(successors(quote["fleet"])[-1] == quote["fleet"], "detached price superseded")
            record(path / f"detached-price-{time.time_ns()}.json", quote)
        if submitted.exists():
            require(json.loads(read(submitted)[0]) == intent["argv"], "different previous submission attempt")
        else:
            record(submitted, intent["argv"])
    # Release the holding flock before exec. The immutable verifier must acquire it
    # and authenticate the latest fleet before it can lease files or fork its worker.
    host.submit(intent["argv"])
    manager, events = host.state()
    return host.accepted(manager, events, intent)


def main():
    require(len(sys.argv) == 2 and os.geteuid() == 0 and sys.flags.isolated and __debug__
            and Path(__file__).resolve() == PACKAGE / "run-recovery", "use deployed run-recovery FLEET")
    _, fleet = read(Path(sys.argv[1]))
    seal = json.loads(read(PACKAGE / "deployment-seal-receipt.json")[0])
    require(seal["destination"] == str(PACKAGE) and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            and seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3",
            "unsealed handoff package")
    for member in seal["members"]:
        require(Path(member["name"]).name == member["name"], "indirect package member")
        read(PACKAGE / member["name"], member["sha256"])
    review = json.loads(read(PACKAGE / "admission-review.json", REVIEW_SHA)[0])
    HANDOFF.mkdir(mode=0o700, exist_ok=True)
    m = HANDOFF.lstat()
    require(m.st_uid == 0 and m.st_mode == stat.S_IFDIR | 0o700 and HANDOFF.resolve() == HANDOFF, "foreign handoff state")
    fd = os.open(HANDOFF / "dispatch.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = advance(Host(review, fd), fleet, HANDOFF)
        receipt = HANDOFF / "submission-result.json"
        if receipt.exists():
            require(json.loads(read(receipt)[0]) == result, "different durable submission")
        else:
            record(receipt, result)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
