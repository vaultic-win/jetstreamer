"""Qualify and start the epoch 145 follower after the previous generation exited."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import envelope
from qualify import cmd_json, fixture, need, pathcheck

RETRY = __name__ == "__main__" and "--retry1" in sys.argv[1:]
FIRST = envelope.R / "epoch145-fixture-phase-dispatch-20261122-v1"
DIRECTORY = envelope.R / "epoch145-fixture-retry1-dispatch-20261122-v1" if RETRY else FIRST
STATE = DIRECTORY / "state"
PACKAGE = DIRECTORY / "tools"
UNIT = ("horizon-145-fixture-retry1-dispatch-20261122-v1.service" if RETRY else
        "horizon-145-fixture-phase-dispatch-20261122-v1.service")
PROBE_PREFIX = "horizon-145-retry1-sandbox-20261122-" if RETRY else "horizon-145-fixture-sandbox-20261122-"
GROUP = Path("/sys/fs/cgroup/system.slice") / UNIT
LEGACY_LOCK = envelope.OLD_DIR / "state/controller.lock"
PRED = DIRECTORY / "PREDECESSOR_DRAINED.json"
PRED_HASH = ("e292ddb3e46ff8e5fb0d0dd39bacc6bb5376ac238c4868b622ccfdb42df47b5a" if RETRY else
             "d267b6e774e26fc5c9d5b95f5845b547afbfde74f58e434b835acd63785a7f07")
LOCKS = {"controller_lock": LEGACY_LOCK}
if RETRY:
    LOCKS["recent_controller_lock"] = FIRST / "state/controller.lock"
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def checked(path, digest):
    meta = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(meta.st_mode)
         and meta.st_uid == meta.st_gid == 0 and meta.st_nlink == 1
         and not meta.st_mode & 0o022, f"unexpected evidence file {path}")
    data = path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == digest, f"changed {path}")
    return data


def manager(unit):
    keys = "Id,LoadState,ActiveState,MainPID,ControlPID,InvocationID,ControlGroup,NRestarts,Job,Triggers,TriggeredBy"
    result = subprocess.run(["systemctl", "show", unit, "-p", keys], capture_output=True, text=True)
    props = dict(line.split("=", 1) for line in result.stdout.splitlines())
    need(result.returncode in (0, 4) and props["Id"] == unit and not result.stderr, f"cannot identify {unit}")
    return props


def check_predecessors():
    witness = json.loads(checked(PRED, PRED_HASH))
    for kind in (("previous", "earlier", "earliest") if RETRY else ("previous", "earlier")):
        previous = witness[kind]
        current = manager(previous["Id"])
        # PID1 can collect a failed transient service after its receipt is captured.
        if current["LoadState"] != "not-found":
            need(current["ActiveState"] == previous["ActiveState"]
                 and current["InvocationID"] == previous["InvocationID"], "predecessor changed")
        need(current["MainPID"] == current["ControlPID"] == "0" and
             not any(current[k] for k in ("ControlGroup", "Job", "Triggers", "TriggeredBy")) and
             not (GROUP.parent / current["Id"]).exists(), "predecessor still owns work")
    for tag in ("operation_lock", *LOCKS):
        bound = witness[tag]
        p = Path(bound["path"])
        s = p.lstat()
        need(p.resolve(strict=True) == p and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
             and s.st_uid == s.st_gid == 0 and s.st_size == 0 and s.st_nlink == 1
             and (s.st_dev, s.st_ino) == (bound["device"], bound["inode"]), "original lock replaced")
    return witness


def settings():
    # The native follower opens the predecessor lock read-only. Keep the
    # original directory read-only and follow the host inode without rebinding it.
    return dict(state=STATE, previous=None)


def package(digest):
    seal = json.loads(checked(PACKAGE / "deployment-seal-receipt.json", digest))
    need(seal["sealer_sha256"] == SEALER and seal["destination"] == str(PACKAGE), "wrong dispatcher package")
    members = {row["name"]: row for row in seal["members"]}
    for name in ("follow145", "boundary-inspector"):
        need(members[name]["mode"] == "0555", f"incorrect mode for {name}")
    for name, row in members.items():
        need(Path(name).name == name and stat.S_IMODE((PACKAGE/name).lstat().st_mode) == int(row["mode"], 8),
             "deployment member differs")
        checked(PACKAGE/name, row["sha256"])


def sandbox():
    witness = check_predecessors()
    rel = Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1].lstrip("/")
    group = Path("/sys/fs/cgroup") / rel
    for name, expected in (("cpu.max", "25000 100000"), ("memory.max", "134217728"),
                           ("memory.swap.max", "0"), ("pids.max", "64")):
        need((group/name).read_text().strip() == expected, f"incorrect {name}")
    for key in ("HORIZON_ACCESS_KEY_ID", "HORIZON_SECRET_ACCESS_KEY", "HORIZON_S3_ENDPOINT"):
        need(bool(os.environ.get(key)), "missing service R2 configuration")
    for path in (STATE, envelope.BASE, envelope.STATUS, envelope.PARENT,
                 envelope.PARENT/"immutable-inputs", envelope.MASKS):
        pathcheck(path)
    for path in (LEGACY_LOCK.parent, DIRECTORY, envelope.BASE/"tools",
                 envelope.BASE/"controller", Path("/run/systemd/transient"), Path("/etc/jetstreamer")):
        need(os.statvfs(path).f_flag & os.ST_RDONLY, f"{path} must be read-only")
    for role, lock in LOCKS.items():
        need(os.statvfs(lock.parent).f_flag & os.ST_RDONLY, "previous controller directory writable")
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            meta = os.fstat(fd)
            expected = witness[role]
            need((meta.st_dev, meta.st_ino) == (expected["device"], expected["inode"]), "wrong projected lock")
        finally:
            os.close(fd)
    fixture()
    need(group.name.startswith(PROBE_PREFIX) and group.name.endswith(".service"), "unexpected qualification unit")
    return dict(service_properties=envelope.props(**settings()), predecessor=PRED_HASH, requests=0,
                unit=group.name, invocation=os.environ["INVOCATION_ID"])


def own_lock(pid, path):
    meta = path.lstat()
    dev = f"{os.major(meta.st_dev):02x}:{os.minor(meta.st_dev):02x}:{meta.st_ino}"
    expected = ["FLOCK", "ADVISORY", "WRITE", str(pid), dev, "0", "EOF"]
    return any(row.split()[1:] == expected for row in Path("/proc/locks").read_text().splitlines())


def owner(actor):
    pid = int(actor["MainPID"])
    if actor["ActiveState"] == "activating":
        return None
    need(actor["ActiveState"] == "active" and pid > 0 and actor["NRestarts"] == "0"
         and actor["ControlGroup"] == "/system.slice/" + UNIT and not actor["Job"], "unsettled dispatcher")
    proc = Path("/proc") / str(pid)
    need((proc/"cgroup").read_text().strip() == "0::" + actor["ControlGroup"] and
         (proc/"exe").samefile(PACKAGE/"follow145") and
         (proc/"cmdline").read_bytes().split(b"\0") == [os.fsencode(PACKAGE/"follow145"), b"follow-v5f", b""],
         "different dispatcher executable")
    if all(p.exists() and own_lock(pid, p) for p in (*LOCKS.values(), STATE/"controller.lock")):
        need(manager(UNIT) == actor, "dispatcher changed while inspecting its locks")
        return actor
    return None


def await_owner():
    until = time.monotonic() + 20
    while time.monotonic() < until:
        actor = manager(UNIT)
        need(actor["LoadState"] != "not-found", "dispatcher disappeared")
        current = owner(actor)
        if current:
            return current
        time.sleep(0.2)
    raise RuntimeError("inspect the existing dispatcher; original locks have not both been observed")


def check_unused_state():
    need(not any(os.path.lexists(DIRECTORY/name) for name in ("OFFER.json", "READY.json")),
         "an existing registration needs reconciliation")
    for path in STATE.iterdir():
        meta = path.lstat()
        need(path.name == "controller.lock" and stat.S_ISREG(meta.st_mode)
             and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1 and meta.st_size == 0
             and meta.st_uid == meta.st_gid == 0, "prior dispatcher state needs reconciliation")


def check_price(path, digest, inspected, witness):
    price = json.loads(checked(path, digest))
    native = price["native"]
    need(price["schema"] == "horizon-145-bootstrap-136-mirror-price-v1"
         and native["schema"] == "horizon-incident-replay-fit-v1"
         and price["semantic_worker"] == witness["semantic"]
         and native["phase145"]["invocation_id"] == inspected["original"]
         and price["fleet"] == native["fleet"] == inspected["fleet"]
         and price["mirrors_fit"] is True and native["fits"] is True
         and price["actual_mirror_writes"] == price["resource_credit_bytes"] == 0
         and price["remaining_after_mirrors_bytes"] > 0
         and 0 <= time.time() - native["recorded_unix_seconds"] < 120,
         "a fresh complete price for the current fleet and verifier is required")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sandbox", "start"))
    parser.add_argument("--retry1", action="store_true", help="select the first same-image V5F retry")
    parser.add_argument("--deployment")
    parser.add_argument("--sandbox-proof", type=Path)
    parser.add_argument("--proof-sha")
    parser.add_argument("--price", type=Path)
    parser.add_argument("--price-sha")
    args = parser.parse_args()
    need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, "run root python3 -IB")
    if args.mode == "sandbox":
        print(json.dumps(sandbox()))
        return
    need(bool(args.deployment and args.sandbox_proof and args.proof_sha), "deployment and sandbox proof are required")
    package(args.deployment)
    proof = json.loads(checked(args.sandbox_proof, args.proof_sha))
    need(proof["service_properties"] == envelope.props(**settings()) and proof["predecessor"] == PRED_HASH
         and proof["requests"] == 0, "sandbox proof differs from this launch")
    journal = subprocess.check_output(["journalctl", "--no-pager", "-o", "json",
        "INVOCATION_ID=" + proof["invocation"], "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448"])
    need(proof["unit"].startswith(PROBE_PREFIX) and any(json.loads(line).get("UNIT") == proof["unit"]
         for line in journal.splitlines()), "PID1 did not record a successful sandbox exit")
    witness = check_predecessors()
    if manager(UNIT)["LoadState"] != "not-found":
        print(json.dumps(await_owner()))
        return
    need(not GROUP.exists() and not os.path.lexists(envelope.REG), "existing dispatcher cgroup or donor registry")
    check_unused_state()
    info = cmd_json([PACKAGE/"follow145", "inspect-v5f"])
    need(info["original"] == witness["live_semantic"]["InvocationID"] and info["launch"] is False,
         "different semantic reader")
    need(args.price and args.price_sha, "supply the current complete mirror price")
    check_price(args.price, args.price_sha, info, witness)
    subprocess.run(envelope.cmd(UNIT, PACKAGE/"follow145", ["follow-v5f"], **settings()), check=True)
    print(json.dumps(await_owner()))


if __name__ == "__main__":
    main()
