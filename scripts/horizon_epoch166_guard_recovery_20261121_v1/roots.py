#!/usr/bin/python3 -I
"""Prepare a disjoint epoch 166 namespace and retain the last private archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

DATA = Path("/var/lib/jetstreamer/horizon_runtime_data")
OLD = DATA / "epoch166-independent-cold-20261120-v1"
STATE = DATA / "epoch166-independent-cold-recovery-20261121-v1"
LANE = Path("/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1")
RUN = LANE / "replacement-local3retry10-20261121-v1"
PREVIOUS = LANE / "replacement-local3retry9-20261110-v1"
OLD_UNIT = "horizon-qualify-independent-cold166-20261120-v1.service"
OLD_IID = "fa16ee2f14fe44ecbc37c59e197553ac"
GUARD_IID = "0198408ab9684de9a69b0f91082d495f"
STOP = OLD / "preparation/epoch166/local3retry9/guard-state/receipts"
NATIVE = OLD / "native-witness-v1/NATIVE_WITNESS_0355.json"
RECEIPT = STATE / "ROOTS_BEFORE_WITNESS.json"
TREE = PREVIOUS / "private/destination-a016b4284060be2297b683ac3b88b986ff008872d936fd6e13eb4a9564ac54ae/work/root-cohort-166-166/run-2452922-1795147000182734926"
DIGESTS = {
    NATIVE: "93bb2ffcdc20c8df19cdf73b00214e7a901c9b14a0044a2c3ee75ff8624ce099",
    STOP / "stop-completion.json": "21b336b726372a48993ac5d302671aad001f8d41791c29c75be4fd0e465ced04",
    STOP / "stop-intent.json": "21bee05b4efba487e0005f608c53ccff356131a3b0d32d93eea9ca87221ae81a",
    STOP / ("sample-" + GUARD_IID + ".json"): "227fb4824da3a485aa1432f1a0a26b046e0f372f0f58d53978b42a71137d7564",
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sealed(path):
    m = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode) and m.st_uid == 0
         and not m.st_mode & 0o022 and m.st_size <= 2 << 20, "unsafe receipt " + str(path))
    b = path.read_bytes()
    need(hashlib.sha256(b).hexdigest() == DIGESTS[path], "receipt changed " + str(path))
    return json.loads(b)


def stat_key(p):
    s = p.lstat()
    need(p.resolve(strict=True) == p, "noncanonical " + str(p))
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size,
            s.st_blocks, s.st_mtime_ns, s.st_ctime_ns]


def drains():
    intent = sealed(STOP / "stop-intent.json")
    done = sealed(STOP / "stop-completion.json")
    sample = sealed(STOP / ("sample-" + GUARD_IID + ".json"))
    need(intent["sample"] == sample and intent["reason"] == "DATA-fulfillment-observation-failed"
         and done["intent"] == str(STOP / "stop-intent.json")
         and done["producer_invocation_id"] == sample["producer_invocation_id"] == OLD_IID
         and done["terminal"]["pid"] == 0 and done["terminal"]["sub"] == "dead"
         and sample["producer"]["pid"] == 2452922 and sample["workers"][0][0] == 2453240,
         "different stopped producer or guard")
    props = subprocess.check_output(["/usr/bin/systemctl", "show", OLD_UNIT, "-p", "ActiveState",
                                     "-p", "MainPID", "-p", "ControlPID", "-p", "Job"],
                                    text=True, timeout=20)
    need(dict(line.split("=", 1) for line in props.splitlines()) ==
         dict(ActiveState="inactive", MainPID="0", ControlPID="0", Job=""),
         "original unit is transitioning or live")
    need(not (Path("/sys/fs/cgroup/system.slice") / OLD_UNIT).exists(), "original cgroup exists")
    return dict(intent=DIGESTS[STOP / "stop-intent.json"], completion=DIGESTS[STOP / "stop-completion.json"],
                sample=DIGESTS[STOP / ("sample-" + GUARD_IID + ".json")], invocation=OLD_IID)


def witness_view():
    members = sealed(NATIVE)["allocation"]["first"]
    need(len(members) == len({m["path"] for m in members}) == 12, "wrong witness set")
    paths = {Path(m["path"]) for m in members}
    paths.update(Path(a["path"]) for m in members for a in m["ancestors"])
    for p in (LANE, RUN, STATE, DATA):
        need(p not in paths and not any(f.is_relative_to(p) for f in paths),
             "staging changes a witness ancestor " + str(p))
    return {str(p): stat_key(p) for p in sorted(paths)}


def previous():
    partial = TREE / "archives/epoch-166.jet"
    m = stat_key(partial)
    need(m[:2] == [64512, 93717159] and m[6] == 69065203228, "private stopped archive differs")
    need(json.loads((TREE / "cohort-state.json").read_bytes())["status"] == "running-private",
         "private cohort changed")
    banks = sorted(p.name for p in TREE.glob("scratch/.historical-runtime/*/jetstreamer-historical-v*/unpacked/snapshots/*")
                   if p.is_dir())
    need(banks == ["71711708"], "additional rooted Bank requires reassessment")
    return dict(partial=str(partial), identity=m, retained_bootstrap_slot=71711708, last_log_slot=71971571)


def fsync_dir(p):
    fd = os.open(p, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def precreate():
    need(os.geteuid() == 0 and LANE.resolve() == LANE and DATA.resolve() == DATA,
         "requires native original host paths")
    home = Path("/home/sol").stat()
    need(LANE.stat().st_dev == DATA.stat().st_dev == home.st_dev == 64512
         and LANE.stat().st_ino == 93717034, "wrong HOME backing or original lane")
    evidence = drains()
    before = witness_view()
    custody = previous()
    if RECEIPT.exists():
        value = json.loads(RECEIPT.read_bytes())
        need(RECEIPT.lstat().st_uid == 0 and stat.S_IMODE(RECEIPT.lstat().st_mode) == 0o400
             and value["root_identity"][:2] == stat_key(RUN)[:2] and value["stopped"] == evidence
             and value["custody"] == custody, "a different successor is already staged")
        return value
    STATE.mkdir(mode=0o700, exist_ok=True)
    sm = STATE.lstat()
    need(STATE.resolve() == STATE and sm.st_uid == 0 and stat.S_IMODE(sm.st_mode) == 0o700,
         "untrusted receipt directory")
    # The parent exclusively owns the physical staging slot; reject any pre-existing unreceipted generation.
    RUN.mkdir(mode=0o700)
    for d in (RUN, RUN / "private", RUN / "output"):
        if d != RUN:
            d.mkdir(mode=0o700)
        os.chown(d, 1001, 1003)
        fsync_dir(d)
    log = RUN / "producer.log"
    with log.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        os.fchown(handle.fileno(), 1001, 1003)
        os.fsync(handle.fileno())
    fsync_dir(RUN)
    fsync_dir(LANE)
    need(before == witness_view(), "the 12 witnesses or their ancestors changed during staging")
    value = dict(schema="horizon-166-guard-stop-successor-roots-v1", observed_ns=time.time_ns(),
                 root=str(RUN), root_identity=stat_key(RUN), stopped=evidence, custody=custody,
                 protected_paths_sha256=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
                 previous_witness=DIGESTS[NATIVE], members=12, replay_launch_authorized=False)
    with RECEIPT.open("x") as out:
        os.fchmod(out.fileno(),0o400)
        json.dump(value,out,indent=2,sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    fsync_dir(STATE)
    fsync_dir(DATA)
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["inspect", "precreate"])
    mode = parser.parse_args().mode
    print(json.dumps(precreate() if mode == "precreate" else
                     dict(stopped=drains(), retained=previous(), protected_path_count=len(witness_view())),
                     sort_keys=True))
