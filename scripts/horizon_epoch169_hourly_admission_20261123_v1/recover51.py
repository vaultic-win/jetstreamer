"""Recover the accepted V50 fleet and its completed observer under the sole writer lock."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = BASE / "survivor172-cadence-20261122-v1"
NEW = ROOT / "tools-cold168-retry5-failed166-v51-entry146"
EVIDENCE = BASE / "epoch169-hourly-admission-20261123-v1/v51-deployment"
FLEET = BASE / "root004808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
CENSUS = BASE / "root011808-live166167170-20261128-v1/CYCLE_OBSERVATION.json"
INITIAL = BASE / "epoch162-first-hourly-completion-20261127-v2/split-v1/INITIAL_STATUS.json"
FLEET_SHA = "cf902add3783618390edc7c4dd405aa67459e549ab7730144a82aec950fd788b"
SAMPLE_SHA = "0cdbcac9a70ba35d470a7fdfa509891137ad55a8f902c4e65f04b9671c2d561f"
CENSUS_SHA = "dfceded53e15fb834218a68fdd8599f749eaa474df98ceafa2154cc08949a37d"
INITIAL_SHA = "8a8d84ed75e4e7ec0ae99b50a8306442a611ba26e235084a60adae70b4941c4c"
V50_REBOUND = "76e9bad312e85015599a9fd6025284677e0b713718f424d30140adb504190d2d"
RETRY = "35db41427652404f9fdac2788eeb53b1"
INITIAL_ACTOR = "e08ac6700a714ea0bf2d08a40516fc7e"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def load(package_sha):
    seal = NEW / "deployment-seal-receipt.json"
    require(os.geteuid() == 0 and Path(__file__).resolve() == NEW/"recover51.py", "unexpected V51 entry")
    require(seal.resolve() == seal and seal.stat().st_uid == 0 and not seal.stat().st_mode & 0o222
            and hashlib.sha256(seal.read_bytes()).hexdigest() == package_sha, "changed V51 package")
    manifest = json.loads(seal.read_bytes())
    require(manifest["destination"] == str(NEW), "moved V51 package")
    for item in manifest["members"]:
        path = NEW / item["name"]
        meta = path.lstat()
        require(path.parent == NEW and path.resolve() == path and stat.S_ISREG(meta.st_mode)
                and meta.st_uid == 0 and meta.st_nlink == 1 and not meta.st_mode & 0o222
                and meta.st_size == item["bytes"] and stat.S_IMODE(meta.st_mode) == int(item["mode"],8),
                "changed V51 member " + path.name)
        with path.open("rb") as file:
            require(hashlib.file_digest(file, "sha256").hexdigest() == item["sha256"], "different " + path.name)
    sys.path.insert(0, str(NEW))
    import status_cycle
    import cutover51
    return status_cycle, cutover51


def failed_owner(h, actor):
    require(actor == h.doc(h.OLD_ACTIVE, h.OLD_OWNER)["new"] and actor["program"] == str(h.OLD/"status_cycle.py"),
            "different V50 owner")
    st = h.state(h.WRITER, "InvocationID", "ActiveState", "SubState", "Result", "MainPID", "ControlPID", "Job", "ExecMainStatus")
    require(st["InvocationID"] == RETRY and st["ActiveState"] == st["SubState"] == "failed"
            and st["MainPID"] == st["ControlPID"] == "0" and st["Result"] == "exit-code"
            and st["ExecMainStatus"] == "1" and not st["Job"], "V50 is no longer failed and drained")
    proc = Path("/proc") / str(actor["pid"])
    require(not proc.exists() or int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19]) != actor["start_ticks"],
            "old writer is alive")
    def single(*fields):
        rows = h.command("/usr/bin/journalctl","-b","--no-pager","-q","-o","json",*fields).splitlines()
        require(len(rows) == 1, "missing or ambiguous V50 terminal journal record")
        return json.loads(rows[0])["__CURSOR"]
    result = {}
    for invocation, pid, message in (
        (actor["invocation_id"], actor["pid"], "FileNotFoundError: [Errno 2] No such file or directory: '" + str(INITIAL) + "'"),
        (RETRY, 551659, "ValueError: epoch 166 cadence rejoin lost its latest fleet or observer clock"),
    ):
        end = single("_PID=1","_UID=0","UNIT="+h.WRITER,"INVOCATION_ID="+invocation,
                     "COMMAND=ExecStart","EXIT_CODE=exited","EXIT_STATUS=1","MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15")
        trace = single("_SYSTEMD_UNIT="+h.WRITER,"_SYSTEMD_INVOCATION_ID="+invocation,"_PID="+str(pid),"MESSAGE="+message)
        result[invocation] = dict(exit=end, trace=trace)
    return result


def check(c, h):
    require(not h.ACTIVE.exists(), "V51 already activated")
    deaths = failed_owner(h, h.doc(h.OLD_ACTIVE,h.OLD_OWNER)["new"])
    head = h.ref(FLEET)
    require(head["sha256"] == FLEET_SHA and h.ref(CENSUS)["sha256"] == CENSUS_SHA
            and h.ref(INITIAL)["sha256"] == INITIAL_SHA, "changed V50 recovery inputs")
    fleet = c.checked(head)
    ready = c.transition_v51.ready(vars(c), head, c.entry())
    sample = ready["completed_sample"]
    require(sample and sample["sha256"] == SAMPLE_SHA and not c.timer_names()
            and c.sealed(ready["config"])["output"] == sample["path"], "wrong V50 clock or sample")
    out = c.names(c.sealed(ready["config"])["not_before_utc"])
    require(not (out["out"]/"ROOT_COMPLETE_OPERATIONAL_FLEET.json").exists(), "observation already accepted")
    stored = c.checked(h.ref(CENSUS))
    require(stored["fleet_predecessor"] == head and stored["observer"] == sample, "foreign saved census")
    actor = stored["capacity"][c.status162.FIELD]
    ref = c.initial162.baseline(type("Sample", (), {"split162": actor}), None)
    store = c.status.Storage()
    row = c.authenticated(store, 162, ref)
    require(ref == h.ref(INITIAL) and row["producer_invocation_id"] == actor["producer_invocation_id"] == INITIAL_ACTOR
            and row["after_status"]["sampled_at_utc"] > c.checked(sample)["recorded_at_utc"]
            and "162" not in fleet["complete_active_status_receipts"], "wrong split 162 event ordering")
    # V50 stopped before making any conditional status writes for this sample.
    require(not list(out["statuses"].glob("epoch-*.json")), "unexpected partial V50 status batch")
    refs = dict(fleet["complete_active_status_receipts"])
    refs["162"] = ref
    c.read_statuses(store, refs, out["statuses"])
    for epoch, binding in refs.items():
        c.authenticated(store, int(epoch), binding)
    require(set(map(int,refs)) == store.inventory()[0], "unreconciled status population")
    if h.LISTENER_RECEIPT.exists():
        listener = h.preserve143()
    else:
        prior = h.TARGET / "REENTRY_V50_REBOUND.json"
        previous = h.doc(prior,V50_REBOUND)
        live = h.listener_state(h.ORIGINAL_LISTENER)
        require(all(live[k] == previous["new"][k] for k in ("InvocationID","MainPID"))
                and previous["writer_package"] == h.member(h.OLD,h.ORIGINAL_LISTENER.name), "unrecognized 143 listener")
        listener = dict(handoff=h.ref(prior),listener=live)
    roster = h.endpoints(fleet, listener)
    require(len(roster["producers"]) == 4, "protected roster changed")
    return ready, dict(predecessor_terminals=deaths, fleet=head, observer=sample, saved_census=h.ref(CENSUS),
                       initial_162=ref, verified_statuses=refs, protected_endpoints=roster)


def save(h, path, document):
    if path.exists():
        require(h.doc(path) == document, "different saved V51 handoff " + path.name)
    else:
        h.private_write(path, (json.dumps(document,sort_keys=True)+"\n").encode(), 0o400)


def run(package_sha, apply):
    c, h = load(package_sha)
    with h.BOOKING_LOCK.open("rb") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if h.ACTIVE.exists():
            active = h.doc(h.ACTIVE)
            h.owner(active["new"],NEW)
            require(active["ready"] == h.ref(h.READY), "foreign V51 activation")
            return dict(active=h.ref(h.ACTIVE))
        ready, record = check(c,h)
        if not apply:
            return record
        listener = h.rebind_listener()
        current = h.endpoints(c.checked(record["fleet"]), listener)
        require(current == dict(record["protected_endpoints"],hourly143=listener), "roster changed during rebind")
        record["protected_endpoints"] = current
        save(h, EVIDENCE/"SAME_SAMPLE_RECOVERY.json",record)
        save(h, h.READY, ready)
        directory = h.SYSTEMD_DIRECTORY / (h.WRITER+".d")
        old = max(directory.glob("*-v50-*.conf"),key=lambda p:p.name)
        raw = old.read_bytes()
        require(raw.count(os.fsencode(h.OLD)) == 1 and h.member(h.OLD,"status_cycle.py")["sha256"] == h.ORIGINAL_SEAL,
                "unexpected V50 service definition")
        new = raw.replace(os.fsencode(h.OLD), os.fsencode(NEW))
        target = directory / ("z"+old.name.replace("-v50-","-v51-"))
        if target.exists():
            require(target.read_bytes() == new,"foreign V51 service definition")
        else:
            h.private_write(target,new,0o644)
        h.systemctl("daemon-reload")
        require(failed_owner(h,h.doc(h.OLD_ACTIVE)["new"]) == record["predecessor_terminals"]
                and str(NEW/"status_cycle.py") in h.state(h.WRITER,"ExecStart")["ExecStart"]
                and not c.timer_names(), "writer or clock changed before start")
        h.systemctl("start",h.WRITER)
        return dict(ready=h.ref(h.READY), recovery=h.ref(EVIDENCE/"SAME_SAMPLE_RECOVERY.json"), writer_started=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-sha256", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.package_sha256,args.apply), sort_keys=True))
