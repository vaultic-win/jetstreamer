"""Conditionally create and adopt the status for the issued epoch 162 split producer."""

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time
from types import SimpleNamespace

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch162-first-hourly-completion-20261127-v2"
DATA = ROOT / "split-v1"
INITIAL = DATA / "INITIAL_STATUS.json"
PENDING = DATA / "INITIAL_STATUS_PENDING.json"
RESPONSE = DATA / "INITIAL_STATUS_PUT.json"
ENROLL = ROOT / "SPLIT162_ENROLLMENT.json"
PKG = ROOT / "initial-status-tools-v1"
COMMON = RT / "prefix140-status-cadence-20261122-v1/cadence-tools"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
OPERATOR_SHA = "ca5ac887bdb0ca18b607966df05e890dbbc0ba3f73fb1112c4717ab97dc9415e"
COMMON_SHA = "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e"
ROUTE_SHA = "56d486bb0d3d054e05ee8abbcbd3f9997f1021c9fc4a7c9c8306ff4e63823ca7"
KEY = "epoch-162.epoch-status.json"
FIELDS = {"epoch", "jet_size_bytes", "elapsed_execution_millis", "estimated_remaining_millis", "sampled_at_utc", "phase"}
SCHEMA = "horizon-epoch162-split-initial-status-v1"
EVENT = "before-sign.s3.PutObject"
SLOTS = 432_000


def need(value, reason):
    if not value:
        raise ValueError(reason)


def body(status):
    return (json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_ref(path):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and not st.st_mode & 0o022 and st.st_nlink == 1, "untrusted receipt " + str(path))
    raw = path.read_bytes()
    end = path.lstat()
    need((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
         (end.st_dev, end.st_ino, len(raw), end.st_mtime_ns, end.st_ctime_ns), "changed receipt " + str(path))
    return {"path": str(path), "sha256": digest(raw)}, raw


def ref(path):
    return file_ref(path)[0]


def checked(binding):
    real, raw = file_ref(Path(binding["path"]))
    need(real == binding, "digest or path changed " + binding["path"])
    return json.loads(raw)


def validate_wire(status):
    need(set(status) == FIELDS and all(type(status[k]) is int for k in
         ("epoch", "jet_size_bytes", "elapsed_execution_millis", "estimated_remaining_millis"))
         and status["epoch"] == 162 and min(status["jet_size_bytes"], status["elapsed_execution_millis"]) >= 0
         and status["estimated_remaining_millis"] > 0 and status["phase"] in ("replay","verification","upload","readback")
         and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", status["sampled_at_utc"]),
         "invalid public epoch 162 status")
    dt.datetime.strptime(status["sampled_at_utc"], "%Y-%m-%dT%H:%M:%SZ")


def verify_proof(proof, row, enrollment, grant):
    status = proof["after_status"]
    validate_wire(status)
    model = proof["forecast"]
    progress = proof["transaction_progress"]
    if progress is not None:
        first, last = progress["first"], progress["last"]
        need(proof["private_phase"] == "worker" and progress["guard"] == proof["guard"]
             and progress["selectors"]["_SYSTEMD_INVOCATION_ID"] == row["producer_invocation_id"]
             and progress["selectors"]["_PID"] == str(row["actor"]["producer_pid"])
             and progress["selectors"]["_SYSTEMD_UNIT"] == row["actor"]["producer_unit"]
             and progress["selectors"]["_BOOT_ID"] == row["actor"]["boot_id"].replace("-","")
             and 69_984_000 <= first["slot"] < last["slot"] <= 69_991_076
             and first["transactions"] < last["transactions"]
             and 0 < first["monotonic_us"] < last["monotonic_us"] <= proof["sample_monotonic_us"]
             and progress["worker"]["pid"] > 1, "foreign or nonadvancing epoch 162 journal evidence")
    need(proof["schema"] == SCHEMA and proof["epoch"] == 162 and proof["key"] == KEY
         and proof["conditional_header"] == "If-None-Match" and proof["conditional_value"] == "*"
         and proof["previous_receipt"] is None and proof["after_sha256"] == digest(body(status))
         and proof["private162_split_held"] == row["held_owner"] and proof["private162_split_grant"] == grant
         and proof["private162_split_enrollment"] == enrollment
         and proof["producer_invocation_id"] == row["producer_invocation_id"]
         and proof["producer_pid"] == row["actor"]["producer_pid"]
         and (status["phase"] == ("replay" if proof["transaction_progress"] else "verification"))
         and status["jet_size_bytes"] == proof["archive"]["size"]
         and status["elapsed_execution_millis"] ==
         (proof["sample_monotonic_us"] - proof["exec_start_monotonic_us"]) // 1000
         and proof["exec_start_monotonic_us"] > 0
         and model["route"]["sha256"] == ROUTE_SHA and model["canonical_slots"] == SLOTS
         and model["canonical_replay_ms"] == (SLOTS * 100_000 + 142) // 143
         and model["bootstrap_ms"] == 506_272
         and model["private_remaining_ms"] == max(0, 6_300_000-status["elapsed_execution_millis"])
         and model["delivery"]["epoch"] == 162 and model["delivery"]["total_millis"] > 0
         and model["delivery"]["total_millis"] == sum(model["delivery"]["phase_milliseconds"].values())
         and model["delivery"]["observed_archive_bytes"] == status["jet_size_bytes"]
         and status["estimated_remaining_millis"] == model["private_remaining_ms"] + model["bootstrap_ms"] +
         model["canonical_replay_ms"] + model["delivery"]["total_millis"], "foreign initial epoch 162 status or forecast")


def adopted(row, previous, initial_ref, enrollment, grant, read=checked):
    initial = read(initial_ref)
    verify_proof(initial, row, enrollment, grant)
    need(initial["authenticated_readback"] is True and valid_etag(initial["after_etag"]),
         "epoch 162 initial lacks authenticated readback")
    cursor, seen = previous, set()
    while cursor is not None and cursor != initial_ref:
        need(cursor["sha256"] not in seen, "cycle in epoch 162 status history")
        seen.add(cursor["sha256"])
        current = read(cursor)
        validate_wire(current["after_status"])
        older_ref = current["previous_receipt"]
        need(older_ref is not None, "unrelated initial epoch 162 status")
        older = read(older_ref)
        need(current["epoch"] == 162 and current["key"] == KEY and current["conditional_header"] == "If-Match"
             and current["authenticated_readback"] is True and valid_etag(current["after_etag"])
             and current["after_sha256"] == digest(body(current["after_status"]))
             and current["before_etag"] == older["after_etag"] and current["before_status"] == older["after_status"]
             and current["before_sha256"] == older["after_sha256"], "foreign epoch 162 status predecessor")
        cursor = older_ref
    return previous or initial_ref


def baseline(c, previous):
    row = c.split162
    if row is None:
        need(previous is None and not INITIAL.exists(), "epoch 162 status without an actor or retained scope")
        return None
    return adopted(row, previous, ref(INITIAL), ref(ENROLL), ref(DATA/"GRANT.json"))


def valid_etag(value):
    return isinstance(value, str) and re.fullmatch(r'"[0-9a-f]{32}"', value) is not None


def conditional_create(store, raw):
    def absent(request, **_):
        need(store.pending == (KEY, "*") and request.headers["If-Match"] == "*",
             "conditional creation targeted another object")
        del request.headers["If-Match"]
        request.headers["If-None-Match"] = "*"
    hooks = store.s3.meta.events
    hooks.register_last(EVENT, absent)
    try:
        return store.put(162, "*", raw)
    finally:
        hooks.unregister(EVENT, handler=absent)


def publish(store, files, new_proof, check_actor, save):
    pending, response, final = files
    statuses, ready, archives = store.inventory()
    need(162 not in ready and 162 not in archives, "epoch 162 already has a canonical archive or sidecar")
    listed = 162 in statuses
    if final.exists():
        need(listed and pending.exists(), "previously published epoch 162 status disappeared")
        existing = checked(ref(final))
        validated = checked(ref(pending))
        check_actor(validated)
        etag, raw = store.get(162)
        need(valid_etag(etag) and existing == dict(validated, after_etag=etag, authenticated_readback=True)
             and raw == body(existing["after_status"]), "published epoch 162 status changed; use the cadence predecessor")
        return ref(final)
    if not pending.exists():
        need(not listed and not response.exists(), "foreign epoch 162 status exists before intent")
        proof = new_proof()
        check_actor(proof)
        save(pending, proof)
    proof = checked(ref(pending))
    check_actor(proof)
    raw = body(proof["after_status"])
    need(digest(raw) == proof["after_sha256"], "pending epoch 162 bytes changed")
    if not listed:
        need(not response.exists(), "acknowledged epoch 162 status disappeared")
        try:
            etag = conditional_create(store, raw)
        except Exception:
            # No second PUT. A dropped response and a failed precondition can
            # both be reconciled only by reading the exact durable intent.
            etag, observed = store.get(162)
            need(valid_etag(etag) and observed == raw, "foreign or uncertain epoch 162 creation")
        need(valid_etag(etag), "invalid epoch 162 PUT ETag")
        save(response, {"etag": etag, "pending": ref(pending)})
    etag, observed = store.get(162)
    need(valid_etag(etag) and observed == raw, "epoch 162 authenticated readback differs")
    if response.exists():
        need(checked(ref(response)) == {"etag": etag,"pending":ref(pending)}, "epoch 162 PUT/GET ETag differs")
    after, ready, archives = store.inventory()
    need(162 in after and 162 not in ready and 162 not in archives, "epoch 162 inventory changed during creation")
    save(final, dict(proof, authenticated_readback=True, after_etag=etag))
    return ref(final)


def projected_archive(layout, row):
    pid = row["actor"]["producer_pid"]
    tree = Path("/proc")/str(pid)/"root"/layout.RUN.relative_to("/")
    device = row["mounts"]["disk_device"]
    ledger = os.open(tree/"ledger", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(ledger)
        need(st.st_dev == device and (st.st_uid, st.st_gid) == (1001,1003), "foreign 162 ledger mount")
        name = "epoch-162.diagnostic.jet"
        try:
            fd = os.open(name, os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDONLY, dir_fd=ledger)
        except FileNotFoundError:
            return {"path":str(layout.RUN/"ledger"/name), "size":0, "device":device,"inode":None}
        try:
            st = os.fstat(fd)
            named = os.stat(name, dir_fd=ledger, follow_symlinks=False)
            need(stat.S_ISREG(st.st_mode) and st.st_dev == named.st_dev == device and st.st_ino == named.st_ino
                 and st.st_nlink == 1 and st.st_uid == 1001 and 0 <= st.st_size <= layout.HOME_IMAGE,
                 "foreign epoch 162 partial archive")
            return {"path":str(layout.RUN/"ledger"/name), "size":st.st_size, "device":device,"inode":st.st_ino}
        finally:
            os.close(fd)
    finally:
        os.close(ledger)


def journal_progress(unit, row):
    if not row["worker"]:
        return None
    import subprocess
    actor = row["actor"]
    selectors = {"_SYSTEMD_UNIT":unit, "_SYSTEMD_INVOCATION_ID":row["producer_invocation_id"],
                 "_PID":str(actor["producer_pid"]), "_BOOT_ID":actor["boot_id"].replace("-","")}
    raw = subprocess.check_output(["/usr/bin/journalctl","-q","--no-pager","-o","json","-n","32",
                                   "--grep=block slot [0-9]+ total_txs=", *(k+"="+v for k,v in selectors.items())],
                                  timeout=30)
    rows = []
    worker_start_us = row["worker"]["start_ticks"] * 1_000_000 // os.sysconf("SC_CLK_TCK")
    for line in raw.splitlines():
        record = json.loads(line)
        marker = re.search(r"\bblock slot (\d+) total_txs=(\d+)\b", record["MESSAGE"])
        need(all(record[k] == v for k,v in selectors.items()) and marker, "foreign epoch 162 journal marker")
        slot, tx = map(int, marker.groups())
        stamp = int(record["__MONOTONIC_TIMESTAMP"])
        need(69_984_000 <= slot <= 69_991_076, "epoch 162 marker outside its qualified interval")
        if stamp >= worker_start_us:
            rows.append({"slot":slot, "transactions":tx, "monotonic_us":stamp, "cursor":record["__CURSOR"]})
    if len(rows) < 2:
        return None
    # journalctl combines --grep and -n in reverse chronological order.
    rows.sort(key=lambda r: r["monotonic_us"])
    if any(a["slot"] > b["slot"] or a["transactions"] > b["transactions"] for a, b in zip(rows, rows[1:])):
        return None
    first, last = rows[0], rows[-1]
    if (last["monotonic_us"] <= first["monotonic_us"] or last["slot"] <= first["slot"]
        or last["transactions"] <= first["transactions"]
        or not 0 <= time.monotonic_ns()//1000 - last["monotonic_us"] <= 1800_000_000):
        return None
    return {"first":first,"last":last,"selectors":selectors,"worker":row["worker"],"guard":row["guard"]}


def modules():
    for package, expected in [(COMMON,COMMON_SHA), (ROOT/"issued-split-v1",OPERATOR_SHA), (PKG,None)]:
        p = package/"deployment-seal-receipt.json"
        seal_ref, raw = file_ref(p)
        need(expected is None or seal_ref["sha256"] == expected, "different package " + str(package))
        seal = json.loads(raw)
        need(seal["destination"] == str(package), "unexpected deployment directory")
        for member in seal["members"]:
            name = member["name"]
            if name.endswith(".py"):
                source = package/name
                need(source.parent == package and not source.lstat().st_mode & 0o222
                     and file_ref(source)[0]["sha256"] == member["sha256"], "changed module " + str(source))
    need(Path(__file__).resolve() == PKG/"initial162.py", "use the sealed epoch 162 entry")
    sys.path.insert(0,str(COMMON))
    import status
    import delivery_eta
    actor = SimpleNamespace(**runpy.run_path(str(ROOT/"issued-split-v1/status162.py")))
    return status, delivery_eta, actor


def main(mode):
    need(os.geteuid() == 0 and __debug__, "root checked entry required")
    store_module, delivery, actor = modules()
    layout = actor.api()
    route, route_ref = layout.pinned(ROOT/"static/COMPLETION_ROUTE.json", ROUTE_SHA)
    need(route["planning_slots_per_second"] == 1.43 and route["observed_bootstrap_to_first_output_seconds"] == 506.272
         and route["runtime_max_seconds"] == 6300 and route["target_slot"] == 69_991_076, "changed forecast basis")
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        def latest():
            return max(RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p:p.stat().st_mtime_ns)
        fleet_path = latest()
        fleet, fleet_ref = layout.pinned(fleet_path)
        enrollment, enrollment_ref = layout.pinned(ENROLL)
        need(enrollment["operator"]["sha256"] == OPERATOR_SHA and fleet["owner"] == "/root", "foreign status scope")
        row = actor.current(fleet)
        if mode == "check" and row is None:
            return {"issued":False, "enrollment":enrollment_ref, "fleet":fleet_ref, "initial":str(INITIAL)}
        need(row is not None and row["phase"] in ("held","bootstrap","worker"), "no live enrolled 162 producer")
        grant, grant_ref = layout.pinned(DATA/"GRANT.json")
        held = row["actor"]
        pre = layout.bound(layout.bound(held["intent"])["prestart"])
        need(grant["iid"] == row["producer_invocation_id"] and grant["held"] == row["held_owner"]
             and grant["writer"] == pre["enrollment"] == enrollment_ref and pre["fits"]
             and not grant["canonical_publication_authorized"] and layout.ALLOW.read_bytes() == grant["iid"].encode()
             and layout.bound(grant["postguard"])["held_invocation"] == grant["iid"], "foreign issued epoch 162")

        def proof():
            progress = journal_progress(layout.UNIT, row)
            archive = projected_archive(layout, row)
            props = layout.manager(layout.UNIT,"Id,ActiveState,MainPID,InvocationID,NRestarts,ExecMainStartTimestampMonotonic,Job")
            need(props["Id"] == layout.UNIT and props["MainPID"] == str(held["producer_pid"]) and props["ActiveState"] == "active"
                 and props["InvocationID"] == grant["iid"] and props["NRestarts"] == "0" and not props["Job"],
                 "unbound 162 invocation start")
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            monotonic = time.monotonic_ns()//1000
            started = int(props["ExecMainStartTimestampMonotonic"])
            elapsed = (monotonic-started)//1000
            cost = delivery.estimate(SimpleNamespace(prior={"inventory":fleet["authenticated_inventory"]}),162,archive["size"])
            model = {"route":route_ref, "canonical_slots":SLOTS, "canonical_replay_ms":(SLOTS*100_000+142)//143,
                     "private_remaining_ms":max(0,6_300_000-elapsed), "bootstrap_ms":506_272,"delivery":cost,
                     "assumption":"After this bounded diagnostic, allow a full canonical replay at the 1.43 slots/s planning rate. Serial delivery uses the authenticated neighbor and playback model."}
            remaining = model["canonical_replay_ms"] + model["private_remaining_ms"] + model["bootstrap_ms"] + cost["total_millis"]
            payload = dict(epoch=162, phase="replay" if progress else "verification", jet_size_bytes=archive["size"],
                           elapsed_execution_millis=elapsed,estimated_remaining_millis=remaining,sampled_at_utc=stamp)
            return dict(schema=SCHEMA, epoch=162,key=KEY,conditional_header="If-None-Match",conditional_value="*",
                        previous_receipt=None,private162_split_enrollment=enrollment_ref,private162_split_held=row["held_owner"],
                        private162_split_grant=grant_ref,producer_invocation_id=grant["iid"],producer_pid=held["producer_pid"],
                        producer_start_ticks=held["start_ticks"],fleet_predecessor=fleet_ref,private_phase=row["phase"],
                        guard=row["guard"],transaction_progress=progress,archive=archive,forecast=model,
                        sample_monotonic_us=monotonic,exec_start_monotonic_us=started,after_sha256=digest(body(payload)),
                        after_status=payload,archive_publication_authorized=False)

        def recheck(sample):
            actor.recheck(fleet,row)
            need(latest() == fleet_path and ref(DATA/"GRANT.json") == grant_ref and ref(ENROLL) == enrollment_ref
                 and sample["producer_start_ticks"] == held["start_ticks"], "162 status owner changed")
            verify_proof(sample,row,enrollment_ref,grant_ref)
        if mode == "check":
            sample = proof()
            recheck(sample)
            return sample
        store = store_module.Storage()
        return publish(store,(PENDING,RESPONSE,INITIAL),proof,recheck,layout.save)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("mode",choices=("check","publish"))
    os.umask(0o077)
    print(json.dumps(main(parser.parse_args().mode),sort_keys=True))
