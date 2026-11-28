"""Bind local epoch 172 archive finalization to the original worker and checkpoint."""
import hashlib
import os
from pathlib import Path
import re

import full172
import full172_completion as original
from evidence import BASE, bound, checked, durable, need

ROOT = BASE/"epoch172-current-delivery-20261121-v1"
INPUT = dict(path=str(ROOT/"ORIGINAL_INPUT_END.json"),sha256="d062d9ad0fda4e8e92dc8f37f1ea82766da6c81219c39998c87049cd48b361bd")
END = ROOT/"ORIGINAL_ARCHIVE_FINALIZATION.json"
FIELD = "current_full172_finalization"


def final_record():
    finished = checked(INPUT)
    live = checked(finished["live"])
    independent = checked(live["independent_boundary"])
    log = Path(finished["log"]["path"])
    ref = finished["records"]
    with os.fdopen(os.open(log,os.O_RDONLY|os.O_NOFOLLOW),"rb") as file:
        meta = os.fstat(file.fileno())
        need((meta.st_dev,meta.st_ino) == (live["producer_log"]["device"],live["producer_log"]["inode"])
             and meta.st_uid == 0 and meta.st_nlink == 1 and os.path.samestat(meta,log.stat()),
             "different full 172 producer log")
        raw = os.pread(file.fileno(),ref["length"],ref["offset"])
        need(hashlib.sha256(raw).hexdigest() == ref["sha256"],"different final input lines")
        offset = ref["offset"] + ref["length"]
        raw = os.pread(file.fileno(),256*1024,offset)
    lines = raw[:raw.rfind(b"\n")+1].splitlines(keepends=True)
    def one(pattern):
        hits = [(i,line,m) for i,line in enumerate(lines) if (m:=pattern.search(line))]
        need(len(hits)==1,"missing or ambiguous original full 172 finalization record")
        return hits[0]
    checkpoint = re.compile(rb" INFO +jetstreamer_node::historical_replay\] historical checkpoint slot=(\d+) bank_hash=(\w+) accounts_hash=(\w+) last_blockhash=(\w+) .* complete=true ")
    archive = re.compile(rb" INFO +jetstreamer_node::horizon\] horizon archive complete: slots=(\d+) blocks=(\d+) txs=(\d+) .* epochs=1 buckets=(\d+) bytes=(\d+) ")
    i,_,checkpoint_match = one(checkpoint)
    j,_,_ = one(re.compile(rb" INFO +jetstreamer_node\] snapshot verification complete\s*$"))
    k,_,archive_match = one(archive)
    slot,bank_hash,accounts_hash,blockhash = (b.decode() for b in checkpoint_match.groups())
    slots,blocks,transactions,buckets,size = map(int,archive_match.groups())
    need(i < j < k and int(slot) == independent["terminal_slot"] == full172.LAST and
         independent["terminal_blockhash"] == blockhash and slots == full172.LAST-full172.FIRST+1
         and 0 < blocks <= slots and transactions > 0 and buckets > 0 and size > 0,
         "different terminal checkpoint or original archive counters")
    original_file = live["native"]["open_work_archive"]
    binding = {key:original_file[key] for key in ("path","device","inode")}
    proof = b"".join(lines[:k+1])
    return dict(input_end=INPUT,admission=original.ADMISSION,first_worker=original.FIRST,live=finished["live"],
                producer_invocation_id=finished["producer_invocation_id"],epoch=172,
                expected_boundary=live["independent_boundary"],terminal_slot=int(slot),bank_hash=bank_hash,
                accounts_hash=accounts_hash,terminal_blockhash=blockhash,slots=slots,blocks=blocks,
                transactions=transactions,buckets=buckets,size=size,original_work_archive=binding,
                log=finished["log"],record_offset=offset,record_length=len(proof),
                record_sha256=hashlib.sha256(proof).hexdigest(),retained_cap_bytes=full172.CAP,
                resource_credit_bytes=0,reservation_ending_bytes=0,archive_publication_authorized=False)


def confirm_finalizing():
    from owners import ticks
    result = final_record()
    live = checked(result["live"])
    actor = full172.identity({"actual_executing_replays":[],"actual_active_bootstraps":[]})
    guard = full172.guard_view(original.ADMISSION)
    parent = live["native"]["parent"]
    old_worker = live["native"]["worker"]
    pid = parent["pid"]
    proc = Path("/proc")/str(pid)
    unit = actor["unit"]
    group = Path("/sys/fs/cgroup"+unit["ControlGroup"])
    old_pid = Path("/proc")/str(old_worker["pid"])
    need(actor["admission"] == original.ADMISSION and unit["InvocationID"] == result["producer_invocation_id"]
         and unit["MainPID"] == str(pid) and ticks(pid) == parent["start_ticks"]
         and (not old_pid.exists() or ticks(old_worker["pid"]) != old_worker["start_ticks"])
         and (group/"cgroup.procs").read_text().split() == [str(pid)] and guard["observer_config"] is None
         and guard["proof"]["timer"]["InvocationID"] == live["native"]["timer"]["InvocationID"],
         "different parent, historical worker or finalization guard")
    src = result["original_work_archive"]
    meta = Path(src["path"]).stat()
    need((meta.st_dev,meta.st_ino,meta.st_size) == (src["device"],src["inode"],result["size"])
         and any(os.path.samestat(meta,os.stat(fd)) for fd in (proc/"fd").iterdir() if fd.exists()),
         "original 172 parent does not hold its finalized work inode")
    durable(END,result)
    return dict(phase="finalizing",archive_result=bound(END),identity=actor,guard=guard)


ARCHIVE = dict(path=str(END),sha256="973e3314cf7666298920d750322675c6c0c0d42dbbf665a089681041ba97f845")
SELECTED = dict(path=str(ROOT/"observer-134808-post-replay/ACTIVE.json"),sha256="1efea101f266fabd8de292d6a388954821063b30caadc360f3e0aab9234fc0e6")
PRIOR = "historical_full172_replay_before_finalization"


def observe(fleet):
    from paired_cadence import full172_authority
    evidence = checked(ARCHIVE)
    need(evidence == final_record(), "original 172 completion records changed")
    row = full172.owned(fleet) or fleet.get(PRIOR)
    original_proof = original.preceding(dict(fleet,actual_executing_replays=[row],actual_active_bootstraps=[],
        current_full172_admission=original.ADMISSION,current_full172_post_guard_fit=row["post_guard_capacity"])) if row else None
    need(original_proof and original_proof["actor"]["producer_invocation_id"] == evidence["producer_invocation_id"]
         and original.retained_cap(original_proof) == evidence["retained_cap_bytes"],
         "unregistered original epoch 172 worker or reservation")
    route = full172_authority()
    if not (ROOT/"TERMINAL_SUCCESS.json").exists():
        need(not route.DONE.exists() and not fleet.get(route.FIELD), "lost original 172 closure")
        return confirm_finalizing()
    proof = route.inspect() if route.DONE.exists() else route.retire()
    terminal = checked(proof["terminal"])
    need(proof["admission"] == original.ADMISSION and proof["first_worker"] == original.FIRST
         and terminal["local_archive"]["size"] == evidence["size"]
         and proof["producer_invocation_id"] == evidence["producer_invocation_id"], "foreign full 172 commit")
    if route.FIELD in fleet:
        need(fleet[route.FIELD] == proof["terminal"] and fleet["full172_guard_retirement"] == proof["guard_retirement"],
             "different adopted full 172 commit")
    return dict(phase="committed",archive_result=ARCHIVE,identity=None,**proof)


def effective(config):
    rows = [r for r in config["replays"] if r["range"] == "172"]
    if not rows:
        return config
    from evidence import sealed
    active = checked(SELECTED)
    receipt = checked(active["selection"])
    projected = dict(config,replays=[r for r in config["replays"] if r["range"] != "172"])
    need(receipt["archive"] == ARCHIVE and active["retained_original_deadline"] is True
         and receipt["removed"] == checked(original.FIRST)["observer_row"] and rows == [receipt["removed"]]
         and sealed(receipt["original"]) == config and sealed(receipt["effective"]) == projected,
         "unexpected original 172 observer or clock")
    return projected


def publish(c,old,prior):
    import delivery_eta
    from evidence import utc
    local = checked(ARCHIVE)
    need(prior["phase"] in ("replay","verification") and local["size"] >= prior["jet_size_bytes"],
         "unrecognized epoch 172 status")
    age = round((c.now - utc(prior["sampled_at_utc"])).total_seconds()*1000)
    quote = delivery_eta.estimate(c,172,local["size"],committed=True)
    need(age >= 0 and quote["total_millis"] > 0,"different finalization clock")
    remaining = prior["estimated_remaining_millis"]-age
    if old.get("full172_archive_finalization") != ARCHIVE or remaining <= 0:
        remaining = quote["total_millis"]
    state = dict(prior,sampled_at_utc=c.stamp,phase="verification",jet_size_bytes=local["size"],
                 elapsed_execution_millis=prior["elapsed_execution_millis"]+age,estimated_remaining_millis=remaining)
    proof = dict(full172_archive_finalization=ARCHIVE,delivery_forecast=quote,current_repair_owner="/root",
                 producer_invocation_id=c.original172["identity"]["unit"]["InvocationID"] if c.original172["identity"] else None,
                 archive_sample=dict(path=local["original_work_archive"]["path"],size=local["size"]),
                 measured_canonical_progress=False)
    if c.original172["phase"] == "committed":
        proof.update(full172_local_commit=c.original172["terminal"],full172_guard_retirement=c.original172["guard_retirement"])
    return state,proof


def install(fleet,c,entry):
    original_row = full172.owned(c.fleet)
    if original_row:
        need(PRIOR not in fleet, "duplicated original full 172 ownership")
        fleet[PRIOR] = original_row
    fleet[FIELD] = c.original172
    entry.pop("current_replay",None)
    entry.pop("current_bootstrap",None)
    entry.update(state="verification",current_repair_owner="/root",no_live_producer_claimed=True,
                 current_status_scope="Original epoch 172 replay finished. Its archive is in local verification.")
    if c.original172["phase"] == "committed":
        for key in ("full172_local_commit","full172_guard_retirement"):
            value = c.original172["terminal" if key.endswith("commit") else "guard_retirement"]
            fleet[key] = value
            entry[key] = value
        fleet.pop("current_full172_admission",None)
        fleet.pop("current_full172_post_guard_fit",None)
