#!/usr/bin/env python3
"""Run the held full-172 session or inspect its native guard for the existing observer."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity
from profile import (ACTOR_BYTES, BASE, CAP, GIB, GUARD, GUARD_SHA, GUARD_UNIT, INPUT, LANE,
                     LOG, PACKAGE, RUN, RUNTIME, TIMER, UNIT, VMA, atomic_file, bound, checked,
                     digest, guard_argv, guard_plan, iid, native, need, payload, producer_argv,
                     record, reference, run, ticks)

INPUT_SHA = "dfb0e87467d2eeca3b17810dafe44fb202eb4a66d7ed214e83789e34f2f46c7b"
MODULE = "scripts/horizon_epoch172_half_core_20261120_v1/"
REPO = "/home/sol/workspace/jetstreamer"
LOCK = "/run/horizon-epoch171-to136-g1.operation.lock"


def git(*arguments):
    return run("/usr/bin/sudo", "-u", "sol", "--", "/usr/bin/git", "--no-replace-objects",
               "-C", REPO, *arguments, timeout=35).strip()


def provenance(seal_sha):
    seal = checked(PACKAGE / "deployment-seal-receipt.json", seal_sha)
    need(seal["destination"] == str(PACKAGE), "wrong sealed package")
    members = {i["name"]:i for i in seal["members"]}
    need(set(members) == {"session.py","profile.py","capacity.py","public_audit.py","gate",
                          "reservations","build-proof.json"}, "incomplete package")
    for name, entry in members.items():
        p = PACKAGE / name
        need(p.stat().st_uid == 0 and p.stat().st_mode & 0o222 == 0 and digest(p) == entry["sha256"],
             f"changed package member {name}")
    proof = checked(PACKAGE/"build-proof.json", members["build-proof.json"]["sha256"])
    source = proof["source_commit"]
    need(re.fullmatch("[0-9a-f]{40}", source) and proof["tests_failed"] == 0 and proof["tests_passed"] > 0,
         "invalid tested release")
    need(proof["artifacts"] == {name:members[name]["sha256"] for name in ("gate","reservations")},
         "native build differs from sealed artifacts")
    remote = "https://github.com/vaultic-win/jetstreamer.git"
    tip = git("-c","credential.helper=","ls-remote",remote,"refs/heads/account-updates").split()[0]
    try:
        git("cat-file","-e",tip+"^{commit}")
    except subprocess.CalledProcessError:
        git("-c","credential.helper=","fetch","--no-write-fetch-head","--no-tags",remote,tip)
    git("merge-base","--is-ancestor",source,tip)
    # Exclude Rust targets, deployment state and all external inputs from this source check.
    for rel, expected in proof["source_blobs"].items():
        need(re.fullmatch(r"scripts/[A-Za-z0-9_./-]+",rel) and ".." not in Path(rel).parts,
             "invalid build input")
        need(git("rev-parse", f"{source}:{rel}") == expected == git("rev-parse",f"{tip}:{rel}"),
             f"account-updates build input changed {rel}")
    required = {MODULE+n for n in ("gate.rs","session.py","profile.py","capacity.py")} | {
        "scripts/horizon_epoch169_focused_admission_20261120_v1/main.rs",
        "scripts/horizon_epoch169_focused_admission_20261120_v1/fit.rs",
        "scripts/horizon_epoch136_donor171_20261120_v1/public_audit.py"}
    need(required <= proof["source_blobs"].keys(), "release lacks required inputs")
    for n in ["session.py","profile.py","capacity.py","public_audit.py"]:
        rel = ("scripts/horizon_epoch136_donor171_20261120_v1/" if n == "public_audit.py" else MODULE) + n
        blob = (PACKAGE / n).read_bytes()
        oid = hashlib.sha1(f"blob {len(blob)}\0".encode() + blob).hexdigest()
        need(oid == proof["source_blobs"][rel], f"runtime script differs {n}")
    for commit in ["e6f48efe2749d35d6875fdd3cbd7f6f4379adf75","f07bab4fdcaeca7efcf189aa62a518eeda3f2f3b",
                   "9ee7073ec10015bd29ce11c7d9f71eeb2f8cf8fe"]:
        git("merge-base","--is-ancestor",commit,tip)
    need(digest(GUARD) == GUARD_SHA, "historical guard binary changed")
    return {"source":source,"origin":tip,"seal":seal_sha,"native":proof["artifacts"]}


def input_check():
    v = payload()
    source = checked(INPUT/"FULL_REPLAY_INPUTS.json", INPUT_SHA)
    for item in source["local_input_members"].values():
        p = Path(item["path"])
        m = p.stat()
        need(p.resolve() == p and (m.st_dev,m.st_ino,m.st_size) == (item["device"],item["inode"],item["bytes"])
             and digest(p) == item["sha256"], f"changed cached file {p}")
    for item in v["file_binds"]:
        p = Path(item["source"])
        m = p.stat()
        need(p.resolve() == p and [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns] == item["identity"]
             and digest(p) == item["sha256"], f"changed index or genesis {p}")
    seal = json.loads((Path(v["package_source"])/"deployment-seal-receipt.json").read_bytes())
    required = {"jetstreamer-node":"a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
                "jetstreamer-historical-worker-v1-5-6":"b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541",
                "preflight-172-v4.json":"aefb693dff2a917c4cd68e8be148b9b716859238f5a0b3d3583139fc212b6fa9",
                "FULL_REPLAY_INPUTS.json":INPUT_SHA}
    for item in seal["members"]:
        p = Path(v["package_source"])/item["name"]
        need(digest(p) == required.pop(item["name"]) == item["sha256"] and p.stat().st_uid == 0
             and p.stat().st_mode & 0o222 == 0, "changed normal replay package")
    need(not required, "missing normal replay package member")
    return v


def verify_sample(s, actor, plan, sha, require_worker=False):
    p = s["producer"]
    need(s.get("schema") == "jetstreamer-horizon-standalone-guard-sample-v1"
         and s["plan_sha256"] == sha and s["guard_sha256"] == GUARD_SHA and iid(s["guard_invocation_id"])
         and s["producer_invocation_id"] == plan["invocation_id"] == actor["InvocationID"] == p["invocation_id"]
         and p["pid"] == int(actor["MainPID"]) and p["cgroup"] == "/system.slice/" + UNIT
         and p["active"] == "active" and p["sub"] == "running" and p["restarts"] == 0, "guard identity")
    need(s["producer_stop_enabled"] is True and s["trip_reason"] is None and s["worker_observation_error"] is None
         and s["root_physical_observation_error"] is None and not s["bounded_measurement"]
         and not s["r2_mutations"] and not s["remote_mutations"] and s["native_main"] is None
         and s["maximum_worker_vmas"] == VMA and s["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and s["available_bytes"] >= plan["minimum_free_bytes"], "guard incomplete or tripped")
    obs = s["root_physical_observation"]
    need(obs["maximum_physical_bytes"] == s["maximum_root_physical_bytes"] == CAP
         and 0 < obs["conservative_physical_bytes"] <= CAP and obs["exceeds_budget"] is False, "guard disk coverage")
    workers = s["workers"]
    if require_worker:
        need(len(workers) == 1 and len(workers[0]) == 2 and 0 < workers[0][1] < VMA, "worker protection missing")
    else:
        need(workers == [], "worker escaped before guard authorization")


def latest_guard(actor, plan, sha, worker=False):
    receipts = Path(plan["receipt_directory"])
    need(not any(receipts.glob("stop-*.json")), "protective guard stop present")
    service, timer = native(GUARD_UNIT), native(TIMER)
    need(timer["ActiveState"] == "active" and timer["Job"] == "" and timer["Triggers"] == GUARD_UNIT
         and service["TriggeredBy"] == TIMER and int(service["MemoryMax"]) == GIB
         and service["CPUQuotaPerSecUSec"] == "250ms", "native guard units or limits changed")
    # The writer is periodic; use a completed PID 1 invocation, including the previous
    # completed receipt while a new oneshot may already be running.
    candidates = sorted(receipts.glob("sample-*.json"), key=lambda p:p.stat().st_mtime_ns, reverse=True)[:4]
    for path in candidates:
        if time.time()-path.stat().st_mtime > 30: continue
        r = reference(path)
        s = bound(r)
        sid = s["guard_invocation_id"]
        if time.time()-s["recorded_unix_seconds"] > 30: continue
        need(path.name == f"sample-{sid}.json", "guard receipt filename")
        if worker and not s["workers"]: continue
        verify_sample(s,actor,plan,sha,worker)
        native_records = run("/usr/bin/journalctl","--no-pager","-ojson","--output-fields=_PID,INVOCATION_ID,MESSAGE_ID,UNIT,JOB_RESULT",
                             "_PID=1",f"UNIT={GUARD_UNIT}",f"INVOCATION_ID={sid}","-n12")
        events = [json.loads(l) for l in native_records.splitlines()]
        completed = any(v.get("JOB_RESULT") == "done" and v.get("INVOCATION_ID") == sid for v in events)
        if not completed and not (service["InvocationID"] == sid and service["ActiveState"] == "inactive"
                                  and service["Result"] == "success" and service["ExecMainStatus"] == "0"
                                  and any(v.get("INVOCATION_ID") == sid for v in events)):
            continue
        return {"receipt":r,"timer":timer,"guard_invocation":sid,"producer":actor,
                "genuine_first_timer_driven_success":not worker}, s
    return None


def wait_first(actor, plan, sha):
    until = time.monotonic() + 90
    while time.monotonic() < until:
        need(native(UNIT)["InvocationID"] == actor["InvocationID"], "gated owner ended")
        found = latest_guard(actor,plan,sha)
        if found: return found[0]
        time.sleep(.25)
    raise ValueError("first timer-driven guard deadline expired")


def observer_row(ad):
    actor = native(UNIT)
    need(actor["InvocationID"] == ad["producer_invocation_id"] and actor["ActiveState"] == "active"
         and actor["NRestarts"] == "0" and int(actor["MainPID"]) == ad["producer_pid"]
         and ticks(ad["producer_pid"]) == ad["start_ticks"], "different live 172")
    plan = bound(ad["actual_guard_plan"])
    found = latest_guard(actor,plan,ad["actual_guard_plan"]["sha256"],worker=True)
    need(found is not None, "waiting for first protected historical worker")
    proof,s = found
    pid = s["workers"][0][0]
    image = Path(os.readlink(f"/proc/{pid}/exe"))
    need(image.name == "historical-worker" and image.is_relative_to(RUN/"private") and "scratch" in image.parts
         and digest(f"/proc/{pid}/exe") == "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541",
         "unrecognized historical worker")
    scratch = next(p for p in image.parents if p.name == "scratch")
    log = LOG.stat()
    out = Path(f'/proc/{actor["MainPID"]}/fd/1').stat()
    need((log.st_dev,log.st_ino) == (out.st_dev,out.st_ino), "unbound append log")
    row = {"range":"172","controller_unit":UNIT,"producer_unit":UNIT,"scratch_path":str(scratch),
           "expected_controller_invocation_id":actor["InvocationID"],"expected_producer_invocation_id":actor["InvocationID"],
           "worker_executable_basename":"historical-worker",
           "append_log":{"device":log.st_dev,"inode":log.st_ino,"path":str(LOG)}}
    return {"observer_row":row,"worker_guard":proof,"worker_pid":pid,"worker_start_ticks":ticks(pid),
            "advancing_replay_claimed":False,"authenticated_status_write_by_existing_owner":True}


def confirm_adoption(admission, fleet_ref):
    """Bind the new unit to the existing sole observer and authenticated R2 status."""
    fleet = bound(fleet_ref)
    need(0 <= time.time() - fleet["recorded_unix_seconds"] <= 40 * 60, "stale adoption fleet")
    ad = bound(admission)
    current = native(UNIT)
    need(current["InvocationID"] == ad["producer_invocation_id"] and current["ActiveState"] == "active"
         and current["MainPID"] == str(ad["producer_pid"]) and ticks(ad["producer_pid"]) == ad["start_ticks"],
         "adopted producer identity changed")
    rows = fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"]
    own = [v for v in rows if v["epoch"] == 172]
    need(len(own) == 1 and own[0]["admission"] == admission and own[0]["unit"]["Id"] == UNIT
         and own[0]["unit"]["InvocationID"] == current["InvocationID"], "fleet does not own this admission")
    status_row = next(v for v in fleet["epochs"] if v["epoch"] == 172)
    status_ref = status_row["current_authenticated_status_receipt"]
    status = bound(status_ref)
    need(status["epoch"] == 172 and status["authenticated_readback"] is True
         and status["producer_invocation_id"] == current["InvocationID"]
         and status["after_status"] == status_row["current_status"]
         and status["after_status"]["phase"] == own[0]["phase"], "authenticated 172 status differs")
    if own[0]["phase"] == "replay":
        expected = observer_row(ad)["observer_row"]
        scheduled = bound(fleet["sole_next_observer"])["replays"]
        need(any(all(r.get(k) == v for k,v in expected.items()) for r in scheduled),
             "next coordinated observer lacks the actual worker")
        observation = bound(own[0]["observer"])
        measured = next(v for v in observation["replays"] if v["range"] == "172")
        useful = measured["useful_work"]
        need(measured["producer_after"]["invocation_id"] == current["InvocationID"]
             and useful["sufficient_for_rates"] is True and useful["slot_delta"] > 0
             and useful["transaction_delta"] > 0, "no live slot and transaction progression")
    return {"admission":admission, "fleet":fleet_ref, "status":status_ref,"phase":own[0]["phase"],
            "authenticated_readback":True}


def fresh_inventory():
    template = capacity.ORIGINAL / "ADMISSION_INVENTORY-ORIGINAL-ARGV.json"
    original = checked(template, "ecf370dc0da1a47ddcee8a46bf2d6905d05500244993c69de0f236358bd105ee")
    nonce = uuid.uuid4().hex
    destination = BASE/f"inventory-{nonce}.json"
    need(original[-4:] == ["inventory","/home/sol/horizon","--epochs","101-200"], "unexpected R2 operation")
    cmd = []
    for arg in original:
        if arg.startswith("--unit="): arg = "--unit=horizon-full172-readonly-inventory-" + nonce
        elif arg == "CPUQuota=200%": arg = "CPUQuota=25%"
        elif arg.startswith("ReadWritePaths="): arg = "ReadWritePaths=" + str(BASE)
        elif arg.startswith("StandardOutput=file:"): arg = "StandardOutput=file:" + str(destination)
        elif arg == "101-200": arg = "172-172"
        cmd.append(arg)
    run(*cmd, timeout=180)
    r = reference(destination)
    v = bound(r)
    need(v["schema"] == "jetstreamer-horizon-r2-inventory-v1" and v["anomalies"] == 0
         and v["requested_epochs"] == v["missing"] == 1
         and [e["epoch"] for e in v["entries"]] == [172] and v["entries"][0]["state"] == "missing",
         "epoch 172 not freshly authenticated missing")
    return r


def recover_setup():
    final = BASE/"ACTUAL_ADMISSION_AND_PROTECTION.json"
    if final.exists():
        return reference(final)
    allowed = BASE/"barrier/allow"
    if allowed.exists():
        # An interruption after the permit's atomic link can only finish recording the
        # original release. Never start a second invocation after useful work began.
        authorized = bound(reference(BASE/"AUTHORIZED_GATED_PAYLOAD.json"))
        need(allowed.read_text() == authorized["producer_invocation_id"], "different surviving permit")
        return record(final, authorized)
    prior = BASE/"PRODUCER_ARGV.json"
    names = ["barrier","guard-receipts","guard.stdout","guard.stderr","FINAL_PRELAUNCH_FIT.json",
             "PRODUCER_ARGV.json","ACTUAL_GUARD_PLAN.json","GUARD_ARGV.json","FIRST_GUARD.json",
             "POST_GUARD_CAPACITY.json","AUTHORIZED_GATED_PAYLOAD.json"]
    if not any((BASE/n).exists() for n in names):
        return None
    actor = native(UNIT)
    if actor["ActiveState"] in ("active","activating"):
        args = bound(reference(prior))
        need(f"--unit={UNIT}" in args and f'--description={actor["Description"]}' in args
             and actor["Description"].startswith("guarded-full172-"), "foreign unreleased producer")
        run("/usr/bin/systemctl","stop",UNIT,timeout=150)
    timer = native(TIMER)
    if timer["ActiveState"] == "active":
        plan = bound(reference(BASE/"ACTUAL_GUARD_PLAN.json"))
        need(actor["InvocationID"] == plan["invocation_id"] and timer["Triggers"] == GUARD_UNIT,
             "foreign uncompleted guard")
        run("/usr/bin/systemctl","stop",TIMER)
    for u in (UNIT,GUARD_UNIT,TIMER):
        state = native(u)
        need(state["ActiveState"] in ("inactive","failed") and state["Job"] == ""
             and state.get("MainPID","0") == state.get("ControlPID","0") == "0", "prior generation busy")
        if state["ActiveState"] == "failed":
            run("/usr/bin/systemctl","reset-failed",u)
    archive = BASE/("closed-setup-"+uuid.uuid4().hex)
    archive.mkdir(mode=0o700)
    for n in names:
        path=BASE/n
        if path.exists():
            path.rename(archive/n)
    return None


def guard_session(fleet_ref, source):
    existing = recover_setup()
    if existing:
        return existing
    bound(fleet_ref)
    inventory = fresh_inventory()
    v = input_check()
    pre = capacity.capture(fleet_ref)
    floor = capacity.select(pre)
    need(all(native(u)["LoadState"] == "not-found" for u in (UNIT,GUARD_UNIT,TIMER)), "existing generation")
    for leaf in ("barrier","guard-receipts"):
        (BASE/leaf).mkdir(mode=0o755 if leaf == "barrier" else 0o700)
    (BASE/"barrier").chmod(0o755)
    token = "guarded-full172-" + uuid.uuid4().hex
    original = bound(v["original_normal_producer"])
    command = producer_argv(v, original, token)
    record(BASE/"FINAL_PRELAUNCH_FIT.json",pre)
    record(BASE/"PRODUCER_ARGV.json",command)
    released = False
    owned_timer = None
    try:
        run(*command)
        actor = native(UNIT)
        need(actor["ActiveState"] == "active" and actor["Description"] == token and iid(actor["InvocationID"])
             and int(actor["MemoryMax"]) == ACTOR_BYTES and actor["CPUQuotaPerSecUSec"] == "500ms", "native gate start")
        invocation = actor["InvocationID"]
        started = ticks(int(actor["MainPID"]))
        plan = guard_plan(invocation,floor)
        planref = record(BASE/"ACTUAL_GUARD_PLAN.json",plan)
        sealed = Path(planref["path"])
        static = json.loads(run(GUARD,sealed,"--plan-sha256",planref["sha256"],"--self-sha256",GUARD_SHA,"--validate-plan-only"))
        need(static["validated"] is True and static["unit"] == UNIT, "static guard qualification")
        cmd = guard_argv(sealed,planref["sha256"])
        record(BASE/"GUARD_ARGV.json",cmd)
        run(*cmd)
        owned_timer = native(TIMER)["InvocationID"]
        first = wait_first(actor,plan,planref["sha256"])
        firstref = record(BASE/"FIRST_GUARD.json",first)
        post = capacity.capture(fleet_ref,invocation)
        capacity.select(post,floor)
        postref = record(BASE/"POST_GUARD_CAPACITY.json",post)
        need(latest_guard(actor,plan,planref["sha256"]) is not None and native(UNIT)["InvocationID"] == invocation,
             "protective proof expired before gate release")
        pending = {"epoch":172,"producer_unit":UNIT,"producer_invocation_id":invocation,
                   "producer_pid":int(actor["MainPID"]),"start_ticks":started,"first_guard":firstref,
                   "post_guard_capacity":postref,"actual_guard_plan":planref,"fleet":fleet_ref,
                   "branch":source,"authenticated_inventory":inventory,"bootstrap_only":True,"transaction_replay_claimed":False,
                   "archive_publication_authorized":False,"r2_mutations":False}
        record(BASE/"AUTHORIZED_GATED_PAYLOAD.json",pending)
        atomic_file(BASE/"barrier/allow",invocation.encode())
        released = True
        return record(BASE/"ACTUAL_ADMISSION_AND_PROTECTION.json",pending)
    except BaseException:
        if not released:
            actor = native(UNIT)
            if actor["Description"] == token and actor["ActiveState"] in ("active","activating"):
                run("/usr/bin/systemctl","stop",UNIT,timeout=150)
            if owned_timer and native(TIMER)["InvocationID"] == owned_timer:
                run("/usr/bin/systemctl","stop",TIMER)
        raise


def cli():
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=["preflight","launch","observe","confirm-adoption"])
    parser.add_argument("path",type=Path)
    parser.add_argument("sha")
    parser.add_argument("seal_sha")
    parser.add_argument("--fleet",type=Path)
    parser.add_argument("--fleet-sha")
    args=parser.parse_args()
    need(os.geteuid() == 0 and Path(__file__).resolve() == PACKAGE/"session.py", "use sealed controller")
    source = provenance(args.seal_sha)
    incoming = {"path":str(args.path),"sha256":args.sha}
    if args.mode == "confirm-adoption":
        need(args.path == BASE/"ACTUAL_ADMISSION_AND_PROTECTION.json" and args.fleet and args.fleet_sha, "adoption arguments")
        return confirm_adoption(incoming,{"path":str(args.fleet),"sha256":args.fleet_sha})
    if args.mode == "observe":
        need(args.path == BASE/"ACTUAL_ADMISSION_AND_PROTECTION.json", "different epoch admission")
        return observer_row(bound(incoming))
    lockfd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CREAT, 0o600)
    try:
        st = os.fstat(lockfd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o7777 == 0o600
             and st.st_nlink == 1, "invalid fleet lock")
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.mode == "preflight":
            fresh_inventory()
            input_check()
            fit = capacity.capture(incoming)
            fit["armed_floor"] = capacity.select(fit)
            return fit
        return guard_session(incoming,source)
    finally:
        os.close(lockfd)


if __name__ == "__main__":
    print(json.dumps(cli(),sort_keys=True))
