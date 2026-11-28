"""Bind the complete incident fit to the held normal 168 gate and its registered peers."""
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import fit
import overlap
import same_five
import status168 as s

HERE=Path(__file__).resolve().parent
ROOTS=s.ref(s.D/"STABLE_167_168_ROOTS_BEFORE_DATA_WITNESS.json","57d99faeaed6817dc1afc29dec368039ae4cb4f1cbad28df2075b894d397321d")
FITDIR=s.ROOT/"incident-replay-fit-20261121-v1"
TIMER_DRAIN=s.ref(FITDIR/"ORIGINAL_GUARD_TIMERS_RETIRED.json","59ec2c86879321c3fb6499d0e602d1eab78c4a4d8dbcdef6f48264ded650ecbc")
REGISTRATION=s.ref(fit.READY,"02027e3e35364f64913b34162fde295bfb96b3123a9d9794545ce4e0b1a4e8ba")
FAILED="add576f115cc4d3b897f47d024af72fd"
STATE=fit.ANCHOR.parent.parent/FAILED
STARTED=s.ref(STATE/"recovery-started.json","9cdcfdb688ee018b9cddd43c9c5ba129712195e11d6c8172104a7f4a9a160a28")
FAILURE=s.ref(STATE/"failed.json","33e011228a58df3c2a82ca49013a7d524eeca1e849fc59993effe5d2faf18e74")
CAPS={"166":288*fit.G,"167":512*fit.G,"168":288*fit.G,"170":288*fit.G}


def provider():
    cfg,ref=s.read(HERE/"incident-fit.json")
    package=Path(cfg["seal"]["path"]).parent
    s.need(package.parent==FITDIR and package.name in ("tools","tools-v2"),"unknown incident provider package")
    seal=s.bound(cfg["seal"],package/"deployment-seal-receipt.json")
    p=package/"post-stop-fit"
    s.need(seal["destination"]==str(p.parent) and seal["sealer_sha256"]==cfg["sealer_sha256"]
           and cfg["image"]["path"]==str(p) and any(r["name"]==p.name and
           r["sha256"]==cfg["image"]["sha256"] for r in seal["members"]),"foreign incident fit provider")
    for row in seal["members"]:
        name=row["name"]
        s.need(Path(name).name==name,"invalid fit member")
        fit.binary(p.parent/name,row["sha256"])
    return p,ref


def drained_phase(phase):
    manager=s.show(fit.A145)
    s.need(not fit.members(fit.A145) and not manager["Job"] and int(manager["MainPID"])==0 and
           manager["ActiveState"] in ("inactive","failed") and all(phase[k]==manager[k] for k in
           ("Id","MainPID","ActiveState","SubState","InvocationID")),"145 no longer drained")
    failure=s.bound(FAILURE,STATE/"failed.json")
    started=s.bound(STARTED,STATE/"recovery-started.json")
    s.need(failure["iid"]==started["iid"]==FAILED and "exit status: 124" in failure["error"] and
           started["r2_mutations"] is False and (manager["ActiveState"]!="failed" or
           (manager["InvocationID"]==FAILED and manager["ExecMainStatus"]=="1" and phase["failure"]==FAILURE)),
           "different 145 recovery failure")
    old=same_five.predecessor(started["prior_frozen_recovery"],started["fresh_fit"],fit.A145)
    append=started["prior_frozen_recovery"]["append"]
    value=s.bound(append,same_five.STATE/"append-complete.json")
    s.need(append["sha256"]=="9d8fc46ba227c4875f516d2318b2e397caa8884d058ccb217313ec3ae9071fc4" and
           value["device"]==64512 and value["inode"]==103237059 and value["appended"]+
           value["prefix_bytes_compared"]==105610995833 and value["no_semantic_verification_claimed"] is True and
           not any((STATE/n).exists() for n in ("source-semantics.json","verified-frozen.json","complete.json")),
           "different frozen 145 custody")
    frozen=[]
    candidate=Path(started["file"])
    s.need(candidate==overlap.OUTPUT/".tmp36MvkN","different 145 candidate")
    for p,ino,length in ((overlap.SOURCE,100214450,105633748687),(overlap.MANIFEST,100214429,1809),
                         (candidate,103237059,105610995833)):
        m=p.lstat()
        s.need(p.resolve(strict=True)==p and (m.st_dev,m.st_ino,m.st_size,m.st_uid,m.st_nlink,m.st_mode)==
               (64512,ino,length,0,1,stat.S_IFREG|0o400),"different frozen 145 input")
        frozen.append([str(p),m.st_dev,m.st_ino,m.st_size])
    for pid,ticks in ((3839142,360478723),(3839343,360480014)):
        try: observed=s.process(pid)[1]
        except (FileNotFoundError,ProcessLookupError): continue
        s.need(observed!=ticks,"failed 145 process still present")
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-","")
    raw=fit.command("/usr/bin/journalctl","-b","--no-pager","-ojson","_PID=1","UNIT="+fit.A145,
                    "INVOCATION_ID="+FAILED,"MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15","-n2")
    rows=[json.loads(line) for line in raw.splitlines()]
    s.need(len(rows)==1 and rows[0]["_BOOT_ID"]==boot and rows[0]["EXIT_CODE"]=="exited" and
           rows[0]["EXIT_STATUS"]=="1","missing original PID1 145 completion")
    return dict(phase=phase,failed=FAILURE,started=STARTED,prior_failure=old,append=append,
                event_cursor=rows[0]["__CURSOR"],frozen=frozen,resource_credit_bytes=0)


def status(proof):
    s.need(proof["registration"]==REGISTRATION,"different 168 registration")
    s.bound(REGISTRATION,fit.READY)
    m=s.show(fit.PUBLISHER);pid=proof["pid"];proc=Path(f"/proc/{pid}")
    s.need(m["ActiveState"]=="active" and m["SubState"]=="running" and not m["Job"] and
           m["InvocationID"]==proof["invocation_id"] and int(m["MainPID"])==pid and
           s.process(pid)[1:]==(proof["start_ticks"],"0::/system.slice/"+fit.PUBLISHER) and
           s.same_file(proc/"fd/9",fit.LOCK) and any(" FLOCK " in line and " WRITE " in line for line in
           (proc/"fdinfo/9").read_text().splitlines()),"cadence consumer changed")
    script=(proc/"fd/255").readlink()
    s.need(script.name=="consume" and script.parent.parent.parent==s.ROOT and s.same_file(proc/"fd/255",script),
           "different cadence consumer FD")
    seal=s.bound(proof["consumer_seal"],script.parent/"deployment-seal-receipt.json")
    s.need(seal["destination"]==str(script.parent),"foreign consumer seal")
    digest=next(v["sha256"] for v in seal["members"] if v["name"]==script.name)
    fit.binary(script,digest)
    return proof


def peer_population(native,actor):
    peers={}
    for row in native["survivors"].values():
        peers[row["unit"]]=(row["invocation_id"],row["timer"],row["timer_invocation_id"],row["processes"])
    for row in native["replacements"].values():
        peers[row["producer_unit"]]=(row["producer_invocation_id"],row["timer"],row["timer_invocation_id"],row["processes"])
    candidate=native["candidate136"]
    if candidate["occupied"]:
        ident=candidate["identity"]
        peers[fit.N136]=(ident["iid"],None,None,ident["processes"])
    expected=set(peers)|({s.U} if actor else set())
    s.need(fit.units()==expected and set(native["population"])==expected,"different executing qualifier membership")
    for unit,(gen,timer,tid,processes) in peers.items():
        m=s.show(unit)
        s.need(m["InvocationID"]==gen and m["ActiveState"]=="active" and not m["Job"] and
               fit.members(unit)==tuple(sorted(x[0] for x in processes)) and
               native["population"][unit]==[x[:2] for x in processes],"different peer generation")
        for pid,ticks,*inode in processes:
            m=Path(f"/proc/{pid}/exe").stat()
            s.need(s.process(pid)[1:]==(ticks,"0::/system.slice/"+unit) and
                   (not inode or inode==[m.st_dev,m.st_ino]),"different executing peer")
        if timer:
            m=s.show(timer)
            s.need(m["InvocationID"]==tid and m["ActiveState"]=="active" and not m["Job"] and
                   m["Triggers"]==timer.removesuffix(".timer")+".service","different continuing guard")
    if actor:
        s.identity(s.native_actor(s.read(s.D/"START_INTENT.json")[0])[1],actor)
        s.need(fit.members(s.U)==(actor["producer_pid"],) and native["population"][s.U]==[
               [actor["producer_pid"],actor["start_ticks"]]],"unexpected held-gate membership")
    return {u:[gen,t,tid,p] for u,(gen,t,tid,p) in peers.items()}


def unchanged(row,actor=None):
    native=row["native_incident_fit"]
    return (drained_phase(native["phase145"])==row["phase145"] and
            status(native["status_registration"])==row["status_registration"] and
            peer_population(native,actor)==row["population"])


def capacity(v,fleet,actor):
    s.need(v["schema"]=="horizon-incident-replay-fit-v1" and v["epoch"]==168 and v["fleet"]==fleet and
           set(v["actual_original_stops"])=={"166","167","170"} and all(
               x["guard_timer_retirement"]==TIMER_DRAIN for x in v["actual_original_stops"].values()) and
           set(v["survivors"])=={"169","172"} and set(v["bookings"])==set(CAPS) and v["candidate"]==actor and
           v["stopped_generation_resident_credit_bytes"]==v["resource_credit_bytes"]==0 and
           v["complete_cpu_quota_micros"]==64_000_000 and v["complete_memory_plus_reserve_bytes"]==fit.MEM and
           0<=time.time()-v["recorded_unix_seconds"]<=90,"foreign incident fit")
    for epoch,row in v["bookings"].items():
        s.need(row["cap_bytes"]==CAPS[epoch] and 0<=row["remaining_bytes"]<=CAPS[epoch] and
               row["physical_bytes"]+row["remaining_bytes"]==row["cap_bytes"],"incorrect whole-lane accounting")
    c=v["candidate136"];n=v["normal168"]
    s.need(v["bookings"]["168"]["root"]==str(s.TREE) and c["cap"]==72*fit.G and
           0<=c["remaining"]<=c["cap"] and (c["occupied"] or c["remaining"]==c["cap"]) and
           v["complete_required_HOME_bytes"]==v["protected_raw_floor_bytes"]+v["bookings"]["168"]["remaining_bytes"] and
           v["protected_raw_floor_bytes"]>=8297502499408 and
           ((actor is None and n is None) or (actor is not None and n and n["stage"]=="gated" and n["actor"]==actor)),
           "missing protected 168 allowance or wrong gate")
    return v["fits"] is True and v["available_HOME_bytes"]>=v["complete_required_HOME_bytes"] and (
           v["available_memory_bytes"]>=v["required_available_memory_bytes"]>0)


def capture(fleet,actor=None):
    p,ref=provider()
    proc=subprocess.run([p,"168",fleet["path"],fleet["sha256"]],stdout=subprocess.PIPE,timeout=150,check=False)
    s.need(proc.returncode in (0,1) and proc.stdout,"incident fit provider failed")
    v=json.loads(proc.stdout)
    eligible=capacity(v,fleet,actor)
    s.need((proc.returncode==0)==eligible,"inconsistent incident capacity decision")
    phase=drained_phase(v["phase145"])
    population=peer_population(v,actor)
    return dict(schema="horizon-168-incident-reservation-fresh-fit-v1",fleet=fleet,provider=ref,native_incident_fit=v,
                phase145=phase,population=population,status_registration=status(v["status_registration"]),
                registered_population_compatible=True,fresh_phase_compatible=True,retired_original_peers=v["actual_original_stops"],
                producer_invocation_id=actor["producer_invocation_id"] if actor else None,resource_credit_bytes=0,
                eligible_with_168_alone=eligible,complete_required_DATA_bytes=v["complete_required_HOME_bytes"],
                standalone_guard_floor=v["protected_raw_floor_bytes"],available_HOME_bytes=v["available_HOME_bytes"],
                complete_memory_plus_reserve_bytes=fit.MEM,complete_cpu_quota_micros=v["complete_cpu_quota_micros"],
                required_available_memory_bytes=v["required_available_memory_bytes"],available_memory_bytes=v["available_memory_bytes"])
