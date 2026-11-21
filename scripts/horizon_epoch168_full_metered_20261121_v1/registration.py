#!/usr/bin/python3 -I
"""Record a genuinely released and guarded normal 168 after the root admission transaction."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("production",here/"production.py")
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
STATE=p.STATE
GUARD_SHA="b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
TRACE=STATE.parent/"epoch168-terminal-trace-20261121-v1/TERMINAL.json"
TRACE_SHA="29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"


def evidence(path):
    need=p.need
    m=path.lstat()
    need(path.is_absolute() and path.resolve(strict=True)==path and stat.S_ISREG(m.st_mode)
         and m.st_uid==0 and not m.st_mode&0o022 and m.st_nlink==1 and 0<m.st_size<=32<<20,
         f"incorrect original root evidence: {path}")
    data=path.read_bytes()
    need(len(data)==m.st_size and m.st_ino==path.lstat().st_ino,"evidence changed")
    return json.loads(data),{"path":str(path),"sha256":hashlib.sha256(data).hexdigest()}


def bound(ref):
    v,actual=evidence(Path(ref["path"]))
    p.need(actual==ref,"root evidence digest differs")
    return v


def show(unit):
    names="Id,InvocationID,ActiveState,SubState,Job,MainPID,ControlPID,NRestarts,ControlGroup,Triggers,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax"
    raw=subprocess.check_output(["/usr/bin/systemctl","show",unit,"-p",names],text=True,timeout=15)
    return dict(line.split("=",1) for line in raw.splitlines())


def guard_sample(sample,plan_ref,generation,pid):
    p.need(sample["schema"]=="jetstreamer-horizon-standalone-guard-sample-v1"
           and sample["guard_sha256"]==GUARD_SHA and sample["plan_sha256"]==plan_ref["sha256"]
           and sample["producer_invocation_id"]==generation and sample["producer"]["invocation_id"]==generation
           and sample["producer"]["active"]=="active" and sample["producer"]["pid"]==pid
           and sample["producer"]["restarts"]==0 and sample["producer_stop_enabled"] is True
           and sample["trip_reason"] is None and sample["worker_observation_error"] is None
           and sample["root_physical_observation_error"] is None
           and sample["root_physical_observation"]["exceeds_budget"] is False,
           "standalone guard did not protect the original producer")


def main():
    p.need(os.geteuid()==0,"root registration required")
    j,args=p.normal_spec()
    unit=j["producer_unit"]; timer=j["guard_unit"]+".timer"
    mgr=show(unit);tmgr=show(timer);iid=mgr["InvocationID"];pid=int(mgr["MainPID"])
    p.need(mgr["ActiveState"]=="active" and mgr["SubState"]=="running" and pid>1 and mgr["Id"]==unit
           and re.fullmatch("[0-9a-f]{32}",iid) and mgr["ControlGroup"]=="/system.slice/"+unit
           and mgr["ControlPID"]=="0" and not mgr["Job"] and mgr["NRestarts"]=="0"
           and mgr["CPUQuotaPerSecUSec"]=="9s" and mgr["MemoryMax"]==str(68<<30) and mgr["MemorySwapMax"]=="0",
           "original producer PID or budget differs")
    p.need(tmgr["Id"]==timer and tmgr["ActiveState"]=="active" and tmgr["SubState"]=="waiting"
           and re.fullmatch("[0-9a-f]{32}",tmgr["InvocationID"]) and not tmgr["Job"]
           and tmgr["Triggers"].split()==[j["guard_unit"]+".service"],"original standalone timer differs")
    proc=Path("/proc")/str(pid)
    ticks=int((proc/"stat").read_text().rsplit(")",1)[1].split()[19])
    original=Path(j["members"]["jetstreamer-node"][0]).stat()
    current=(proc/"exe").stat()
    p.need((current.st_dev,current.st_ino)==(original.st_dev,original.st_ino)
           and (proc/"cgroup").read_text().strip()=="0::"+mgr["ControlGroup"]
           and (proc/"cmdline").read_bytes().split(b"\0")[:-1]==[os.fsencode(a) for a in j["regular_node_argv"]],
           "candidate has not execed the authenticated normal node")
    permit=STATE/"barrier/allow"
    m=permit.lstat()
    p.need(m.st_uid==0 and m.st_mode==(stat.S_IFREG|0o444) and m.st_nlink==1 and permit.read_bytes()==iid.encode(),
           "root did not release this invocation")
    authorized,_=evidence(STATE/"AUTHORIZED_GATED_PAYLOAD.json")
    first,fr=evidence(STATE/"FIRST_GUARD.json")
    plan,pr=evidence(STATE/"ACTUAL_GUARD_PLAN.json")
    capacity,cr=evidence(STATE/"POST_GUARD_CAPACITY.json")
    expected,_=p.guard(j,iid,plan["minimum_free_bytes"])
    p.need(plan==expected and authorized["producer_unit"]==unit and authorized["producer_invocation_id"]==iid
           and authorized["producer_pid"]==pid and authorized["start_ticks"]==ticks
           and authorized["actual_guard_plan"]==pr and authorized["first_guard"]==fr
           and authorized["post_guard_capacity"]==cr and authorized["epoch"]==168,
           "root's authorized gated payload or actual guard plan differs")
    p.need(first["genuine_first_timer_driven_success"] is True and first["timer"]["InvocationID"]==tmgr["InvocationID"]
           and first["producer"]["InvocationID"]==iid,"first guard belongs to another invocation")
    first_sample=bound(first["receipt"])
    p.need(first["receipt"]["path"]==str(STATE/"guard-receipts"/("sample-"+first["guard_invocation"]+".json"))
           and first_sample["guard_invocation_id"]==first["guard_invocation"],"wrong first standalone sample")
    guard_sample(first_sample,pr,iid,pid)
    # Rebind the current native sample, including the receipt bytes from its exact original service.
    log=STATE/"guard.stdout"
    with log.open("rb") as f:
        f.seek(max(0,log.stat().st_size-65536))
        last=next(json.loads(line) for line in reversed(f.read().splitlines()) if line.startswith(b"{"))
    gid=last["guard_invocation_id"]
    p.need(re.fullmatch("[0-9a-f]{32}",gid) and 0<=time.time()-last["recorded_unix_seconds"]<=90,
           "standalone guard sample stale")
    durable,_=evidence(STATE/"guard-receipts"/("sample-"+gid+".json"))
    p.need(durable==last,"latest native guard differs from durable receipt")
    guard_sample(last,pr,iid,pid)
    fleet=bound(authorized["fleet"])
    p.need(fleet["owner"]=="/root" and fleet["all_reservation_ending_bytes"]==0
           and fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] is True
           and capacity["complete_memory_plus_reserve_bytes"]==810658050048
           and capacity["complete_cpu_quota_micros"]<=64000000 and capacity["resource_credit_bytes"]==0
           and capacity["available_HOME_bytes"]>=capacity["complete_required_DATA_bytes"]
           and capacity["available_memory_bytes"]>=capacity["required_available_memory_bytes"]
           and capacity["producer_invocation_id"]==iid and capacity["fresh_phase_compatible"] is True
           and capacity["registered_population_compatible"] is True,"missing complete joint post-guard fit")
    _,prior_ref=evidence(TRACE);_,inputs_ref=evidence(p.PKG/"deployment-seal-receipt.json")
    p.need(prior_ref["sha256"]==TRACE_SHA and inputs_ref["sha256"]=="e00db5e753a2cc37af403933f54bcb3216594d1fac3d91cc8984623999295a93",
           "prior diagnostic or normal input authority differs")
    p.need(show(unit)==mgr and show(timer)==tmgr and int((proc/"stat").read_text().rsplit(")",1)[1].split()[19])==ticks,
           "manager generation changed before registration")
    result={"schema":"horizon-168-full-metered-admission-protection-v1","epoch":168,"producer_unit":unit,
         "producer_invocation_id":iid,"producer_pid":pid,"start_ticks":ticks,"timer_unit":timer,
         "timer_invocation_id":tmgr["InvocationID"],"actual_guard_plan":pr,"first_guard":fr,
         "post_guard_capacity":cr,"fleet":authorized["fleet"],"prior_trace_terminal":prior_ref,
         "input_seal":inputs_ref,"bootstrap_only":True,"transaction_replay_claimed":False,
         "resource_credit_bytes":0,"archive_publication_authorized":False,"r2_mutations":False}
    data=(json.dumps(result,indent=2,sort_keys=True)+"\n").encode()
    target=STATE/"ACTUAL_ADMISSION_AND_PROTECTION.json"
    tmp=STATE/(".registration-"+str(os.getpid()))
    try:
        with tmp.open("xb") as f:
            f.write(data);os.fchmod(f.fileno(),0o400);f.flush();os.fsync(f.fileno())
        try:
            os.link(tmp,target)
        except FileExistsError:
            p.need(target.read_bytes()==data,"conflicting prior protected owner")
    finally:
        tmp.unlink(missing_ok=True)
    fd=os.open(STATE,os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({"path":str(target),"sha256":hashlib.sha256(data).hexdigest()}))


if __name__=="__main__":
    main()
