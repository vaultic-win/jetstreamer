"""Attach the bounded epoch 136 reproduction to the incumbent scheduled sample."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time

from evidence import BASE, STATUS_ROOT, bound, checked, content, durable, ensure_dir, need

UNIT = "horizon-qualify-136-actual-20261120-g1.service"
WRITER = "horizon-admit-136-actual-20261120-g1.service"
GUARD = "horizon-guard-136-actual-20261120-g1"
ROOT = Path("/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1")
RUN = ROOT / "reproduction"
RECEIPTS = RUN / "receipts"
GROUP = "/system.slice/" + UNIT
HELPER = "93162c6910f01149cb50eccdfa742e5a732658dd8ac17865a5f2eaef526c0594"
NODE = "bf702870fa328cf3fc43dd12a3943cab059fb7b0aa4ea1d3753c6a09b940cd71"
WORKER = "3ea95997d956de6a8c7fa431e679d496a5d3c31e15f8a104a8ddb0086646ea3d"
GUARD_SHA = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
GUARD_IMAGE = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
PARENT = BASE / "epoch136-parent-handoff-20261121-v1"
FIELD = "private_epoch136_observation"
LIMIT = 72 << 30
OLD_UNIT = "horizon-qualify-136-hourly-charge-trace-retry-0002-20261030-v1.service"
OLD_IID = "5e32c880437d464498475df8406ff4c8"
OLD_CONFIG = dict(range="136",producer_unit=OLD_UNIT,controller_unit=OLD_UNIT,
                  expected_producer_invocation_id=OLD_IID,expected_controller_invocation_id=OLD_IID,
                  scratch_path="/home/sol/.jetstreamer-private/epoch136-hourly-charge-trace-run-parent-20261029-v1/attempts/retry-0002/reproduction",
                  worker_executable_basename="historical-worker")

def native(unit, fields):
    result = subprocess.run(["/usr/bin/systemctl","show",unit,"-p"+",".join(fields)],text=True,capture_output=True,timeout=10)
    row = dict(line.split("=",1) for line in result.stdout.splitlines())
    need(result.returncode in (0,4) and all(k in row for k in fields),"cannot resolve "+unit)
    return row

def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])

def members():
    try: return {int(s) for s in (Path("/sys/fs/cgroup"+GROUP)/"cgroup.procs").read_text().splitlines()}
    except FileNotFoundError: return set()

def immutable(path):
    ref=bound(path)
    need(path.stat().st_mode & 0o222 == 0,"writable 136 receipt "+str(path))
    return ref,checked(ref)

def tools(name,digest):
    return dict(path=str(ROOT/"tools"/name),sha256=digest)

def child_role(pid,exe):
    proc=Path(f"/proc/{pid}")
    need((proc/"cgroup").read_text().strip()=="0::"+GROUP,"escaped 136 child")
    name=exe.name
    if name=="jetstreamer-node":
        need(exe == ROOT/"tools"/name and exe.samefile(proc/"exe"),"foreign 136 node")
        return "node"
    if name=="historical-worker":
        need(exe.is_relative_to(RUN/"scratch") and exe.resolve(strict=True)==exe and exe.samefile(proc/"exe"),"foreign staged 136 worker")
        return "worker"
    raise ValueError("unexpected 136 replay image "+str(exe))

def census_child(pid):
    # The existing global census still rejects every other unexpected replay cgroup.
    exe=(Path(f"/proc/{pid}")/"exe").readlink()
    child_role(pid,exe)
    need((ROOT/"admission.json").is_file() and (RECEIPTS/"parent-release.json").is_file(),"136 replay image before admission/release")

def children(group, supervisor):
    found={}
    for pid in sorted(group-{supervisor}):
        p=Path(f"/proc/{pid}")
        exe=(p/"exe").readlink()
        if exe.name=="jetstreamer-node" or exe.name.startswith(("historical-worker","jetstreamer-historical-worker")) or exe.is_relative_to(RUN):
            role=child_role(pid,exe)
            need(role not in found,"duplicate 136 "+role)
            ids=(p/"status").read_text().splitlines()
            need(all(next(l for l in ids if l.startswith(field)).split()[1:]==[str(uid)]*4 for field,uid in (("Uid:",1001),("Gid:",1003))),"incorrect historical identity")
            st=(p/"exe").stat()
            found[role]=dict(pid=pid,start_ticks=ticks(pid),exe=str(exe),identity=[st.st_dev,st.st_ino,st.st_size,st.st_ctime_ns,st.st_mtime_ns])
    need("worker" not in found or "node" in found,"worker without node")
    return found

def worker_digest(worker):
    path=Path(f"/proc/{worker['pid']}/exe")
    with path.open("rb") as inp:
        st=os.fstat(inp.fileno())
        need(0<st.st_size<=256<<20,"136 worker ELF length")
        digest=hashlib.file_digest(inp,"sha256").hexdigest()
    st=path.stat()
    need([st.st_dev,st.st_ino,st.st_size,st.st_ctime_ns,st.st_mtime_ns]==worker["identity"] and
         ticks(worker["pid"])==worker["start_ticks"] and str(path.readlink())==worker["exe"] and digest==WORKER,"changed 136 staged worker ELF")
    return digest

def guard_shape(sample, guard_iid, actor, plan, floor, now):
    pid=int(actor["MainPID"]); iid=actor["InvocationID"]
    need(sample["schema"]=="jetstreamer-horizon-standalone-guard-sample-v1" and sample["guard_invocation_id"]==guard_iid and
         sample["producer_invocation_id"]==sample["producer"]["invocation_id"]==iid and sample["producer"]["pid"]==pid and
         sample["producer"]["active"]=="active" and sample["producer"]["sub"]=="running" and sample["producer"]["cgroup"]==GROUP and
         sample["producer"]["restarts"]==0 and sample["guard_sha256"]==GUARD_SHA and sample["plan_sha256"]==plan["sha256"] and
         sample["producer_stop_enabled"] is True and sample["minimum_free_bytes"]==floor and sample["maximum_root_physical_bytes"]==64<<30 and
         sample["maximum_worker_vmas"]==3500000 and all(sample[k] is None for k in ("trip_reason","worker_observation_error","root_physical_observation_error")) and
         sample["root_physical_observation"]["exceeds_budget"] is False and sample["root_physical_observation"]["conservative_physical_bytes"]<=64<<30 and
         sample["available_bytes"]>=floor and 0<=now-sample["recorded_unix_seconds"]<=120,"unhealthy/foreign 136 protective fire")

def guard(actor, floor):
    ref,g=immutable(RECEIPTS/"guard-plan.json")
    need(g["unit"]==UNIT and g["invocation_id"]==actor["InvocationID"] and g["worker_root"]==str(RUN) and g["receipt_directory"]==str(RECEIPTS/"guard"),"foreign 136 guard plan")
    t=native(GUARD+".timer",("ActiveState","Triggers","Job","InvocationID"))
    fire=native(GUARD+".service",("InvocationID","Type","Result","ExecMainStatus","ExecStart","NRestarts","MainPID","ControlPID","ExecMainStartTimestampMonotonic"))
    path="/org/freedesktop/systemd1/unit/horizon_2dguard_2d136_2dactual_2d20261120_2dg1_2etimer"
    raw=subprocess.check_output(["/usr/bin/busctl","--system","--timeout=5s","get-property","org.freedesktop.systemd1",path,"org.freedesktop.systemd1.Timer","LastTriggerUSecMonotonic"],text=True,timeout=8)
    match=re.fullmatch(r"t ([1-9][0-9]*)\n",raw); gid=fire["InvocationID"]
    cmd=f"{{ path={GUARD_IMAGE} ; argv[]={GUARD_IMAGE} {ref['path']} --plan-sha256 {ref['sha256']} --self-sha256 {GUARD_SHA} ;"
    need(t["ActiveState"]=="active" and t["Triggers"]==GUARD+".service" and not t["Job"] and re.fullmatch("[0-9a-f]{32}",t["InvocationID"]) and
         match and int(fire["ExecMainStartTimestampMonotonic"])>=int(match[1]) and re.fullmatch("[0-9a-f]{32}",gid) and
         (fire["Type"],fire["Result"],fire["ExecMainStatus"],fire["NRestarts"],fire["MainPID"],fire["ControlPID"])==("oneshot","success","0","0","0","0") and
         fire["ExecStart"].startswith(cmd) and fire["ExecStart"].count(" ; argv[]=")==1,"136 guard has no completed authentic last timer fire")
    sr=bound(RECEIPTS/"guard"/f"sample-{gid}.json");s=checked(sr);guard_shape(s,gid,actor,ref,floor,int(time.time()))
    return dict(sample=sr,timer=t["InvocationID"],plan=ref,workers=s["workers"],at=s["recorded_unix_seconds"])

def admission():
    ar,a=immutable(ROOT/"admission.json")
    qr,q=immutable(ROOT/"parent-launch-request.json")
    need(q["schema"]=="horizon-epoch136-parent-launch-request-v1" and q["unit"]==UNIT and q["admission"]==ar and
         q["plan"]==a["plan"] and q["writer_invocation_id"]==a["writer_invocation_id"] and q["writer"]==a["writer"] and
         q["helper"]==a["helper"]==tools("epoch136-actual-payload",HELPER) and a["node"]==tools("jetstreamer-node",NODE) and
         a["worker"]==tools("jetstreamer-historical-worker-v1-4-25",WORKER) and a["bounded_reproduction_authorized"] is True and
         all(a[k] is False for k in ("full_epoch_span_proven","publication_authorized","r2_mutations","remote_mutations")),"unbound 136 admission")
    cap=checked(a["resource_accounting"])
    wp=checked(q["writer_plan"]); seal=checked(wp["controller_deployment"])
    need(a["writer"]==wp["controller"] and seal["destination"]==str(Path(wp["controller_deployment"]["path"]).parent) and
         seal["sealer_sha256"]=="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3" and
         any(m["name"]=="admit136" and m["sha256"]==a["writer"]["sha256"] and m["mode"]=="0555" for m in seal["members"]) and
         cap["writer_invocation_id"]==a["writer_invocation_id"] and cap["exclusive_handoff_receipt"]==q["donor"] and
         cap["payload_plan"]==a["plan"] and cap["writer_plan"]==q["writer_plan"] and cap["candidate_unit"]==UNIT and
         cap["candidate_run_root"]==str(RUN) and cap["candidate_data_bytes"]==LIMIT and cap["candidate_memory_max_bytes"]==68<<30 and
         cap["candidate_reserved_once"] is True,"unbound 136 capacity/normal writer seal")
    return ar,a,qr,q

def release(q,iid):
    rr,v=immutable(RECEIPTS/"parent-release.json")
    reg=checked(v["status_registration"]); sr=reg["status_receipt"];event=checked(sr)
    reqref,req=immutable(RECEIPTS/"parent-status-request.json")
    cap=checked(v["post_prefire_capacity"])
    prior=checked(event["previous_receipt"])
    need(v["schema"]=="horizon-epoch136-actual-parent-release-v1" and v["unit"]==UNIT and v["invocation_id"]==iid and
         v["writer_invocation_id"]==q["writer_invocation_id"] and v["writer"]==q["writer"] and v["node_spawn_authorized"] is True and
         v["initialize_authorized"] is False and v["positive_worker_release_still_required"] is True and req["admission"]==q["admission"] and
         req["ready"]==v["ready"] and req["launch"]==v["launch"] and req["writer_plan"]==q["writer_plan"] and
         req["payload_plan"]==q["plan"] and req["invocation_id"]==iid and reg["request"]==reqref and reg["invocation_id"]==iid and
         reg["ordinary_replay_claim"] is False and reg["authenticated_readback"] is True and
         sr["path"]==str(STATUS_ROOT/f"event-136-waiting-{iid}"/"RECEIPT.json") and event["epoch"]==136 and
         event["request"]==reqref and event["producer_invocation_id"]==iid and event["current_repair_owner"]=="/root" and
         event["authenticated_readback"] is True and event["after_status"]["phase"]=="verification" and event["conditional_header"]=="If-Match" and
         event["before_etag"]==prior["after_etag"] and event["before_sha256"]==prior["after_sha256"] and event["before_status"]==prior["after_status"] and
         event["after_etag"] and event["after_etag"] != event["before_etag"] and
         cap["writer_invocation_id"]==q["writer_invocation_id"] and cap["candidate_reserved_once"] is True and
         cap["candidate_data_bytes"]==LIMIT and cap["exclusive_handoff_receipt"]==q["donor"],"invalid 136 positive node handoff/status chain")
    return dict(release=rr,waiting_status=sr,registered_fleet=reg["fleet_receipt"],post_prefire_capacity=v["post_prefire_capacity"])

def terminal(r,iid):
    need(r["schema"]=="jetstreamer-epoch136-actual-20261120-result-v1" and r["epoch"]==136 and r["unit"]==UNIT and
         r["invocation_id"]==iid and r["node"]==tools("jetstreamer-node",NODE) and r["worker_sha256"]==WORKER and
         r["bootstrap"]==59176548 and r["output_slot_start"]==59176549 and r["terminal_root_slot"]==59183944 and
         r["output_slot_count"]==7396 and r["excluded_epoch_slots"]==55 and
         r["original_repair_backlog_open"] is True and r["cgroup_descendants_empty"] is True and
         all(r[k] is False for k in ("full_epoch_span_proven","ordinary_replay_claim","canonical_sidecar_authorized","publication_authorized","local_retirement_authorized","r2_mutations","remote_mutations")),
         "foreign 136 terminal or canonical promotion")
    if r["success"]:
        need(r["entry_released"] is True and r["final_complete_root_meter"]["complete"] and r["output"] is not None,"successful bounded result missing output custody")

def verified_entry(entry,child,current,iid):
    w=child["worker"]; node=child["node"]; witnessed=entry["worker"]
    need(entry["schema"]=="jetstreamer-epoch136-actual-20261120-entry-v1" and entry["invocation_id"]==iid and
         entry["node_pid"]==node["pid"] and entry["node_start_ticks"]==node["start_ticks"] and
         all(witnessed[k]==w[k] for k in ("pid","start_ticks","exe")) and witnessed["sha256"]==WORKER and
         entry["slot_count"]==7396 and entry["bootstrap"]==59176548 and entry["end"]==59183944 and entry["first"]==59176549 and
         entry["publication_authorized"] is False and entry["restoration_claimed"] is False and
         len(current["workers"])==1 and current["workers"][0][0]==w["pid"] and 0<current["workers"][0][1]<=3500000,"136 guarded entry/worker differs")
    need(len(entry["guard"]["sample"]["workers"])==1 and entry["guard"]["sample"]["workers"][0][0]==w["pid"] and
         entry["guard"]["sample"]["producer_invocation_id"]==iid and entry["guard"]["sample"]["plan_sha256"]==current["plan"]["sha256"],"first worker guard does not bind to entry")

def observation():
    group=members(); ap=ROOT/"admission.json"
    n=native(UNIT,("Id","ActiveState","SubState","InvocationID","MainPID","NRestarts","Job","ControlGroup","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec"))
    if not ap.exists() and not group:
        need(n["MainPID"]=="0" and not n["Job"] and n["ActiveState"]=="inactive" and not (ROOT/"parent-launch-request.json").exists()
             and not RUN.exists(),"136 has a footprint without admission")
        return None
    ar,a,qr,q=admission()
    row=dict(epoch=136, admission=ar,writer_request=qr,writer_plan=q["writer_plan"],writer_iid=q["writer_invocation_id"],
             capacity=a["resource_accounting"],observer_config=None,positive_worker=False,ordinary_replay_claim=False,
             archive_publication_authorized=False,resource_credit_bytes=0,canonical_replay_claimed=False,transaction_replay_claimed=False)
    if not group:
        need(not n["Job"] and n["MainPID"]=="0" and n["ActiveState"] in ("failed","inactive"),"136 task/queue transition")
        if (RECEIPTS/"result.json").exists():
            tr,v=immutable(RECEIPTS/"result.json");launch=content(RECEIPTS/"launch.json")
            need(launch["admission"]==ar and launch["plan"]==q["plan"],"unbound terminal launch")
            terminal(v,launch["invocation_id"])
            if v["entry_released"] is True:row.update(release(q,launch["invocation_id"]))
            return dict(row,phase="terminal-success" if v["success"] else "terminal-failure",result=tr,active_at_capture=False)
        phase="admitted-awaiting-native-start" if int(time.time())<q["launch_expires_unix_seconds"] and not (RECEIPTS/"launch.json").exists() else "drained-without-result"
        return dict(row,phase=phase,active_at_capture=False)
    iid=n["InvocationID"];pid=int(n["MainPID"])
    need(re.fullmatch("[0-9a-f]{32}",iid) and n["ActiveState"]=="active" and n["SubState"]=="running" and n["NRestarts"]=="0" and
         n["Id"]==UNIT and n["ControlGroup"]==GROUP and n["MemoryMax"]==str(68<<30) and n["MemorySwapMax"]=="0" and n["CPUQuotaPerSecUSec"]=="3s" and pid in group and
         (ROOT/"tools/epoch136-actual-payload").samefile(f"/proc/{pid}/exe") and Path(f"/proc/{pid}/cgroup").read_text().strip()=="0::"+GROUP,"136 supervisor identity or limits")
    owner_ticks=ticks(pid)
    argv=Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    expected=[q["helper"]["path"],q["plan"]["path"],"--plan-sha256",q["plan"]["sha256"],"--self-sha256",HELPER,"--admission",ar["path"],"--admission-sha256",ar["sha256"],""]
    need(argv==[v.encode() for v in expected],"wrong 136 native argv")
    row.update(active_at_capture=True,unit=n,native_start_ticks=owner_ticks,phase="staging-before-guard")
    child=children(group,pid)
    if not (RECEIPTS/"ready.json").exists():
        need(not child,"136 children before ready");return row
    pp,pending=immutable(PARENT/q["writer_invocation_id"]/"PARENT_LAUNCHED.json")
    intent=checked(pending["intent"])
    need(pending["unit"]==UNIT and pending["invocation_id"]==iid and pending["pid"]==pid and pending["start_ticks"]==owner_ticks and
         pending["ordinary_replay_claim"] is False and pending["worker_initialize_authorized"] is False and
         intent["request"]==qr and intent["admission"]==ar and intent["writer_plan"]==q["writer_plan"] and
         intent["payload_plan"]==q["plan"] and intent["writer_deployment"]==checked(q["writer_plan"])["controller_deployment"],"wrong parent native launch evidence")
    row["parent_launch"]=pp
    ready_ref,ready=immutable(RECEIPTS/"ready.json")
    launch=checked(ready["launch"])
    need(ready["invocation_id"]==iid and ready["pid"]==pid and ready["start_ticks"]==owner_ticks and ready["unit"]==UNIT and
         ready["helper"]==a["helper"] and ready["node_spawned"] is False and ready["worker_spawned"] is False and launch["admission"]==ar
         and launch["plan"]==q["plan"] and launch["pid"]==pid and launch["start_ticks"]==owner_ticks,"foreign 136 ready/launch")
    current=guard(n,a["protected_existing_free_bytes"]); row.update(guard=current,ready=ready_ref)
    if not (RECEIPTS/"parent-release.json").exists():
        need(not child and not current["workers"],"children before 136 parent release")
        return dict(row,phase="waiting-status-and-post-fit")
    row.update(release(q,iid))
    if not (RECEIPTS/"entry.json").exists():
        return dict(row,phase="guarded-before-worker-authorization",children=child)
    er,entry=immutable(RECEIPTS/"entry.json"); need("worker" in child and "node" in child,"entry worker no longer present")
    verified_entry(entry,child,current,iid)
    w=child["worker"];node=child["node"]
    w["sha256"]=worker_digest(w)
    need(members().issuperset({pid,w["pid"],node["pid"]}) and ticks(pid)==owner_ticks,"136 changed during attestation")
    cfg=dict(range="136",producer_unit=UNIT,controller_unit=UNIT,expected_producer_invocation_id=iid,
             expected_controller_invocation_id=iid,scratch_path=str(RUN/"scratch"),worker_executable_basename="historical-worker")
    return dict(row,phase="private-worker-authorized",positive_worker=True,entry=er,children=child,observer_config=cfg)

def freeze(c):
    path=c.paths["out"]/"PRIVATE136_OBSERVATION.json"
    if not path.exists():
        try:
            row=observation()
        except (ValueError,KeyError,OSError,subprocess.SubprocessError,IndexError,TypeError) as error:
            # Keep the complete incumbent chain and all retained reservations. A
            # failed attestation cannot promote a scratch worker to a seventh owner.
            previous=c.fleet.get(FIELD)
            prior=checked(previous)["row"] if previous else {}
            row=dict(epoch=136,phase="evidence-unavailable",reason=str(error)[:1200],positive_worker=False,
                     resource_credit_bytes=0,ordinary_replay_claim=False,canonical_replay_claimed=False,transaction_replay_claimed=False,
                     archive_publication_authorized=False,observer_config=None,previous_observation=previous,
                     capacity=prior.get("capacity"),post_prefire_capacity=prior.get("post_prefire_capacity"))
        if row is None:
            need(FIELD not in c.fleet,"136 admission disappeared without terminal custody")
            return None
        ensure_dir(c.paths["out"])
        durable(path,dict(schema="horizon-private136-cycle-v1",sample=c.sample_ref,fleet=c.fleet_ref,
                          observed_at_unix_seconds=int(time.time()),row=row))
    doc=content(path)
    need(doc["schema"]=="horizon-private136-cycle-v1" and doc["sample"]==c.sample_ref and doc["fleet"]==c.fleet_ref,
         "foreign private 136 cycle")
    return dict(receipt=bound(path),**doc["row"])

def active(row):
    return int(row is not None and row.get("positive_worker") is True)

def previous(f):
    rows=[r for r in f.get("actual_active_private_diagnostics",[]) if r["epoch"]==136]
    saved=f.get(FIELD)
    if saved is None:
        need(not rows,"unbound previous 136 row");return 0
    doc=checked(saved)
    need(doc["sample"]==f["observer"] and doc["fleet"]==f["previous_Root_operational_review"] and
         len(rows)==active(doc["row"]) and all(r["receipt"]==saved and r["canonical_replay_claimed"] is False and
         all(r[k]==doc["row"][k] for k in ("entry","children","admission","post_prefire_capacity","native_start_ticks","unit")) for r in rows),
         "previous 136 observation/count mismatch")
    return len(rows)

def interpret(c,lane_progress):
    row=c.private136
    old=[r for r in c.cfg["diagnostic_replays"] if r["range"]=="136"]
    samples=[r for r in c.sample["diagnostic_replays"] if r["range"]=="136"]
    need(len(old)==len(samples)<=1,"private 136 configured/sample count")
    legacy=old==[OLD_CONFIG]
    if legacy:
        seen=samples[0]
        need(all(seen[k]==OLD_CONFIG[k] for k in ("range","producer_unit","expected_producer_invocation_id","scratch_path")) and
             seen["ordinary_replay_claim"] is False and seen["publication_authorized"] is False and seen["r2_mutations"] is False and
             seen["status"]=="unavailable" and seen["observation"] is None,"historical 136 diagnostic changed")
    if not row:
        need(not old or legacy,"unexpected prior private 136 sample");return
    if old and not legacy:
        seen=samples[0]
        need(all(old[0][k]==seen[k] for k in ("range","producer_unit","expected_producer_invocation_id","scratch_path"))
             and old[0]["producer_unit"]==UNIT and old[0]["scratch_path"]==str(RUN/"scratch") and
             seen["ordinary_replay_claim"] is False and seen["publication_authorized"] is False and seen["r2_mutations"] is False,
             "foreign scheduled 136 observation")
        row["scheduled_status"]=seen["status"];row["scheduled_config"]=old[0]
        if active(row) and seen["status"]=="observed":
            n=row["unit"]; worker=row["children"]["worker"]; result=seen["observation"]
            need(old[0]==row["observer_config"],"136 native worker replaced during sample")
            measured=lane_progress(result,old[0],n["InvocationID"],int(n["MainPID"]),private_journal=True)
            both=all(result.get(k,{}).get("matching_workers")==1 and result[k].get("pid")==worker["pid"] and
                     result[k].get("executable")==worker["exe"] and result[k].get("executable_beneath_bound_scratch") is True
                     for k in ("worker_before","worker_after"))
            work=result["useful_work"]
            endpoints_in_span=all(59176549<=(work.get(k) or {}).get("slot",0)<=59183944 for k in ("first","last"))
            row["transaction_replay_claimed"]=bool(measured and both and endpoints_in_span)
            row["observed_progress"]=result["useful_work"]
    if legacy:row["historical_observer_config"]=OLD_CONFIG
    elif c.fleet.get(FIELD):
        previous=next((r for r in c.fleet["actual_active_private_diagnostics"] if r["epoch"]==136),{})
        if previous.get("historical_observer_config")==OLD_CONFIG:row["historical_observer_config"]=OLD_CONFIG
    selected=row["observer_config"] if active(row) else row.get("historical_observer_config")
    if old:
        c.next_cfg["diagnostic_replays"]=[selected if r["range"]=="136" else r for r in c.next_cfg["diagnostic_replays"] if r["range"]!="136" or selected]
    elif selected:
        c.next_cfg["diagnostic_replays"].append(selected)

def install(c,f):
    row=c.private136
    if not row:return
    need(not any(r["epoch"]==136 for r in f["actual_executing_replays"]+f["actual_active_bootstraps"]),"bounded 136 became canonical")
    f[FIELD]=row["receipt"]
    f["actual_active_private_diagnostics"]=[r for r in f["actual_active_private_diagnostics"] if r["epoch"]!=136]
    count=active(row)
    if count:f["actual_active_private_diagnostics"].append(row)
    f["active_private_diagnostic_count"]+=count;f["active_producer_count"]+=count
    item=next(r for r in f["epochs"] if r["epoch"]==136)
    need(item["current_status"]["phase"]=="verification" and item["current_repair_owner"]=="/root" and item["repair_open"],
         "136 bounded qualification cannot change phase or close repair")
    item.pop("current_private_diagnostic",None)
    item.update(private136_phase=row["phase"],private136_observation=row["receipt"],no_live_producer_claimed=not bool(count))
    if count:item["current_private_diagnostic"]=row

def status_fields(c, epoch=None):
    row=c.private136
    if row is None:return {}
    out={FIELD:row["receipt"]}
    if epoch==136:
        out.update(private136_phase=row["phase"],epoch_useful_work=row.get("observed_progress"),
                   measured_canonical_progress=False,private_transaction_progress=bool(row.get("transaction_replay_claimed")))
        if active(row):out["producer_invocation_id"]=row["unit"]["InvocationID"]
    return out
