"""Join the recovered epoch 166 commit to the same scheduled native sample and R2 refresh."""
import os
from pathlib import Path
import select
import subprocess
import sys
import time

import closure
from evidence import SEALER, bound, checked, durable, ensure_dir, lock, need, sealed, utc

SEAL=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
REGISTRY="original_disk_guard_recovery_workers"

def transition(fleet):
    existing=fleet.get(closure.FIELD)
    if not (closure.T/"TERMINAL_SUCCESS.json").exists():
        need(existing is None and not closure.DONE.exists(),"registered 166 terminal disappeared")
        return None
    proof=closure.inspect() if closure.DONE.exists() else closure.retire()
    previous=fleet.get(REGISTRY,{}).get("166")
    if existing is not None:
        need(existing==proof["terminal"] and previous is None,"competing registered closure or worker")
    else:
        need(previous and previous["actor"]["producer_unit"]==closure.UNIT and previous["actor"]["producer_invocation_id"]==closure.IID and
             previous["admission"]==proof["admission"] and previous["first_worker"]==proof["first_worker"],"different preceding epoch 166")
    return proof

def projected(cfg,original):
    rows=[r for r in cfg["replays"] if r["range"]=="166"]
    need(rows==[original] and original["producer_unit"]==closure.UNIT and original["expected_producer_invocation_id"]==closure.IID,
         "scheduled worker differs from committed epoch 166")
    return dict(cfg,replays=[r for r in cfg["replays"] if r["range"]!="166"])

def select_config(cfg,path,fleet_ref,fleet,proof):
    if not proof:return cfg,path
    original=checked(proof["first_worker"])["observer_row"]
    if not any(r["range"]=="166" for r in cfg["replays"]):
        need(fleet.get(closure.FIELD)==proof["terminal"],"live predecessor omitted its recovered worker")
        return cfg,path
    if fleet.get(closure.FIELD):
        need(fleet.get("recovered166_preselected_config")==bound(path),"unregistered historical next config")
    effective=projected(cfg,original)
    folder=Path(fleet_ref["path"]).parent/"after-recovered166"
    ensure_dir(folder);guard=lock(folder/"selection.lock")
    try:
        dest=folder/"sealed-next";p=folder/"observer.json"
        durable(p,effective)
        durable(folder/"selection.json",dict(terminal=proof["terminal"],guard_retirement=proof["guard_retirement"],
                fleet=fleet_ref,previous_sample=fleet["observer"],upstream=bound(path),removed=original,projected=bound(p)))
        plan=folder/"seal-plan.json"
        durable(plan,dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(dest),
                          members=[dict(name=p.name,source=str(p),sha256=bound(p)["sha256"],mode=0o444)]))
        if not dest.exists():
            subprocess.run([SEAL,plan,"--plan-sha256",bound(plan)["sha256"],"--self-sha256",SEALER],check=True,stdout=subprocess.DEVNULL)
        selected=dest/p.name;need(sealed(bound(selected))==effective,"different terminal projection")
        return effective,selected
    finally:os.close(guard)

def historical(c,cfg,proof):
    from race166 import successful_sample
    original=checked(proof["first_worker"])["observer_row"]
    live=checked(proof["live"])
    rows=[r for r in c.sample["replays"] if r["range"]=="166"]
    need(len(rows)==1 and original in cfg["replays"] and checked(c.sample_ref)==c.sample and
         c.sample_ref["path"]==cfg["output"] and c.sample["cadence"]["previous_sample_sha256"]==c.fleet["observer"]["sha256"] and
         rows[0]["scratch_path"]==original["scratch_path"]==live["private_scratch"]["path"] and rows[0]["invocation_binding_stable"] and
         original["append_log"]==live["producer_log"],"different historical sample")
    row=rows[0]
    for edge in ("before","after"):
        p=row["producer_"+edge];w=row["worker_"+edge]
        need(p["unit"]==closure.UNIT and p["invocation_id"]==closure.IID and p["main_pid"]==live["native"]["parent"]["pid"] and
             p["restarts"]==0 and p["active_state"]=="active" and w["pid"]==live["native"]["worker"]["pid"] and
             w["matching_workers"]==1 and w["executable"]==live["native"]["worker"]["exe"] and w["executable_beneath_bound_scratch"],
             "foreign source in successful historical sample")
    end=int(checked(proof["terminal"])["manager_terminal"]["__REALTIME_TIMESTAMP"])
    need(utc(c.sample["recorded_at_utc"]).timestamp()*1e6<=end,"terminal predates active sample")
    return dict(sample=c.sample_ref,sampler=successful_sample(c),original_166_row=row,terminal=proof["terminal"])

def select_cycle(c,cfg,path):
    proof=transition(c.fleet)
    c.recovered166=proof
    c.recovered166_history=None
    ranges=lambda x:[r["range"] for r in x["replays"]]
    if proof and "166" in ranges(c.sample):
        need(ranges(cfg)==ranges(c.sample) and not c.fleet.get(closure.FIELD),"incomplete historical roster")
        c.recovered166_history=historical(c,cfg,proof)
        c.original_status_dir=c.paths["statuses"]
        c.paths["statuses"]=c.original_status_dir/"after-recovered166"
        return cfg
    selected,_=select_config(cfg,path,c.fleet_ref,c.fleet,proof)
    need(ranges(selected)==ranges(c.sample),"scheduled native survivor set differs")
    return selected

def dispatch(cfg,path,fleet_ref,fleet,native):
    """Retry a failed scheduled sample only across the authenticated 166 exit."""
    proof=transition(fleet)
    prepared,selected=select_config(cfg,path,fleet_ref,fleet,proof)
    if proof or not any(r["range"]=="166" for r in prepared["replays"]):
        os.execv(native,[native,selected])
    response=subprocess.run([native,selected],stderr=subprocess.PIPE)
    if not response.returncode:return
    text=response.stderr.decode(errors="replace")
    original=next(r for r in cfg["replays"] if r["range"]=="166")
    first=checked(fleet[REGISTRY]["166"]["first_worker"])
    if (Path(cfg["output"]).exists() or len(text)>65536 or
        not any(s in text for s in [closure.UNIT,original["scratch_path"],str(first["worker_pid"])])):
        sys.stderr.write(text)
        raise ValueError("scheduled observer failed outside the recovered 166 transition")
    # The batch can arrive after the worker exits. Watch the terminal directory without resampling any replay.
    from terminal_event import Changes
    changes=Changes()
    try:
        changes.watch(closure.T);deadline=time.monotonic()+1800
        if not (closure.T/"TERMINAL_SUCCESS.json").exists():
            pid=Path("/proc")/str(first["worker_pid"])
            need(not pid.exists() or int((pid/"stat").read_text().rsplit(")",1)[1].split()[19])!=first["worker_start_ticks"],
                 "the original worker still occupies the failed sample")
        while not (closure.T/"TERMINAL_SUCCESS.json").exists():
            left=deadline-time.monotonic()
            need(left>0 and select.select([changes.fd],[],[],left)[0],"recovered 166 terminal not recorded")
            os.read(changes.fd,65536)
    finally:changes.close()
    proof=transition(fleet);need(proof and not Path(cfg["output"]).exists(),"foreign completed observation")
    _,selected=select_config(cfg,path,fleet_ref,fleet,proof)
    os.execv(native,[native,selected])

def forecast(c,old,prior):
    from delivery_eta import prepare
    from race166 import status_clock
    proof=c.recovered166
    t=checked(proof["terminal"]);a=t["local_archive"]
    end=int(t["manager_terminal"]["__REALTIME_TIMESTAMP"])
    clock=status_clock(c.now,end)
    prior_time=utc(old["sampled_at_utc"])
    age=round((clock-prior_time).total_seconds()*1000)
    quote=prepare(c,166,a["size"],committed=True)
    need(age>=0,"newer recovered terminal status")
    if prior.get(closure.FIELD)==proof["terminal"]:
        remain=old["estimated_remaining_millis"]-age
    else:
        need(prior.get("producer_invocation_id")==closure.IID and old["phase"] in ("replay","verification"),
             "status predecessor belongs to another producer")
        remain=end//1000+quote["total_millis"]-round(clock.timestamp()*1000)
    need(remain>0,"fresh committed-source delivery estimate required")
    return (dict(old,sampled_at_utc=clock.strftime("%Y-%m-%dT%H:%M:%SZ"),phase="verification",jet_size_bytes=a["size"],
                 estimated_remaining_millis=remain,elapsed_execution_millis=old["elapsed_execution_millis"]+age),a)

def install(fleet,c):
    proof=c.recovered166
    if not proof:return
    need("166" not in fleet[REGISTRY] and not any(r["epoch"]==166 for k in ("actual_executing_replays","actual_active_bootstraps") for r in fleet[k]),
         "closed epoch still owns a lane")
    fleet[closure.FIELD]=proof["terminal"]
    fleet["recovered166_guard_retirement"]=proof["guard_retirement"]
    previous=c.fleet[REGISTRY].get("166")
    if previous:fleet["historical_recovered166_worker"]=previous
    if c.recovered166_history:fleet["historical_recovered166_observation"]=c.recovered166_history
    if any(r["range"]=="166" for r in c.next_cfg["replays"]):
        need(c.recovered166_history is not None and sealed(fleet["sole_next_observer"])==c.next_cfg,
             "unexpected preselected next config")
        fleet["recovered166_preselected_config"]=fleet["sole_next_observer"]
    else:fleet.pop("recovered166_preselected_config",None)
    row=next(r for r in fleet["epochs"] if r["epoch"]==166)
    row.pop("current_replay",None);row.pop("current_bootstrap",None)
    row.update(current_repair_owner="/root",no_live_producer_claimed=True,state="verification",repair_open=True,
               recovered166_local_commit=proof["terminal"],current_status_scope="Recovered epoch 166 committed locally and awaits full verification and public delivery.")


def retry_cycle(path,sha,sample_sha):
    from cycle import load_fleet
    from evidence import names
    from types import SimpleNamespace
    fleetref=dict(path=str(path),sha256=sha)
    fleet,cfg,_=load_fleet(fleetref)
    from guard_stops import select
    cfg,_=select(cfg,fleetref,fleet)
    paths=names(cfg["not_before_utc"]);sample=dict(path=str(paths["sample"]),sha256=sample_sha)
    need(not (paths["out"]/"ROOT_COMPLETE_OPERATIONAL_FLEET.json").exists(),"fleet already accepted")
    c=SimpleNamespace(fleet=fleet,cfg=cfg,sample_ref=sample,sample=checked(sample))
    proof=transition(fleet)
    need(proof is not None,"recovered epoch 166 still active")
    historical(c,cfg,proof)
    consumer=Path(__file__).with_name("consume")
    from race166 import properties
    pid=properties("horizon-archive-status-cadence-after172-20261120-v1.service","MainPID")["MainPID"]
    proc=Path("/proc")/pid
    need((proc/"fd/255").samefile(consumer) and (proc/"fd/9").samefile(closure.R/"stable-cadence-controller-20261120-v1/consumer.lock")
         and " FLOCK " in (proc/"fdinfo/9").read_text() and Path("/proc/self/cgroup").read_bytes()==(proc/"cgroup").read_bytes(),
         "retry requires the original single cadence consumer")

if __name__=="__main__":
    need(os.geteuid()==0 and __debug__ and len(sys.argv)==5 and sys.argv[1]=="retry-cycle","expected the registered failed cycle")
    retry_cycle(Path(sys.argv[2]),sys.argv[3],sys.argv[4])
