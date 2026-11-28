"""Project the released, guarded epoch 167 price through the two existing native replay owners."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

G = 1 << 30
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
WRITER = RT / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v34-entry146/status_cycle.py"
BASE = RT / "epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1"
RETRY = RT / "epoch167-checkpoint-bounded-20261127-v2"
BRIDGE = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service"
PREFIX = "horizon-170-preserved-prefix-readonly-20261127-v1.service"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def call(*args):
    return subprocess.check_output(args, text=True, timeout=35)


def show(unit, fields):
    out = subprocess.run(["/usr/bin/systemctl","show","--all","-p",",".join(fields),"--",unit],
                         capture_output=True,text=True,timeout=8)
    obj = dict(line.split("=",1) for line in out.stdout.splitlines())
    need(out.returncode in (0,4) and obj.get("Id")==unit and all(k in obj for k in fields), "unit changed: "+unit)
    return obj


def peers(row):
    unit=row["unit"]
    procs=row["processes"]
    kernel=Path("/sys/fs/cgroup/system.slice")/unit
    need(sorted(map(int,(kernel/"cgroup.procs").read_text().split()))==sorted(p[0] for p in procs)
         and int((kernel/"memory.max").read_text())==68*G and int((kernel/"memory.swap.max").read_text())==0,
         "incumbent group or memory changed: "+unit)
    pss=0
    for pid, ticks, dev, ino in procs:
        proc=Path("/proc")/str(pid)
        m=(proc/"exe").stat()
        tick=int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19])
        need((tick,m.st_dev,m.st_ino)==(ticks,dev,ino) and (proc/"cgroup").read_text().strip()=="0::/system.slice/"+unit,
             "incumbent process changed")
        pss+=1024*int(next(v.split()[1] for v in (proc/"smaps_rollup").read_text().splitlines() if v.startswith("Pss:")))
    memory=dict((s,int(v)) for s,v in (line.split() for line in (kernel/"memory.stat").read_text().splitlines()))
    return min(pss,memory["anon"]+memory["file_mapped"],68*G)


def protected(row,plan_ref,goal,timer_iid,when):
    plan=checked(plan_ref)
    unit=row["unit"]
    manager=show(unit,("Id","ActiveState","MainPID","InvocationID","Job"))
    need(manager["ActiveState"]=="active" and manager["InvocationID"]==plan["invocation_id"] and not manager["Job"]
         and manager["MainPID"]==str(row["processes"][0][0]) and plan["unit"]==unit and plan["filesystem"]=="/home/sol",
         "incumbent identity or plan changed")
    timer=unit.replace("-qualify-","-guard-").replace(".service",".timer")
    tm=show(timer,("Id","ActiveState","InvocationID","Triggers","Job"))
    need(tm["ActiveState"]=="active" and tm["InvocationID"]==timer_iid and not tm["Job"]
         and tm["Triggers"]==timer.replace(".timer",".service"),"incumbent guard timer changed")
    dir=Path(plan["receipt_directory"])
    need(not (dir/"stop-intent.json").exists(),"guard trip: "+unit)
    paths=sorted(dir.glob("sample-*.json"),key=lambda path:path.stat().st_mtime_ns,reverse=True)
    current_ref=bound(paths[0])
    current=checked(current_ref)
    def values(s):
        w=s["root_physical_observation"]
        need(s["plan_sha256"]==plan_ref["sha256"] and s["producer_invocation_id"]==manager["InvocationID"]
             and s["producer"]["pid"]==row["processes"][0][0] and s["trip_reason"] is None and s["producer_stop_enabled"]
             and s["worker_observation_error"] is s["root_physical_observation_error"] is None
             and len(s["workers"])==1 and s["workers"][0][0]==row["processes"][1][0]
             and not w["exceeds_budget"] and s["minimum_free_bytes"]==plan["minimum_free_bytes"]
             and s["available_bytes"]>=plan["minimum_free_bytes"],"foreign incumbent guard sample")
        return [w[k]["physical_bytes"] for k in ("first","second")]
    lower=min(values(current))
    need(0<=time.time()-current["recorded_unix_seconds"]<=120,"stale incumbent guard")
    # Anchor the price in the exact native predecessor input and both neighboring samples.
    # This covers an incumbent shrinking between accepted pricing and the new guard.
    anchor=checked(goal)
    upper=max(values(anchor)) if abs(anchor["recorded_unix_seconds"]-when)<=120 else 0
    previous=[]
    for p in paths:
        t=p.stat().st_mtime
        if t<when-120:
            break
        if t<=when+60:
            s=checked(bound(p))
            upper=max(upper,*values(s))
            previous.append(s["recorded_unix_seconds"])
    need(any(t<=when for t in previous) and any(t>=when for t in previous), "unbracketed original guard")
    return max(0,upper-lower),current_ref,lower


def successor_fleet(release_ref, current_ref, fleet, intent, release, actor, processes):
    if current_ref == release_ref:
        return
    origin = checked(release_ref)
    sample = checked(fleet["observer"])
    cadence = sample["cadence"]
    need(cadence["previous_sample"] == origin["observer"]["path"]
         and cadence["previous_sample_sha256"] == origin["observer"]["sha256"]
         and cadence["routine_minimum_interval_enforced"] and cadence["minimum_interval_seconds"] == 1800,
         "fleet is not the direct accepted successor of the released 167 price")
    cfg = checked(origin["sole_next_observer"])
    # The first cadence after launch enrolls this route in the following observer.
    candidate = fleet[retry.FIELD]
    need(candidate["phase"] == "worker" and candidate["actor"] == actor
         and candidate["processes"] == processes and candidate["intent"] == intent
         and candidate["release"] == release and candidate["observer"] == fleet["observer"]
         and fleet["actual_active_private_diagnostics"] == [candidate]
         and not retry.assigned(cfg) and candidate["resource_credit_bytes"] == candidate["reservation_ending_bytes"] == 0,
         "released 167 is absent from the accepted fleet")
    for key in ("complete_DATA_bytes","complete_projected_memory_bytes",
                "current_full172_admission","current_full172_post_guard_fit","cold170_full_metered_guard_stop"):
        need(fleet[key] == origin[key], "changed fleet commitment: "+key)
    previous_holding = checked(origin["epoch185_lanel_holding"])
    current_holding = checked(fleet["epoch185_lanel_holding"])
    need(current_holding["schema"] == previous_holding["schema"]
         and current_holding["result"] == previous_holding["result"]
         and current_holding["observer"] == fleet["observer"] and current_holding["fleet"] == release_ref,
         "185 private restore or holding commitments changed")
    for key in ("current_joint168_checkpoint","current_bounded167_checkpoint"):
        need(fleet[key]["phase"] == origin[key]["phase"] == "terminal"
             and fleet[key]["actor"] == origin[key]["actor"], "changed retained producer: "+key)
    old, current = origin["active_ready_range_audit_obligation"], fleet["active_ready_range_audit_obligation"]
    for k in ("additional_cpu_quota_micros","additional_memory_bytes","maximum_output_allocation_bytes",
              "cargo_growth_allowance_bytes","archive_staging_bytes"):
        need(current[k] == old[k], "audit reservation changed: "+k)
    def replay_owners(f):
        return sorted((r["epoch"],r["unit"]["Id"],r["unit"]["InvocationID"],r["unit"]["MainPID"],
                       r["start_ticks"],r["admission"]["sha256"]) for r in f["actual_executing_replays"])
    need(replay_owners(fleet) == replay_owners(origin) and fleet["actual_active_bootstraps"] == [],
         "fleet acquired another production owner")


def project(request, held):
    ref=request["fleet"]
    fleet=checked(ref)
    original=checked(request["native_reference"])
    released,epoch167,post=retry.bound_release(bound(retry.INTENT))
    need(released==request["released167"]
         and request["writer"]==post["native"]["writer_binding"] and post["native"]["provider"]==request["capacity_deployment"]
         and post["phase"]=="post-guard" and post["resource_credit_bytes"]==0 and post["archive_publication_authorized"] is False
         and original["mode"]=="terminal",
         "released 167 is outside the accepted pricing cycle")
    intent,payload,operator=retry.launched_intent(bound(retry.INTENT))
    manager=retry.route.props(retry.UNIT,retry.MANAGER)
    processes,worker=retry.native_owner(manager,epoch167,payload,operator)
    guard,observed=retry.current_guard(intent,epoch167,post,worker)
    need(worker and observed,"bounded 167 is missing its protected worker")
    successor_fleet(post["native"]["fleet"], ref, fleet, bound(retry.INTENT), released, epoch167, processes)
    base=original["full146"]["native_successor_quote"]
    original170=checked(base["retained_170"]["admission"])
    need(base["retained_170"]["admission"] == fleet["cold170_full_metered_guard_stop"]["admission"]
         and original170["producer_unit"] == "horizon-qualify-170-full-metered-20261124-v1.service",
         "foreign original epoch 170 compute reservation")
    prepared=checked(checked(original170["intent"])["prepared"])["profile"]
    argv=prepared["actor"]["producer_argv_after_protection"]
    need("--property=MemoryMax=73014444032" in argv and "--property=CPUQuota=900%" in argv
         and prepared["guard"]["cap_bytes"] == 384*G and prepared["guard"]["worker_root"] == base["bookings"]["170"]["root"]
         and prepared["guard"]["producer_unit"] == original170["producer_unit"], "epoch 170 compute envelope changed")
    old=original["replacement167_fit"]
    settlement=original["terminal168_compute_settlement"]
    compute=old["compute"]
    need(original["full146"]["retained_185_restore_overlap_bytes"]==123350028052
         and original["full146"]["retained_185_restore_enlargement_bytes"]==54016054271
         and settlement["released_memory_bytes"]==54*G and compute["post_replacement_memory_plus_reserve_bytes"]==782740762624
         and compute["complete_cpu_quota_micros"]==64000000 and old["admitted_producer_bytes"]==42*G
         and old["admitted_guard_bytes"]==G and old["resource_credit_bytes"]==0
         and original["archive_publication_authorized"] is False
         and old["required_available_memory_bytes"]==compute["post_replacement_memory_plus_reserve_bytes"]
             -sum(compute["incumbent_guarded_resident_lower_bounds"].values())+60*G-settlement["released_memory_bytes"]
         and base["bookings"]["170"]["cap_bytes"]==384*G and base["retained_170"]["reservation_ending_bytes"]==0
         and base["retained_170"]["booking"]==base["bookings"]["170"]
         and fleet["all_reservation_ending_bytes"]==fleet["resource_credit_bytes"]==0
         and fleet["actual_active_holding_transfers"]==fleet["actual_active_retirements"]==[]
         and not fleet["actual_active_retirement_checks"], "complete incumbent obligations changed")
    selector=settlement["active_selector"]
    s=show(selector["unit"],("Id","MainPID","ActiveState","InvocationID","MemoryMax","CPUQuotaPerSecUSec","Job"))
    need(s["ActiveState"]=="active" and not s["Job"] and s["InvocationID"]==selector["invocation_id"]
         and int(s["MainPID"])==selector["pid"] and s["MemoryMax"]==str(4*G) and s["CPUQuotaPerSecUSec"]=="1s",
         "paid 168 selector changed")
    pref=show(PREFIX,("Id","MainPID","ActiveState","InvocationID","MemoryMax","CPUQuotaPerSecUSec","Job"))
    need(not pref["Job"] and ((pref["ActiveState"]=="inactive" and pref["MainPID"]=="0") or
         (pref["ActiveState"]=="active" and pref["InvocationID"]=="571a66120c14464590918ba19158186e"
          and pref["MemoryMax"]==str(2*G) and pref["CPUQuotaPerSecUSec"]=="1s")), "170 prefix changed")
    r146=original["full146"]["active_full146"]
    r172=base["survivors"]["172"]
    exact146=checked(post["native"]["current_full146_request"])["guard"]
    need(set(post["native"]["population"])=={r146["unit"],r172["unit"],retry.UNIT}, "incomplete original population")
    rosters={p["unit"]:p["processes"] for p in (r146,r172)}
    rosters[retry.UNIT]=processes
    if held:
        who=checked(bound(BASE/"BRIDGE_ACTOR.json"))
        state=bridge.native.props(BRIDGE,bridge.PROPS)
        held_procs,child=bridge.live_owner(bridge.interface(),state,who,False)
        need(child is None,"170 escaped the gate")
        rosters[BRIDGE]=held_procs
    units={line.split()[0] for line in call("/usr/bin/systemctl","list-units","--type=service","--state=running,activating,deactivating",
                                             "--plain","--no-legend","horizon-qualify-*").splitlines() if line}
    need(units==set(rosters),"foreign active replay unit")
    allowed={str(p[0]) for ps in rosters.values() for p in ps}
    for p in Path("/proc").iterdir():
        if not p.name.isdigit() or p.name in allowed: continue
        try:
            name=(p/"comm").read_text().strip()
            if name=="jetstreamer-r2":
                need(not any(b"holding-" in arg for arg in (p/"cmdline").read_bytes().split(b"\0")),"occupied private holding")
            need(not name.startswith(("jetstreamer-nod","historical-work")),"foreign replay process")
        except (FileNotFoundError,ProcessLookupError):
            continue
    samples={}
    losses=0
    residents=0
    for x,pr,gr,ti in ((r146,exact146["plan"],exact146["sample"],exact146["timer_invocation_id"]),
                       (r172,r172["guard"]["plan"],r172["guard"]["guard"],r172["timer_invocation_id"])):
        need([p[:2] for p in x["processes"]]==post["native"]["population"][x["unit"]],"incumbent changed since release")
        loss,sample,lower=protected(x,pr,gr,ti,post["native"]["recorded_unix_seconds"])
        residents+=min(peers(x),peers(x))
        losses+=loss
        samples[x["unit"]]=dict(sample=sample,lower=lower,additional_growth=loss)
    # Rebook the *full* metadata allowances of the active audit, private selector
    # and serial holding transport. Their historical credits are unnecessary.
    metadata=fleet["active_ready_range_audit_obligation"]["current_storage"]["maximum_host_allocation_bytes"]+16*(1<<20)+(2<<20)
    need(metadata==274*(1<<20),"ancillary disk promises changed")
    frozen=max(post["native"]["strongest_floor"],post["native"]["incumbent_home"])+losses+metadata
    # The accepted incumbent obligation includes the entire remaining 384 GiB
    # booking for the *same* epoch 170 tree; the bridge spends 40 GiB of it.
    book=base["bookings"]["170"]
    need(book["physical_bytes"]+book["remaining_bytes"]==book["cap_bytes"] and book["remaining_bytes"]>=40*G
         and old["candidate_guard_counterfactual"]["original_epoch170_remaining_bytes"]==book["remaining_bytes"],
         "bridge increment is not covered by the existing epoch 170 booking")
    remaining=guard["run_guard_cap_bytes"]-guard["run_physical_bytes"]
    need(remaining>=0 and guard["floor"]==intent["armed_floor"] and checked(guard["sample"])["trip_reason"] is None,
         "bad bounded 167 remaining growth")
    return dict(when=int(time.time()),aggregate=frozen-40*G,aggregate_with_entire_170_booking=frozen,old170_book=book,armed167=guard["floor"],growth167=remaining,
                required_ram=compute["post_replacement_memory_plus_reserve_bytes"]+6*G-residents,
                fleet=ref,release=released,checked_samples=samples,incumbent_guard=guard,
                credit_bytes=0,tracked_processes=rosters)


if __name__=="__main__":
    runpy.run_path(str(WRITER))["entry"]()
    import bounded167_status_v2 as retry
    import bridge170_status as bridge
    from evidence import bound,checked
    req=checked({"path":sys.argv[1],"sha256":sys.argv[2]})
    print(json.dumps(project(req,sys.argv[3]=="held"),sort_keys=True))
