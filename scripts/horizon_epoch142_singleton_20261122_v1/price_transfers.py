"""Offline epoch 142 alternatives from an observed same-image price and existing grants model."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import runpy


R = Path("/var/lib/jetstreamer/horizon_runtime_data")
Q = R / "epoch142-full-local-20261122-v1"
G = 1 << 30
MODEL = R / "actual-retry1-074010-dependent-forecast-20261122-v1/MODEL.json"
P = R / "incident-replay-fit-20261121-v1"
NATIVE = P / "V23_NATIVE_ACTIVE_074010.json"
N = R / "epoch142-next-lane-20261122-v1"


def ref(path):
    return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def read(reference, expected=None):
    p = Path(reference["path"])
    if expected is not None and p != expected or p.resolve(strict=True) != p or ref(p) != reference:
        raise ValueError("different bound input " + str(p))
    return json.loads(p.read_bytes())


def fixed(path, digest):
    return read(dict(path=str(path),sha256=digest))


def candidate_shape():
    handoff = fixed(Q/"FULL_REPLAY_HANDOFF.json","a2eec5cfc92192dde08470d8c65c0f0125761196cdc6536931e66cd367f35342")
    route = read(handoff["route"],Q/"ROUTE.json")
    qual = read(handoff["qualification"],Q/"NORMAL_ENTRY_QUALIFIED.json")
    sel = read(handoff["selection"],Q/"CANDIDATE_SELECTION.json")
    snap = route["snapshot"]
    path, outer = Path(snap["source"]),Path(snap["outer_image"])
    sealed = read(route["qualified_snapshot"])
    m = path.lstat()
    assert path.resolve(strict=True)==path and (m.st_dev,m.st_ino,m.st_size) == (snap["device"],snap["inode"],snap["length"])
    assert m.st_uid==0 and m.st_mode&0o222==0 and snap["sha256"]==qual["complete_digest"]["sha256"]==sealed["sha256"]
    assert (os.major(m.st_dev),os.minor(m.st_dev)) == (7,3)
    assert Path("/sys/block/loop3/loop/backing_file").read_text().strip()==str(outer) and outer.stat().st_ino==snap["outer_inode"]
    assert sealed["generation"]==snap["generation"] and qual["route"]==handoff["route"] and route["copy_bytes"]==0
    assert route["mandatory_root"]==61775538 and route["full_output_slot_range"]==[61344000,61775999]
    assert set(k for k,v in sel["candidates"].items() if v.get("snapshot_local"))=={"142"} and handoff["selected"]==142
    shape=handoff["funding"]
    guard=read(shape["qualified_guard_shape"])
    test=fixed(N/"guard-fixture/QUALIFIED.json","127cd9a077349e54ae92cf439e0b5bda79353c4a3197cca656a1bf930873ec55")
    plan=read(test["source_plan"]);sample=read(test["cases"]["protective-pass"]["sample"])
    assert guard["plan_sha256"]==test["source_plan"]["sha256"] and sample["guard_sha256"]==guard["self_sha256"]
    assert Path(route["run_parent"]).parent == Path(plan["worker_root"])
    assert sample["maximum_root_physical_bytes"]==plan["maximum_root_physical_bytes"]==shape["whole_tree_home_cap"]
    assert sample["workers"]==[] and test["holder_exe"]=="/usr/bin/sleep" and not test["production_replay_started"]
    demand=dict(disk=shape["whole_tree_home_cap"], memory=shape["actor_memory"]+shape["guard_memory"],
                cpu=(shape["actor_cores"]+shape["guard_cores"])*1000000)
    assert demand==dict(disk=288*G,memory=69*G,cpu=10000000)
    return demand,dict(handoff=ref(Q/"FULL_REPLAY_HANDOFF.json"),candidate_selection=handoff["selection"],
        staged_snapshot=route["qualified_snapshot"],normal_entry=handoff["qualification"],route=handoff["route"],
        guard_fixture=ref(N/"guard-fixture/QUALIFIED.json"),candidates={k:v["current_gate"] for k,v in sel["candidates"].items()},
        bytes_staged=snap["length"],new_copy_bytes=0,outer_inode=snap["outer_inode"],source_inode=m.st_ino)


def gaps(row, demand, free_disk, free_memory, ram):
    return dict(disk=max(0,row["protected"]+demand["disk"]-free_disk),
                committed_memory=max(0,row["committed_memory_before_candidate"]+demand["memory"]-ram),
                available_memory=max(0,row["required_available_memory_before_candidate"]+demand["memory"]-free_memory),
                cpu=max(0,row["committed_cpu_micros_before_candidate"]+demand["cpu"]-64000000))


def model():
    demand, candidate=candidate_shape()
    sched=fixed(MODEL,"fb6f289306654814642c73fd83a883e3bb5e5d74b60f8146fdb9b071a9bb5030")
    paid=read(sched["live_mirror_price"])
    native=fixed(NATIVE,"28c3fd1948b8316ea840120b6bacf47bd815c6efec8f0d8ba3799b1eb82d7f41")
    transfer=sched["conditional_transition"]
    assert paid["native"]["phase145"]["window"]["recovery"]==native["phase145"]["window"]["recovery"]
    assert paid["mirrors_fit"] and native["fits"] and paid["resource_credit_bytes"]==0 and not paid["admission_granted"]
    assert paid["fleet"]==native["fleet"]==sched["native_fleet"] and paid["semantic_worker"]==sched["actual_retry_worker"]
    assert transfer["actual_grants"]==transfer["actual_new_physical_release_bytes"]==0
    fleet=read(native["fleet"]);sample=read(fleet["observer"]);ram=sample["host_memory"]["total_kib"]*1024
    status={int(k):read(v) for k,v in sched["active_statuses"].items()}
    deadlines={n:int(dt.datetime.fromisoformat(status[n]["after_status"]["sampled_at_utc"].replace("Z","+00:00")).timestamp()*1000+.5)
                 +status[n]["after_status"]["estimated_remaining_millis"] for n in (166,167,168,170,172)}
    closures={int(n):t for n,t in transfer["native_terminal_and_guard_drain_forecasts"].items()}
    assert set(closures)==set(deadlines)
    available=min(transfer["measured_free_HOME_lower_bound"],paid["available_HOME_bytes"],native["available_HOME_bytes"])
    available_memory=min(transfer["measured_free_memory_lower_bound"],native["available_memory_bytes"])
    reserve=transfer["ready_growth_bytes"]+paid["missing_mirror_bytes"];prefix=native["remaining_prefix140_bytes"]
    assert 0<=prefix<=16<<20 and 0<=transfer["ready_growth_bytes"]<=256<<20 and paid["missing_mirror_bytes"]==transfer["missing_mirror_bytes"]
    v4=R/"epoch199-delivery-recovery-20261121-v1/phase-transition-v4"
    seal=fixed(v4/"deployment-seal-receipt.json","91e7a02eec6d52c55ee6dc1b2b43b1586235ec47c6aa44f9c7d6b07909f59f57")
    def member(name):
        p=v4/name;entry,=(m for m in seal["members"] if m["name"]==name)
        assert ref(p)["sha256"]==entry["sha256"]
        return runpy.run_path(str(p))
    budget=member("transition_budget.py");route=member("forecast_routes.py")
    assert all(status[e]["producer_invocation_id"]==budget["GENERATIONS"][e] for e in closures)
    prior=fixed(R/"epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json","803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc")
    args=(fleet,read(native["registered_host_equation"]["source"]),prior["protected_raw_floor_bytes"],ram,budget)
    actual=dict(native,available_HOME_bytes=available,available_memory_bytes=available_memory)
    full=route["price_rows"](actual,*args)
    zero=route["price_rows"](dict(actual,candidate136=dict(actual["candidate136"],remaining=0)),*args)
    provider=transfer["registered_floor_provider"];path=Path(provider["path"])
    assert ref(path)==provider and provider["sha256"]=="7ffc1925f72164c4b8e4cd7139e040f5e9134db10bcac4c2dbf3974d0d9bae9b"
    registered=runpy.run_path(str(path))["post145_floor"]
    assert full[0]["complete_protected_HOME_bytes"]==native["native_before_registered_floor"] and zero[0]["complete_protected_HOME_bytes"]==native["zero_candidate_floor"]
    grants=set(transfer["exclusive_grants"]);assert grants=={166,168,170,172}
    joint=dict(disk=448*G,memory=153*G,cpu=8000000)
    combined={k:demand[k]+v for k,v in joint.items()}
    rows=[]
    for row,z in zip(full,zero,strict=True):
        assert all(row[k]==z[k] for k in ("closed","transferred","private169_closed","retained_growth_bytes"))
        assert set(row["transferred"])<=set(row["closed"]) and set(row["retained_growth_bytes"])==set(row["transferred"])
        assert all(v>=16<<20 for v in row["retained_growth_bytes"].values())
        copy={k:row[k] for k in ("closed","transferred","private169_closed","actual_unspent_transferred_bytes",
                "retained_growth_bytes","absolute_surviving_floor_bytes","committed_memory_before_candidate",
                "required_available_memory_before_candidate","committed_cpu_micros_before_candidate")}
        copy["protected"]=registered(row["complete_protected_HOME_bytes"],z["complete_protected_HOME_bytes"],
                                     actual["candidate136"],prefix)+reserve
        copy["142_gaps"]=gaps(copy,demand,available,available_memory,ram)
        copy["142_and_199200_gaps"]=gaps(copy,combined,available,available_memory,ram)
        rows.append(copy)
    assert len(rows)==486 and rows[0]["protected"]==native["complete_required_HOME_bytes"]+reserve
    assert all(r["142_gaps"]["cpu"]==10000000 for r in rows if not r["transferred"])
    assert all(r["142_gaps"]["cpu"]>=2000000 and r["142_gaps"]["committed_memory"]>0 for r in rows if len(r["transferred"])==1)
    closed_no_grants=next(r for r in rows if r["private169_closed"] and set(r["closed"])==set(closures) and not r["transferred"])
    assert closed_no_grants["142_gaps"]["committed_memory"]==rows[0]["142_gaps"]["committed_memory"]
    choices=[]
    for alternative in transfer["alternatives"]:
        case=alternative["case"]
        assert len(set(case["sources"]))==len(case["sources"])
        for scenario in ("142_only","142_preserving_joint"):
            eligible=[];key="142_gaps" if scenario=="142_only" else "142_and_199200_gaps"
            for row in rows:
                gr=set(row["transferred"])
                if 166 in gr or 167 in gr:
                    if scenario=="142_only":continue  # protect 173/141 owner routes
                if scenario=="142_preserving_joint" and gr!=grants:continue
                g=row[key]
                if any(g[k] for k in ("cpu","committed_memory","available_memory")) or g["disk"]>case["net_bytes"]:continue
                start=max(case["ready_ms"],*[closures.get(e,0) for e in row["closed"]],*[deadlines[e] for e in gr],
                          transfer["focused169_private_endpoint_ms"] if row["private169_closed"] else 0)
                if set(row["closed"])!={e for e,t in closures.items() if t<=start}:continue
                if row["private169_closed"]!=(transfer["focused169_private_endpoint_ms"]<=start):continue
                eligible.append((start,len(gr),tuple(sorted(gr)),row))
            best=min(eligible,key=lambda item:item[:3]) if eligible else None
            choices.append(dict(case=case,scenario=scenario,eligible=len(eligible),start_ms=best[0] if best else None,
                                row=best[-1] if best else None))
    current=rows[0];selected=next(r for r in rows if r["private169_closed"] and set(r["closed"])==set(closures)
                                  and set(r["transferred"])==grants)
    def dated_grant(owners):
        start=max(deadlines[e] for e in owners)
        row=next(r for r in rows if set(r["transferred"])==set(owners) and
                 set(r["closed"])=={e for e,t in closures.items() if t<=start} and
                 r["private169_closed"]==(transfer["focused169_private_endpoint_ms"]<=start))
        return dict(expected_grant_ms=start,row=row)
    two=dated_grant((168,170)); three=dated_grant((168,170,172))
    later={int(k):dict(lane=v["proposed_lane"],publication_ms=v["absolute_forecast_ms"]) for k,v in sched["models"].items()
           if v.get("proposed_lane") in three["row"]["transferred"]}
    serial_earliest=max(sched["models"]["200"]["absolute_forecast_ms"],*(r["publication_ms"] for r in later.values()))
    serial=dict(planned_predecessors=later,also_wait_for_199_and_200_publication=True,conditional_lower_bound_ms=serial_earliest,
                projected_data_margin_before_new_tails=available-three["row"]["protected"]-demand["disk"],
                projected_available_memory_margin_before_new_tails=available_memory-three["row"]["required_available_memory_before_candidate"]-demand["memory"],
                continue_to_book_all_physical_outputs_and_repair=True,
                actual_requirements=["All 168/170/172 donor owners finish and transfer named residuals after guard drain and publication.",
                                     "199/200 and every listed scheduled dependent relinquish the same residuals to 142. All intermediate actual usage, repairs and retained archive bodies must be included at handback.",
                                     "Reserve the entire 142 envelope only on a fresh accepted capacity and registered producer/guard/staged-input identity."])
    return dict(candidate=candidate,epoch142_demand=demand,joint_199200_demand=joint,capacity_model=ref(MODEL),
                observed_mirrors=sched["live_mirror_price"],observed_native=ref(NATIVE),fleet=paid["fleet"],integrity_provider=provider,available_home_lower_bound=available,
                available_memory_lower_bound=available_memory,host_ram=ram,reserved_audit_growth_and_mirrors=reserve,
                original_136_unspent=actual["candidate136"]["remaining"],prefix_140_growth=prefix,
                current=current,all_native_drained_without_grants=closed_no_grants,
                existing_joint_four_grants_condition=selected,cases=choices,rows_priced=len(rows),
                first_168_170_publication=two,first_168_170_172_publication=three,after_existing_joint_and_standby=serial,
                real_grants=0,real_released_HOME_bytes=0,admission_granted=False,
                basis="Each row independently reprices surviving guards, retained repair and publication growth. All future physical retirements and exclusive grants require controller receipts. The 142-only alternative competes with 199/200. The joint alternative reserves both candidates against the same four grants once. Dates represent capacity prerequisites, with producer/guard drainage, audit registration and a fresh launch fit required.")


if __name__=="__main__":
    print(json.dumps(model(),sort_keys=True,indent=2))
