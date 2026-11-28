"""Qualify a patched publisher against its authenticated predecessor and private scenarios."""
import argparse
import copy
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

p=argparse.ArgumentParser();p.add_argument("package",type=Path);p.add_argument("fleet",type=Path);p.add_argument("sha");p.add_argument("scratch",type=Path);a=p.parse_args()
sys.path.insert(0,str(a.package))
import private136 as q
from cycle import load_fleet
from evidence import bound, checked
ref=bound(a.fleet)
assert ref["sha256"]==a.sha and os.geteuid()==0
f,cfg,prior=load_fleet(ref)
assert len(prior["receipts"])==19 and f["active_producer_count"]==6 and q.previous(f)==0
assert q.observation() is None
old136=checked(prior["receipts"]["136"])
assert old136["after_status"]["phase"]=="verification"
# These interfaces are shared by the original cadence and current public archive audit.
for name in ("public_witness.py","audit_handoff.py","consume","run-cycle.sh","focused169.py","private168.py","full172.py","replay167_event.py"):
    deployed=Path("/var/lib/jetstreamer/horizon_runtime_data/public-audit73-observer-20261121-v1/observer-package")/name
    assert (a.package/name).read_bytes()==deployed.read_bytes(),name

def denied(fn):
    try: fn()
    except (ValueError,AssertionError,KeyError):return
    raise AssertionError("invalid case passed")

iid="1"*32
config=dict(range="136",producer_unit=q.UNIT,controller_unit=q.UNIT,expected_producer_invocation_id=iid,
            expected_controller_invocation_id=iid,scratch_path=str(q.RUN/"scratch"),worker_executable_basename="historical-worker")
def snap(phase,positive=False):
    return dict(epoch=136,phase=phase,receipt=dict(path="/synthetic/capture",sha256="a"*64),
        positive_worker=positive,canonical_replay_claimed=False,ordinary_replay_claim=False,
        archive_publication_authorized=False,resource_credit_bytes=0,
        transaction_replay_claimed=False,observer_config=config if positive else None,unit={"InvocationID":iid,"MainPID":"290"},
        children=dict(worker=dict(pid=292,exe=str(q.RUN/"scratch/nested/historical-worker"))))
for state in (None,"staging-before-guard","waiting-status-and-post-fit","guarded-before-worker-authorization","private-worker-authorized","terminal-success","terminal-failure","drained-without-result","evidence-unavailable"):
    pos=(state=="private-worker-authorized"); row=snap(state,pos) if state else None
    sample=checked(f["observer"])
    c=SimpleNamespace(private136=row,cfg=cfg,fleet=f,sample=sample,next_cfg=copy.deepcopy(cfg))
    assert [r for r in cfg["diagnostic_replays"] if r["range"]=="136"]==[q.OLD_CONFIG]
    q.interpret(c,None)
    assert [r for r in c.next_cfg["diagnostic_replays"] if r["range"]=="136"]==([config] if pos else [q.OLD_CONFIG])
    assert [r for r in c.next_cfg["diagnostic_replays"] if r["range"]!="136"]==[r for r in cfg["diagnostic_replays"] if r["range"]!="136"]
    trial=copy.deepcopy(f);q.install(c,trial)
    for key in ("actual_executing_replays","actual_active_bootstraps","canonical_producer_count","useful_replay_count","complete_DATA_bytes",
                 "complete_projected_memory_bytes","all_reservation_ending_bytes","continuing_audit_obligation","effective_status_receipts"):
        assert trial[key]==f[key],(state,key)
    assert trial["active_producer_count"]==6+int(pos) and trial["active_private_diagnostic_count"]==2+int(pos)
    assert [r for r in trial["actual_active_private_diagnostics"] if r["epoch"]!=136]==f["actual_active_private_diagnostics"]
    assert next(r for r in trial["epochs"] if r["epoch"]==136)["current_status"]==old136["after_status"]
    fields=q.status_fields(c,136)
    assert fields.get("producer_invocation_id")== (iid if pos else None)
# Exercise the real native shape and multiple independent failure gates.
n={"MainPID":"290","InvocationID":iid};plan={"sha256":"f"*64};gid="2"*32
sample=dict(schema="jetstreamer-horizon-standalone-guard-sample-v1",guard_invocation_id=gid,producer_invocation_id=iid,
 producer=dict(invocation_id=iid,pid=290,active="active",sub="running",cgroup=q.GROUP,restarts=0),
 guard_sha256=q.GUARD_SHA,plan_sha256=plan["sha256"],producer_stop_enabled=True,minimum_free_bytes=100,
 maximum_root_physical_bytes=64<<30,maximum_worker_vmas=3500000,trip_reason=None,worker_observation_error=None,
 root_physical_observation_error=None,root_physical_observation=dict(exceeds_budget=False,conservative_physical_bytes=30),
 available_bytes=1000,recorded_unix_seconds=550)
q.guard_shape(sample,gid,n,plan,100,600)
for key,wrong in (("guard_sha256","0"*64),("producer_stop_enabled",False),("trip_reason","disk"),("available_bytes",99),("recorded_unix_seconds",400)):
    denied(lambda:q.guard_shape(dict(sample,**{key:wrong}),gid,n,plan,100,600))
# Entry and current guard must independently bind the same real historical worker.
w=dict(pid=292,start_ticks=91,exe=str(q.RUN/"scratch/nested/historical-worker"))
children={"worker":w,"node":{"pid":291,"start_ticks":90}}
g=dict(workers=[[292,100]],plan=plan)
entry=dict(schema="jetstreamer-epoch136-actual-20261120-entry-v1",invocation_id=iid,node_pid=291,node_start_ticks=90,
    worker=dict(w,sha256=q.WORKER),slot_count=7396,bootstrap=59176548,first=59176549,end=59183944,
    publication_authorized=False,restoration_claimed=False,guard={"sample":dict(sample,workers=[[292,100]])})
q.verified_entry(entry,children,g,iid)
for e,child,gu in ((dict(entry,slot_count=432000),children,g),(dict(entry,worker=dict(w,sha256="0"*64)),children,g),
    (dict(entry,node_start_ticks=9),children,g),(dict(entry,restoration_claimed=True),children,g),
    (entry,children,dict(g,workers=[])),(entry,children,dict(g,workers=[[292,100],[293,99]]))):
    denied(lambda:q.verified_entry(e,child,gu,iid))
# A real subsequent native sample can prove progress only for both matched worker endpoints.
row=snap("private-worker-authorized",True)
expected={"range":"136","producer_unit":q.UNIT,"expected_producer_invocation_id":iid,"scratch_path":config["scratch_path"],
          "ordinary_replay_claim":False,"publication_authorized":False,"r2_mutations":False,"status":"observed"}
wr={"pid":292,"executable":row["children"]["worker"]["exe"],"matching_workers":1,"executable_beneath_bound_scratch":True}
own={"unit":q.UNIT,"invocation_id":iid,"main_pid":290,"active_state":"active","sub_state":"running","restarts":0}
work={"journal_invocation_id":iid,"sufficient_for_rates":True,"elapsed_seconds":61,"slot_delta":5,"transaction_delta":5,
      "first":{"realtime_microseconds":10,"slot":59176550,"transactions":10},"last":{"realtime_microseconds":20,"slot":59176555,"transactions":15}}
observed={"range":"136","scratch_path":config["scratch_path"],"invocation_binding_stable":True,"producer_before":own,"producer_after":own,
          "worker_before":wr,"worker_after":wr,"useful_work":work}
from cycle import observed_lane
for later,first_slot,expected_progress in ((wr,59176550,True),(dict(wr,pid=999),59176550,False),
                                           (dict(wr,matching_workers=0),59176550,False),(wr,59176548,False)):
    proposed=copy.deepcopy(observed)
    proposed["useful_work"]["first"]["slot"]=first_slot
    snap_row=copy.deepcopy(row);conf=dict(cfg,diagnostic_replays=[config])
    c=SimpleNamespace(private136=snap_row,cfg=conf,fleet=f,next_cfg=copy.deepcopy(conf),
                      sample={"diagnostic_replays":[dict(expected,observation=dict(proposed,worker_after=later))]})
    q.interpret(c,observed_lane);assert snap_row["transaction_replay_claimed"] is expected_progress
result=dict(schema="jetstreamer-epoch136-actual-20261120-result-v1",epoch=136,unit=q.UNIT,invocation_id=iid,
            bootstrap=59176548,output_slot_start=59176549,terminal_root_slot=59183944,node=q.tools("jetstreamer-node",q.NODE),worker_sha256=q.WORKER,
            output_slot_count=7396,excluded_epoch_slots=55,original_repair_backlog_open=True,cgroup_descendants_empty=True,
            full_epoch_span_proven=False,ordinary_replay_claim=False,canonical_sidecar_authorized=False,publication_authorized=False,
            local_retirement_authorized=False,r2_mutations=False,remote_mutations=False,success=False)
q.terminal(result,iid)
q.terminal(dict(result,success=True,entry_released=True,final_complete_root_meter={"complete":True},output={"bounded":True}),iid)
denied(lambda:q.terminal(dict(result,full_epoch_span_proven=True),iid))
denied(lambda:q.terminal(dict(result,success=True,entry_released=False),iid))
# Test the additive private count against a future independently qualified
# 166-closed input. This fixture grants no release or admission on that branch.
reduced=copy.deepcopy(f)
reduced["actual_executing_replays"]=[x for x in reduced["actual_executing_replays"] if x["epoch"]!=166]
reduced["active_producer_count"]-=1;reduced["canonical_producer_count"]-=1
canonical=copy.deepcopy(reduced["actual_executing_replays"])
q.install(SimpleNamespace(private136=snap("private-worker-authorized",True)),reduced)
assert reduced["active_producer_count"]==6 and reduced["canonical_producer_count"]==3 and reduced["active_private_diagnostic_count"]==3
assert reduced["actual_executing_replays"]==canonical and reduced["complete_DATA_bytes"]==f["complete_DATA_bytes"]
# Freeze once, survive retries, keep a stale/foreign guard out of positive counts.
with tempfile.TemporaryDirectory(dir=a.scratch) as tmp:
    d=Path(tmp)
    c=SimpleNamespace(fleet=f,fleet_ref=ref,sample_ref=f["observer"],paths={"out":d})
    with patch.object(q,"observation",side_effect=ValueError("stale guard")):
        loss=q.freeze(c)
    assert loss["phase"]=="evidence-unavailable" and not q.active(loss)
    with patch.object(q,"observation",side_effect=AssertionError("resampled")):
        assert q.freeze(c)==loss
    trial=copy.deepcopy(f);trial[q.FIELD]=loss["receipt"];trial["previous_Root_operational_review"]=ref
    assert q.previous(trial)==0
    forged=snap("private-worker-authorized",True)
    trial["actual_active_private_diagnostics"].append(forged)
    denied(lambda:q.previous(trial))
print(json.dumps(dict(source_fleet=ref,actual_absent_baseline=True,original_owners=6,authenticated_status_receipts=19,
    positive_fixture_count=7,phase_fixtures=9,guard_negative_cases=5,entry_negative_cases=6,worker_sample_cases=4,terminal_negative_cases=2,
    scope="bounded private reproduction",unchanged_public_audit_modules=True,remote_mutations=False,production_activation=False)))
