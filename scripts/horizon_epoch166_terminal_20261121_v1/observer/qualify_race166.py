"""Exercise the unmodified four-row native sample across a hypothetical late 166 commit."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

pkg, predecessor, complete, scratch=map(Path,sys.argv[1:])
sys.path.insert(0,str(pkg))
import closed166, race166, reconcile, status
from cycle import Cycle
from evidence import bound,checked,content,durable

old=bound(predecessor);fleet=content(complete);sample=checked(fleet["observer"])
c=Cycle(old["path"],old["sha256"],fleet["observer"]["sha256"])
assert c.historical166 is None and c.next_cfg==checked(fleet["sole_next_observer"])
registered=copy.deepcopy(c.cfg);live=checked(race166.LIVE_REF)
node,worker=race166.original(live);assert node and worker
# Exercise the same Linux pidfd on our short-lived child; no producer is signalled.
with subprocess.Popen(["/usr/bin/sleep","0.15"]) as child:
    p=Path("/proc")/str(child.pid)
    st=(p/"exe").stat()
    role=dict(pid=child.pid,start_ticks=int((p/"stat").read_text().rsplit(")",1)[1].split()[19]),
              exe=str((p/"exe").readlink()),identity=dict(device=st.st_dev,inode=st.st_ino))
    group=(p/"cgroup").read_text().strip().removeprefix("0::")
    before=time.monotonic();race166.await_exit(role,group,2);child.wait();assert time.monotonic()-before<2

scratch.mkdir(mode=0o700,exist_ok=True)
archive={"path":"/fixture/epoch-166.jet","size":100000000000,"device":1,"inode":2,"sha256":"ab"*32}
start=int(c.now.timestamp());end=start+77
terminal=scratch/"private-terminal.json"
durable(terminal,dict(epoch=166,producer_invocation_id=race166.IID,live=race166.LIVE_REF,canonical_r2_verified=False,
                     resource_credit_bytes=0,local_archive=archive,manager_terminal={"__REALTIME_TIMESTAMP":str(end*1000000+1)}))
term=bound(terminal)
with (patch.object(race166,"original",return_value=(False,False)),patch.object(race166,"terminal",return_value=term)):
    c.terminal166=closed166.native_config(c)
assert c.terminal166==term and c.cfg==registered and c.sample==sample and c.historical166["sample"]==fleet["observer"]
native_binding=c.historical166["sampler"]
assert len(native_binding["invocation"])==32 and native_binding["unit"].endswith(".service")
assert c.historical166["original_166_row"]==sample["replays"][0] and not c.historical166["live_owner_claimed"]
c.owner_fleet=closed166.owner_view(c.fleet,term)
c.rows={e:r for e,r in c.rows.items() if e!=166}
c.native={e:r for e,r in c.native.items() if e!="166"}
select=c.paths["out"]/"observer.json";exists=Path.exists
with patch.object(Path,"exists",lambda p:False if p==select else exists(p)):c.interpret()
assert c.sample==sample and c.cfg==registered and [r["range"] for r in c.next_cfg["replays"]]==["167","170","172"]
assert set(c.lanes)=={167,170,172} and all(r["range"]!="166" for r in c.next_cfg["replays"])
# Simulate permanent real receipts, ambiguous prior PUT, untouched intent, and brand-new keys.
seen=checked(fleet["authenticated_status_audit"])
records={int(k):checked(v) for k,v in seen["receipts"].items()}
class Store:
    def __init__(self):
        self.objects={e:(r["before_etag"],status.body(r["before_status"])) for e,r in records.items()}
        self.puts=[]
    def get(self,e):return self.objects[e]
    def put(self,e,etag,raw):
        assert self.get(e)[0]==etag
        self.puts.append(e);after='"fixture-'+status.digest(raw)+'"'
        self.objects[e]=(after,raw);return after
storage=Store()
old_dir=scratch/"partial-six";old_dir.mkdir(mode=0o700)
out=scratch/"terminal-five";out.mkdir(mode=0o700)
c.original_status_dir=old_dir
for ep in (136,137,141,166):
    r=records[ep];rp=Path(seen["receipts"][str(ep)]["path"])
    ip=rp.with_name(f"epoch-{ep}.intent.json")
    intent=content(ip)
    durable(old_dir/ip.name,intent)
    if ep in (136,137,166):storage.objects[ep]=(r["after_etag"],status.body(r["after_status"]))
    if ep==136:durable(old_dir/rp.name,r)
with (patch.object(c,"unchanged"),patch.object(c,"public_fresh"),
      patch.object(status,"observed_archive",side_effect=lambda c,e:records[e].get("archive_sample"))):
    done=status._publish(c,storage,out,seen["ready_epochs"])
    # Restart the identical cycle; no further PUT is needed.
    snapshot=list(storage.puts);assert status._publish(c,storage,out,seen["ready_epochs"])==done and storage.puts==snapshot
rows=checked(done)["receipts"];assert set(map(int,rows))==set(records)
assert not {136,137}&set(storage.puts) and storage.puts.count(166)==storage.puts.count(141)==1
final=checked(rows["166"]);previous=checked(final["previous_receipt"])
assert previous["after_status"]==records[166]["after_status"] and previous["after_etag"]==records[166]["after_etag"]
assert final["after_status"]["phase"]=="verification" and final["after_status"]["sampled_at_utc"]==race166.status_clock(c.now,end*1000000+1).strftime("%Y-%m-%dT%H:%M:%SZ")
assert final["after_status"]["sampled_at_utc"]!=c.stamp and final["after_status"]["jet_size_bytes"]==archive["size"]
nextfile=scratch/"effective-next.json";durable(nextfile,c.next_cfg)
aggregate=reconcile.assemble(c,done,fleet["continuing_audit_obligation"]["current_observation"],fleet["current_home_cycle_capacity"],bound(nextfile))
assert aggregate["historical166_scheduled_sample_before_local_commit"]==c.historical166
assert aggregate["observer"]==fleet["observer"] and aggregate["sampled_at_utc"]==fleet["sampled_at_utc"]
assert aggregate["canonical_producer_count"]==fleet["canonical_producer_count"]-1==3
assert aggregate["active_producer_count"]==fleet["active_producer_count"]-1
assert aggregate["active_private_diagnostic_count"]==fleet["active_private_diagnostic_count"]
assert aggregate.get("terminal168_trace_mismatch")==fleet.get("terminal168_trace_mismatch")
assert [r["epoch"] for r in aggregate["actual_active_private_diagnostics"]]==[r["epoch"] for r in fleet["actual_active_private_diagnostics"]]
assert len(aggregate["effective_status_receipts"])==19
for k in ("complete_DATA_bytes","complete_projected_memory_bytes","all_reservation_ending_bytes","additional_independent166_DATA_cap_bytes"):
    assert aggregate[k]==fleet[k]
def denied(call):
    try:call()
    except (ValueError,AssertionError):return
    raise AssertionError("invalid input accepted")
saved=c.sample
for mutation in ("missing","extra","wrong-worker","wrong-clock"):
    bad=copy.deepcopy(saved)
    if mutation=="missing":bad["replays"].pop()
    if mutation=="extra":bad["replays"].append(bad["replays"][0])
    if mutation=="wrong-worker":bad["replays"][0]["worker_before"]["pid"]=1
    if mutation=="wrong-clock":bad["cadence"]["previous_sample"]="/another/sample"
    c.sample=bad;denied(lambda:race166.original_row(c,live,term))
c.sample=saved
cfg=dict(registered,output=str(scratch/"native-output"))
with patch.object(race166,"original",return_value=(True,False)):
    race166.after_failure(1,"failed to read maps for worker "+str(live["native"]["worker"]["pid"]),cfg,live,registered["replays"][0])
    denied(lambda:race166.after_failure(1,"unrelated epoch 170 failure",cfg,live,registered["replays"][0]))
    (scratch/"native-output").write_text("{")
    denied(lambda:race166.after_failure(1,race166.TARGET,cfg,live,registered["replays"][0]))
# Run the actual dispatch control flow with a disjoint scheduled filesystem and
# process images. Only the sampler subprocess, terminal producer and exec are
# substituted. Its error evidence must name this original failed attempt.
from types import SimpleNamespace
fake=scratch/"registered";(fake/"sealed-next").mkdir(parents=True)
cfg=dict(registered,output=str(scratch/"never-started.json"))
origin=c.fleet["sole_next_observer"];kept=[]
class EnteredSelector(Exception):pass
def exec_record(program,args):
    kept.append(args);raise EnteredSelector
with (patch.object(race166,"validate_scheduled",return_value=(cfg,c.fleet_ref,origin)),
      patch.object(race166,"tool",return_value={"mode":"original","config":origin}),
      patch.object(race166,"original",side_effect=[(True,True),(False,False)]),
      patch.object(race166,"terminal",return_value=term),
      patch.object(race166.subprocess,"run",return_value=SimpleNamespace(returncode=1,stderr=race166.TARGET.encode())),
      patch.object(race166.os,"execv",side_effect=exec_record)):
    try:race166.dispatch(fake/"sealed-next/observer.json")
    except EnteredSelector:pass
    else:raise AssertionError("one real selector was not reached")
failure=checked(bound(fake/"after-166-race/FAILED_NATIVE.json"))
assert len(kept)==1 and kept[0][1]=="dispatch-cadence" and failure["terminal"]==term and failure["output_absent"]
with (patch.object(race166,"validate_scheduled",return_value=(cfg,c.fleet_ref,origin)),
      patch.object(race166,"original",return_value=(True,False)),patch.object(race166,"terminal",return_value=term) as waited,
      patch.object(race166.os,"execv",side_effect=exec_record)):
    try:race166.dispatch(fake/"sealed-next/observer.json")
    except EnteredSelector:pass
    else:raise AssertionError("parent-only handoff was lost")
    waited.assert_called_once()
assert len(kept)==2
print(json.dumps(dict(original_four_row_sample=fleet["observer"],native_manager=native_binding,rows_preserved=len(sample["replays"]),
                     all_status_readbacks=len(rows),actual_fleet_fields=len(fleet),applied_private_puts=storage.puts,
                     disjoint_pidfd_exit=True,late_commit_effective_status=final["after_status"],refused_incomplete=True,
                     original_clock_and_all_bookings_preserved=True,production_writes=0)))
