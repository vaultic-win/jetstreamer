"""Exercise actual local receipts, native process disappearance and changed-prefix denials."""
import argparse
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
from unittest.mock import patch

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("package",type=Path);ap.add_argument("scratch",type=Path)
    a=ap.parse_args();source=Path(__file__).parent
    sys.path.insert(0,str(a.package))
    w=load("new_public_witness",source/"public_witness.py");s=load("following",source/"follow_boundary.py")
    o=s.check_parent();reader=s.one_reader();prefix=s.accepted()
    assert reader and reader["pid"]==3598418 and reader["start_ticks"]==358434125 and len(prefix)==73
    pidfd=os.pidfd_open(reader["pid"])
    try:
        pp=select.poll();pp.register(pidfd,select.POLLIN);assert pp.poll(0)==[]
    finally:os.close(pidfd)
    # A descendant reaped between cgroup.procs and /proc/PID/exe must be
    # checked against a fresh membership, and never signals an unknown PID.
    ch=subprocess.Popen(["/bin/true"]);deadfd=os.pidfd_open(ch.pid)
    try:
        po=select.poll();po.register(deadfd,select.POLLIN);assert po.poll(2500)
        ch.wait();assert s.process_image(ch.pid,lambda:set()) is None
        try:s.process_image(ch.pid,lambda:{ch.pid})
        except (FileNotFoundError,ProcessLookupError):pass
        else:raise AssertionError("unresolved live member accepted")
    finally:os.close(deadfd)
    r=s.doc(s.ref(s.REVIEW));previous=s.ref(s.OWNER);native=s.doc(r["native_report"])
    witness_path=a.scratch/"reader.json";rr=s.persist(witness_path,reader)
    manifest=dict(prefix)
    fixture=dict(schema="horizon-public-audit-natural-successor-v2",original_73_review=s.ref(s.REVIEW),
        native_report=r["native_report"],event=r["branch_event"],inventory=r["inventory"],
        accepted_epochs=list(range(73)),accepted_result_sha256=manifest,previous_child_pid=reader["pid"],
        quiescent_reader=rr,fresh_quiescence_unix_seconds=reader["observed_at"]+2,at=reader["observed_at"]+3,
        sole_quiescent_parent=True,recovery_activated_live_reader=False)
    w.recovery_boundary(fixture,previous,native)
    digest="b"*64;new=copy.deepcopy(fixture)
    new["accepted_epochs"].append(73);new["accepted_result_sha256"]["73"]=digest
    real_bound=w.bound
    def mocked(p):
        if p==w.PUBLIC/"results/epoch-73.json":return {"path":str(p),"sha256":digest}
        return real_bound(p)
    with patch.object(w,"bound",mocked):w.recovery_boundary(new,previous,native)
    cases=[dict(fixture,previous_child_pid=12),dict(fixture,recovery_activated_live_reader=True),
           dict(fixture,fresh_quiescence_unix_seconds=0),dict(fixture,accepted_epochs=list(range(72))),
           dict(fixture,sole_quiescent_parent=False),dict(fixture,original_73_review={"path":"wrong","sha256":digest})]
    for wrong in cases:
        try:w.recovery_boundary(wrong,previous,native)
        except ValueError:pass
        else:raise AssertionError("wrong recovery evidence accepted")
    previous_reader=dict(reader, range_start=73,range_end=73,attempt=str(Path(r["native_report"]["path"]).parent.parent),
                         argv=native["invocation"])
    assert s.durable_native(previous_reader)==r["native_report"]
    now=int(s.time.time())
    fake_attempt=a.scratch/"range-73-135-1"
    fake_attempt.mkdir()
    fake_report=fake_attempt/"reports";fake_report.mkdir()
    assert s.durable_native(dict(reader,attempt=str(fake_attempt))) is None
    fake_events=a.scratch/"events";fake_events.mkdir()
    fake_reader=dict(reader,pid=ch.pid,attempt=str(fake_attempt),observed_at=now-20)
    rr2=s.persist(fake_events/"reader-dead.json",fake_reader)
    actual_readproof=s.doc(reader["reader_proof"])
    s.persist(fake_attempt/"branch-change.json",dict(reader_commit=actual_readproof["branch_commit"],completed=1,at=now-12))
    with patch.object(s,"events",return_value=(fake_events,"e"*32)):
        assert s.recent_closed_reader()==(fake_reader,rr2,now-12)
    assert s.cut(dict(reader,attempt=str(fake_attempt)),rr2,now) is False
    # Exercise the full fence logic against a separate native parent. The
    # only live PID eligible for an actual signal in this block is our sleep.
    with subprocess.Popen(["/usr/bin/sleep","20"]) as native_parent:
        with contextlib.ExitStack() as stack:
            def substitute(name,value):stack.enter_context(patch.object(s,name,value))
            def fixed(name,value):
                substitute(name,lambda *args,**kwargs:value)
            substitute("PARENT_PID",native_parent.pid)
            substitute("PARENT_TICKS",s.ticks(native_parent.pid))
            for name,value in (("roster",[]),("check_parent",{}),("must_idle",None),("events",(fake_events,"d"*32)),
                               ("publisher",{}),("peers",[]),("accepted",prefix)):
                fixed(name,value)
            fixed("current_fleet",(r["inventory"],{"continuing_audit_obligation":{"current_observation":r["inventory"]}},
                                   {"timer":"fixture.timer","sample":str(a.scratch/"missing"),"due":"unused"}))
            fixed("unit",{"ActiveState":"active"})
            real_changes=s.reader_changes
            substitute("reader_changes",lambda repo,tip:real_changes(Path("/home/sol/workspace/jetstreamer"),tip))
            renamed=[]
            def run(*args,**options):
                if args[0]=="/usr/bin/git":return s.doc(s.EQUIVALENT_BUILD)["branch_commit"]
                if args[0]=="/usr/bin/date":return str(now+1000)
                if args[-1]=="recovery-facts":
                    return json.dumps(dict(old_row={"MainPID":str(native_parent.pid)},
                                source_comparison={"identical_scoped_paths":400},v14_e2e={},native_independent_trials=[]))
                assert args==("/usr/bin/systemctl","stop",s.UNIT)
                assert "State:\tT" in Path(f"/proc/{native_parent.pid}/status").read_text()
                native_parent.terminate()
            substitute("command",run)
            substitute("finish",lambda draft:renamed.append(s.doc(draft)))
            assert s.cut(previous_reader,rr2,now)
            assert len(renamed)==1 and renamed[0]["closed_retry_native_report"]==r["native_report"]
            native_parent.wait(timeout=2)
    assert s.one_reader()["pid"]==reader["pid"] and s.check_parent()==o
    print(json.dumps(dict(reader=reader,original_review=s.ref(s.REVIEW),genuine_prefix=73,synthetic_prefix=74,
                         rejected=len(cases),real_pidfd_exit=True,live_pidfd_unsignalled=True,disjoint_real_parent_fence=True,actual_historical_report=True,marker_age_preserved=True,owner=o,shared_writes=0)))
