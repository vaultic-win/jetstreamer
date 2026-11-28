"""Private artifact and Linux notification fixtures. The publisher is never executed."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path

src, qa = map(Path, sys.argv[1:])
spec=importlib.util.spec_from_file_location("terminal_event",src)
event=importlib.util.module_from_spec(spec)
spec.loader.exec_module(event)

def denied(fn, exception=Exception):
    try:
        fn()
    except exception:
        return
    raise AssertionError("unexpected admission")

def write(p, data):
    tmp=p.with_suffix(".pending")
    tmp.write_bytes(json.dumps(data).encode())
    os.chmod(tmp,0o600)
    os.replace(tmp,p)
    return event.document(p,0o600)[1]

root=qa/"runtime"; reports=qa/"reports"
root.mkdir();reports.mkdir()
boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
for exe,sha in event.PROGRAMS:
    assert event.member(exe,0o555)[1]["sha256"]==sha
prior=event.DELIVERY/"controller-qa-7f283df27a0e487ba7333a445f52adf6/authority/TERMINAL_SUCCESS.json"
t,prior_ref=event.document(prior,0o400)
archive=t["local_archive"];p=Path(archive["path"]);meta=p.stat()
assert (meta.st_dev,meta.st_ino,meta.st_size)==(archive["device"],archive["inode"],archive["size"]) and meta.st_size<4096
assert hashlib.sha256(p.read_bytes()).hexdigest()==archive["sha256"]
native_commit=Path(t["committed_receipt"]["path"])
assert hashlib.sha256(native_commit.read_bytes()).hexdigest()==t["committed_receipt"]["sha256"]
assert json.loads(native_commit.read_bytes())["transaction_id"]==t["transaction_id"]
assert event.terminal_evidence(prior,lambda:t,boot)==prior_ref
denied(lambda:event.terminal_evidence(prior,lambda:t,"different-boot"),event.Rejected)
denied(lambda:event.terminal_evidence(prior,lambda:dict(t,transaction_id="c"*64),boot),event.Rejected)
denied(lambda:event.terminal_evidence(root/"missing",lambda:t,boot),FileNotFoundError)
stamp=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
tag,day,sample=stamp.strftime("%H%M%S"),stamp.strftime("%Y%m%d"),stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
fd=root/f"root{tag}-live166167170-{day}-v1"
rd=reports/f"cycle{tag}-live166167170-19-{day}-v1"
fd.mkdir();rd.mkdir()
source=event.R/"root094959-live166167170-20261121-v1"/event.FLEET_NAME
original, _=event.document(source,0o600)
# The real report supplies the normal 19 existing receipt bindings.
report,_=event.document(Path(original["authenticated_status_audit"]["path"]),0o600)
report["sampled_at_utc"]=sample
report_ref={"path":str(rd/"COMPLETED.json"),"sha256":hashlib.sha256(json.dumps(report).encode()).hexdigest()}
fleet=dict(owner="/root",sampled_at_utc=sample,recorded_unix_seconds=int(stamp.timestamp()),observer=report["observer"],
           authenticated_status_audit=report_ref,authenticated_status_count=19,all_active_status_reports_authenticated_readback=True)
watch=event.Changes()
scan=lambda now=stamp.timestamp(), head=lambda r:r:event.accepted(root,reports,prior_ref,watch,head,now)
assert scan() is None
fref=write(fd/event.FLEET_NAME,fleet);assert scan() is None
fleet["terminal166_local_commit"]=prior_ref
fref=write(fd/event.FLEET_NAME,fleet);assert scan() is None
def delayed():
    time.sleep(0.15)
    write(rd/"COMPLETED.json",report)
w=threading.Thread(target=delayed);w.start()
deadline=time.monotonic()+5
while not (proof:=scan()):
    assert time.monotonic()<deadline
    watch.wait()
w.join()
assert proof=={"fleet":fref,"report":report_ref}
assert scan(stamp.timestamp()+2401) is None
assert scan(head=lambda r:{"path":"newer","sha256":"x"}) is None
write(rd/"COMPLETED.json",dict(report,authenticated_readback=False))
denied(scan,event.Rejected)
write(rd/"COMPLETED.json",report)
write(fd/event.FLEET_NAME,dict(fleet,terminal166_local_commit=dict(prior_ref,sha256="d"*64)))
denied(scan,event.Rejected)
watch.close()
state=qa/"state";state.mkdir()
calls=[]
def launch(f,s):
    calls.append(f)
    return {"fixture_unit":True}
assert event.submit(state,prior_ref,proof,"private-agent",launch,lambda _:None)=="submitted"
assert event.submit(state,prior_ref,proof,"private-agent",launch,lambda _:None)=="already-submitted-or-uncertain"
assert len(calls)==1
denied(lambda:event.submit(state,dict(prior_ref,sha256="a"*64),proof,"private-agent",launch,lambda _:None),event.Rejected)
uncertain=qa/"uncertain";uncertain.mkdir()
def lost(f,s): raise RuntimeError("private lost manager acknowledgement")
denied(lambda:event.submit(uncertain,prior_ref,proof,"private-agent",lost,lambda _:None))
assert event.submit(uncertain,prior_ref,proof,"private-agent",launch,lambda _:None)=="already-submitted-or-uncertain"
completed=qa/"completed";completed.mkdir()
assert event.submit(completed,prior_ref,proof,"private-agent",launch,lambda _:{"prior_sync":True})=="prior-publication"
assert len(calls)==1
# Confirm the normal handler can authenticate the current parent head locally.
head=event.head(event.document(source,0o600)[1])
actual,_=event.document(Path(head["path"]),0o600)
assert actual["owner"]=="/root" and actual.get("terminal166_local_commit") is None
native=json.loads(event.subprocess.check_output([event.NATIVE,"inspect"],timeout=25))
assert native["outcome"]=="awaiting-original-node-exit" and (native["node_alive"] or native["worker_alive"])
assert not event.TERMINAL.exists()
print(json.dumps({"schema":"private-qualified-166-terminal-publication-event-v1","actual_native_commit":t["committed_receipt"],
    "source_terminal_fixture":prior_ref,"native_original":native,"accepted_head":head,"same_report_count":len(report["receipts"]),
    "private_inotify_late_report":True,"submissions_in_fixture":len(calls),"uncertain_replay_denied":True,
    "boot_mismatch_denied":True,"changed_terminal_and_report_denied":True,"stale_or_missing_fleet_denied":True,
    "prior_controller_completion_denied":True,"real_controller_submissions":0,"r2_mutations":False}))
