"""Read actual cadence inputs and qualify a prospective 136 event entirely on HOME scratch."""
import argparse
import copy
import hashlib
import json
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from datetime import timedelta, timezone

parser = argparse.ArgumentParser()
parser.add_argument("fleet", type=Path)
parser.add_argument("digest")
parser.add_argument("fixture_parent", type=Path)
a = parser.parse_args()
pkg = Path("/var/lib/jetstreamer/horizon_runtime_data/active-delivery-eta-20261121-v1/publisher-v1")
assert hashlib.sha256((pkg/"deployment-seal-receipt.json").read_bytes()).hexdigest() == "d7bb6adb2390bcc534915cb4e78b0e3743ca5de62f481302dac226207bb44e33"
sys.path.insert(0,str(pkg))
import status
from cycle import load_fleet
from evidence import bound, checked, durable, lock, names, utc

f, cfg, cohort = load_fleet({"path":str(a.fleet),"sha256":a.digest})
assert f["active_producer_count"] == 6 and f["all_active_status_reports_authenticated_readback"]
oldref = cohort["receipts"]["136"]
original = checked(oldref)
assert oldref==f["effective_status_receipts"]["136"] and original["current_repair_owner"]=="/root"
old=original["after_status"]
stamp = utc(old["sampled_at_utc"]) + timedelta(seconds=17)
stamp_text=stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
after, archive=status.forecast(SimpleNamespace(stamp=stamp_text,now=stamp,lanes={}),136,old)
assert archive is None and set(after)==set(old)==status.FIELDS and after["phase"]=="verification"
assert after["estimated_remaining_millis"]+17000==old["estimated_remaining_millis"] and after["elapsed_execution_millis"]==old["elapsed_execution_millis"]+17000
assert status.follow_event(136,oldref,original["after_etag"],status.body(old))[0]==oldref
dev = a.fixture_parent.stat().st_dev
home_dev = Path("/home/sol").stat().st_dev
seen = set()
while dev != home_dev:
    assert dev not in seen, "loop backing cycle"
    seen.add(dev)
    backing = Path("/sys/dev/block") / f"{os.major(dev)}:{os.minor(dev)}" / "loop/backing_file"
    filename = Path(backing.read_text().strip())
    assert filename.is_absolute() and filename.is_file(), "unproven scratch backing"
    dev = filename.stat().st_dev
iid="e"*32
tag='"simulated-conditional-returned-etag"'
fake_request={"path":"synthetic-parent-status-request","sha256":"a"*64}
owner={"unit":"horizon-qualify-136-actual-20261120-g1.service","invocation_id":iid,"helper":{"path":"synthetic-payload","sha256":"b"*64},"ready_recorded_unix_seconds":int(stamp.timestamp()),"ready":{"path":"synthetic-ready","sha256":"c"*64},"parent_request":fake_request,"node_spawned":False,"worker_spawned":False,"repair_open":True,"ordinary_replay_claim":False}
candidate={"epoch":136,"key":"epoch-136.epoch-status.json","previous_receipt":oldref,"before_sha256":original["after_sha256"],"before_etag":original["after_etag"],"before_status":old,"after_status":after,"after_etag":tag,"after_sha256":hashlib.sha256(status.body(after)).hexdigest(),"authenticated_readback":True,"conditional_header":"If-Match","current_repair_owner":"/root","epoch136_pending_owner":owner,"producer_invocation_id":iid,"epoch136_registration_unix_seconds":int(stamp.timestamp())}

with tempfile.TemporaryDirectory(dir=a.fixture_parent) as temp:
    root=Path(temp)
    head = json.loads(subprocess.check_output([sys.executable,"-IB",str(Path(__file__).with_name("transport.py")),"head"],
                          input=json.dumps({"fleet":{"path":str(a.fleet),"sha256":a.digest}}).encode(),timeout=25))
    upcoming = names(head["due"])
    assert head["next_lock"] == str(upcoming["statuses"]/"cycle.lock") and head["timer"]==upcoming["timer"]
    assert Path(head["next_lock"]).parent != Path(oldref["path"]).parent
    lock_path=root/"cycle.lock"
    fd=lock(lock_path)
    try:
        try:lock(lock_path)
        except BlockingIOError:pass
        else:raise AssertionError("two concurrent cycle writers")
    finally:os.close(fd)
    os.close(lock(lock_path))
    def fixture(name,document):
        folder=root/name
        folder.mkdir(mode=0o700)
        event=folder/("event-136-waiting-"+iid)
        event.mkdir(mode=0o700)
        p=event/"RECEIPT.json"
        durable(p,document)
        return folder,p
    folder,p=fixture("positive",candidate)
    with patch.object(status,"STATUS_ROOT",folder):
        assert status.follow_event(136,oldref,tag,status.body(after))[0]==bound(p)
    projection=copy.deepcopy(f)
    projection["epoch136_pending_owner"]=owner
    projection["epoch136_registration_unix_seconds"]=int(stamp.timestamp())
    projection["effective_status_receipts"]["136"]=bound(p)
    preserved=["complete_DATA_bytes","complete_projected_memory_bytes","all_reservation_ending_bytes","actual_executing_replays","actual_active_bootstraps","actual_active_private_diagnostics","terminal172_closure"]
    assert all(projection[k]==f[k] for k in preserved)
    assert not any(r.get("epoch")==136 for k in preserved[3:6] for r in projection[k])
    for key,bad in [("before_etag",tag),("before_sha256","d"*64),("previous_receipt",fake_request),("current_repair_owner","other"),("authenticated_readback",False)]:
        folder,_=fixture(key,dict(candidate,**{key:bad}))
        with patch.object(status,"STATUS_ROOT",folder):
            try:status.follow_event(136,oldref,tag,status.body(after))
            except ValueError:pass
            else:raise AssertionError("unbound "+key)
print(json.dumps({"source_fleet":a.digest,"actual_prior_status":oldref,"forecast_age_ms":17000,"six_dashboard_fields_preserved":True,"positive_simulated_event_followed":True,"malformed_event_denials":5,"preserved_initial_fleet_fields":preserved,"actual_next_cadence_lock":head["next_lock"],"simulated_cadence_lock_contention":True,"no_r2_client":True,"no_actor":True}))
