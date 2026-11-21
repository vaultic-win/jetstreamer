"""Qualify the fixed provider on the native registered fleet before normal deployment."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

def digest(b):return hashlib.sha256(b).hexdigest()

def rejected(call):
    try:call()
    except (ValueError,KeyError):return
    raise ValueError("invalid input passed its gate")

def main():
    if os.geteuid() or not sys.flags.isolated or not __debug__:raise ValueError("native isolated root session required")
    here=Path(__file__).resolve().parent;repo=here.parent.parent
    path=here/"post-stop-fit"
    m=runpy.run_path(str(path));s=m["s"];D=m["D"]
    fleet=s.ref(Path(sys.argv[1]),sys.argv[2]);commit=sys.argv[3]
    def git(*args):
        return subprocess.check_output(["/usr/bin/git","-c","safe.directory="+str(repo),"-C",repo,*args])
    git("merge-base","--is-ancestor",commit,"origin/account-updates")
    src={}
    for name in ("post-stop-fit","retire-original-timers.py","qualify.py"):
        p=here/name;b=p.read_bytes()
        s.need(b==git("show",commit+":"+str(p.relative_to(repo))),"unpublished qualification source")
        src[name]=digest(b)
    rejected(lambda:m["fleet_head"](dict(fleet,sha256="0"*64)))
    if fleet!=m["PREV"]:rejected(lambda:m["fleet_head"](m["PREV"]))
    rejected(lambda:m["capture"](171,fleet))
    observed=m["capture"](170,fleet)
    s.need(observed["fits"] and observed["stopped_generation_resident_credit_bytes"]==0 and
           set(observed["actual_original_stops"])=={"166","167","170"} and set(observed["survivors"])=={"169","172"} and
           set(observed["bookings"])=={"166","167","168","170"} and
           observed["available_HOME_bytes"]>=observed["complete_required_HOME_bytes"] and
           observed["available_memory_bytes"]>=observed["required_available_memory_bytes"],"native capacity failed")
    floor=m["disk_budget"];raw=observed["original_aggregate_HOME_bytes"];books=observed["bookings"];peer=observed["survivors"];optional=observed["candidate136"]
    for epoch in (145,166,167,168,170):
        required,protected,delta=floor(raw,optional,books,epoch,peer,{})
        allowance=books.get(str(epoch),{}).get("remaining_bytes",0)
        s.need(required==protected+allowance and required<=observed["available_HOME_bytes"] and delta>=0,"unfunded candidate")
    # A replacement's new bytes consume its own prepaid interval exactly once.
    older=books["170"];grown=dict(books);amount=1<<20
    grown["170"]=dict(older,remaining_bytes=older["remaining_bytes"]-amount,physical_bytes=older["physical_bytes"]+amount)
    baseline=floor(raw,optional,books,170,peer,{})
    realized=floor(raw,optional,grown,170,peer,{"170":dict(prestart_remaining=older["remaining_bytes"],floor=baseline[1])})
    s.need(realized[0]+amount==baseline[0] and realized[1]==baseline[1],"own growth changes protected unrelated claims")
    name="native-"+os.environ["INVOCATION_ID"]+".json"
    receipt=dict(schema="horizon-incident-replay-fit-native-qualification-v1",source_commit=commit,source_sha256=src,fit=observed,
                 rejected=["wrong fleet digest","nonmember epoch","superseded incident fleet"],own_growth_conservation=True)
    target=D/name
    with target.open("xb") as f:
        os.fchmod(f.fileno(),0o400);f.write((json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode());f.flush();os.fsync(f.fileno())
    fd=os.open(D,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    print(json.dumps(dict(path=str(target),sha256=digest(target.read_bytes()))))

if __name__=="__main__":main()
