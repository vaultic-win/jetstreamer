"""Follow the one original 166 node across an in-flight scheduled sample."""
import datetime as dt
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

from evidence import BASE,bound,checked,content,digest,durable,ensure_dir,need,sealed,utc
import closed166

LIVE_REF={"path":str(closed166.PACKAGE.parent/"LIVE.json"),"sha256":"23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe"}
NATIVE=Path("/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe")
NATIVE_SHA="6b06665ac4dd0654f6684f4fd178787c37e30af332a657c6c5a6502c2f3e2ab8"
TARGET="horizon-qualify-independent-cold166-20261120-v1.service"
IID="fa16ee2f14fe44ecbc37c59e197553ac"

def properties(unit,*keys):
    output=subprocess.check_output(["/usr/bin/systemctl","show",unit,"-p",",".join(keys)],text=True,timeout=15)
    result=dict(line.split("=",1) for line in output.splitlines())
    need(result.keys()==set(keys),"incomplete native unit identity")
    return result

def checked_tool():
    need(bound(closed166.PACKAGE/"deployment-seal-receipt.json")["sha256"]==closed166.SEAL and
         bound(closed166.PACKAGE/"terminal166")["sha256"]==closed166.SHA,"166 disposition executable changed")
    return str(closed166.PACKAGE/"terminal166")

def tool(*args):
    return json.loads(subprocess.check_output([checked_tool(),*args],timeout=60))

def incarnation(who,group):
    pid=who["pid"];p=Path("/proc")/str(pid)
    try:
        fields=(p/"stat").read_text().rsplit(")",1)[1].split()
        if int(fields[19])!=who["start_ticks"]:return False
        if fields[0] in ("Z","X"):return False
        st=(p/"exe").stat()
        need((p/"exe").readlink()==Path(who["exe"]) and (st.st_dev,st.st_ino)==(who["identity"]["device"],who["identity"]["inode"])
             and (p/"cgroup").read_text().strip()=="0::"+group,"166 process image changed")
        return True
    except (FileNotFoundError,ProcessLookupError):
        try:
            fields=(p/"stat").read_text().rsplit(")",1)[1].split()
        except (FileNotFoundError,ProcessLookupError):return False
        if fields[0] in ("Z","X") or int(fields[19])!=who["start_ticks"]:return False
        raise

def original(live):
    group=live["native"]["manager"]["ControlGroup"]
    node=incarnation(live["native"]["parent"],group)
    worker=incarnation(live["native"]["worker"],group)
    if node:
        u=properties(TARGET,"InvocationID","MainPID","NRestarts")
        need(u==dict(InvocationID=IID,MainPID=str(live["native"]["parent"]["pid"]),NRestarts="0")
             or not incarnation(live["native"]["parent"],group),"166 producer changed")
    need(node or not worker,"detached 166 worker still owns resources")
    return node,worker

def await_exit(who,group,seconds):
    try:fd=os.pidfd_open(who["pid"])
    except ProcessLookupError:return
    try:
        if not incarnation(who,group):return
        poll=select.poll();poll.register(fd,select.POLLIN)
        need(any(flags&select.POLLIN for _,flags in poll.poll(max(0,int(seconds*1000)))),"original 166 node still finalizing at deadline")
    finally:os.close(fd)

def terminal(live,deadline):
    node,worker=original(live)
    need(not worker,"active historical 166 replay")
    if node:await_exit(live["native"]["parent"],live["native"]["manager"]["ControlGroup"],deadline-time.monotonic())
    # PID 1 can still be reaping the just-exited node. Only query that single unit.
    settle=min(deadline,time.monotonic()+20)
    while time.monotonic()<settle:
        u=properties(TARGET,"ActiveState","MainPID","Job")
        if u["MainPID"]=="0" and not u["Job"] and u["ActiveState"] in ("inactive","failed"):break
        time.sleep(.25)
    disposition=tool("record")
    binding=bound(closed166.TERMINAL)
    need(checked(binding)==disposition and disposition["epoch"]==166 and disposition["live"]==LIVE_REF
         and disposition["producer_invocation_id"]==IID and disposition["resource_credit_bytes"]==0
         and not disposition["canonical_r2_verified"],"unqualified 166 publication")
    return binding

def validate_scheduled(path):
    p=Path(path);directory=p.parent.parent
    need(p==directory/"sealed-next/observer.json" and directory.parent==BASE,"foreign scheduled config")
    ref=bound(p);cfg=sealed(ref)
    fleet_ref=bound(directory/"ROOT_COMPLETE_OPERATIONAL_FLEET.json");fleet=checked(fleet_ref)
    timer=fleet["sole_next_timer"];unit=timer.removesuffix(".timer")+".service"
    need(fleet["sole_next_observer"]==ref and cfg["previous_sample"]==fleet["observer"]["path"]
         and cfg["not_before_utc"]==checked(fleet["observer"])["cadence"]["next_routine_observation_not_before_utc"]
         and cfg["observation_reason"]=="routine" and cfg["minimum_interval_seconds"]==1800 and
         Path("/proc/self/cgroup").read_text().strip()=="0::/system.slice/"+unit,"unregistered scheduled sample")
    props=properties(unit,"MainPID","InvocationID")
    need(props==dict(MainPID=str(os.getpid()),InvocationID=os.environ["INVOCATION_ID"]),"not the scheduled main process")
    need(not Path(cfg["output"]).exists(),"scheduled output already exists")
    return cfg,fleet_ref,ref

def relevant_failure(message,live,row):
    # Certain errors (e.g. a disappearing cgroup) have no PID in their text.
    # Without an unambiguous reference to 166 the caller retains the error.
    labels=(TARGET,live["native"]["manager"]["ControlGroup"],str(live["native"]["worker"]["pid"]),
            row["scratch_path"])
    return any(label in message for label in labels) and len(message)<=65536

def after_failure(code,stderr,cfg,live,row):
    need(code!=0 and not Path(cfg["output"]).exists(),"partial or committed original sample retained")
    need(relevant_failure(stderr,live,row) and not original(live)[1],"sampler failed outside the 166 transition")

def dispatch(path):
    cfg,fleet_ref,ref=validate_scheduled(path)
    live=checked(LIVE_REF);node,worker=original(live)
    row=next((r for r in cfg["replays"] if r["range"]=="166"),None)
    if not row or not worker:
        if row:terminal(live,time.monotonic()+1800)
        os.execv(checked_tool(),[checked_tool(),"dispatch-cadence",str(path)])
    try:
        result=tool("inspect-cadence",str(path))
    except (ValueError,subprocess.CalledProcessError):
        if original(live)[1]:raise
        terminal(live,time.monotonic()+1800)
        os.execv(checked_tool(),[checked_tool(),"dispatch-cadence",str(path)])
    if result["mode"]=="closed":
        os.execv(checked_tool(),[checked_tool(),"dispatch-cadence",str(path)])
    need(result["mode"]=="original" and result["config"]==ref and node,"foreign original 166 selection")
    need(bound(NATIVE)["sha256"]==NATIVE_SHA,"original native sampler changed")
    observed=subprocess.run([NATIVE,path],stderr=subprocess.PIPE)
    if observed.returncode==0:
        value=content(Path(cfg["output"]))
        need(value["cadence"]["previous_sample_sha256"]==checked(fleet_ref)["observer"]["sha256"] and
             [r["range"] for r in value["replays"]]==[r["range"] for r in cfg["replays"]],"incomplete native sample")
        return
    message=observed.stderr.decode(errors="replace")
    print(message,file=sys.stderr,flush=True)
    after_failure(observed.returncode,message,cfg,live,row)
    ref_terminal=terminal(live,time.monotonic()+1800)
    root=Path(path).parent.parent/"after-166-race";ensure_dir(root)
    durable(root/"FAILED_NATIVE.json",dict(schema="horizon-166-scheduled-native-race-v1",at=int(time.time()),unit=os.environ["INVOCATION_ID"],
        previous_fleet=fleet_ref,original=ref,attempt_exit=observed.returncode,stderr=message,output_absent=True,terminal=ref_terminal))
    os.execv(checked_tool(),[checked_tool(),"dispatch-cadence",str(path)])

def successful_sample(c):
    unit=c.fleet["sole_next_timer"].removesuffix(".timer")+".service"
    start=int(utc(c.sample["recorded_at_utc"]).timestamp())
    finish=int(utc(c.sample["completed_at_utc"]).timestamp())
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-","")
    native=subprocess.check_output(["/usr/bin/journalctl","--no-pager","-o","json","--since",f"@{start-1800}",
        "--until",f"@{finish+121}","_PID=1","_BOOT_ID="+boot,"UNIT="+unit],timeout=15)
    need(len(native)<1<<20,"unexpected scheduled sampler journal size")
    events=[json.loads(line) for line in native.splitlines()]
    started="39f53479d3a045ac8e11786248231fbf";success="7ad2d189f7e94e70a38c781354912448"
    endings=[e for e in events if e.get("MESSAGE_ID")==success and finish*1000000<=int(e["__REALTIME_TIMESTAMP"])<(finish+121)*1000000]
    need(len(endings)==1,"missing or ambiguous completed scheduled sampler")
    end=endings[0];iid=end["INVOCATION_ID"]
    records=[e for e in events if e.get("INVOCATION_ID")==iid]
    begins=[e for e in records if e.get("MESSAGE_ID")==started]
    programs=(str(NATIVE)+" ",str(closed166.PACKAGE/"terminal166")+" dispatch-cadence ",
              "/usr/bin/python3 -B "+str(Path(__file__).resolve())+" ")
    # A previously armed timer can still execute the preceding sealed sampler.
    original=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-terminal-status-20261121-v1/publisher-v1")
    command="/usr/bin/python3 -B "+str(original/"race166.py")+" "
    if len(begins)==1 and command in begins[0]["MESSAGE"]:
        need(bound(original/"deployment-seal-receipt.json")["sha256"]=="76283826f8700557ffa359aa274ba991f7f644302476dde78e436c1011d4ed53"
             and bound(original/"race166.py")["sha256"]=="eecc61efb7203defeace51625cd59ee94efa99901927823c9585513a6f0219ec","preceding native sampler changed")
        programs+= (command,)
    need(len(begins)==1 and any(program in begins[0]["MESSAGE"] for program in programs)
         and int(begins[0]["__REALTIME_TIMESTAMP"])<(start+1)*1000000
         and c.fleet["sole_next_observer"]["path"] in begins[0]["MESSAGE"]
         and not any(e.get("MESSAGE_ID") in {"be02cf6855d2428ba40df7e9d022f03d","98e322203f7a4ed290d09fe03c09fe15"}
                     for e in records),"failed or foreign scheduled sampler")
    return dict(unit=unit,invocation=iid,boot_id=boot,start_monotonic=begins[0]["__MONOTONIC_TIMESTAMP"],
                success_monotonic=end["__MONOTONIC_TIMESTAMP"])

def original_row(c,live,term):
    """Authenticate the additional 166 row in an immutable successful pre-closure sample."""
    cfg=c.cfg;sample=c.sample;ref=c.sample_ref
    need(bound(Path(ref["path"]))==ref and Path(ref["path"])==Path(cfg["output"]) and checked(ref)==sample,
         "original 166 sample binding changed")
    need([r["range"] for r in sample["replays"]]==[r["range"] for r in cfg["replays"]]==["166","167","170","172"]
         and sample["cadence"]["previous_sample_sha256"]==c.fleet["observer"]["sha256"] and
         sample["cadence"]["previous_sample"]==c.fleet["observer"]["path"],"partial original scheduled sample")
    row=sample["replays"][0];expected=cfg["replays"][0]
    need(row["scratch_path"]==expected["scratch_path"] and row["invocation_binding_stable"] is True and
         expected["producer_unit"]==TARGET and expected["expected_producer_invocation_id"]==IID and
         expected["append_log"]==live["producer_log"],"166 historical config differs")
    for edge in ("before","after"):
        producer=row["producer_"+edge];worker=row["worker_"+edge]
        need(producer["unit"]==TARGET and producer["invocation_id"]==IID and producer["restarts"]==0
             and producer["main_pid"]==live["native"]["parent"]["pid"] and producer["active_state"]=="active"
             and worker["pid"]==live["native"]["worker"]["pid"] and worker["executable"]==live["native"]["worker"]["exe"]
             and worker["matching_workers"]==1 and worker["executable_beneath_bound_scratch"] is True,"wrong historical 166 endpoint")
    end=int(checked(term)["manager_terminal"]["__REALTIME_TIMESTAMP"])
    need(utc(sample["recorded_at_utc"]).timestamp()*1e6<=end and utc(sample["completed_at_utc"])>=utc(sample["recorded_at_utc"]),
         "166 local commit predates original sample")
    return dict(sample=ref,sampler=successful_sample(c),scheduled_config=c.fleet["sole_next_observer"],original_166_row=row,terminal=term,
                live_owner_claimed=False,resource_credit_bytes=0)

def before_publish(c):
    """Return a historical row only across an authenticated completed-166 transition."""
    if [r["range"] for r in c.sample["replays"]]!=["166","167","170","172"]:return None
    live=checked(LIVE_REF)
    if original(live)[1]:return None
    ref=terminal(live,time.monotonic()+1800)
    return original_row(c,live,ref)

def status_clock(sample_at,terminal_us):
    completed=dt.datetime.fromtimestamp((int(terminal_us)+999999)//1000000,dt.timezone.utc)
    return max(sample_at,completed)

def inherited_status(c,epoch,etag,data):
    """Resume authentic pre-closure writes, preserving their original intents and receipts."""
    from status import body,receipt_identity
    old=getattr(c,"original_status_dir",None)
    if old is None or epoch!=166:return None
    intent=old/f"epoch-{epoch}.intent.json";receipt=old/f"epoch-{epoch}.receipt.json"
    if not intent.exists():
        need(not receipt.exists(),"original receipt without intent");return None
    entry=content(intent);receipt_identity(entry,c,epoch)
    if receipt.exists():
        result=checked(bound(receipt))
        need(result["authenticated_readback"] and all(result[k]==v for k,v in entry.items()),"foreign original readback")
        if result["after_etag"]!=etag or result["after_sha256"]!=digest(data):
            # Our newer 166 intent may already have landed across a process exit.
            # The calling loop resumes it before consulting this predecessor.
            raise ValueError("inherited pre-close status differs from current object")
        return bound(receipt)
    expected=body(entry["after_status"])
    if data==expected and digest(data)==entry["after_sha256"]:
        recovered=True
    else:
        need(etag==entry["before_etag"] and digest(data)==entry["before_sha256"],"foreign pre-close conditional result")
        return None   # Its replay intent was never applied.
    durable(receipt,dict(entry,authenticated_readback=True,after_etag=etag,
                         verified_at_utc=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         already_published_intent_read_back=recovered))
    return bound(receipt)

def retry_status(fleet,sha,sample_sha):
    from cycle import load_fleet
    from evidence import names,pair
    from types import SimpleNamespace
    fleetref=pair(fleet,sha);f,cfg,_=load_fleet(fleetref)
    paths=names(cfg["not_before_utc"]);sampleref=pair(paths["sample"],sample_sha)
    need(not (paths["out"]/"ROOT_COMPLETE_OPERATIONAL_FLEET.json").exists(),"fleet was already accepted")
    c=SimpleNamespace(fleet=f,cfg=cfg,paths=paths,sample=checked(sampleref),sample_ref=sampleref)
    witness=before_publish(c)
    need(witness,"publisher failure is unrelated to the original 166 ending")
    # Only the existing flock-holding cadence parent can retry its failed cycle.
    unit="horizon-archive-status-cadence-after172-20261120-v1.service"
    p=Path("/proc")/properties(unit,"MainPID")["MainPID"]
    need((p/"fd/9").readlink()==BASE/"stable-cadence-controller-20261120-v1/consumer.lock"
         and "FLOCK" in (p/"fdinfo/9").read_text() and (p/"fd/255").readlink()==Path(__file__).resolve().parent/"consume"
         and Path("/proc/self/cgroup").read_text()==(p/"cgroup").read_text(),"foreign status retry")
    root=Path(cfg["output"]).parent / Path(fleet).parent.name / "after-166-race"
    ensure_dir(root);durable(root/"PREPUBLICATION_NATIVE.json",witness)

if __name__=="__main__":
    need(os.geteuid()==0 and __debug__,"run as root under the existing cadence")
    if len(sys.argv)==2:dispatch(Path(sys.argv[1]))
    else:
        need(len(sys.argv)==5 and sys.argv[1]=="retry-status","unknown scheduled action")
        retry_status(*sys.argv[2:])
