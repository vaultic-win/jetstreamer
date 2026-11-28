"""Hand the existing audit to v14 only after its real reader exits naturally."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import tempfile
import time

BASE=Path("/var/lib/jetstreamer/horizon_runtime_data")
WORK=BASE/"public-audit73-observer-20261121-v1"
PUBLIC=BASE/"r2-audit-storage-20261119-v1/state/public-stream-v1"
STATE=Path("/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/public-stream-v1")
UNIT="horizon-r2-chronological-plugin-audit-20261118-v1.service"
GROUP="/horizonaudit.slice/"+UNIT
PUBLISHER="horizon-archive-status-cadence-after172-20261120-v1.service"
OWNER=BASE/"public-stream-observer-continuity-20261120-v1/PUBLIC_OWNER.json"
OWNER_SHA="1990f8fe2c1c215586ad7c54980d2278ff937ce658588b5f6d321cd63ba04851"
REVIEW=WORK/"ORIGINAL_73_CLOSED_REPORT_REVIEW.json"
REVIEW_SHA="a39e2af5dacf83186fc72ccc52b51ad112f4614992980becf37297c70d7c9834"
PREFIX_SHA="2e787eea29b2b0cf749dd4c9a809d02352bd4e516ba8d67df4ffee58e6c9afd4"
TRUSTED_SEALER="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
HERE=Path(__file__).resolve().parent
LOCK=BASE/"stable-cadence-controller-20261120-v1/consumer.lock"
ORIGIN="https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev"
PARENT_PID=3224192
PARENT_TICKS=354111936
EQUIVALENT_BUILD={
    "path":str(BASE/"public-reader-refresh-20261121-v1/build-2be87499054e4f3690ecabfb6faa7152/CURRENT_BRANCH_BUILD.json"),
    "sha256":"97c769f5f32522c9974f79536dfe565674fe37da4c57a16c84b067b647b90d1e",
}

def require(ok, reason):
    if not ok: raise ValueError(reason)

def sha(data): return hashlib.sha256(data).hexdigest()

def raw(path):
    path=Path(path)
    require(path.is_absolute() and path.resolve(strict=True)==path,"noncanonical metadata "+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        require(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and not a.st_mode&0o022 and a.st_size<=32<<20,"unsafe metadata "+str(path))
        data=f.read((32<<20)+1); b=path.lstat()
    identity=lambda m:(m.st_dev,m.st_ino,m.st_size,m.st_ctime_ns,m.st_mtime_ns)
    require(len(data)==a.st_size and identity(a)==identity(b),"changed metadata "+str(path))
    return data

def ref(path): return {"path":str(path),"sha256":sha(raw(path))}

def doc(binding):
    data=raw(binding["path"]);require(sha(data)==binding["sha256"],"stale "+binding["path"])
    return json.loads(data)

def persist(path, value):
    payload=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
    if path.exists():
        require(raw(path)==payload,"existing record differs "+str(path));return ref(path)
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix=".pending-handoff-")
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(payload);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
        os.link(tmp,path)
        os.unlink(tmp)
        directory=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return ref(path)

def command(*args,timeout=45):
    return subprocess.check_output(args,text=True,timeout=timeout).strip()

def unit(name,keys):
    out=command("/usr/bin/systemctl","show",name,"-p"+",".join(keys))
    row=dict(line.split("=",1) for line in out.splitlines())
    require(set(keys)==row.keys(),"incomplete systemd properties");return row

def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])

def members():
    return {int(x) for x in (Path("/sys/fs/cgroup"+GROUP)/"cgroup.procs").read_text().split()}

def process_image(pid, membership=members):
    """Do not misidentify a transient git/ssh whose proc entry just disappeared."""
    try:return Path(f"/proc/{pid}/exe").readlink()
    except (FileNotFoundError,ProcessLookupError):
        if pid not in membership():return None
        # A transient task can remain listed briefly until its parent reaps it.
        try: state=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[0]
        except (FileNotFoundError,ProcessLookupError):
            if pid not in membership():return None
            raise
        if state in {"Z","X"}:return None
        raise

def check_parent():
    row=unit(UNIT,("MainPID","InvocationID","ActiveState","SubState","NRestarts","Job","ControlGroup"))
    saved=doc({"path":str(OWNER),"sha256":OWNER_SHA})
    require(row["InvocationID"]==saved["InvocationID"] and row["MainPID"]==str(saved["pid"])==str(PARENT_PID)
            and ticks(PARENT_PID)==saved["start_ticks"]==PARENT_TICKS and row["NRestarts"]=="0" and not row["Job"]
            and (row["ActiveState"],row["SubState"],row["ControlGroup"])==("active","running",GROUP),"old audit owner changed")
    require(Path(f"/proc/{PARENT_PID}/exe").readlink()==PUBLIC.parent.parent/"runtime-v13-public/audit","old audit executable changed")
    return row

def sealed(package):
    binding=ref(package/"deployment-seal-receipt.json");seal=doc(binding)
    require(seal["destination"]==str(package) and seal["sealer_sha256"]==TRUSTED_SEALER and not seal["remote_mutations"],"wrong normal seal")
    for m in seal["members"]:
        require(Path(m["name"]).name==m["name"] and sha(raw(package/m["name"]))==m["sha256"],"changed sealed publisher member")
    return binding

def read_current_reader(pid):
    proc=Path(f"/proc/{pid}")
    start=ticks(pid)
    argv=proc.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    require(len(argv)==10 and argv[2:8]==[ORIGIN,"--verify-only","--threads","4","--archive-inventory",str(STATE/"inventory.json")]
            and argv[8]=="--verification-report-dir","foreign reader arguments")
    span=re.fullmatch(r"([0-9]+):([0-9]+)",argv[1]);require(span,"invalid reader range")
    first,last=map(int,span.groups())
    reports=Path(argv[9]);target=PUBLIC/reports.relative_to(STATE)
    require(73<=first<=last and target.parent.parent==PUBLIC/"attempts" and target.name=="reports" and
            re.fullmatch(rf"range-{first}-{last}-[0-9]+",target.parent.name),"foreign report directory")
    log=reports.parent/"playback.log"
    require(all((proc/"fd"/str(fd)).readlink()==log and (proc/"fd"/str(fd)).samefile(target.parent/"playback.log")
                for fd in (1,2)), "reader no longer owns this attempt log")
    proof=ref(target.parent/"reader.json");reader=doc(proof);exe=Path(reader["artifact"])
    require(argv[0]==str(exe) and process_image(pid)==exe and proc.joinpath("exe").samefile(exe) and
            proc.joinpath("cgroup").read_text().strip()=="0::"+GROUP and proc.joinpath("stat").read_text().rsplit(")",1)[1].split()[1]==str(PARENT_PID)
            and ticks(pid)==start and pid in members(),"reader ownership changed")
    seal_path=exe.parent/"deployment-seal-receipt.json";seal=doc({"path":str(seal_path),"sha256":reader["seal_receipt_sha256"]})
    st=exe.stat()
    require(st.st_uid==0 and st.st_mode&0o777==0o555 and seal["sealer_sha256"]==TRUSTED_SEALER and
            seal["destination"]==str(exe.parent) and any(m["name"]==exe.name and m["sha256"]==reader["artifact_sha256"]
            and m["bytes"]==st.st_size for m in seal["members"]),"unsealed public reader")
    return dict(schema="horizon-previous-public-reader-v2",observed_at=int(time.time()),parent=ref(OWNER),pid=pid,start_ticks=start,argv=argv,
                range_start=first,range_end=last,attempt=str(target.parent),reader_proof=proof,reader_sha256=reader["artifact_sha256"])

AUX={Path(p) for p in ("/usr/bin/git","/usr/bin/ssh","/usr/bin/ssh-keygen","/usr/bin/ssh-add","/usr/bin/dash","/usr/lib/git-core/git")}

def roster():
    result=[]
    for pid in sorted(members()-{PARENT_PID}):
        exe=process_image(pid)
        if exe is not None:result.append((pid,exe))
    return result

def one_reader():
    live=[p for p,e in roster() if e.name=="horizon_pipeline"]
    require(len(live)<=1,"multiple live audit decoders")
    if not live:return None
    try:return read_current_reader(live[0])
    except (FileNotFoundError,ProcessLookupError):
        if live[0] not in members():return None
        raise

def old_prefix(manifest):
    first={str(i):manifest.get(str(i)) for i in range(73)}
    require(sha(json.dumps(first,sort_keys=True,separators=(",",":")).encode())==PREFIX_SHA,"accepted 0–72 changed")

def accepted():
    review=doc({"path":str(REVIEW),"sha256":REVIEW_SHA});inventory=doc(review["inventory"])
    files={}
    for p in (PUBLIC/"results").iterdir():
        m=re.fullmatch(r"epoch-(0|[1-9][0-9]*)\.json",p.name)
        require(m,"unexpected audit result");n=int(m[1]);binding=ref(p);r=doc(binding)
        require(r["epoch"]==n and r["status"]=="passed" and r["epoch_plugin_completed"] and not r["remote_mutations"]
                and r["inventory_sha256"]==review["inventory"]["sha256"],"invalid accepted result")
        files[n]=(binding["sha256"],r["object"])
    numbers=sorted(files)
    require([files[i][1] for i in numbers]==inventory["objects"][:len(numbers)],"results differ from inventory prefix")
    manifest={str(i):files[i][0] for i in numbers};old_prefix(manifest)
    return manifest

def durable_native(reader):
    reports=Path(reader["attempt"])/"reports"
    # The v14 supervisor alone decides whether to commit or replay a closed
    # report. Here require positive evidence that this reader reached a whole
    # epoch or that the incumbent has already authenticated its initial epoch.
    for n in range(reader["range_start"],reader["range_end"]+1):
        p=reports/f"epoch-{n}.json"
        if not p.exists():break
        r=doc(ref(p));s=r["report"]
        require(r["invocation"]==reader["argv"] and r["source"]==ORIGIN and r["full_epoch_verified"] and
                r["schema"]=="jetstreamer-horizon-plugin-playback-v1" and s["epoch"]==n and s["worker_count"]==4 and
                s["first_slot"]==r["expected_first_slot"]==n*432000 and s["last_slot"]==r["expected_last_slot"]==(n+1)*432000-1 and
                s["blocks"]+s["skipped"]==s["slots"]==432000 and len(s["stream_digest"])==32,"invalid terminal reader evidence")
        return ref(p)
    return None

def publisher(want_updated=True):
    u=unit(PUBLISHER,("InvocationID","MainPID","ActiveState","SubState","NRestarts","Job","ControlGroup"))
    require(u["ActiveState"]=="active" and u["SubState"]=="running" and not u["Job"] and u["NRestarts"]=="0","publisher not steady")
    p=Path("/proc")/u["MainPID"];exe=(p/"fd/255").readlink();package=exe.parent
    require(exe.name=="consume" and package.is_relative_to(BASE) and (p/"fd/9").readlink()==LOCK and
            any("FLOCK" in line and "WRITE" in line for line in (p/"fdinfo/9").read_text().splitlines() if line.startswith("lock:")),
            "existing sole publisher lock or executable missing")
    binding=sealed(package)
    if want_updated:require(sha(raw(package/"public_witness.py"))==sha(raw(HERE/"public_witness.py")),"active cadence lacks successor witness")
    return dict(unit=u,package=binding,consumer=ref(exe))

def current_fleet(owner):
    pid=owner["unit"]["MainPID"];args=Path(f"/proc/{pid}/cmdline").read_bytes().strip(b"\0").decode().split("\0")
    require(len(args)==4 and args[1]==owner["consumer"]["path"],"publisher argv changed")
    current={"path":args[2],"sha256":args[3]}
    package=Path(owner["package"]["path"]).parent
    for _ in range(1024):
        f=doc(current)
        # Use the publisher's regular Python entry mode so its sealed siblings
        # are importable, exactly as in the real consuming service.
        meta=json.loads(command("/usr/bin/python3","-B",str(package/"describe.py"),current["path"],current["sha256"]))
        nxt=Path(meta["out"])/"ROOT_COMPLETE_OPERATIONAL_FLEET.json"
        if not nxt.exists():break
        nr=ref(nxt);require(doc(nr)["previous_Root_operational_review"]==current,"fleet history diverged");current=nr
    else:raise ValueError("no finite complete fleet head")
    return current,f,meta

def peers(fleet):
    result=[]
    rows=fleet["actual_executing_replays"]+fleet["actual_active_bootstraps"]+fleet["actual_active_private_diagnostics"]
    require(len(rows)==fleet["active_producer_count"] and len({r["epoch"] for r in rows})==len(rows),"duplicate owner")
    for r in rows:
        old=r["unit"];u=unit(old["Id"],("Id","MainPID","InvocationID","NRestarts","ActiveState"))
        require(u["NRestarts"]=="0" and u["ActiveState"]=="active" and all(u[k]==old[k] for k in ("Id","InvocationID","MainPID")),"fleet is reconciling an owner")
        result.append(u)
    return result

def events():
    iid=os.environ["INVOCATION_ID"]
    require(re.fullmatch("[0-9a-f]{32}",iid),"unbound service")
    root=WORK/"following-events"
    root.mkdir(mode=0o700,exist_ok=True)
    require(root.is_dir() and root.resolve()==root and root.stat().st_uid==0 and root.stat().st_mode&0o777==0o700,"unsafe event directory")
    return root,iid

def closed():
    u=unit(UNIT,("ActiveState","MainPID","Job","InvocationID"))
    try:alive=ticks(PARENT_PID)==PARENT_TICKS
    except (FileNotFoundError,ProcessLookupError):alive=False
    try:group=members()
    except FileNotFoundError:group=set()
    return not alive and not group and u["ActiveState"]=="inactive" and u["MainPID"]=="0" and not u["Job"] and u["InvocationID"] in ("",doc(ref(OWNER))["InvocationID"])

def finish(draft):
    require(closed(),"audit parent or descendant still owns the unit")
    record=doc(draft);require(accepted()==record["accepted_result_sha256"],"prefix changed after old unit drain")
    persist(WORK/"BOUNDARY.json",record)
    command(str(HERE/"audit73-cutover"),"finish-boundary",timeout=90)

def resume_parent(pfd):
    with contextlib.suppress(ProcessLookupError):signal.pidfd_send_signal(pfd,signal.SIGCONT)

def must_idle():
    u=unit(PUBLISHER,("ControlGroup","MainPID"));all_pids=[int(x) for x in (Path("/sys/fs/cgroup"+u["ControlGroup"])/"cgroup.procs").read_text().split()]
    require(len(all_pids)==2 and int(u["MainPID"]) in all_pids and
            all(Path(f"/proc/{p}/exe").readlink()==Path("/usr/bin/sleep") for p in all_pids if p!=int(u["MainPID"])),"cadence is consuming")

def scoped_tree(repo, revision, paths):
    data = subprocess.check_output([
        "/usr/bin/git", "--no-replace-objects", "--literal-pathspecs", "-c", "safe.directory=" + str(repo),
        "-C", str(repo), "ls-tree", "-rz", "--full-tree", revision, "--", *paths,
    ], timeout=30)
    rows = (entry.split(b"\t", 1) for entry in data.split(b"\0") if entry)
    return {os.fsdecode(name): descriptor for descriptor, name in rows}

def reader_changes(repo, tip):
    """The shallow audit checkout and the build checkout can have disjoint Git history."""
    build = doc(EQUIVALENT_BUILD)
    require(re.fullmatch("[0-9a-f]{40}", tip) and build["byte_identical_to_sealed_reader"] is True,
            "invalid reader comparison")
    paths = sorted({".cargo", *build["resolved_local_packages"], *build["current_source_files"]})
    original = scoped_tree(Path("/home/sol/workspace/jetstreamer"), build["branch_commit"], paths)
    require(set(build["current_source_files"]) <= original.keys(), "qualified build tree is incomplete")
    current = scoped_tree(repo, tip, paths)
    return sorted(path for path in original.keys() | current.keys() if original.get(path) != current.get(path))

def cut(reader,reader_ref,at):
    """Return while a new real reader or build owns the cgroup. Never signal it."""
    proof=durable_native(reader)
    if proof is None and str(reader["range_start"]) not in accepted():return False
    if any(exe not in AUX for _,exe in roster()):return False
    repo = STATE.parent / "source"
    tip = command("/usr/bin/git", "--no-replace-objects", "-c", "safe.directory=" + str(repo),
                  "-C", str(repo), "rev-parse", "--verify", "refs/remotes/origin/account-updates")
    changes = reader_changes(repo, tip)
    if changes:
        print(json.dumps({"branch":tip, "changed_reader_paths":changes, "parent_continues":True,
                          "reader_pid":reader["pid"]}), flush=True)
        return False
    root,iid=events()
    # Only a successfully opened native pidfd, fresh natural exit and a role
    # census permit suspension of the *original* parent for the metadata cut.
    pfd=os.pidfd_open(PARENT_PID)
    try:
        check_parent();must_idle()
        if any(exe not in AUX for _,exe in roster()):return False
        require(0<=time.time()-at<=90,"natural exit is no longer fresh")
        require(not any(line.startswith(("State:\tT","State:\tt")) for line in Path(f"/proc/{PARENT_PID}/status").read_text().splitlines()),"parent independently suspended")
        attempt=f"{iid}-{reader['pid']}-{reader['start_ticks']}"
        ip=root/("intent-"+attempt+".json")
        persist(ip,dict(parent=ref(OWNER),pid=PARENT_PID,ticks=PARENT_TICKS,reader=reader_ref,exit_time=at,service=iid))
        signal.pidfd_send_signal(pfd,signal.SIGSTOP)
        def timeout(signum,frame):raise TimeoutError("bounded audit parent fence expired")
        previous=signal.signal(signal.SIGALRM,timeout);signal.alarm(85)
        try:
            until=time.monotonic()+5
            while time.monotonic()<until:
                current=roster()
                if any(exe not in AUX for _,exe in current):return False
                tasks=list(Path(f"/proc/{PARENT_PID}/task").glob("*/status"))
                if not current and tasks and all(any(l.startswith("State:\tT") for l in t.read_text().splitlines()) for t in tasks):break
                time.sleep(0.015)
            else:return False
            owner=publisher();fleet,f,cfg=current_fleet(owner);other=peers(f)
            require(unit(cfg["timer"],("ActiveState",))["ActiveState"]=="active" and not Path(cfg["sample"]).exists() and
                    int(command("/usr/bin/date","-u","-d",cfg["due"],"+%s"))>int(time.time())+180,"cadence boundary is imminent")
            facts=json.loads(command(str(HERE/"audit73-cutover"),"recovery-facts"))
            prefix=accepted();checked_review=doc({"path":str(REVIEW),"sha256":REVIEW_SHA})
            require(facts["old_row"]["MainPID"]==str(PARENT_PID) and facts["source_comparison"]["identical_scoped_paths"]>=400,"audit reader source or resources changed")
            require(not roster() and publisher()==owner and other==peers(f),"owners changed while parent was frozen")
            event=dict(schema="horizon-public-audit-natural-successor-v2",at=int(time.time()),epoch=73,
                event=checked_review["branch_event"],native_report=checked_review["native_report"],original_73_review=ref(REVIEW),
                inventory=checked_review["inventory"],previous_owner=ref(OWNER),old_row=facts["old_row"],prior_fleet=fleet,
                prior_audit_observation=f["continuing_audit_obligation"]["current_observation"],qualifying_branch=facts["source_comparison"],
                v14_e2e=facts["v14_e2e"],independent_trials=facts["native_independent_trials"],peers=other,next_timer=cfg["timer"],cadence_owner=owner,
                accepted_epochs=sorted(map(int,prefix)),accepted_result_sha256=prefix,previous_child_pid=reader["pid"],previous_child_drained=True,
                new_playback_started=False,sole_quiescent_parent=True,recovery_activated_live_reader=False,
                quiescent_reader=reader_ref,fresh_quiescence_unix_seconds=at,closed_retry_native_report=proof,
                original_closed_child_pid=3376515)
            draft=persist(root/("stop-"+attempt+".json"),event)
            # SIGTERM through PID1 is only requested once the exact old parent is
            # frozen and every other cgroup member has left. SIGCONT is automatic
            # on systemd stop; the pidfd unwinds only our original identity.
            require(not roster() and ticks(PARENT_PID)==PARENT_TICKS,"old unit no longer quiescent")
            command("/usr/bin/systemctl","stop",UNIT)
        finally:
            signal.alarm(0);signal.signal(signal.SIGALRM,previous);resume_parent(pfd)
        finish(draft)
        return True
    finally:os.close(pfd)

def wait_reader(reader):
    pid=reader["pid"]
    try:fd=os.pidfd_open(pid)
    except ProcessLookupError:return None
    try:
        try:
            require(ticks(pid)==reader["start_ticks"] and read_current_reader(pid)["argv"]==reader["argv"],
                    "reader changed before pidfd")
        except (FileNotFoundError,ProcessLookupError):
            if process_image(pid) is None:return None
            raise
        root,iid=events();r=persist(root/f"reader-{iid}-{pid}-{reader['start_ticks']}.json",reader)
        poll=select.poll();poll.register(fd,select.POLLIN)
        print(json.dumps({"waiting_for":r,"pid":pid}),flush=True)
        while True:
            if any(flags&select.POLLIN for _,flags in poll.poll()):break
        return r,int(time.time())
    finally:os.close(fd)

def recent_closed_reader():
    """Replay an independently dated terminal marker when the watch was interrupted."""
    root,_=events();now=time.time()
    candidates=[]
    for p in root.glob("reader-*.json"):
        rr=ref(p);r=doc(rr)
        require(r["parent"]==ref(OWNER) and r["schema"]=="horizon-previous-public-reader-v2","foreign watched reader")
        try:still=ticks(r["pid"])==r["start_ticks"]
        except (FileNotFoundError,ProcessLookupError):still=False
        if still:continue
        proof=doc(r["reader_proof"]);attempt=Path(r["attempt"])
        marker=attempt/"branch-change.json"
        dates=[]
        if marker.exists():
            event=doc(ref(marker))
            if event["reader_commit"]==proof["branch_commit"] and type(event["completed"]) is int:
                dates.append(event["at"])
        prefix=accepted()
        if prefix:
            n=max(map(int,prefix));result_path=PUBLIC/"results"/f"epoch-{n}.json"
            last=doc({"path":str(result_path),"sha256":prefix[str(n)]})
            if last["invocation"]==r["argv"] and Path(last["range_attempt"]).samefile(attempt):
                dates.append(last["finished_at"])
        dates=[d for d in dates if type(d) is int and 0<=now-d<=90 and d>=r["observed_at"]]
        if dates:candidates.append((max(dates),r,rr))
    if not candidates:return None
    marker_time,r,rr=max(candidates,key=lambda x:x[0])
    return r,rr,marker_time

def watch():
    if (WORK/"PUBLIC_OWNER.json").exists():return
    check_parent();publisher()
    reader=one_reader()
    if reader is None:
        recent=recent_closed_reader()
        if recent:cut(*recent)
        return # The path unit watches genuine native child changes.
    event=wait_reader(reader)
    if event is None:return
    ref_reader,at=event
    print(json.dumps({"closed":ref_reader,"at":at}),flush=True)
    cut(reader,ref_reader,at)

def recover():
    if (WORK/"PUBLIC_OWNER.json").exists():return
    root,iid=events()
    intents=list(root.glob("intent-"+iid+"-*.json"))
    if not intents:return
    require(len(intents)==1,"ambiguous recovery intent")
    intent=doc(ref(intents[0]))
    require(intent["service"]==iid and intent["parent"]==ref(OWNER) and intent["pid"]==PARENT_PID and intent["ticks"]==PARENT_TICKS,"foreign native suspension intent")
    if closed():
        drafts=list(root.glob("stop-"+iid+"-*.json"));require(len(drafts)==1,"missing stopped-boundary proposal")
        finish(ref(drafts[0]));return
    u=unit(UNIT,("InvocationID","MainPID"))
    if u["MainPID"]==str(PARENT_PID) and ticks(PARENT_PID)==PARENT_TICKS and u["InvocationID"]==doc(ref(OWNER))["InvocationID"]:
        pfd=os.pidfd_open(PARENT_PID)
        try:
            if ticks(PARENT_PID)==PARENT_TICKS and any(l.startswith("State:\tT") for l in Path(f"/proc/{PARENT_PID}/status").read_text().splitlines()):resume_parent(pfd)
        finally:os.close(pfd)
    elif (WORK/"BOUNDARY.json").exists():command(str(HERE/"audit73-cutover"),"finish-boundary",timeout=90)

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("action",choices=("watch","recover","inspect"));a=p.parse_args()
    require(os.geteuid()==0 and __debug__,"run with checked root metadata")
    if a.action=="watch":watch()
    elif a.action=="recover":recover()
    else:
        parent=check_parent();reader=one_reader();prefix=accepted();owner=publisher(False);fleet,f,cfg=current_fleet(owner)
        print(json.dumps(dict(parent=parent,reader=reader,accepted=len(prefix),owner=owner,fleet=fleet,peers=peers(f),timer=cfg["timer"],signals_sent=0)))
