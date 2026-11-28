"""Hold, guard and reprice the separate private 169 attempt before releasing its exact worker."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c
import namespace
import observe
import prepare
import quote
from writer_receipt import read_active_writer

DEP=prepare.DEPLOY
ROSTER=c.CONTROL/"roster-v1"
GUARD=c.RT/"epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
GUARD_SHA="b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
BOOT=Path("/proc/sys/kernel/random/boot_id")


def static_scope(fixture, source):
    first,fr=c.read(fixture)
    inputs,ir=c.read(prepare.CURRENT,"efa0ebcceb5792c0a2be1c9f4db449e2c753ce06a907501787452712ef87afdb")
    merges,mr=c.read(source)
    package,pr=c.read(DEP/"deployment-seal-receipt.json")
    _,rr=c.read(ROSTER/"deployment-seal-receipt.json")
    guard,vr=c.read(c.CONTROL/"GUARD_STATIC_ACCEPTED.json",
                    "f529b1e98258d74be2ca90d596d5a0992819ec352af007ad5eeb463990e6fd84")
    check=json.loads(guard["stdout"])
    c.need(fixture.parent==c.CONTROL and source==c.CONTROL/"MERGED_SOURCE.json" and first["current_inputs"]==ir
           and first["host"]["mounts"]==first["readback"]["mounts"]
           and guard["exit_code"]==0 and check["validated"] and check["self_sha256"]==GUARD_SHA
           and check["unit"]==c.UNIT and check["replay_launch_authorized"] is False
           and first["readback"]["limits"]["memory.max"]==str(c.RAM)
           and first["readback"]["limits"]["cpu.max"]=="200000 100000" and not first["admission"]
           and merges["branch"]=="origin/account-updates" and merges["operator"]==pr and merges["roster"]==rr
           and re.fullmatch("[a-f0-9]{40}",merges["commit"]) and merges["remote_contains_commit"],
           "different qualified source, memory or namespace")
    quote.verified_provider(DEP,pr["sha256"])
    quote.verified_provider(ROSTER,rr["sha256"])
    _,cu=c.read(c.CONTROL/"PREDECESSOR_CUSTODY.json","31a30e9eb09e11514c64b9c7102871aeefa58a543c77dff576588b07b0327b0b")
    prereq=inputs["output"]
    return dict(schema="horizon-169-hourly-retry-scope-v1",producer_unit=c.UNIT,guard_timer=observe.TIMER,
                watcher=prepare.TERMINAL,operator=pr,roster=rr,merged_source=mr,namespace_fixture=fr,guard_static=vr,inputs=ir,
                predecessor=cu,quota=dict(producer_cpu=c.PRODUCER_CPU,producer_ram=c.RAM,guard_cpu=c.GUARD_CPU,
                                          guard_ram=c.GUARD_RAM,home_output=c.HOME_OUTPUT,home_control=c.CONTROL_BYTES,
                                          scratch=44*c.G,maximum_worker_vmas=3_500_000),
                cadence_source=dict(path=str(DEP/"cadence.py"),sha256=next(m["sha256"] for m in package["members"] if m["name"]=="cadence.py")),
                node=inputs["seal"]["node"],worker=inputs["seal"]["worker"],
                output=str(c.RETRY/"v158"/c.BASE_NAME),log=str(observe.LOG),bootstrap=73_238_440,
                first=73_238_441,last=73_245_218,position_count=6778,terminal_hash=prereq["terminal_hash"],
                canonical_publication_authorized=False)


def checked_inputs(scope):
    data=quote.bound(scope["inputs"])
    for key in ("node","worker"):
        ref=data["seal"][key]
        c.need(scope[key]==ref, "different historical image")
        c.stable(Path(ref["path"]),expected=ref["sha256"],sealed=True)
    for entry in data["indexes"]:
        st=Path(entry["path"]).stat()
        c.need(all(entry[k]==v for k,v in zip(("device","inode","size","mtime_ns","ctime_ns"),
               (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns))), "pinned index changed")
    src=data["sources"]["169"]
    history,sr=c.read(Path(src["receipt"]),src["sha256"],sealed=False)
    snapshot=Path(history["destination"])
    s=snapshot.lstat()
    c.need(snapshot==c.OLD/"inputs"/namespace.START and snapshot.resolve()==snapshot and stat.S_ISREG(s.st_mode)
           and s.st_nlink==1 and s.st_uid==1001 and s.st_ctime_ns==src["verified_ctime_ns"]
           and [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns]==[src["file"][k] for k in ("device","inode","size","mtime_ns")]
           and src["file"]["sha256"]=="938601317822ddb739d14b3ab214075dfaac4ece1fa467813747f131dc27c39b",
           "bootstrap changed since authenticated checksum readback")
    return dict(source=sr,identity=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns],sha256=src["file"]["sha256"])


def funded(scope,scope_ref):
    c.need(Path(__file__).resolve()==DEP/"issuer.py", "execute the sealed issuer")
    quote.verified_provider(DEP,scope["operator"]["sha256"])
    quote.verified_provider(ROSTER,scope["roster"]["sha256"])
    prior=quote.bound(scope["predecessor"])["retained_incomplete_archive"]
    path=Path(prior["path"])
    signature=c.identity(path.lstat())
    c.need(all(prior[k]==v for k,v in signature.items()), "retained partial changed")
    loan=quote.returned_loan()
    core=runpy.run_path(str(ROSTER/"capacity.py"))
    q=quote.calculate(core["base_for_retry_only"](),scope["predecessor"],loan)
    c.need(quote.returned_loan()==loan and c.identity(path.lstat())==signature, "loan or predecessor changed")
    current=q["whole_roster"]["writer"]
    active=read_active_writer(c,current)
    ready=quote.bound(active["ready"])
    c.need(ready.get("private169_retry_scope")==scope_ref and ready.get("private169_retry_cadence")==scope["cadence_source"]
           and not active["producer_mutations"], "active cadence writer has not enrolled this retry")
    q.update(scope=scope_ref,writer=current,stage="native-prestart" if not q["whole_roster"]["base_169"]["native"]["independent_retry169"]
             else "native-postguard")
    return q


def control_file(path,data,mode):
    """Install only a first immutable barrier or these two exact runtime unit files."""
    allowed={Path("/run/systemd/system")/c.UNIT,Path("/run/systemd/system")/prepare.TERMINAL,c.BARRIER/"allow.json"}
    c.need(path in allowed and path.parent.resolve(strict=True)==path.parent and path.parent.stat().st_uid==0
           and not path.parent.stat().st_mode&0o022, "unregistered small runtime file")
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix=".horizon169-",delete=False) as out:
        tmp=Path(out.name)
        try:
            out.write(data)
            out.flush()
            os.fchmod(out.fileno(),mode)
            os.fsync(out.fileno())
            try:
                os.link(tmp,path)
            except FileExistsError:
                pass
        finally:
            tmp.unlink()
    st=path.lstat()
    c.need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and path.resolve()==path
           and stat.S_IMODE(st.st_mode)==mode and path.read_bytes()==data, "different runtime file "+str(path))
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def guard_command(plan,ref):
    previous=c.RT/"epoch169-focused-admission-20261120-v4"
    profile,_=c.read(previous/"GUARD_ARGV.json","b9874a84eb7d127d4be36ba23593985218f101a6247c04131d53ea6c4ee65624")
    c.need(profile[-6]==str(GUARD) and profile[-1]==GUARD_SHA, "different historical guard")
    c.stable(GUARD,sealed=True,expected=GUARD_SHA)
    receipts=c.RETRY/"hourly-guard-receipts"
    def change(item):
        for old,new in (("horizon-qualify-169-focused-20261120-v4.service",c.UNIT),
                        ("horizon-guard-169-focused-20261120-v4",observe.TIMER.removesuffix(".timer")),
                        (str(previous/"guard-receipts"),str(receipts)),(str(previous/"guard.stdout"),str(receipts/"guard.stdout")),
                        (str(previous/"guard.stderr"),str(receipts/"guard.stderr"))):
            item=item.replace(old,new)
        return item
    c.need(plan["unit"]==c.UNIT and ref["path"]==str(c.CONTROL/"GUARD_PLAN.json"), "different guard plan")
    return ["/usr/bin/systemd-run",*[change(v) for v in profile[:-6]],str(GUARD),ref["path"],
            "--plan-sha256",ref["sha256"],"--self-sha256",GUARD_SHA]


def props(unit,fields):
    rows=subprocess.check_output(["systemctl","show","--all","-p",",".join(fields),unit],text=True,timeout=10)
    answer=dict(line.split("=",1) for line in rows.splitlines())
    c.need(set(answer)==set(fields),"incomplete manager properties "+unit)
    return answer


def held_process():
    owner=props(c.UNIT,("Id","ActiveState","SubState","Job","InvocationID","MainPID","NRestarts","OnSuccess","OnFailure"))
    iid=owner["InvocationID"]
    pid=int(owner["MainPID"])
    process=Path("/proc")/str(pid)
    c.need(owner["Id"]==c.UNIT and (owner["ActiveState"],owner["SubState"])==("active","running")
           and not owner["Job"] and owner["NRestarts"]=="0" and re.fullmatch("[a-f0-9]{32}",iid) and pid>1
           and owner["OnFailure"]==owner["OnSuccess"]==prepare.TERMINAL
           and (process/"cgroup").read_text().strip()=="0::/system.slice/"+c.UNIT
           and (process/"exe").samefile("/usr/bin/python3") and (process/"cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                ==[b"/usr/bin/python3",b"-IB",os.fsencode(c.BARRIER/"gate.py")], "not the registered held gate")
    ticks=int((process/"stat").read_text().rsplit(")",1)[1].split()[19])
    return owner,dict(unit=c.UNIT,invocation_id=iid,pid=pid,start_ticks=ticks,boot_id=BOOT.read_text().strip(),
                      namespace=namespace.inspect(pid))


def watcher():
    manager=props(prepare.TERMINAL,("Id","LoadState","ActiveState","Job","MemoryMax","CPUQuotaPerSecUSec",
                                   "MemorySwapMax","ExecStart","FragmentPath"))
    file=Path(manager["FragmentPath"])
    c.need(manager["Id"]==prepare.TERMINAL and manager["LoadState"]=="loaded" and manager["ActiveState"]=="inactive"
           and not manager["Job"] and manager["MemoryMax"]==str(c.GUARD_RAM) and manager["CPUQuotaPerSecUSec"]=="1s"
           and manager["MemorySwapMax"]=="0" and file==Path("/run/systemd/system")/prepare.TERMINAL
           and file.read_bytes()==(DEP/prepare.TERMINAL).read_bytes()
           and f"/usr/bin/python3 -IB {DEP}/watch.py --terminal-event" in manager["ExecStart"],"terminal watcher not bound")
    return manager


def first(held,plan,gr,timer_id):
    stop=time.monotonic()+50
    helper=c.OLD_CONTROL/"issued-split-v1/hourly.py"
    c.stable(helper,expected="4caf9e2cad0d414fcc86c4a1f9038dc62e70dcdafdfa2254705eaed24388ce4f",sealed=True)
    native=runpy.run_path(str(helper))["first_guard"]
    native.__globals__.update(UNIT=c.UNIT,GUARD_UNIT=observe.TIMER.removesuffix(".timer"),LANE=c.RETRY)
    directory=Path(plan["receipt_directory"])
    while time.monotonic()<stop:
        matches=sorted(directory.glob("sample-*.json"),key=lambda p:p.lstat().st_mtime_ns)
        if not matches:
            time.sleep(.2)
            continue
        sample,ref=c.read(matches[-1],sealed=False)
        timer=props(observe.TIMER,("Id","ActiveState","InvocationID","Job","Triggers"))
        manager=props(timer["Triggers"],("Id","Job","Result","ExecMainStatus","TriggeredBy","InvocationID"))
        producer,check=held_process()
        c.need(check==held and timer["InvocationID"]==timer_id, "actor changed during guard startup")
        if manager["InvocationID"]!=sample["guard_invocation_id"] or manager["Job"]:
            time.sleep(.2)
            continue
        native(sample,plan,gr["sha256"],producer,timer,manager)
        c.need(sample["guard_sha256"]==GUARD_SHA and 0<=time.time()-sample["recorded_unix_seconds"]<20,
               "different or stale first guard")
        return ref
    raise TimeoutError("no invocation-bound first guard before gate timeout")


def launch():
    scope,sr=c.read(c.CONTROL/"SCOPE.json")
    c.need(not any((c.CONTROL/n).exists() for n in ("PRESTART.json","HELD_GATE.json","START_INTENT.json","GRANT.json",
               "results/TERMINAL.json")) and not os.path.lexists(c.BARRIER/"allow.json"), "prior attempt requires closure")
    prepare.layout()
    bank=checked_inputs(scope)
    initial=funded(scope,sr)
    c.need(initial["fits"] and initial["stage"]=="native-prestart","169 prestart does not fit the current full roster")
    for name in (c.UNIT,prepare.TERMINAL):
        control_file(Path("/run/systemd/system")/name,(DEP/name).read_bytes(),0o644)
    subprocess.run(["/usr/bin/systemctl","daemon-reload"],check=True)
    watch=watcher()
    # The candidate cap covers every write in the new private tree. CONTROL's
    # existing receipts remain physically charged and retain a separate 64 MiB.
    physical=int(subprocess.check_output(["/usr/bin/du","-sx","--block-size=1",str(c.RETRY)],text=True).split()[0])
    before=c.recorded(c.CONTROL/"PRESTART.json",initial)
    subprocess.run(["/usr/bin/systemctl","start",c.UNIT],check=True)
    producer,held=held_process()
    hr=c.recorded(c.CONTROL/"HELD_GATE.json",held)
    iid,pid=held["invocation_id"],held["pid"]
    cushion=min(512*c.M,max(0,initial["home_margin"])//5)
    plan=dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=c.UNIT,invocation_id=iid,filesystem=str(c.HOME),
        worker_root=str(c.RETRY),receipt_directory=str(c.RETRY/"hourly-guard-receipts"),maximum_worker_vmas=3_500_000,
        minimum_free_bytes=initial["guard_floor"]+cushion,maximum_root_physical_bytes=physical+c.HOME_OUTPUT)
    gr=c.recorded(c.CONTROL/"GUARD_PLAN.json",plan)
    command=guard_command(plan,gr)
    subprocess.run([*command[-6:],"--validate-plan-only"],check=True)
    subprocess.run(command,check=True)
    tid=props(observe.TIMER,("InvocationID",))["InvocationID"]
    first_ref=first(held,plan,gr,tid)
    intent=dict(schema="epoch169-hourly-retry-first-guard-v1",unit=c.UNIT,
                producer_invocation_id=iid,pid=pid,start_ticks=held["start_ticks"],boot_id=held["boot_id"],timer_iid=tid,
                fixed_control_allowance=c.CONTROL_BYTES,charged_worker_growth=c.HOME_OUTPUT,prestart_physical_bytes=physical,
                actor_memory_bytes=c.RAM,guard_memory_bytes=c.GUARD_RAM,actor_cpu_micros=c.PRODUCER_CPU,guard_cpu_micros=c.GUARD_CPU,
                previous_producer_iid=c.OLD_IID,previous_terminal=quote.bound(scope["predecessor"])["terminal"],
                guard_plan=gr,first_guard=first_ref,held=hr,prestart=before,sealed_node=scope["node"],scope=sr,
                namespace=held["namespace"],private_scratch_mount=held["namespace"]["scratch"],canonical_publication_authorized=False)
    c.recorded(c.CONTROL/"START_INTENT.json",intent,0o444)
    post=funded(scope,sr)
    peer=post["whole_roster"]["base_169"]["native"]["independent_retry169"]
    c.need(post["fits"] and post["stage"]=="native-postguard" and peer["invocation"]==iid and peer["phase"]=="held"
           and peer["guard_plan"]==gr and post["writer"]==initial["writer"] and post["whole_roster"]["fleet"]==initial["whole_roster"]["fleet"]
           and post["guard_floor"]<=plan["minimum_free_bytes"] and
           post["home_margin"] >= plan["minimum_free_bytes"]-post["guard_floor"] and
           held_process()[1]==held and watcher()==watch and checked_inputs(scope)==bank,
           "held retry crossed funding, guard floor, cadence, namespace or input generation")
    post.update(armed_floor=plan["minimum_free_bytes"],armed_home_margin=post["home_margin"]-(plan["minimum_free_bytes"]-post["guard_floor"]))
    pr=c.recorded(c.CONTROL/"POST_GUARD_PRICE.json",post)
    log=observe.LOG.lstat()
    c.need(log.st_size==0 and log.st_nlink==1 and os.path.samestat(log,(Path("/proc")/str(pid)/"fd/1").stat()),
           "foreign pre-payload log")
    granted=dict(schema="epoch169-hourly-retry-postguard-release-v1",unit=c.UNIT,invocation_id=iid,pid=pid,
                 start_ticks=held["start_ticks"],boot_id=held["boot_id"],issued_unix_seconds=int(time.time()),
                 producer_cpu_micros=c.PRODUCER_CPU,guard_cpu_micros=c.GUARD_CPU,memory_max=c.RAM,guard_memory_max=c.GUARD_RAM,
                 registered_watcher_sha256=hashlib.sha256(json.dumps(watch,sort_keys=True).encode()).hexdigest(),
                 verified_source_receipt_sha256=bank["source"]["sha256"],snapshot_sha256=bank["sha256"],snapshot_identity=bank["identity"],
                 first_guard_sha256=first_ref["sha256"],native_post_guard_price_sha256=pr["sha256"],guard_plan_sha256=gr["sha256"],
                 private_scratch_mount=held["namespace"]["scratch"],namespace=held["namespace"],log_device=log.st_dev,log_inode=log.st_ino,
                 canonical_publication_authorized=False)
    runpy.run_path(str(DEP/"gate.py"))["verify_grant"](granted,iid,pid,held["start_ticks"],held["boot_id"],time.time())
    grant=c.recorded(c.CONTROL/"GRANT.json",granted,0o444)
    control_file(c.BARRIER/"allow.json",(c.CONTROL/"GRANT.json").read_bytes(),0o444)
    return dict(held=hr,postguard=pr,grant=grant)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("scope","quote","launch"))
    cli.add_argument("--fixture",type=Path)
    args=cli.parse_args()
    if args.action=="scope":
        result=c.recorded(c.CONTROL/"SCOPE.json",static_scope(args.fixture,c.CONTROL/"MERGED_SOURCE.json"))
    else:
        with quote.LOCK.open("rb") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if args.action=="launch":
                result=launch()
            else:
                scope,ref=c.read(c.CONTROL/"SCOPE.json")
                result=funded(scope,ref)
    print(json.dumps(result))
