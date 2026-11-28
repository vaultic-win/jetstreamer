"""Reprice the already-booked 168 tree inside the original complete host calculation."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import status168 as s
import overlap

R = s.ROOT
D = s.D
G = 1 << 30
MEM = 810658050048
CAP = 288*G
FULL = R / "epoch172-full-half-core-20261120-v1"
BOOK = s.ref(FULL/"POST_GUARD_CAPACITY.json","e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb")
ANCHOR = R/"epoch145-guarded-export-20261121-v1/state/de6780b860b3467bae21fbd19176ca14/first-guard.json"
BASELINE = "5860cc4748c58a76b34ec56234e1d8fd2ae7293df8cb424f22f1cc1dca677be4"
F169 = R/"epoch169-focused-admission-20261120-v4"
P169 = s.ref(F169/"ACTUAL_GUARD_PLAN.json","3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58")
AD172 = s.ref(FULL/"ACTUAL_ADMISSION_AND_PROTECTION.json","c1dc591288eca1a2f6e2ab37888c57f108d2d25e6639d292d612def83ff2f2df")
W172 = s.ref(FULL/"FIRST_PROTECTED_HISTORICAL_WORKER_20261121.json","165d1600fb91aebef3903532ed997db46658f8901d765c49e3550fb548c39148")
CPUS = {166:"9s",167:"9s",169:"3s",170:"9s",172:"500ms"}
N136 = "horizon-qualify-136-actual-20261120-g1.service"
A145 = "horizon-holding-export145-20261121-v1.service"
PUBLISHER = "horizon-archive-status-cadence-after172-20261120-v1.service"
CAD = R/"epoch166-post168-cadence-20261121-v1"
READY = CAD/"METERED168_STATUS_REGISTERED.json"
LOCK = R/"stable-cadence-controller-20261120-v1/consumer.lock"


def binary(path, digest):
    m = path.lstat()
    s.need(stat.S_ISREG(m.st_mode) and not m.st_mode & 0o022 and m.st_uid == 0
           and path.resolve(strict=True) == path, "untrusted native member " + str(path))
    with path.open("rb") as f:
        s.need(hashlib.file_digest(f,"sha256").hexdigest() == digest and os.path.samestat(m,os.fstat(f.fileno())),
               "native member digest changed")


def command(*argv):
    return subprocess.check_output(list(argv),text=True,timeout=25)


def members(name):
    p = Path("/sys/fs/cgroup/system.slice")/name/"cgroup.procs"
    return tuple(sorted(map(int,p.read_text().split()))) if p.exists() else ()


def units():
    rows = command("/usr/bin/systemctl","list-units","--type=service","--state=running,activating,deactivating",
                   "--no-legend","--plain","horizon-qualify-*").splitlines()
    return {line.split()[0] for line in rows if line.split()}


def measure_tree():
    # Both passes use the original whole root, including the retired diagnostic output.
    # Cap traversal at the gate. No writable accounts database can exist at this stage.
    raw = []
    for _ in range(2):
        m = s.TREE.stat()
        s.need(s.TREE.resolve(strict=True)==s.TREE and m.st_dev == Path("/home/sol").stat().st_dev,
               "wrong original 168 filesystem")
        seen=set()
        total=0
        stack=[s.TREE]
        while stack:
            p=stack.pop()
            z=p.lstat()
            key=(z.st_dev,z.st_ino)
            s.need(z.st_dev == m.st_dev and not p.is_mount(), "168 tree crossed a mount")
            if key in seen:
                continue
            seen.add(key)
            s.need(len(seen)<=20000, "unexpected 168 tree growth before release")
            total+=512*z.st_blocks
            if stat.S_ISDIR(z.st_mode):
                stack.extend(p.iterdir())
        raw.append((m.st_dev,m.st_ino,len(seen),total))
    s.need(raw[0]==raw[1] and 0 < raw[0][3] <= CAP,"original 168 tree changed during capture or exceeded cap")
    return dict(device=m.st_dev,inode=m.st_ino,entries=len(seen),physical_bytes=total,root=str(s.TREE),cap=CAP)


def remaining(planref, owner, guard_sha):
    plan=s.bound(planref,Path(planref["path"]))
    directory=Path(plan["receipt_directory"])
    with (directory.parent/"guard.stdout").open("rb") as f:
        f.seek(max(0,os.fstat(f.fileno()).st_size-(1<<20)))
        latest=next(json.loads(l) for l in reversed(f.read().splitlines()) if l.startswith(b"{"))
    gid=latest["guard_invocation_id"]
    s.need(s.iid(gid), "bad standalone guard generation")
    sample, sr=s.read(directory/("sample-"+gid+".json"))
    ident=owner["iid"]
    s.need(sample==latest and sample["schema"]=="jetstreamer-horizon-standalone-guard-sample-v1"
           and sample["plan_sha256"]==planref["sha256"] and sample["guard_sha256"]==guard_sha and plan["invocation_id"]==ident
           and sample["producer_invocation_id"]==sample["producer"]["invocation_id"]==ident
           and sample["producer"]["pid"]==owner["processes"][0][0] and sample["producer_stop_enabled"] is True
           and sample["producer"]["active"]=="active" and sample["producer"]["restarts"]==0
           and sample["trip_reason"] is None and sample["root_physical_observation_error"] is None
           and sample["worker_observation_error"] is None and sample["workers"]
           and sample["workers"][0][0]==owner["processes"][1][0] and 0<=time.time()-sample["recorded_unix_seconds"]<=120,
           "stale or foreign peer guard: "+plan["unit"])
    o=sample["root_physical_observation"]
    s.need(o["exceeds_budget"] is False and o["maximum_physical_bytes"]==plan["maximum_root_physical_bytes"],
           "unprotected incumbent tree")
    # A vanished entry removes its entire walk's credit. The peer's whole growth cap stays booked.
    lower=min(o[k]["physical_bytes"] for k in ("first","second")) if all(o[k]["vanished_entries"]==0 for k in ("first","second")) else 0
    return dict(plan=planref,guard=sr,floor=plan["minimum_free_bytes"],cap=plan["maximum_root_physical_bytes"],
                remaining=plan["maximum_root_physical_bytes"]-lower)


def incumbent(epoch,row,anchor,planref,timer,timer_iid,guard_sha):
    unit=anchor["unit"]
    mgr=s.show(unit)
    t=s.show(timer)
    s.need(row["unit"]["Id"]==unit and row["unit"]["InvocationID"]==mgr["InvocationID"]==anchor["iid"]
           and mgr["ActiveState"]=="active" and mgr["SubState"]=="running" and mgr["ControlGroup"]=="/system.slice/"+unit
           and mgr["CPUQuotaPerSecUSec"]==CPUS[epoch] and mgr["NRestarts"]=="0" and mgr["ControlPID"]=="0"
           and mgr["MemoryMax"]==str(68*G) and mgr["MemorySwapMax"]=="0" and not mgr["Job"]
           and t["InvocationID"]==timer_iid and t["ActiveState"]=="active" and t["SubState"] in ("waiting","running")
           and not t["Job"] and t["Triggers"]==timer.removesuffix(".timer")+".service", "incumbent owner/timer changed")
    ps=members(unit)
    s.need(ps==tuple(sorted(p[0] for p in anchor["processes"])) and int(mgr["MainPID"])==anchor["processes"][0][0],
           "native peer process membership changed")
    for pid, ticks, device, inode in anchor["processes"]:
        parent, actual, group=s.process(pid)
        m=Path(f"/proc/{pid}/exe").stat()
        s.need(actual==ticks and group=="0::/system.slice/"+unit and (m.st_dev,m.st_ino)==(device,inode)
               and (pid==int(mgr["MainPID"]) or parent==int(mgr["MainPID"])), "changed peer image/PID")
    def resident():
        pss=sum(int(next(l.split()[1] for l in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()
                         if l.startswith("Pss:")))*1024 for pid in ps)
        v=dict(l.split() for l in (Path("/sys/fs/cgroup/system.slice")/unit/"memory.stat").read_text().splitlines())
        return min(pss,int(v["anon"])+int(v["file_mapped"]),68*G)
    charged=min(resident(),resident())
    guard=remaining(planref,anchor,guard_sha)
    s.need(members(unit)==ps and s.show(unit)==mgr and s.show(timer)["InvocationID"]==timer_iid,
           "peer changed during capacity capture")
    return dict(epoch=epoch,unit=unit,invocation_id=anchor["iid"],processes=anchor["processes"],
                timer=timer,timer_invocation_id=timer_iid,resident=charged,guard=guard)


def inventory(fleetref):
    fleet=s.bound(fleetref,Path(fleetref["path"]))
    s.need(Path(fleetref["path"]).parent.parent==R and Path(fleetref["path"]).name=="ROOT_COMPLETE_OPERATIONAL_FLEET.json"
           and fleet["owner"]=="/root" and 0<=time.time()-fleet["recorded_unix_seconds"]<=2400
           and fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] is True
           and fleet["all_reservation_ending_bytes"]==0 and fleet["complete_projected_memory_bytes"]==761131708416
           and fleet["complete_DATA_bytes"]==6794761027378 and fleet["terminal168_trace_mismatch"]==s.ref(s.TRACE,s.CLOSED),
           "stale or incomplete root fleet")
    ledger=s.bound(BOOK,Path(BOOK["path"]))
    trace,_=s.read(s.TRACE,s.CLOSED)
    partial=trace["partial"]
    p=Path(partial["path"]);m=p.lstat()
    s.need(p.is_relative_to(s.TREE) and p.resolve(strict=True)==p and m.st_dev==partial["device"] and
           m.st_ino==partial["inode"] and m.st_size==partial["length"] and m.st_blocks*512>=partial["allocated"]
           and trace["resource_credit_bytes"]==0 and ledger["owners"]["168"]["iid"]==s.OLD,"original 168 retained trace differs")
    ad=s.bound(AD172,Path(AD172["path"]))
    w=s.bound(W172,Path(W172["path"]))
    anchors=dict(ledger["owners"])
    # 172 was admitted after this ledger. Pin the original process pair to the first native worker receipt.
    rm=Path(f"/proc/{ad['producer_pid']}/exe").stat()
    wm=Path(f"/proc/{w['worker_pid']}/exe").stat()
    actual=Path(f"/proc/{ad['producer_pid']}/exe")
    s.need(s.same_file(actual,R/"epoch172-full-replay-20261120-v1/inputs-v1/jetstreamer-node") and actual.readlink()==Path("/run/horizon-full172-half-core/jetstreamer-node")
           and Path(f"/proc/{w['worker_pid']}/exe").readlink().is_relative_to(Path(w["observer_row"]["scratch_path"])),
           "172 process images differ")
    anchors["172"]=dict(unit=ad["producer_unit"],iid=ad["producer_invocation_id"],
        processes=[[ad["producer_pid"],ad["start_ticks"],rm.st_dev,rm.st_ino],
                   [w["worker_pid"],w["worker_start_ticks"],wm.st_dev,wm.st_ino]])
    prior=[]
    for k in ("actual_executing_replays","actual_active_bootstraps","actual_active_private_diagnostics"):
        prior.extend(fleet[k])
    ids={row["epoch"] for row in prior}
    s.need(len(ids)==len(prior) and 172 in ids and ids<=set(CPUS)|{136},
           "unregistered fleet or duplicate prior 168")
    closed={}
    if 166 not in ids:
        terminal=R/"epoch166-terminal-20261121-v1/TERMINAL_SUCCESS.json"
        t,closed["166"]=s.read(terminal)
        live,live_ref=s.read(terminal.with_name("LIVE.json"),"23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe")
        mgr=s.show(anchors["166"]["unit"])
        s.need(fleet.get("terminal166_local_commit")==closed["166"] and t["live"]==live_ref and t["epoch"]==166
               and t["producer_invocation_id"]==anchors["166"]["iid"] and t["source_admission"]==live["admission"]
               and t["terminal_166_disposition"]=="node-published-local-cohort" and t["resource_credit_bytes"]==0
               and t["reservation_ending_bytes"]==0 and mgr["ActiveState"]=="inactive" and mgr["Result"]=="success"
               and not members(anchors["166"]["unit"]) and t["local_archive"]["size"]>0,"unbound terminal 166")
    for k in {167,169,170}-ids:
        anchor=anchors[str(k)]
        closed[str(k)]=overlap.retired(k,anchor,s.show(anchor["unit"]),members(anchor["unit"]))
    peers={}
    for row in prior:
        epoch=row["epoch"]
        if epoch==136: continue
        anchor=anchors[str(epoch)]
        if epoch in (166,167,170):
            proof=s.bound(row["guard_protection"],Path(row["guard_protection"]["path"]))
            plan,timer,ti=proof["plan"],proof["timer_unit"],anchor["timer_iid"]
            original=proof["first_guard_sample"]
            guard_sha=s.bound(original,Path(original["path"]))["guard_sha256"]
        else:
            guard_sha=s.GIMAGE
            plan=P169 if epoch==169 else ad["actual_guard_plan"]
            timer=row["guard_timer"]["Id"]
            ti=anchor["timer_iid"] if epoch==169 else w["worker_guard"]["timer"]["InvocationID"]
        peers[str(epoch)]=incumbent(epoch,row,anchor,plan,timer,ti,guard_sha)
    return fleet,ledger,peers,closed


def floor(fleet,ledger,tree,peers):
    anchor=s.read(ANCHOR,BASELINE)[0]["fit"]
    x=ledger["native_inputs"];roots=x["roots"];audit=fleet["continuing_audit_obligation"]
    s.need(anchor["charged_cpu_micros"]==64000000 and anchor["existing_total_memory"]==MEM
           and anchor["temporary"]==x["temporary_workers"]==[] and anchor["holding_transfer_memory"]==2*G
           and anchor["holding_transfer_cpu_micros"]==1000000 and all(x["auxiliary"][k]==anchor["auxiliary"][k] for k in ("cpu_quota_micros","memory_bytes","retained_bookings"))
           and audit["additional_cpu_quota_micros"]==4000000 and audit["additional_memory_bytes"]==24*G
           and audit["current_storage"]["remaining_DATA_growth_bytes"]==18*G and roots["root_cap_bytes"]==CAP,
           "changed complete host, holding, temporary or audit commitments")
    audit_group=Path("/sys/fs/cgroup/horizonaudit.slice")
    s.need((audit_group/"cpu.max").read_text().split()==["400000","100000"]
           and int((audit_group/"memory.max").read_text())==24*G and int((audit_group/"memory.swap.max").read_text())==0,
           "changed native audit allocation")
    remaining=CAP-tree["physical_bytes"]
    fixed=max(x["historical_floor_bytes"],audit["configured_free_floor_bytes"])
    other=(fixed+roots["peer_remaining_growth_bytes"]+10*G+x["auxiliary"]["remaining_growth_bytes"]+
           (64<<20)+x["independent166_whole_cap_bytes"]+18*G)
    prior169=s.read(F169/"POST_GUARD_CAPACITY.json","803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc")[0]["protected_raw_floor_bytes"]
    def base(unspent):
        return max(other+unspent,prior169,8297502499408+unspent)
    s.need(base(roots["remaining_standard_root_bytes"])==anchor["reservation_baseline"],"original fit does not reproduce")
    b=peers["172"]["guard"]
    if "169" in peers:
        a=peers["169"]["guard"]
    else:
        plan=s.bound(P169,Path(P169["path"]))
        a=dict(floor=plan["minimum_free_bytes"],remaining=plan["maximum_root_physical_bytes"])
    complete=max(max(base(remaining),a["floor"])+a["remaining"]+16*G,b["floor"])+b["remaining"]+(128<<20)
    return complete,dict(retained_168_remaining=remaining,historical_168_remaining=roots["remaining_standard_root_bytes"],
        rebased_floor=base(remaining),original_base=anchor["reservation_baseline"],source=BOOK,shared_host=s.ref(ANCHOR,BASELINE))


def status_ready():
    if not READY.exists(): return None
    v,vr=s.read(READY)
    paths=dict(intent="START_INTENT",gated="NATIVE_GATED",admission="ACTUAL_ADMISSION_AND_PROTECTION",first_worker="FIRST_PROTECTED_WORKER")
    s.need(v["schema"]=="horizon-metered168-status-registered-v1" and v["epoch"]==168 and v["producer_unit"]==s.U
           and v["timer_unit"]==s.T and v["resource_credit_bytes"]==0 and v["prior_trace_terminal"]==s.ref(s.TRACE,s.CLOSED)
           and v["prepared"]==s.ref(D/"PREPARED.json",s.PREPARED) and v["controller"]==s.ref(D/"controller/deployment-seal-receipt.json",s.CONTROLLER)
           and v["evidence_paths"]=={k:str(D/(n+".json")) for k,n in paths.items()}, "foreign 168 readiness scope")
    seal=s.bound(v["publisher_seal"],CAD/"publisher-v1/deployment-seal-receipt.json")
    s.bound(v["parent_seal"],CAD/"parent-package/deployment-seal-receipt.json")
    s.need(Path(v["qualification"]["path"]).is_relative_to(CAD), "foreign publisher fixture")
    s.bound(v["qualification"],Path(v["qualification"]["path"]))
    own=v["publisher"]
    m=s.show(PUBLISHER);pid=own["pid"]
    consumer=CAD/"publisher-v1/consume"
    s.need(any(x["name"]=="consume" and x["sha256"]==own["consumer"]["sha256"] for x in seal["members"])
           and own["consumer"]["path"]==str(consumer),"foreign publisher member")
    binary(consumer,own["consumer"]["sha256"])
    lock=LOCK.stat(); proc=Path(f"/proc/{pid}")
    s.need(own["unit"]==PUBLISHER and own["invocation_id"]==m["InvocationID"] and m["ActiveState"]=="active"
           and m["SubState"]=="running" and not m["Job"] and int(m["MainPID"])==pid
           and m["ControlGroup"]==own["cgroup"]=="/system.slice/"+PUBLISHER
           and s.process(pid)[1:]==(own["start_ticks"],"0::"+own["cgroup"])
           and own["lock"]==dict(path=str(LOCK),device=lock.st_dev,inode=lock.st_ino)
           and s.same_file(proc/"fd/9",LOCK) and s.same_file(proc/"fd/255",consumer),"status publisher replaced")
    info=(proc/"fdinfo/9").read_text()
    s.need(any(l.startswith("lock:") and " FLOCK " in l and " WRITE " in l and str(lock.st_ino) in l
               for l in info.splitlines()), "publisher lost consumer.lock")
    return vr


def phase145():
    m=s.show(A145)
    stable={k:m.get(k) for k in ("Id","InvocationID","MainPID","ControlGroup","ActiveState","SubState","Job","Result")}
    if m["ActiveState"]=="active":
        pid=int(m["MainPID"]);p=Path(f"/proc/{pid}")
        image=(p/"exe").stat()
        stable.update(start_ticks=s.process(pid)[1],exe=str((p/"exe").readlink()),inode=image.st_ino,
                      device=image.st_dev,argv=[os.fsdecode(x) for x in (p/"cmdline").read_bytes().split(b"\0") if x])
        lockpath=Path("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock")
        lock=lockpath.stat()
        holding=[]
        for fd in (p/"fd").iterdir():
            try:
                if os.path.samestat(fd.stat(),lock) and any(" FLOCK " in l and " WRITE " in l for l in
                    (p/"fdinfo"/fd.name).read_text().splitlines()):
                    holding.append(int(fd.name))
            except FileNotFoundError:
                continue
        stable["holding_lock"]=dict(path=str(lockpath),device=lock.st_dev,inode=lock.st_ino,fds=sorted(holding))
        window=overlap.inspect(stable,m,A145,members(A145))
        return dict(stable,window=window),window is not None
    # The publication producer writes this only after verified pair, checksum, public playback and final inventory.
    # A transient gap between recovery and publication cannot satisfy it.
    pub=R/"epoch145-publication-20261121-v1"
    terminal=[p for p in pub.glob("network-*/complete.json") if s.iid(p.parent.name.removeprefix("network-"))]
    if len(terminal)!=1: return stable,False
    final,fr=s.read(terminal[0])
    g=final["invocation"]
    s.need(terminal[0].parent.name=="network-"+g and final["original_source_retained"] is True
           and final["canonical_output_retained"] is True and m["ActiveState"]=="inactive" and not m["Job"]
           and int(m.get("MainPID",0))==0 and not members(A145),"145 publication is not fully drained")
    receipt=s.bound(final["verified_pair"],terminal[0].parent/"receipts/epoch-145.r2.json")
    after=s.bound(final["authenticated_inventory"],terminal[0].parent/"after.json")
    played=s.bound(final["public_playback"],Path(final["public_playback"]["path"]))
    entry=next(x for x in after["entries"] if x["epoch"]==145)
    s.need(receipt["epoch"]==played["epoch"]==145 and receipt["remote_sha256_readback"] is True and entry["state"]=="ready-pair"
           and receipt["archive_sha256"]==entry["sidecar_sha256"]==entry["archive_metadata_sha256"]==played["remote_playback"]["object"]["sha256"]
           and receipt["archive_etag"]==entry["archive_etag"]==played["remote_playback"]["object"]["etag"]
           and entry["archive_length"]==receipt["archive_length"]==105610995833,"unverified 145 terminal pair")
    return dict(stable,publication=fr),True


def remaining136(plan, sample):
    # The 72 GiB booking includes 8 GiB beyond the native 64 GiB subtree stop.
    # Only the subtree blocks seen by both complete walks can offset the booking.
    cap = 64 * G
    scan = sample["root_physical_observation"]
    s.need(plan["maximum_root_physical_bytes"] == sample["maximum_root_physical_bytes"] == cap
           and scan["maximum_physical_bytes"] == cap and scan["exceeds_budget"] is False,
           "different 136 subtree guard")
    walks = [scan["first"], scan["second"]]
    s.need(all(type(w["physical_bytes"]) is int and 0 <= w["physical_bytes"] <= cap
               and type(w["vanished_entries"]) is int and w["vanished_entries"] >= 0
               for w in walks), "invalid 136 physical measurement")
    realized = 0 if any(w["vanished_entries"] for w in walks) else min(w["physical_bytes"] for w in walks)
    return 72 * G - realized


def candidate136(fleet,ready):
    unit=s.show(N136)
    root=Path("/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1")
    managed=members(N136)
    registry=Path("/run/horizon-epoch171-exclusive-to136-g1/standard169-cpu.json")
    if not managed:
        s.need(unit["ActiveState"]=="inactive" and not unit["Job"] and not registry.exists()
               and not (root/"admission.json").exists(),"136 or its donor is transitioning")
        return dict(occupied=False,cap=72*G,remaining=72*G,loan_micros=0,identity=None)
    s.need(ready is not None,"unregistered occupied 136")
    row=next(x for x in fleet["actual_active_private_diagnostics"] if x["epoch"]==136)
    v=s.bound(ready,READY)
    seal=s.bound(v["publisher_seal"],CAD/"publisher-v1/deployment-seal-receipt.json")
    pkg=CAD/"publisher-v1"
    for item in seal["members"]:
        if item["name"].endswith(".py"):
            binary(pkg/item["name"],item["sha256"])
    # Use the status owner's exact current 136 admission, first/latest guard and parent-release verifier.
    code="import sys,json;sys.path.insert(0,sys.argv[1]);import private136;print(json.dumps(private136.observation()))"
    current=json.loads(command("/usr/bin/python3","-IB","-c",code,str(pkg)))
    s.need(current["active_at_capture"] is True and current["unit"]["InvocationID"]==row["unit"]["InvocationID"]==unit["InvocationID"]
           and current.get("guard") and current.get("post_prefire_capacity"),"136 is outside its protected phase")
    guard=current["guard"]; plan=s.bound(guard["plan"],root/"reproduction/receipts/guard-plan.json")
    sample=s.bound(guard["sample"],Path(guard["sample"]["path"]))
    fire=sample["guard_invocation_id"]
    s.need(s.iid(fire) and Path(guard["sample"]["path"])==root/"reproduction/receipts/guard"/f"sample-{fire}.json"
           and sample["plan_sha256"]==guard["plan"]["sha256"]
           and sample["producer_invocation_id"]==plan["invocation_id"]==unit["InvocationID"],"different 136 guard receipt")
    pref=current["post_prefire_capacity"]; post=s.bound(pref,root/"capacity-post-prefire.json")
    donor=post["exclusive_handoff_receipt"]; s.bound(donor,root/"donor171.json")
    masks,regref=s.read(registry)
    lease=post["complete_fresh_fit"]["exclusive_standard169_cpu_lease"]
    routes=lease["masked_standard_routes"]
    s.need(lease["registry"]==regref and lease["cpu_quota_micros"]==4250000 and len(routes)>0
           and masks["schema"]=="epoch136-standard169-cpu-mask-v1" and set(routes)==set(masks["standard_routes"])
           and masks["boot"]==Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"136 donor loan changed")
    anchor=registry.parent/"mask"
    for name in routes:
        path=Path("/run/systemd/system.control")/name
        s.need("/" not in name and path.is_symlink() and path.readlink()==Path("/dev/null")
               and os.path.samestat(path.lstat(),anchor.lstat()) and s.show(name)["LoadState"]=="masked" and not members(name),
               "standard 169 route is no longer fenced")
    remain=remaining136(plan,sample)
    s.need(members(N136)==managed,"136 fit changed")
    return dict(occupied=True,cap=72*G,remaining=remain,loan_micros=4250000,guard_floor=plan["minimum_free_bytes"],
                guard_plan=guard["plan"],guard_sample=guard["sample"],
                identity=dict(unit=N136,iid=unit["InvocationID"],processes=[[p,s.process(p)[1]] for p in managed],fence=regref))


def membership(peers,own,candidate):
    expected={v["unit"] for v in peers.values()}
    worker_pids={v["processes"][1][0] for v in peers.values()}
    if own is not None: expected.add(s.U)
    if candidate["occupied"]: expected.add(N136)
    s.need(units()==expected,"unexpected executing qualifier topology")
    for v in peers.values():
        unit=v["unit"]; t=s.show(v["timer"]); mgr=s.show(unit)
        s.need(mgr["InvocationID"]==v["invocation_id"] and int(mgr["MainPID"])==v["processes"][0][0]
               and mgr["ActiveState"]=="active" and not mgr["Job"] and mgr["NRestarts"]=="0"
               and t["InvocationID"]==v["timer_invocation_id"] and t["ActiveState"]=="active"
               and t["Triggers"]==v["timer"].removesuffix(".timer")+".service"
               and members(unit)==tuple(sorted(p[0] for p in v["processes"])),"incumbent generation changed")
        for pid,ticks,dev,ino in v["processes"]:
            m=Path(f"/proc/{pid}/exe").stat()
            s.need(s.process(pid)[1:]==(ticks,"0::/system.slice/"+unit) and (m.st_dev,m.st_ino)==(dev,ino),
                   "incumbent process generation changed")
    if candidate["occupied"]:
        identity=candidate["identity"]
        s.need(s.show(N136)["InvocationID"]==identity["iid"] and
               [[p,s.process(p)[1]] for p in members(N136)]==identity["processes"],"136 ownership changed")
    actual=set()
    for p in Path("/proc").iterdir():
        if not p.name.isdigit(): continue
        try:
            comm=(p/"comm").read_text().strip()
            if comm.startswith("historical-work"):
                if candidate["occupied"] and int(p.name) in members(N136): continue
                actual.add(int(p.name))
        except (FileNotFoundError,ProcessLookupError):
            continue
    s.need(actual==worker_pids,"unregistered or missing native historical worker")
    if own is not None:
        s.need(members(s.U)==(own["producer_pid"],),"private worker before normal 168 release")
    return dict(incumbents={k:{key:v[key] for key in ("unit","invocation_id","processes","timer","timer_invocation_id")}
                           for k,v in peers.items()},candidate=candidate["identity"])


def capture(fleetref,own=None):
    gate=None
    if own is not None:
        intent=s.read(D/"START_INTENT.json")[0]
        _,gate=s.native_actor(intent)
        s.identity(gate,own)
    phase,compatible=phase145()
    ready=status_ready()
    fleet,ledger,peers,closed=inventory(fleetref)
    candidate=candidate136(fleet,ready)
    topo=membership(peers,own,candidate)
    tree=measure_tree()
    raw,evidence=floor(fleet,ledger,tree,peers)
    protected=max(raw,candidate.get("guard_floor",0))
    required=protected+(candidate["remaining"] if candidate["occupied"] else 0)
    joint=protected+candidate["remaining"]
    info={l.split()[0]:int(l.split()[1])*1024 for l in Path("/proc/meminfo").read_text().splitlines()
          if l.startswith(("MemTotal:","MemAvailable:"))}
    vfs=os.statvfs("/home/sol")
    available=vfs.f_bavail*vfs.f_frsize
    early=bool((phase.get("window") or {}).get("original_five_peer_failure"))
    need_mem=MEM-sum(v["resident"] for epoch,v in peers.items() if not early or epoch!="166")
    s.need(len(os.sched_getaffinity(0))>=1 and int(command("/usr/bin/getconf","_NPROCESSORS_ONLN"))==64
           and info["MemTotal:"]>=MEM and need_mem>0,"host resource baseline changed")
    s.need(phase145()==(phase,compatible) and status_ready()==ready and membership(peers,own,candidate)==topo,
           "intervening 145, status or peer generation")
    if own is not None:
        s.identity(s.native_actor(intent)[1],own)
    fits=available>=(joint if early else required) and info["MemAvailable:"]>=need_mem
    return dict(schema="horizon-168-original-reservation-fresh-fit-v1",recorded_unix_seconds=int(time.time()),
        fleet=fleetref,producer_invocation_id=gate["producer_invocation_id"] if gate else None,
        complete_cpu_quota_micros=64000000,complete_memory_plus_reserve_bytes=MEM,
        required_available_memory_bytes=need_mem,available_memory_bytes=info["MemAvailable:"],
        complete_required_DATA_bytes=required,available_HOME_bytes=available,resource_credit_bytes=0,
        complete_raw_disk_floor=raw,standalone_guard_floor=max(8297502499408,required),
        candidate136=candidate,combined_required_HOME_bytes=joint,combined_disk_fits=available>=joint,
        candidate136_requires_standard169_loan_micros=4250000,normal_168_actor_quota_micros=9000000,
        normal_168_guard_quota_micros=250000,normal_168_actor_memory_bytes=68*G,
        normal_168_guard_memory_bytes=G,original_whole_tree=tree,booking=evidence,incumbents=peers,
        retired166=closed.get("166"),retired_original_peers=closed,population=topo,phase145=phase,status_registration=ready,
        registered_population_compatible=bool(ready),fresh_phase_compatible=compatible,
        original166_resident_credit_bytes=0 if early else peers.get("166",{}).get("resident",0),
        resource_fits=fits,eligible_with_168_alone=bool(fits and ready and compatible),
        replay_launch_authorized=False,r2_mutations=False)


def select(before,after=None,armed=None):
    item=after or before
    s.need(item["eligible_with_168_alone"] and item["registered_population_compatible"] and item["fresh_phase_compatible"]
           and item["available_HOME_bytes"]>=item["complete_required_DATA_bytes"]
           and item["available_memory_bytes"]>=item["required_available_memory_bytes"],"168 capacity/phase/status admission denied")
    window=item["phase145"].get("window") or {}
    if window.get("original_five_peer_failure"):
        s.need(item["combined_disk_fits"] and item["available_HOME_bytes"]>=item["combined_required_HOME_bytes"],
               "live-166 recovery needs the full 136 donor allowance")
    if after is not None:
        for k in ("population","phase145","status_registration","fleet","retired_original_peers"):
            s.need(before[k]==after[k],"intervening change: "+k)
        s.need(armed is not None and item["standalone_guard_floor"]<=armed<=item["available_HOME_bytes"],
               "post-guard protected floor exceeds armed guard or available HOME")
    return item["standalone_guard_floor"]
