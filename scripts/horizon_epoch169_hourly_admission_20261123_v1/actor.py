"""Recognize the gated private actor in the existing complete native provider."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

BASE=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-admission-20261123-v1")
SEED=BASE/"START_INTENT.json"
UNIT="horizon-qualify-169-focused-hourly-20261123-v1.service"
TIMER="horizon-guard-169-focused-hourly-20261123-v1.timer"
TREE=Path("/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1")
SCOPE="/system.slice/"+UNIT
G=1<<30
WORKSPACE=68_117_473_606
FIXED=8<<20
CPU=64_000_000
RAM=810_658_050_048
GUARD_SHA="b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
IMAGE="b22fe558888143543594ddaf1bf7de0584a69448f7d27fde6803f8ae95d5bd92"
WORKER="9665351525b7a6a8b67e985fc35ad896a5adbcb7aeda0cab379be16cf693796a"
FAILED_PEERS = {
    "166": ("failed_cold166", "cold166_retry11_write_version_failure", "pid1_exit",
            "horizon-qualify-166-independent-retry11-20261122.service"),
    "170": ("failed_cold170", "cold170_retry13_execution_failure", "manager_exit",
            "horizon-qualify-170-replacement-local3retry13-20261122.service"),
}


def need(ok,msg):
    if not ok:
        raise ValueError(msg)


def pinned(ref):
    p=Path(ref["path"]);m=p.lstat()
    need(m.st_uid==0 and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and not (m.st_mode&0o022) and
         p.resolve(strict=True)==p and m.st_size<1<<24,"unsafe root receipt "+str(p))
    body=p.read_bytes()
    need(hashlib.sha256(body).hexdigest()==ref["sha256"],"wrong receipt digest "+str(p))
    return json.loads(body)


def props(unit,names):
    out=subprocess.check_output(["/usr/bin/systemctl","show",unit,"--property="+",".join(names)],timeout=10,text=True)
    row=dict(line.split("=",1) for line in out.splitlines())
    need(set(row)==set(names),"incomplete native owner")
    return row


def before(fleet, row=None):
    m=SEED.lstat()
    need(m.st_uid==0 and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and not m.st_mode&0o222 and
         SEED.resolve(strict=True)==SEED, "unsafe release intent")
    raw=SEED.read_bytes(); src=json.loads(raw); ref=dict(path=str(SEED),sha256=hashlib.sha256(raw).hexdigest())
    need(src["schema"]=="epoch169-hourly-bound-first-guard-intent-v1" and src["unit"]==UNIT and
         src["previous_producer_iid"]=="0dfa0d36fbc246c28443a1c90a82c9cb" and
         src["actor_memory_bytes"]==68*G and src["guard_memory_bytes"]==G and
         src["actor_cpu_micros"]==3_000_000 and src["guard_cpu_micros"]==1_000_000 and
         src["canonical_publication_authorized"] is False and 0<src["fixed_control_allowance"]==FIXED and
         src["charged_worker_growth"]==WORKSPACE-FIXED,"different private producer funding")
    need(src["boot_id"]==Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"different machine boot")
    iid=src["producer_invocation_id"]
    n=props(UNIT,["Id","ActiveState","SubState","InvocationID","MainPID","NRestarts","Job","ControlGroup",
                  "CPUQuotaPerSecUSec","MemoryMax","MemoryHigh","MemorySwapMax","User","Group"])
    pid=int(n["MainPID"])
    need(n["Id"]==UNIT and not n["Job"] and (n["ActiveState"],n["SubState"])==("active","running") and
         n["InvocationID"]==iid and pid==src["pid"]>1 and n["NRestarts"]=="0" and n["ControlGroup"]==SCOPE and
         n["CPUQuotaPerSecUSec"]=="3s" and int(n["MemoryMax"])==68*G and int(n["MemoryHigh"])==64*G and
         n["MemorySwapMax"]=="0" and n["User"]=="sol" and n["Group"]=="horizon","wrong hourly cgroup")
    t=props(TIMER,["Id","ActiveState","InvocationID","Job","Triggers"])
    need(t["Id"]==TIMER and t["ActiveState"]=="active" and not t["Job"] and t["InvocationID"]==src["timer_iid"]
         and t["Triggers"]==TIMER.replace(".timer",".service"),"hourly guard timer changed")
    guard=props(t["Triggers"],["CPUQuotaPerSecUSec","MemoryMax","MemorySwapMax"])
    need(guard["CPUQuotaPerSecUSec"]=="1s" and int(guard["MemoryMax"])==G and guard["MemorySwapMax"]=="0",
         "hourly guard resource limits changed")
    group=Path("/sys/fs/cgroup")/SCOPE[1:]
    need((group/"cpu.max").read_text().split()==["300000","100000"] and int((group/"memory.max").read_text())==68*G
         and int((group/"memory.swap.max").read_text())==0,"native hourly kernel limits")
    members=sorted(map(int,(group/"cgroup.procs").read_text().split()))
    need(pid in members and 1<=len(members)<=2,"unexpected hourly process count")
    boot=Path("/proc")/str(pid)
    cmd=boot.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    main=boot/"exe"
    ticks=lambda p:int((Path("/proc")/str(p)/"stat").read_text().rsplit(")",1)[1].split()[19])
    process=lambda p:[p,ticks(p),*(lambda st:(st.st_dev,st.st_ino))((Path("/proc")/str(p)/"exe").stat())]
    prs=[process(pid)]
    need(prs[0][1]==src["start_ticks"],"hourly parent reused")
    held=cmd==[b"/usr/bin/python3",b"-IB",b"/run/horizon-169-hourly/hourly_gate.py"]
    if held:
        need(os.path.samefile(main,"/usr/bin/python3") and members==[pid],"not the held hourly barrier")
    else:
        need(main.readlink()==Path("/run/horizon-169-hourly/jetstreamer-node") and
             src["sealed_node"]==dict(path=str(BASE.parent/"epoch169-hourly-release-proof-1795425829301762377/sealed/jetstreamer-node"),sha256=IMAGE) and os.path.samefile(main,src["sealed_node"]["path"]),
             "unrecognized hourly main process")
        if len(members)==2:
            child=next(p for p in members if p!=pid)
            ex=Path("/proc")/str(child)/"exe"
            name=ex.readlink()
            need(name.name=="historical-worker" and name.is_relative_to(TREE/"v158/scratch"),"escaped hourly worker")
            with ex.open("rb") as fd:
                need(hashlib.file_digest(fd,"sha256").hexdigest()==WORKER,"wrong hourly worker image")
            prs.append(process(child))
    plan=pinned(src["guard_plan"])
    need(plan["unit"]==UNIT and plan["invocation_id"]==iid and plan["worker_root"]==str(TREE) and
         plan["receipt_directory"]==str(TREE/"hourly-guard-receipts") and plan["filesystem"]=="/home/sol" and
         plan["maximum_worker_vmas"]==3_500_000 and plan["maximum_root_physical_bytes"]==
         src["prestart_physical_bytes"]+src["charged_worker_growth"],"different paid guard")
    if row is not None:
        need(row["epoch"]==169 and row["unit"]["Id"]==UNIT and row["unit"]["InvocationID"]==iid and
             int(row["unit"]["MainPID"])==pid and row["hourly169_start_intent"]==ref,"unjoined private observer row")
    else:
        need(fleet["focused169_terminal"]==src["previous_terminal"]==dict(
             path="/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-terminal-20261121-v1/TERMINAL.json",
             sha256="218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5"),"unjoined prior closure")
    return dict(unit=UNIT,processes=prs,held=held,intent=ref,plan=src["guard_plan"],producer_iid=iid,
                timer_iid=t["InvocationID"],initial_physical=src["prestart_physical_bytes"])


def public_workers(native, fleet):
    observation = pinned(fleet["current_audit_progress"]["observation"])
    workers = native["recovery_obligations"]["public_workers"]
    need(workers == observation["active_ready_workers"] and
         len({(w["pid"], w["start_ticks"]) for w in workers}) == len(workers) and
         len({tuple(w["range"]) for w in workers}) == len(workers),
         "public audit roster differs from the coordinated fleet")
    return workers


def replay_peers(native, fleet):
    """Join the funded live peers and prove any missing retry is terminal."""
    survivors = native["survivors"]
    replacements = native["replacements"]
    need(set(survivors) == {"172"} and {"167", "168"} <= set(replacements)
         and set(replacements) <= {"166", "167", "168", "170"}, "unexpected native replay peers")
    expected = {e: (row["unit"], row["invocation_id"]) for e, row in survivors.items()}
    expected.update({e: (row["producer_unit"], row["producer_invocation_id"])
                     for e, row in replacements.items()})
    rows = fleet["actual_executing_replays"]
    actual = {str(row["epoch"]): (row["unit"]["Id"], row["unit"]["InvocationID"]) for row in rows}
    need(len(actual) == len(rows) and actual == expected, "native replay peers differ from the fleet")

    for epoch, (native_key, fleet_key, event_key, unit) in FAILED_PEERS.items():
        if epoch in replacements:
            need(native_key not in native and fleet_key not in fleet, f"live retry {epoch} also appears terminal")
            continue
        failure = native.get(native_key)
        need(failure and failure == fleet.get(fleet_key) and failure["reservation_ending_bytes"] == 0,
             f"missing matching native and fleet terminal for {epoch}")
        event = pinned(failure["terminal"])[event_key]
        need(event["UNIT"] == unit and event["INVOCATION_ID"] == failure["producer_invocation_id"]
             and event["_PID"] == "1" and event["EXIT_CODE"] == "exited" and event["EXIT_STATUS"] == "1",
             f"foreign terminal invocation for {epoch}")


def price(native, fleet, binding, guard):
    """Retain the previous 96 GiB booking and count new growth once."""
    plan=pinned(binding["plan"])
    need(native["complete_cpu_quota_micros"]==CPU and native["complete_memory_plus_reserve_bytes"]==RAM and
         native["candidate136"]["occupied"] is False and native["candidate136"]["loan_micros"]==0 and
         native["resource_credit_bytes"]==0 and native["closed_focused169"]["terminal"]==fleet["focused169_terminal"],
         "different funding, donor, or predecessor terminal")
    replay_peers(native, fleet)
    public_workers(native, fleet)
    b=native["bookings"]["169"]
    need(b["cap_bytes"]==96*G==b["physical_bytes"]+b["remaining_bytes"],"lost original 169 disk obligation")
    cap=plan["maximum_root_physical_bytes"]; obs=guard["root_physical_observation"]
    need(guard["guard_sha256"]==GUARD_SHA and guard["plan_sha256"]==binding["plan"]["sha256"] and
         guard["producer_invocation_id"]==binding["producer_iid"] and guard["producer_stop_enabled"] is True and
         guard["trip_reason"] is None and guard["worker_observation_error"] is None and
         guard["root_physical_observation_error"] is None and guard["maximum_root_physical_bytes"]==cap and
         obs["maximum_physical_bytes"]==cap and not obs["exceeds_budget"] and
         guard["minimum_free_bytes"]==plan["minimum_free_bytes"] and 0<=time.time()-guard["recorded_unix_seconds"]<=90,
         "no recent guard sample for this actor")
    baseline=binding["initial_physical"]
    need(baseline>=0 and cap-baseline==WORKSPACE-FIXED,"incorrect initial private tree")
    raw = [obs[k]["physical_bytes"] for k in ("first","second")]
    need(all(baseline<=value<=cap for value in raw),"lost the frozen source or exceeded its cap")
    # Match the two-pass booked-tree policy of the five-owner provider. Use only the
    # immutable baseline if either pass saw a disappearance, otherwise use the lower
    # allocation. The matching guard free-space reading is also a lower bound.
    physical=min(raw) if all(obs[k]["vanished_entries"]==0 for k in ("first","second")) else baseline
    pending = cap-physical+FIXED
    ob=native["recovery_obligations"]
    # Current public report growth is tracked by the active native obligation and can only increase
    # this floor. Source staging has already completed and is in the actual free-space measurement.
    audit=ob["public_storage"]
    need(audit["remaining_archive_growth_bytes"]==0,"unexpected audit archive staging")
    public_growth=audit["remaining_DATA_growth_bytes"]
    protected=max(native["complete_required_HOME_bytes"]+public_growth+FIXED,plan["minimum_free_bytes"])
    total=protected+cap-physical
    free=min(native["available_HOME_bytes"],guard["available_bytes"])
    return dict(native=native,fits=free>=total and native["available_memory_bytes"]>=native["required_available_memory_bytes"],
                required_HOME=total,available_HOME=free,required_available_memory=native["required_available_memory_bytes"],
                complete_memory=RAM,complete_cpu=CPU,previous_cap=b["cap_bytes"],disjoint_workspace=WORKSPACE,workspace_remaining=pending,worker_physical_bytes=physical,
                private_actor=binding,current_guard=guard["guard_invocation_id"],resource_credit_bytes=0,
                canonical_publication_authorized=False)

def roster(fleet):
    public=fleet["actual_executing_replays"]+fleet["actual_active_bootstraps"]
    private=fleet["actual_active_private_diagnostics"]
    own=[v for v in private if v["epoch"]==169]
    need(len(own)<=1 and not any(v["epoch"]==169 for v in public),"unexpected canonical 169 or duplicate private owner")
    return public+[v for v in private if v["epoch"]!=169],own[0] if own else None


def archival_roster(fleet):
    """Retain the closed G4 evidence and positively join its disjoint successor."""
    peers, row = roster(fleet)
    return peers, before(fleet, row)


def newest_guard(binding):
    plan=pinned(binding["plan"])
    directory=Path(plan["receipt_directory"])
    # Each receipt filename is the invocation UUID of the timer-driven guard run.
    # The newest receipt may be replaced only by a later fresh receipt for this same producer.
    files=[p for p in directory.glob("sample-*.json") if re.fullmatch(r"sample-[0-9a-f]{32}\.json",p.name)]
    need(files,"waiting for first real hourly guard sample")
    p=max(files,key=lambda f:f.stat().st_mtime_ns)
    ref=dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    sample=pinned(ref)
    need(p.name=="sample-"+sample["guard_invocation_id"]+".json" and
         sample["producer"]["invocation_id"]==binding["producer_iid"] and
         sample["producer"]["pid"]==binding["processes"][0][0] and sample["plan"]==binding["plan"]["path"],
         "wrong guard receipt owner")
    return sample, ref
