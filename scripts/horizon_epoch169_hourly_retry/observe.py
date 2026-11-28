"""Observe the private retry for both native censuses and the existing fleet cadence."""
import hashlib
import os
from pathlib import Path
import re
import runpy
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as c
import namespace
import quote

HERE=Path(__file__).resolve().parent
FIELD="current_private169_retry"
TIMER="horizon-guard-169-hourly-retry-20261128-v1.timer"
LOG=c.RETRY/"hourly-run/producer.log"


def guard(actor):
    plan=quote.bound(actor["plan"])
    receipts=c.RETRY/"hourly-guard-receipts"
    files=(p for p in receipts.glob("sample-*.json") if re.fullmatch(r"sample-[a-f0-9]{32}\.json",p.name))
    latest=max(files,key=lambda p:p.stat().st_mtime_ns,default=None)
    c.need(latest is not None, "no native retry guard sample")
    row,ref=c.read(latest,sealed=False)
    cap=actor["initial_physical"]+c.HOME_OUTPUT
    measure=row["root_physical_observation"]
    c.need(plan["filesystem"]=="/home/sol" and plan["worker_root"]==str(c.RETRY)
           and plan["receipt_directory"]==str(receipts) and plan["unit"]==c.UNIT
           and plan["invocation_id"]==actor["producer_iid"]==row["producer_invocation_id"]
           and plan["maximum_worker_vmas"]==row["maximum_worker_vmas"]==3_500_000
           and plan["maximum_root_physical_bytes"]==row["maximum_root_physical_bytes"]==cap
           and plan["minimum_free_bytes"]==row["minimum_free_bytes"]<=row["available_bytes"]
           and row["schema"]=="jetstreamer-horizon-standalone-guard-sample-v1"
           and row["guard_sha256"]=="b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
           and row["plan_sha256"]==actor["plan"]["sha256"] and latest.name=="sample-"+row["guard_invocation_id"]+".json"
           and row["producer"]["pid"]==actor["processes"][0][0] and row["producer"]["cgroup"]=="/system.slice/"+c.UNIT
           and row["producer_stop_enabled"] and not any(row[key] for key in
            ("trip_reason","worker_observation_error","root_physical_observation_error","r2_mutations","remote_mutations"))
           and not measure["exceeds_budget"] and 0<measure["conservative_physical_bytes"]<=cap
           and 0<=time.time()-row["recorded_unix_seconds"]<=90, "stale, unbound or tripped retry guard")
    return row,ref


def current(fleet):
    """A terminal read uses the immutable event result and an empty native cgroup."""
    actor_path=c.CONTROL/"START_INTENT.json"
    props=quote.state(c.UNIT)
    previous=fleet.get(FIELD)
    if props["ActiveState"] in ("inactive","failed"):
        c.need(not props["ControlGroup"] and props["MainPID"]==props["ControlPID"]=="0" and
               not (Path("/sys/fs/cgroup/system.slice")/c.UNIT/"cgroup.procs").exists(), "169 retry still draining")
        end_path=c.CONTROL/"results/TERMINAL.json"
        if not end_path.exists():
            c.need(not previous and not actor_path.exists() and not (c.CONTROL/"HELD_GATE.json").exists(),
                   "169 retry is awaiting its terminal event")
            return None
        terminal,ref=c.read(end_path)
        held,hr=c.read(c.CONTROL/"HELD_GATE.json")
        iid=held["invocation_id"]
        c.need(props["InvocationID"] in ("",iid) and terminal["canonical_publication_authorized"] is False,
               "foreign stopped retry")
        if terminal["disposition"]=="private-payload-never-released":
            c.need(not (c.CONTROL/"GRANT.json").exists(), "retry grant exists for unreleased payload")
        else:
            grant,gr=c.read(c.CONTROL/"GRANT.json",terminal["grant_sha256"])
            c.need(grant["invocation_id"]==iid==terminal["invocation_id"] and terminal["unit"]==c.UNIT,
                   "different stopped retry grant")
        return dict(epoch=169,phase="terminal",unit=props,invocation_id=iid,held=hr,terminal=ref,
                    canonical_replay_claimed=False,archive_publication_authorized=False,resource_credit_bytes=0)
    frozen=runpy.run_path(str(HERE/"actor.py"))
    actor=frozen["before"](fleet,split_scratch=True)
    pid=actor["processes"][0][0]
    iid=actor["producer_iid"]
    plan=quote.bound(actor["plan"])
    seed=quote.bound(actor["intent"])
    mounts=namespace.inspect(pid)
    c.need(seed["namespace"]==mounts and props["InvocationID"]==iid and props["MainPID"]==str(pid),
           "retry changed mount or process")
    sample,ref=guard(actor)
    observed=[p[0] for p in sample["workers"]]
    worker=actor["processes"][1] if len(actor["processes"])==2 else None
    c.need(len(observed)<=1 and (not observed or worker and observed==[worker[0]]),
           "guard found another historical worker")
    phase="held" if actor["held"] else "worker" if observed else "bootstrap"
    release=None
    log=None
    if not actor["held"]:
        grant,release=c.read(c.CONTROL/"GRANT.json")
        log=LOG.lstat()
        c.need(grant["invocation_id"]==iid and grant["pid"]==pid and grant["namespace"]==mounts
               and (log.st_dev,log.st_ino)==(grant["log_device"],grant["log_inode"])
               and os.path.samestat(log,(Path("/proc")/str(pid)/"fd/1").stat()), "unregistered retry payload")
    row=dict(epoch=169,unit=props,invocation_id=iid,phase=phase,actor={"producer_pid":pid,"producer_invocation_id":iid},
             processes=actor["processes"],start_ticks=actor["processes"][0][1],intent=actor["intent"],
             guard_plan=actor["plan"],guard=ref,guard_floor=plan["minimum_free_bytes"],release=release,
             observer_config=None,canonical_replay_claimed=False,archive_publication_authorized=False,resource_credit_bytes=0)
    if phase=="worker":
        row["worker"]=dict(pid=worker[0],start_ticks=worker[1],device=worker[2],inode=worker[3],
                           path=str((Path("/proc")/str(worker[0])/"exe").readlink()))
        row["observer_config"]=dict(range="169",producer_unit=c.UNIT,controller_unit=c.UNIT,
                                    expected_producer_invocation_id=iid,expected_controller_invocation_id=iid,
                                    scratch_path=mounts["scratch"]["path"],worker_executable_basename="historical-worker",
                                    append_log=dict(path=str(LOG),device=log.st_dev,inode=log.st_ino))
    return row


def census(fleet):
    row=current(fleet)
    if not row or row["phase"]=="terminal":
        return None
    return dict(unit=c.UNIT,invocation=row["invocation_id"],pid=row["actor"]["producer_pid"],phase=row["phase"],
                guard_plan=row["guard_plan"],floor=row["guard_floor"],intent=row["intent"],release=row["release"])


def predecessor_view(fleet):
    """Adapt the former reader's one-private-row contract after authenticating the successor."""
    pri=fleet.get(FIELD)
    existing=[r for r in fleet["actual_active_private_diagnostics"] if r["epoch"]==169]
    if not existing:
        return fleet
    c.need(pri and existing==[pri] and pri["unit"]["Id"]==c.UNIT and pri["phase"] in ("held","bootstrap","worker")
           and pri["intent"]==c.read(c.CONTROL/"START_INTENT.json")[1]
           and quote.bound(pri["intent"])["producer_invocation_id"]==pri["invocation_id"]
           and not pri["archive_publication_authorized"] and not pri["canonical_replay_claimed"],
           "foreign private 169 row alongside historical closure")
    return dict(fleet,actual_active_private_diagnostics=[r for r in fleet["actual_active_private_diagnostics"] if r!=pri])
