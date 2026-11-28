"""Exercise the actual V60 handoff and all three epoch 162 histories in a private mount namespace."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def check(writer, route, ready, derive):
    def rejects(reason, run):
        try:
            run()
        except (KeyError, AssertionError, ValueError) as error:
            if reason and reason not in str(error):
                raise
            return
        raise AssertionError("accepted invalid case " + reason)

    fleet = writer.checked(ready["fleet"])
    cfg = writer.sealed(ready["config"])
    first = route.history.first_terminal(fleet)
    prior_ref = writer.checked(fleet["complete_active_status_audit"])["receipts"]["162"]
    before = writer.checked(prior_ref)
    prior_gate = route.previous(fleet)
    assert route.current(fleet) == prior_gate and prior_gate["phase"] == "terminal"
    assert route.baseline(SimpleNamespace(fleet=fleet), prior_ref) == prior_ref
    assert route.frozen({route.history.first.FIELD:first,route.history.second.FIELD:prior_gate}) == prior_gate
    assert ready["private169_retry4_scope"] == writer.retry169_status.SCOPE
    assert ready["second_ram_gap170_interface"] == writer.ram170_second_status.INTERFACE
    assert route.second.api().UNIT == route.SECOND and route.second.api().scope()["unreleased_predecessor"] == route.CLOSED
    assert ready["split162_reader"] == writer.bound(derive.NEW/"status162.py")
    assert ready["second162_reader"] == writer.bound(derive.NEW/"second162_status.py")
    assert ready["second162_retry_reader"] == writer.bound(derive.NEW/"second162_retry_status.py")
    assert ready["second162_retry_predecessor"] == route.CLOSED
    assert ready["old_owner"]["sha256"] == derive.OWNER
    for name in ("ram170_second_status.py","fourth169_status.py","status162.py","second162_status.py","second162_route.py","second162_progress.py"):
        assert (derive.NEW / name).read_bytes() == (derive.OLD / name).read_bytes()
    cases = ["V59 handoff on the incumbent clock", "fourth 169 and second 170 preserved", "first split and original interval-two gate retained"]
    iid = "105a4e3254f24dfe8afe00f00dbeef12"
    boot = "7f76387d-d961-4046-8b39-dcf01e726fea"
    held = {"path":"fixture-held","sha256":"c"*64}
    row = dict(first,unit=dict(Id=route.SECOND,ActiveState="active",SubState="running",InvocationID=iid,MainPID="7321"),
               actor=dict(producer_unit=route.SECOND,producer_pid=7321,producer_invocation_id=iid,boot_id=boot,start_ticks=100,
                          mounts={"disk_device":421,"scratch_device":422},guard_plan={"path":"fixture-plan","sha256":"e"*64}),
               held_owner=held,producer_invocation_id=iid,observer_config=None,native_diagnostic=None,terminal=None,
               phase="held",worker=None,guard={"path":"fixture-guard","sha256":"9"*64},observer={"path":"fixture-observer"},
               mounts={"disk_device":421,"scratch_device":422},canonical_replay_claimed=False,transaction_replay_claimed=False)
    now = writer.utc(before["after_status"]["sampled_at_utc"]) + timedelta(seconds=1800)
    c = SimpleNamespace(fleet=fleet,now=now,stamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),cfg=cfg,
                        next_cfg={"diagnostic_replays":[]},sample={"diagnostic_replays":[]},sample_ref=row["observer"])
    delivery = lambda _c, _epoch, _size: {"total_millis":600000}
    with patch.object(route.second,"current",return_value=deepcopy(row)):
        assert route.observe(c,lambda *_:False)["held_owner"] == held
        assert route.current(fleet)["phase"] == "held"
    old_phase = before["after_status"]["phase"]
    with patch.object(route.history.split_wire,"elapsed",return_value=45000):
        after,extra = route.forecast(c,row,before["after_status"],before,prior_ref,delivery)
    assert after["phase"] == "verification" and extra["private162_second_retry_turnover"]["unreleased"] == route.CLOSED
    assert extra["private162_second_retry_held"] == held and extra["private162_split_enrollment"] == before["private162_split_enrollment"]
    assert before["after_status"]["phase"] == old_phase
    old_replay = dict(before,after_status=dict(before["after_status"],phase="replay"),producer_invocation_id=route.PRIOR,private162_second_held=prior_gate["held_owner"])
    with patch.object(route.history.split_wire,"elapsed",return_value=45000):
        assert route.forecast(c,row,old_replay["after_status"],old_replay,prior_ref,delivery)[1]["private162_second_retry_turnover"]["after_etag"] == before["after_etag"]
        rejects("foreign 162 predecessor", lambda:route.forecast(c,row,old_replay["after_status"],dict(old_replay,producer_invocation_id="f"*32),prior_ref,delivery))
    cases += ["retry acquired from authenticated held-gate closure", "old unissued gate census binds retry transition", "foreign prior replay refused"]
    c.fleet = dict(fleet)
    for phase in ("held","bootstrap","worker","terminal"):
        current = dict(row,phase=phase)
        summary = {"actual_active_private_diagnostics":[], "actual_active_bootstraps":[], "actual_executing_replays":[],
                   "active_private_diagnostic_count":0,"active_producer_count":0,"epochs":[{"epoch":162}]}
        route.install(summary,fleet,current)
        assert summary[route.history.first.FIELD] == first and summary[route.history.second.FIELD] == prior_gate and summary[route.second.FIELD] == current
        assert summary["active_producer_count"] == summary["active_private_diagnostic_count"] == int(phase!="terminal")
        cap = {}
        route.save(cap,fleet,current)
        assert route.frozen(cap) == current and route.fields(fleet,current)["private162_split_held"] == first["held_owner"]
        assert route.fields(fleet,current)["private162_second_retry_held"] == held and route.fields(fleet,current)["private162_second_held"] == prior_gate["held_owner"]
        view = route.earlier_fleet(dict(fleet,**{route.second.FIELD:current},actual_active_private_diagnostics=summary["actual_active_private_diagnostics"]))
        assert not any(r["epoch"] == 162 for r in view["actual_active_private_diagnostics"])
    rejects("duplicate", lambda:route.earlier_fleet(dict(fleet,actual_active_private_diagnostics=[row,row],**{route.second.FIELD:row})))
    rejects("foreign 162", lambda:route.receiver(dict(row,unit={"Id":"another.service"})))
    cases += ["held/bootstrap/worker/terminal each counted once", "both prior 162 terminals retained with retry", "foreign and duplicate actors refused"]

    progress = route.progress
    start = int(c.now.timestamp())
    start_utc = (c.now-timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
    prior_sample = {"schema":"jetstreamer-horizon-live-resource-sample-v2", "completed_at_utc":start_utc,"recorded_at_utc":start_utc}
    sample = {"schema":prior_sample["schema"],"recorded_at_utc":c.stamp,"completed_at_utc":c.stamp,"diagnostic_replays":[],
              "cadence":{"previous_sample":"previous","previous_sample_sha256":"p","previous_sample_recorded_at_utc":start_utc}}
    worker = {"pid":7322,"path":str(Path(progress.SCRATCH)/"runtime/historical-worker"),"start_ticks":101}
    current = dict(row,phase="worker",worker=worker)
    plan = {"invocation_id":iid,"unit":route.SECOND,"minimum_free_bytes":20,"maximum_worker_vmas":3500000}
    guard = dict(producer_invocation_id=iid,producer=dict(invocation_id=iid,pid=7321,restarts=0,cgroup="/system.slice/"+route.SECOND,
        active="active",sub="running"),producer_stop_enabled=True,trip_reason=None,plan_sha256="e"*64,
        guard_sha256=route.second.api().GUARD_SHA,worker_observation_error=None,root_physical_observation_error=None,
        root_physical_observation={"exceeds_budget":False},available_bytes=80,minimum_free_bytes=20,
        workers=[[7322,120]],maximum_worker_vmas=3500000,recorded_unix_seconds=start)
    lookup={"fixture-observer":sample,"previous":prior_sample,"fixture-held":row["actor"],"fixture-plan":plan,"fixture-guard":guard}
    def records(selectors,_since,_until):
        return [dict(selectors,MESSAGE=f"block slot {slot} total_txs={700+i}",__REALTIME_TIMESTAMP=str((start-2+i)*1000000),
                __MONOTONIC_TIMESTAMP=str(9000000+i*1000000),__CURSOR=f"cur{i}") for i,slot in enumerate((69991078,69991081))]
    assert progress.SCRATCH == "/home/sol/.jetstreamer-private/epoch162-second-replay-20261128-v2/scratch"
    confirmed = progress.reconcile(current,sample,read=lambda ref:lookup[ref["path"]],read_journal=records)
    assert confirmed["private162_journal_progress"]["useful_work"]["slot_delta"] == 3 and confirmed["transaction_replay_claimed"]
    replay_old = dict(before, private162_second_retry_held=held,producer_invocation_id=iid)
    paths = []
    def archive(_row,path):
        paths.append(str(path)); return {"size":before["after_status"]["jet_size_bytes"]+1}
    with patch.object(route.history.split_wire,"archive",side_effect=archive):
        result,meta = route.forecast(c,confirmed,before["after_status"],replay_old,prior_ref,delivery)
        assert result["phase"] == "replay" and meta["measured_slots_per_second"] == 3.0
        assert paths == [str(Path(progress.SCRATCH).parent/"ledger/epoch-162.diagnostic.jet")]
    lookup["fixture-guard"] = dict(guard,guard_sha256="0"*64)
    rejects("worker guard",lambda:progress.reconcile(current,sample,read=lambda ref:lookup[ref["path"]],read_journal=records))
    bad = records({"_SYSTEMD_UNIT":route.SECOND},0,0)
    bad[0]["MESSAGE"]="block slot 69991076 total_txs=700"
    rejects("outside admitted interval",lambda:progress.work(bad,{"_SYSTEMD_UNIT":route.SECOND},start-10,start,0))
    cases += ["second worker native guard/journal and forecast", "exact second output and scratch paths", "old guard and out-of-range progress refused"]
    return cases


def main():
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import derive60 as d
    from derive56 import verified
    os.umask(0o077)
    if len(sys.argv) == 1:
        fixture = Path(tempfile.mkdtemp(prefix="second162-v60-fixture-",dir=d.SECOND))
        print(str(fixture),flush=True)
        subprocess.run(["unshare","--mount","--propagation","private",sys.executable,"-IB",__file__,str(fixture)],check=True)
        return
    fixture = Path(sys.argv[1]).resolve(strict=True)
    root = d.OLD.parent
    assert len(sys.argv) == 2 and fixture.parent == d.SECOND and fixture.name.startswith("second162-v60-fixture-")
    assert not Path("/proc/self/ns/mnt").samefile("/proc/1/ns/mnt")
    assert subprocess.check_output(["findmnt","-n","-o","PROPAGATION","-T","/"],text=True).strip() == "private"
    upper,work = fixture/"upper",fixture/"work"
    upper.mkdir()
    work.mkdir()
    subprocess.run(["mount","-t","overlay","overlay","-o",f"lowerdir={root},upperdir={upper},workdir={work}",root],check=True)
    plan = d.stage(fixture/"input")
    def save(name,value):
        path = fixture/name
        with path.open("xb") as out:
            out.write((json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
            out.flush()
            os.fchmod(out.fileno(),0o400)
            os.fsync(out.fileno())
        fd = os.open(fixture, os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    ref = save("plan.json",plan)
    sealer = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
    digest = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
    verified(sealer,digest)
    subprocess.run([sealer,ref["path"],"--plan-sha256",ref["sha256"],"--self-sha256",digest],stdout=subprocess.DEVNULL,check=True)
    args = [sys.executable,"-IB",d.NEW/"status_cycle.py"]
    package = json.loads(subprocess.check_output(args+["--check-entry"]))
    head = max(root.parent.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    head_sha = hashlib.sha256(head.read_bytes()).hexdigest()
    ready = json.loads(subprocess.check_output(args+["--check-v60-handoff",head,head_sha]))
    assert ready["package"] == package and ready["old_owner"]["sha256"] == d.OWNER
    sys.path.insert(0,str(d.NEW))
    import status_cycle
    import second162_retry_route
    cases = check(status_cycle,second162_retry_route,ready,d)
    receipt = save("RESULT.json",dict(schema="horizon-cadence-v60-second162-private-qualification-v1",plan=ref,
        package=package,parent=ready["old_owner"],writer_handoff=save("ready.json",ready),
        fixture_fleet=ready["fleet"],cases=cases))
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
