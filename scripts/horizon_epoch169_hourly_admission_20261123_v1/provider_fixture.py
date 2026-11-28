"""Exercise the exact complete-provider census function on an isolated six-owner cgroup fixture."""
import ast
import copy
import json
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import time

HERE=Path(__file__).resolve().parent


def cases(native, test, need):
    module=runpy.run_path(str(HERE/"actor.py"))
    provider=HERE.parent/"horizon_incident_replay_fit_20261121_v1/post-stop-fit"
    code=ast.parse(provider.read_text())
    node=next(n for n in code.body if isinstance(n,ast.FunctionDef) and n.name=="census")
    selected=ast.Module(body=[node],type_ignores=[])
    compiled=compile(ast.fix_missing_locations(selected),str(provider),"exec")
    ps=[*native["population"]]
    need(len(ps)==5,"not the real historical five-owner population")
    own=dict(unit=module["UNIT"],processes=[[24,59]],producer_iid="12"*16,timer_iid="34"*16,initial_physical=4096)
    with tempfile.TemporaryDirectory(dir="/var/lib/jetstreamer/horizon_runtime_data") as t:
        t=Path(t)
        populations={u:[list(x[:2]) for x in native["population"][u]] for u in ps}
        populations[own["unit"]]=own["processes"]
        statmap={}
        for unit,pr in populations.items():
            for pid,ticks in pr:
                folder=t/str(pid);folder.mkdir()
                (folder/"exe").touch()
                statmap[pid]=(None,ticks,"0::/system.slice/"+unit)
        fit=SimpleNamespace(units=lambda:set(populations),members=lambda u:tuple(sorted(p[0] for p in populations[u])))
        common=SimpleNamespace(need=need,process=lambda pid:statmap[pid])
        projected=lambda path:t/path.removeprefix("/proc").lstrip("/")
        globals_=dict(Path=projected,s=common,fit=fit,HOURLY169=True)
        exec(compiled,globals_)
        peers={u:dict(unit=u,processes=populations[u]) for u in ps}
        call=lambda:globals_["census"](peers,{},None,dict(occupied=False),145,{},own)
        a=test("exact normal native census accounts all five plus the held hourly PID/start",call)
        need(set(a[0])==set(populations) and not a[1],"wrong owner census")
        populations["horizon-qualify-foreign.service"]=[[28,69]]
        test("native census refuses extra seventh owner",call,True)
        del populations["horizon-qualify-foreign.service"]
        statmap[24]=(None,68,"0::/system.slice/"+own["unit"])
        test("native census refuses reused hourly PID",call,True)
        globals_["HOURLY169"]=False
        test("original provider excludes the unregistered hourly actor",call,True)
        plan=t/"fixture-guard.json"; cap=module["WORKSPACE"]-module["FIXED"]+4096
        floor=native["complete_required_HOME_bytes"]
        plan.write_text(json.dumps(dict(maximum_root_physical_bytes=cap,minimum_free_bytes=floor)));plan.chmod(0o400)
        import hashlib
        own["plan"]=dict(path=str(plan),sha256=hashlib.sha256(plan.read_bytes()).hexdigest())
        guard=dict(guard_sha256=module["GUARD_SHA"],plan_sha256=own["plan"]["sha256"],producer_invocation_id=own["producer_iid"],
                   producer_stop_enabled=True,trip_reason=None,worker_observation_error=None,root_physical_observation_error=None,
                   maximum_root_physical_bytes=cap,minimum_free_bytes=floor,recorded_unix_seconds=int(time.time()),
                   available_bytes=native["available_HOME_bytes"],guard_invocation_id="34"*16,
                   root_physical_observation=dict(maximum_physical_bytes=cap,exceeds_budget=False,
                         first=dict(physical_bytes=8192,vanished_entries=0),second=dict(physical_bytes=8192,vanished_entries=0)))
        fleet=module["pinned"](native["fleet"])
        quote=lambda v:module["price"](native,fleet,own,v)
        p=test("registered postguard full quote retains all old bookings and only charges remaining hourly growth",lambda:quote(guard))
        need(p["fits"] and p["workspace_remaining"]==module["WORKSPACE"]-4096 and p["complete_cpu"]==64_000_000,
             "stable hourly physical limits")
        missing=copy.deepcopy(guard);missing["root_physical_observation"]["second"]["vanished_entries"]=1
        x=test("unstable private allocation falls back to immutable source baseline",lambda:quote(missing))
        need(x["workspace_remaining"]==module["WORKSPACE"],"false realized credit")
        test("expired native hourly guard refused",lambda:quote(dict(guard,recorded_unix_seconds=1)),True)
        test("wrong hourly plan refused",lambda:quote(dict(guard,plan_sha256="ef"*32)),True)
        workers=native["recovery_obligations"]["public_workers"][:-1]
        observation=t/"six-public-workers.json"
        observation.write_text(json.dumps(dict(active_ready_workers=workers)))
        observation.chmod(0o400)
        ref=dict(path=str(observation),sha256=hashlib.sha256(observation.read_bytes()).hexdigest())
        six_fleet=dict(fleet,current_audit_progress=dict(observation=ref))
        obligations=native["recovery_obligations"]
        six_native=dict(native,recovery_obligations=dict(obligations,public_workers=workers))
        six=test("hourly postguard accepts the recorded six public readers",
                 lambda:module["price"](six_native,six_fleet,own,guard))
        need(six["fits"] and six["required_HOME"]==p["required_HOME"],"reader turnover changed paid HOME")
        reused=[dict(workers[0],start_ticks=workers[0]["start_ticks"]+1),*workers[1:]]
        changed=dict(native,recovery_obligations=dict(obligations,public_workers=reused))
        test("same-sized public roster with a reused PID is refused",
             lambda:module["price"](changed,six_fleet,own,guard),True)
