"""Verify the exact successor mounts and bounded node arguments without starting a worker."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import next_hourly170 as n
from following_prepare import git, need, read, reference, save
from closed_successor import persist
from next_hourly170_price import inherited

LEGACY = Path("/home/sol/.jetstreamer-private/epoch170-guarded-gap-20261128.cx1SXtA5/build")
BODIES = {"namespace-body":"5266f942192fcbddfdc52a7a5078daf5dfd6c846c5ab3bc7a344684c81fdd855",
          "native-body":"f9cefbc4787d628db86289bd11e68411d6358e50a56e9a23f041a37867b7caae"}
LOCK = "/run/horizon-epoch171-to136-g1.operation.lock"
ROOT = n.ROOT


def launch(unit, props, args, parent=None):
    command = ["/usr/bin/systemd-run","--wait","--pipe","--quiet","--collect","--service-type=exec","--unit="+unit]
    if parent:
        command.append("--slice="+parent)
    command.extend("--property="+p for p in props)
    return subprocess.run([*command,"--",*args],capture_output=True,timeout=150)


@contextmanager
def outer_slice(token):
    name = "horizon170nextfixture"+token+".slice"
    group = Path("/sys/fs/cgroup")/name
    command = ["/usr/bin/busctl","call","org.freedesktop.systemd1","/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager","StartTransientUnit","ssa(sv)a(sa(sv))",name,"fail","4",
        "MemoryMax","t",str(256<<20),"MemorySwapMax","t","0","CPUQuotaPerSecUSec","t","500000","TasksMax","t","128","0"]
    subprocess.run(command,check=True,capture_output=True)
    try:
        subprocess.run(["/usr/bin/systemctl","start",name],check=True)
        need((group/"memory.max").read_text().strip()==str(256<<20)
             and (group/"memory.swap.max").read_text().strip()=="0"
             and (group/"cpu.max").read_text().split()==["50000","100000"],"different parent cgroup")
        yield name
    finally:
        subprocess.run(["/usr/bin/systemctl","stop",name],check=True)
        need(not group.exists(),"fixture cgroup not drained")


def mounts(source, spec, deploy):
    previous = read(reference(n.PREVIOUS/"NAMESPACE.json"))["report"]["readonly_bindings"]
    old_run = read(n.OLD_SCOPE)["run"]
    members = {row["name"]:row["sha256"] for row in read(deploy)["members"]}
    props, targets = [], {}
    skip = {"Type","Restart","KillMode","RuntimeMaxSec","TimeoutStopSec","CPUQuota","MemoryMax","MemoryHigh",
            "TasksMax","StandardOutput","StandardError","ExecStart","Description"}
    for line in spec.read_text().splitlines():
        if "=" not in line:
            continue
        key,value = line.split("=",1)
        if key not in skip:
            props.append(line)
        if key != "BindReadOnlyPaths":
            continue
        actual, dest = map(Path,value.split(":"))
        m = actual.stat()
        identity = [m.st_dev,m.st_ino] if actual.is_dir() else [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns]
        sha = None
        target = str(dest)
        if actual.parent == ROOT/"package":
            sha = members[actual.name]
        elif actual == ROOT/"barrier":
            need(not any(actual.iterdir()),"held barrier is no longer empty")
        elif str(actual) == source["bootstrap"]["path"]:
            record = read(source["bootstrap_custody"])["file"]
            need([m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns] ==
                 [record[key] for key in ("device","inode","size","mtime_ns")],"different snapshot projection")
        else:
            old_target = target.replace(source["run"],old_run).replace(n.ALIAS,n.OLD_ALIAS)
            need(previous[old_target] == identity,"changed inherited projection " + target)
        need(target not in targets,"duplicate projection " + target)
        targets[target] = identity,sha
    need(len(targets)==13 and len(set(props))==len(props),"different service projection set")
    return props, targets


def preflight():
    repo = HERE.parents[1]
    version = git(repo,"rev-parse","HEAD").decode().strip()
    git(repo,"merge-base","--is-ancestor",version,"origin/account-updates")
    for name in (Path(__file__).name,"ram170_workspace.py","next_hourly170_price.py"):
        member = HERE/name
        need(git(repo,"show",f"{version}:{member.relative_to(repo)}")==member.read_bytes(),"unpublished fixture source "+name)
    source_ref = reference(ROOT/"package/source.json")
    source = read(source_ref)
    deploy = reference(ROOT/"package/deployment-seal-receipt.json")
    path = ROOT/"package"/n.UNIT
    spec = reference(path)
    need(n.service(source,source["bootstrap"]["path"])==path.read_text(),"different sealed service")
    prior = ROOT/"NATIVE_PREFLIGHT.json"
    if prior.exists():
        ref = reference(prior)
        proof = read(ref)
        need(proof["source"]==source_ref and proof["service"]==spec and proof["seal"]==deploy
             and proof["route_accepted"] and not proof["worker_executed"],"different previous preflight")
        return ref
    run = Path(source["run"])
    fixture_bodies = {}
    for name,sha in BODIES.items():
        member = LEGACY/name
        need(reference(member)["sha256"]==sha,"different inherited fixture "+name)
        fixture_bodies[name] = member.read_text()
    workspace = (HERE/"ram170_workspace.py").read_text()
    token = str(time.time_ns())
    unit = "horizon-170-next-namespace-"+token
    parser = "horizon-170-next-parser-"+token
    with open(LOCK,"rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        owner = runpy.run_path(str(n.PREVIOUS/"operator-v1/after_ram170_issuer.py"))
        latest, provider = owner["latest_hourly_provider"]()
        roster = runpy.run_path(str(latest/"capacity.py"))["whole_roster"]()
        inherited(roster,source["predecessor"],source["staged_layout"])
        filesystem = os.statvfs("/home/sol")
        available = filesystem.f_bavail*filesystem.f_frsize
        control = int(subprocess.check_output(["/usr/bin/du","-sx","-B1",str(ROOT)]).split()[0])
        need(roster["package"]==provider and roster["fits"] and roster["home_margin"]>=32<<20
             and available>=max(roster["guard_floor"],*roster["observed_sibling_guard_floors"])+(32<<20)
             and control+(32<<20)<64<<20
             and not (Path("/sys/fs/cgroup/system.slice")/n.UNIT).exists(),"insufficient shared runway for the bounded preflight")
        fit = save(ROOT/("PREFLIGHT_FIT_"+token+".json"),dict(provider=provider,whole_roster=roster,source=source_ref,
            staged=source["staged_layout"],predecessor=source["predecessor"],runtime_max=120,memory_max=256<<20,
            cpu_max=500000,control_limit=32<<20,host_available=available,worker_execution_authorized=False))
        props, targets = mounts(source,path,deploy)
        common = ["PrivateNetwork=yes","TasksMax=64","RuntimeMaxSec=120s"]
        info = dict(run=str(run),alias=n.ALIAS,targets=targets,unit=unit)
        probe = """group=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip()[4:]
limits={k:(group/k).read_text().strip() for k in ('memory.max','memory.high','memory.swap.max','cpu.max')}
assert limits == {'memory.max':str(56<<30),'memory.high':str(52<<30),'memory.swap.max':'0','cpu.max':'600000 100000'}
outer=group.parent
assert (outer/'memory.max').read_text().strip()==str(256<<20)
assert (outer/'memory.swap.max').read_text().strip()=='0' and (outer/'cpu.max').read_text().split()==['50000','100000']
scratch=mount(os.getpid(),r/'scratch')
assert not any((r/'scratch').iterdir())
"""
        text = fixture_bodies["namespace-body"].replace(
            "print(json.dumps(dict(invocation=",probe+"print(json.dumps(dict(scratch=scratch,limits=limits,invocation=")
        existing = ROOT/"NAMESPACE.json"
        if existing.exists():
            namespace = reference(existing)
            identified = read(namespace)
            need(identified["service"]==spec and identified["seal"]==deploy
                 and identified["source"]==source_ref,"different previous namespace")
            report = identified["report"]
        else:
            with outer_slice(token) as parent:
                v = launch(unit,props+common+["CPUQuota=600%","MemoryHigh=52G","MemoryMax=56G"],
                           ["/usr/bin/python3","-IB","-c",workspace+"\n"+text,json.dumps(info)],parent)
            need(v.returncode==0,v.stderr.decode(errors="replace")[-3000:])
            report = json.loads(v.stdout)
            need(report["private_mounts"] and report["scratch"]["bytes"]==40<<30
                 and not report["worker_started"] and not any((run/"scratch").iterdir()),"unsafe workerless namespace")
            namespace = save(ROOT/"NAMESPACE.json",dict(report=report,service=spec,seal=deploy,source=source_ref,
                fit=fit,no_host_scratch_payload=True))
        with tempfile.TemporaryDirectory(prefix="parser-fixture-",dir=ROOT) as work:
            stage = Path(work)
            stage.chmod(0o555)
            for leaf in ("private","tmp","scratch","ledger","ledger/compact-indexes","ledger/compact-indexes/170","ledger/compact-indexes/171"):
                p = stage/leaf
                p.mkdir(mode=0o700)
                os.chown(p,1001,1003)
            args = dict(run=str(run),stage_dev=stage.stat().st_dev,stage_ino=stage.stat().st_ino,
                        targets=report["readonly_bindings"])
            body = fixture_bodies["native-body"].replace(
                "print('NATIVE_170_RETRY_PREFLIGHT=",
                "assert mount(os.getpid(),r/'scratch')['bytes']==40<<30\nprint('NATIVE_170_RETRY_PREFLIGHT=")
            node = [n.ALIAS+"/jetstreamer-node","170",str(run/"ledger"),"--verify",
                "--snapshot-archive="+n.ALIAS+"/"+source["endpoints"][0]["name"],
                "--epoch-hashes="+n.ALIAS+"/canonical-hashes.txt",
                "--horizon-output="+str(run/"ledger/epoch-170.diagnostic.jet"),
                "--replay-scratch="+str(run/"scratch"),f"--qualification-end-slot={source['last']}"]
            v = launch(parser,props+common+["CPUQuota=50%","MemoryMax=256M","LimitFSIZE=2M",
                       "InaccessiblePaths=-/run/jetstreamer-ready-bounds-20261121-v1",f"BindPaths={stage}:{run}"],
                       ["/usr/bin/python3","-IB","-c",workspace+"\n"+body,json.dumps(args),*node])
            output = v.stdout+v.stderr
            log = ROOT/("PREFLIGHT_"+token+".log")
            persist(log,output)
            marks = ("File too large (os error 27)",f"{source['first']}..={source['last']}","status-validation=SourceExact")
            need(v.returncode==1 and all(mark.encode() in output for mark in marks)
                 and not (run/"private/state").exists(),"node did not stop before the worker: "+repr(output[-1800:]))
        iid = re.search(rb"NATIVE_170_RETRY_PREFLIGHT=([0-9a-f]{32})",output)[1].decode()
        return save(ROOT/"NATIVE_PREFLIGHT.json",dict(invocation=iid,unit=parser,scope=[source["first"],source["last"]],
            source=source_ref,service=spec,seal=deploy,namespace=namespace,fit=fit,argv=node,
            worker_executed=False,route_accepted=True,log=reference(log),revision=version))


if __name__ == "__main__":
    print(json.dumps(preflight(),sort_keys=True))
