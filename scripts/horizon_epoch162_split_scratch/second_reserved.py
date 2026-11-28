"""Create an independent third interval-two issuer after the held gate's postguard rejection."""
from pathlib import Path
import json
import os
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PREVIOUS = RT / "epoch162-second-replay-20261128-v2"
BASE = RT / "epoch162-second-replay-20261128-v3"
OLD_OP = PREVIOUS / "issued-split-v3"
IID = "a06cf6aeef704fb7b1cc013130913e1a"
CLOSED = "c7ed78cec61b97f93b3645c15af4f95c8aaa243812c96b324f55c9a89249ad90"
OLD_INTERFACE = "2192e657ff4cf56a9404dc41cf5d3223cb437afa3eb7225676b4116d95c18712"
GATE = "fe27e2a708728cfdfb0d112524a7f19e7b9c4bffbf343d751edc5e0942461a3c"
GUARD = "c6049e1161b1a54b2d7193faac077242c24b2f52543e986dfb9c958d47698d72"
NATIVE = "a0c4245d66bf240ff06c0b154327cb3387305ac9"


def translate(s):
    return s.replace("162-second-replay-20261128-v2","162-second-replay-20261128-v3").replace(
        "/run/horizon-162-second-replay-v2","/run/horizon-162-second-replay-v3")


def check_guard(native, path, static, prior):
    plan = json.loads(translate(json.dumps(prior.guard_plan("1"*32,prior.MIN_FLOOR))))
    results = []
    for name, changes in (("exact",{}), ("previous-unit",dict(unit=prior.UNIT)), ("foreign-root",dict(worker_root=plan["worker_root"]+"-other")),
                          ("oversize",dict(maximum_root_physical_bytes=plan["maximum_root_physical_bytes"]+1))):
        ref = prior.save(path/(name+".json"),dict(plan,**changes),0o400)
        q = subprocess.run([native,ref["path"],"--plan-sha256",ref["sha256"],"--self-sha256",GUARD,"--validate-plan-only"],
                           capture_output=True,text=True,check=False)
        if name == "exact":
            value = json.loads(q.stdout)
            prior.need(q.returncode == 0 and value["validated"] and value["unit"] == plan["unit"]
                       and value["self_sha256"] == GUARD and value["resource_samples_taken"] == 0, "incorrect native guard")
        else:
            prior.need(q.returncode == 1 and bool(q.stderr.strip()), "unsafe native guard accepted " + name)
        results.append(dict(name=name,plan=ref,exit=q.returncode,stdout=q.stdout,stderr=q.stderr))
    return prior.save(BASE/"NATIVE_GUARD_VALIDATED.json",dict(guard=GUARD,gate=GATE,native=NATIVE,static=static,cases=results))


def prepare(gate, guard, revision):
    from types import SimpleNamespace
    l = SimpleNamespace(**runpy.run_path(str(OLD_OP / "layout.py")))
    status = runpy.run_path(str(OLD_OP/"status162.py"))
    need, save = l.need, l.save
    old, interface = l.pinned(PREVIOUS/"RETRY_INTERFACE_V3.json",OLD_INTERFACE)
    end, closed = l.pinned(PREVIOUS/"UNRELEASED_POSTGUARD_CLOSURE.json",CLOSED)
    actor = l.bound(end["held"])
    need(os.geteuid() == 0 and __debug__ and end["invocation_id"] == actor["producer_invocation_id"] == IID
         and end["no_grant"] and end["no_worker"] and not end["resource_credit_bytes"]
         and end["native_end"] == status["native_end"](l,actor) and not l.ALLOW.exists() and not (l.DATA/"GRANT.json").exists()
         and not l.CGROUP.exists() and l.manager(l.TIMER)["ActiveState"] == "inactive"
         and l.identity(l.IMAGE) == end["output_image"] and l.IMAGE.stat().st_mode & 0o777 == 0o400, "prior guard or image returned")
    source = Path(__file__).resolve()
    git = ["git", "-c","safe.directory="+str(HERE.parent.parent),"-C",str(HERE.parent.parent)]
    for commit in (revision,NATIVE):
        subprocess.run([*git,"merge-base","--is-ancestor",commit,"origin/account-updates"],check=True)
    need(subprocess.check_output([*git,"show",revision+":"+str(source.relative_to(HERE.parent.parent))])==source.read_bytes(),"unmerged issuer")
    helper = runpy.run_path(str(HERE/"second_interval.py"))
    seal = helper["seal"]
    seal.__globals__["BASE"] = BASE
    stage = BASE/"source"
    for p in (BASE,stage):
        p.mkdir(mode=0o700,exist_ok=True)
        need(p.resolve()==p and p.stat().st_uid==0 and p.stat().st_mode&0o077==0,"untrusted issuance root")
    native = {}
    for p,name,sha in ((gate,"hold-162-second",GATE),(guard,"guard",GUARD)):
        need(l.digest(p)==sha, "different native executable")
        dst=stage/name; save(dst,p.read_bytes(),0o555);native[name]=(dst,0o555)
    static=seal(native,BASE/"static-v3",save)
    validate=check_guard(BASE/"static-v3/guard",stage,static,l)
    previous_scope = l.bound(old["scope"])
    # Translate only this mutable route's paths. Historical references are
    # copied explicitly; they must always resolve under their original roots.
    scope=json.loads(translate(json.dumps(previous_scope)))
    for key in ("previous","unreleased_predecessor"):
        scope[key]=previous_scope[key]
    scope.update(postguard_predecessor=closed,previous_interface=interface,source_commit=revision,
                 gate_deployment=static,guard_deployment=static,native_guard_validation=validate)
    scope.pop("static_fixture_predecessor",None)
    scope["first_hourly_gate"]=dict(path=str(BASE/"static-v3/hold-162-second"),sha256=GATE)
    scope["first_hourly_guard"]=dict(path=str(BASE/"static-v3/guard"),sha256=GUARD)
    for row in scope["profile"]["readonly_projections"]:
        if row["source"]==str(BASE/"static-v2/hold-162-second"):
            row.update(source=scope["first_hourly_gate"]["path"],sha256=GATE)
    scope_ref=save(BASE/"SCOPE.json",scope,0o400)
    members={}
    for m in l.bound(old["provider"])["members"]:
        name=m["name"]
        if not name.endswith(".py"):continue
        p=OLD_OP/name
        need(p.parent==OLD_OP and l.digest(p)==m["sha256"],"changed or foreign prior operator")
        s=translate(p.read_text())
        if name=="layout.py":
            s=s.replace('PKG = BASE / "issued-split-v3"','PKG = BASE / "operator-v1"').replace('SCOPE-V3.json','SCOPE.json')
            s=s.replace(old["scope"]["sha256"],scope_ref["sha256"]).replace(old["guard"]["sha256"],GUARD)
            s=s.replace("static-v2/hold-162-second","static-v3/hold-162-second").replace("guard-v3/guard","static-v3/guard")
        if name=="status162.py":
            s=s.replace(str(BASE/"issued-split-v3"),str(BASE/"operator-v1"))
            s=s.replace('FIELD = "current_private162_second_retry"', 'FIELD = "current_private162_second_reserved"')
            anchor='    registered = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] == 162]'
            s=helper["exact"](s,anchor,'''    rejected = l.bound(l.scope()["postguard_predecessor"])
    earlier = fleet.get("current_private162_second_retry")
    l.need(rejected["no_grant"] and rejected["no_worker"] and rejected["invocation_id"] == "a06cf6aeef704fb7b1cc013130913e1a"
           and (not earlier or earlier["phase"] == "terminal" and earlier["producer_invocation_id"] == rejected["invocation_id"]
                and earlier["held_owner"] == rejected["held"] and earlier["terminal"] == rejected["native_end"]),
           "earlier held gate has no closing receipt")
''' +anchor)
        if name in ("launch.py","status162.py"):
            s=s.replace("second162_retry_provider","second162_reserved_provider").replace("second162_retry_reader","second162_reserved_reader").replace("second162_retry_status.py","second162_reserved_status.py")
        if name=="launch.py":
            anchor='        post = price("postguard", iid)\n'
            s=helper["exact"](s,anchor,anchor+'        l.save(l.DATA / "POST_GUARD_OBSERVED.json", post)\n')
        compile(s,name,"exec")
        dst=stage/name;save(dst,s.encode(),0o444);members[name]=(dst,0o444)
    origin=stage/"ORIGIN.json";save(origin,dict(revision=revision,native=NATIVE,source=helper["reference"](source),guard=validate,
                                              previous_operator=old["provider"],scope=scope_ref,closure=closed))
    members[origin.name]=(origin,0o444)
    operator=seal(members,BASE/"operator-v1",save)
    info=dict(unit=translate(l.UNIT),field="current_private162_second_reserved",provider=operator,reader=helper["reference"](BASE/"operator-v1/status162.py"),
              scope=scope_ref,closure=closed,first_slot=scope["first_slot"],last_slot=scope["last_slot"],immutable_predecessor=scope["previous"],
              previous_interface=interface,guard=scope["first_hourly_guard"],gate=scope["first_hourly_gate"],guard_validation=validate)
    return save(BASE/"INTERFACE.json",info,0o400)


if __name__=="__main__":
    print(json.dumps(prepare(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3])))
