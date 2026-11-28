"""Prepare a separate 169 attempt with a private read-only projection for its native guard."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import time


HERE=Path(__file__).resolve().parent
RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
SECOND=RT/"epoch169-hourly-retry-20261128-v2"
ROOT=RT/"epoch169-hourly-retry-20261128-v3"
OLD=SECOND/"operator-v1"
NEW=ROOT/"operator-v1"
PREVIOUS="904ceb6b6d3f97f5e3c2dce585cff64254c05aee6fdc4d5f229fa92c62d7a876"
SCOPE="322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e"
STOP="c09b0bf82efe4c970a0810219bdccb03a1869333a30cd1fef39e9034dfc40e02"
FIXTURE="2e772ec0fd3582d02c9f7f29b24810ab4389e8d05684851f0bc271a30827f5ec"
SEALER=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def contract():
    path=OLD/"contract.py"
    if hashlib.sha256(path.read_bytes()).hexdigest()!="cc673a4da90aab415f4cf98628492297d0c4b9b713239db24db41e8e89774736":
        raise ValueError("changed second-attempt evidence reader")
    return runpy.run_path(str(path))


def replace(text, old, new):
    if text.count(old)!=1:
        raise ValueError("changed second-attempt source: "+old)
    return text.replace(old,new)


def paths(text):
    return (text.replace("169-hourly-retry-20261128-v2","169-hourly-retry-20261128-v3")
            .replace("169-hourly-retry-terminal-20261128-v2","169-hourly-retry-terminal-20261128-v3")
            .replace("/run/horizon-169-hourly-retry-v2","/run/horizon-169-hourly-retry-v3"))


def adapt(name,text):
    text=paths(text)
    if name=="issuer.py":
        text=replace(text,"worker_root=str(c.RETRY),receipt_directory=","worker_root=str(c.OLD),receipt_directory=")
        text=replace(text,'return ["/usr/bin/systemd-run",*[change(v) for v in profile[:-6]],str(GUARD),',
            'projection=f"--property=BindReadOnlyPaths={c.RETRY}:{c.OLD}"\n'
            '    return ["/usr/bin/systemd-run",*[change(v) for v in profile[:-6]],projection,str(GUARD),')
        text=replace(text,'directory=Path(plan["receipt_directory"])','''# Preserve the original plan's private receipt path and physical limit.
    # In the guard namespace its worker_root names the same output-tree inode.
    original_plan=native.__globals__["guard_plan"]
    def projected_plan(invocation,floor,cap):
        return dict(original_plan(invocation,floor,cap),worker_root=str(c.OLD))
    native.__globals__["guard_plan"]=projected_plan
    directory=Path(plan["receipt_directory"])''')
        text=replace(text,'native(sample,plan,gr["sha256"],producer,timer,manager)',
            '''observed=props(timer["Triggers"],("BindReadOnlyPaths",))["BindReadOnlyPaths"]
        expected=f"{c.RETRY}:{c.OLD}"
        c.need(observed in (expected,expected+":rbind"),"different guard read-only projection")
        native(sample,plan,gr["sha256"],producer,timer,manager)''')
    elif name=="actor.py":
        text=replace(text,'plan["worker_root"]==str(TREE)','plan["worker_root"]==str(Path("/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1"))')
    elif name=="observe.py":
        text=replace(text,'FIELD="current_private169_retry2"','FIELD="current_private169_retry3"')
        text=replace(text,'plan["worker_root"]==str(c.RETRY)','plan["worker_root"]==str(c.OLD)')
        text=replace(text,'    actor_path=c.CONTROL/"START_INTENT.json"',f'''    released, closure=c.read(Path("{SECOND}/WORKER_ALIAS_STOP.json"),"{STOP}")
    prior=fleet.get("current_private169_retry2")
    c.need(released["invocation_id"]=="1446633fdd224bab9297255a7ad66330" and
           (not prior or prior["phase"]=="terminal" and prior["invocation_id"]==released["invocation_id"]
            and prior["terminal"]==released["terminal"]), "changed second 169 terminal")
    for name in released["states"]:
        state=quote.state(name) if not name.endswith(".timer") else None
        if state is None:
            import subprocess
            value=subprocess.check_output(["systemctl","show","--all","-p","ActiveState,Job",name],text=True)
            state=dict(line.split("=",1) for line in value.splitlines())
        c.need(state["ActiveState"]=="inactive" and not state["Job"] and not state.get("ControlGroup")
               and state.get("MainPID","0")==state.get("ControlPID","0")=="0", "second 169 acquired compute")
    actor_path=c.CONTROL/"START_INTENT.json"''')
    return text


def plan(revision, observed):
    c=contract()
    need,read=c["need"],c["read"]
    seal,previous=read(OLD/"deployment-seal-receipt.json",PREVIOUS)
    _,scope=read(SECOND/"SCOPE.json",SCOPE)
    closed,termination=read(SECOND/"WORKER_ALIAS_STOP.json",STOP)
    fixture,proof=read(Path(closed["proof"]["path"]),FIXTURE)
    need(fixture["producer_cleaned"] and closed["proof"]==proof and not closed["first_replay_slot_observed"]
         and closed["scope"]==scope and not closed["resource_credit_bytes"],"different closed attempt")
    need(not os.path.lexists(NEW),"third retry already installed")
    ROOT.mkdir(mode=0o755,exist_ok=True)
    need(ROOT.resolve(strict=True)==ROOT and ROOT.lstat().st_uid==0 and not ROOT.stat().st_mode&0o022
         and ROOT.stat().st_dev==c["HOME"].stat().st_dev,"wrong private control tree")
    stage=Path(tempfile.mkdtemp(prefix="operator-source.",dir=ROOT))
    contents={}
    for row in seal["members"]:
        name=row["name"]
        p=OLD/name
        identity,data=c["stable"](p,expected=row["sha256"],sealed=True,keep_bytes=True)
        need(p.parent==OLD and identity["size"]==row["bytes"],"previous bundle changed")
        if name=="ORIGIN.json":
            continue
        result=adapt(name,data.decode())
        if name.endswith(".py"):
            compile(result,name,"exec")
        dest=stage/paths(name)
        dest.write_text(result)
        contents[dest.name]=dest
    origin=stage/"ORIGIN.json"
    script=HERE/"third_attempt.py"
    tracked=subprocess.check_output(["git","show",revision+":scripts/horizon_epoch169_hourly_retry/third_attempt.py"],cwd=HERE)
    need(tracked==script.read_bytes() and subprocess.run(["git","merge-base","--is-ancestor",revision,observed],cwd=HERE).returncode==0,
         "derivation absent from reviewed branch")
    c["recorded"](origin,dict(commit=revision,remote_observed=observed,branch="origin/account-updates",remote_contains_commit=True,
        derivation=hashlib.sha256(tracked).hexdigest(),parent=previous,parent_scope=scope,closure=termination,guard_fixture=proof))
    contents[origin.name]=origin
    members=[dict(name=n,source=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),mode=0o444) for n,p in contents.items()]
    ref=c["recorded"](ROOT/f"OPERATOR_PLAN_{time.time_ns()}.json",dict(schema="jetstreamer-sealed-deployment-plan-v1",
         destination=str(NEW),members=members))
    c["stable"](SEALER,expected=SEALER_SHA,sealed=True)
    subprocess.run([str(SEALER),ref["path"],"--plan-sha256",ref["sha256"],"--self-sha256",SEALER_SHA],check=True)
    new,seal_ref=read(NEW/"deployment-seal-receipt.json")
    need(new["plan_sha256"]==ref["sha256"] and new["destination"]==str(NEW),"different third operator")
    return seal_ref


def scope():
    sys.path.insert(0,str(NEW))
    import contract as c
    import issuer
    import prepare
    import observe
    prior,pr=c.read(SECOND/"SCOPE.json",SCOPE)
    closed,cr=c.read(SECOND/"WORKER_ALIAS_STOP.json",STOP)
    fixture,fr=c.read(Path(closed["proof"]["path"]),FIXTURE)
    package,op=c.read(NEW/"deployment-seal-receipt.json")
    origin,source=c.read(NEW/"ORIGIN.json")
    q=prepare.fixture(NEW)
    sample=issuer.quote.bound(q)
    c.need(sample["host"]["mounts"]==sample["readback"]["mounts"] and sample["current_inputs"]==prior["inputs"]
           and sample["readback"]["limits"]["memory.max"]==str(c.RAM) and not sample["admission"]
           and origin["closure"]==cr and origin["guard_fixture"]==fr and fixture["projected_root"]==str(c.OLD),
           "different third namespace or guard fixture")
    old,_=c.read(SECOND/"GUARD_STATIC_FIXTURE.json")
    doc=json.loads(paths(json.dumps(old)))
    doc["worker_root"]=str(c.OLD)
    plan=c.recorded(ROOT/"GUARD_STATIC_FIXTURE.json",doc)
    output=json.loads(subprocess.check_output([str(issuer.GUARD),plan["path"],"--plan-sha256",plan["sha256"],
                     "--self-sha256",issuer.GUARD_SHA,"--validate-plan-only"],text=True))
    c.need(output["validated"] and output["unit"]==c.UNIT and not output["protective_guard_proven"]
           and output["resource_samples_taken"]==0 and not output["replay_launch_authorized"],"different native guard validation")
    gr=c.recorded(ROOT/"GUARD_STATIC_ACCEPTED.json",dict(plan=plan,result=output,unit_started=False,projection_fixture=fr))
    row=dict(prior,schema="horizon-169-third-attempt-worker-projection-scope-v1",parent_scope=pr,second_guard_stop=cr,
        guard_projection_qualification=fr,guard_readonly_source=str(c.RETRY),guard_readonly_target=str(c.OLD),
        producer_unit=c.UNIT,guard_timer=observe.TIMER,watcher=prepare.TERMINAL,operator=op,namespace_fixture=q,
        guard_static=gr,merged_source=source,output=str(c.RETRY/"v158"/c.BASE_NAME),log=str(observe.LOG),
        cadence_source=dict(path=str(NEW/"cadence.py"),sha256=next(x["sha256"] for x in package["members"] if x["name"]=="cadence.py")))
    issuer.checked_inputs(row)
    return c.recorded(ROOT/"SCOPE.json",row)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("plan","scope"))
    cli.add_argument("--commit")
    cli.add_argument("--observed")
    opts=cli.parse_args()
    print(json.dumps(plan(opts.commit,opts.observed) if opts.action=="plan" else scope()))
