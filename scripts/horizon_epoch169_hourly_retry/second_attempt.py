"""Derive the same hourly replay in a new tree after its unreleased first gate."""
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
FIRST=RT/"epoch169-hourly-retry-20261128-v1"
ROOT=RT/"epoch169-hourly-retry-20261128-v2"
OLD=FIRST/"operator-v1"
OP=ROOT/"operator-v1"
CLOSE="24d2fc5ecf736827e0b06af6194f85ad1dae055f33065d6e9e20606eb17ee9dc"
OLD_SCOPE="eb589f4c2c51dcf75314d50d7074a9411d034e6bd3f6a8bd826705ca4a1feb3a"
OLD_OPERATOR="8e87b305ba3957ca579a9eafa696eb2410f2498869c31922a8460dc5935943ed"
SEALER=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
HISTORICAL={"issuer.py","prepare.py","writer_receipt.py"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def base():
    src=OLD/"contract.py"
    require(hashlib.sha256(src.read_bytes()).hexdigest()=="b0bd0f2f03868b17b557ad24d227be0b152bb5f530044ecfcbca80cb54d0156b","original contract changed")
    return runpy.run_path(str(src))


def rewrite(text):
    return (text.replace("169-hourly-retry-20261128-v1","169-hourly-retry-20261128-v2")
            .replace("169-hourly-retry-terminal-20261128-v1","169-hourly-retry-terminal-20261128-v2")
            .replace("/run/horizon-169-hourly-retry","/run/horizon-169-hourly-retry-v2"))


def observer(text):
    before='FIELD="current_private169_retry"'
    require(text.count(before)==1, "changed 169 fleet field")
    text=text.replace(before,'FIELD="current_private169_retry2"')
    before='    actor_path=c.CONTROL/"START_INTENT.json"'
    require(text.count(before)==1, "changed 169 census entry")
    return text.replace(before, f'''    previous, previous_ref = c.read(Path("{FIRST}/UNRELEASED_HELD_CLOSURE.json"), "{CLOSE}")
    prior = fleet.get("current_private169_retry")
    c.need(previous["invocation_id"]=="9c271e621bd9484ba6fe8ac1508ffaac"
           and (not prior or prior["phase"]=="terminal" and prior["terminal"]==previous["terminal"]
                and prior["invocation_id"]==previous["invocation_id"]), "first 169 gate has not closed")
    q = quote.state("horizon-qualify-169-hourly-retry-20261128-v1.service")
    c.need(q["ActiveState"] in ("failed","inactive") and q["MainPID"]==q["ControlPID"]=="0" and not q["ControlGroup"],
           "previous private 169 gate active")
'''+before)


def plan(revision, observed, sources):
    c=base()
    _,oldscope=c["read"](FIRST/"SCOPE.json",OLD_SCOPE)
    _,cr=c["read"](FIRST/"UNRELEASED_HELD_CLOSURE.json",CLOSE)
    seal,ref=c["read"](OLD/"deployment-seal-receipt.json",OLD_OPERATOR)
    require(not os.path.lexists(OP),"second operator already exists")
    ROOT.mkdir(mode=0o755,exist_ok=True)
    require(ROOT.resolve()==ROOT and ROOT.lstat().st_uid==0 and not ROOT.stat().st_mode&0o022,"unsafe second attempt root")
    stage=Path(tempfile.mkdtemp(prefix="source.",dir=ROOT))
    frozen={}
    for row in seal["members"]:
        p=OLD/row["name"]
        meta,data=c["stable"](p,expected=row["sha256"],sealed=True,keep_bytes=True)
        require(p.parent==OLD and meta["size"]==row["bytes"],"different operator template")
        frozen[row["name"]]=data
    frozen["writer_receipt.py"]=b""
    require(sources.keys()==HISTORICAL|{"second_attempt.py"},"different source member set")
    for name,digest in sources.items():
        require(hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest,"changed merged derivation "+name)
    rows=[]
    for name,data in frozen.items():
        code=(HERE/name).read_text() if name in HISTORICAL else data.decode()
        new=rewrite(code)
        if name=="observe.py":
            new=observer(new)
        dest=stage/rewrite(name)
        if name.endswith(".py"):
            compile(new,name,"exec")
        dest.write_bytes(new.encode())
        dest.chmod(0o444)
        rows.append(dict(name=dest.name,source=str(dest),sha256=hashlib.sha256(dest.read_bytes()).hexdigest(),mode=0o444))
    binding=c["recorded"](stage/"ORIGIN.json",dict(commit=revision,remote_observed=observed,branch="origin/account-updates",
                            remote_contains_commit=True,source_members=sources,parent=ref,parent_scope=oldscope,closure=cr))
    rows.append(dict(name="ORIGIN.json",source=binding["path"],sha256=binding["sha256"],mode=0o444))
    plan=c["recorded"](ROOT/f"OPERATOR_PLAN_{time.time_ns()}.json",dict(schema="jetstreamer-sealed-deployment-plan-v1",
                        destination=str(OP),members=rows))
    c["stable"](SEALER,expected=SEALER_SHA,sealed=True)
    subprocess.run([str(SEALER),plan["path"],"--plan-sha256",plan["sha256"],"--self-sha256",SEALER_SHA],check=True)
    installed,ir=c["read"](OP/"deployment-seal-receipt.json")
    require(installed["plan_sha256"]==plan["sha256"] and installed["destination"]==str(OP),"different installed attempt")
    return ir


def scope():
    sys.path.insert(0,str(OP))
    import contract as c
    import issuer
    import prepare
    import observe
    old,osr=c.read(FIRST/"SCOPE.json",OLD_SCOPE)
    closed,cr=c.read(FIRST/"UNRELEASED_HELD_CLOSURE.json",CLOSE)
    deployment,dr=c.read(OP/"deployment-seal-receipt.json")
    _,origin=c.read(OP/"ORIGIN.json")
    fixture=prepare.fixture(OP)
    sample=issuer.quote.bound(fixture)
    require(sample["host"]["mounts"]==sample["readback"]["mounts"] and sample["current_inputs"]==old["inputs"]
            and sample["readback"]["limits"]["memory.max"]==str(c.RAM) and not sample["admission"],"different second namespace")
    _,previous_plan=c.read(FIRST/"GUARD_STATIC_FIXTURE.json","e1cd6d7251412b03eba606d9449636d5b86060e9275aeb899ef5557687109f4b")
    projected=rewrite(Path(previous_plan["path"]).read_text())
    plan=c.recorded(ROOT/"GUARD_STATIC_FIXTURE.json",json.loads(projected))
    result=json.loads(subprocess.check_output([str(issuer.GUARD),plan["path"],"--plan-sha256",plan["sha256"],
                "--self-sha256",issuer.GUARD_SHA,"--validate-plan-only"],text=True))
    require(result["validated"] and result["unit"]==c.UNIT and not result["protective_guard_proven"]
            and result["resource_samples_taken"]==0 and not result["replay_launch_authorized"],"different native guard validation")
    guard=c.recorded(ROOT/"GUARD_STATIC_ACCEPTED.json",dict(plan=plan,result=result,unit_started=False))
    row=dict(old,schema="horizon-169-hourly-second-attempt-scope-v1",first_gate_closure=cr,parent_scope=osr,merged_source=origin,
        producer_unit=c.UNIT,guard_timer=observe.TIMER,watcher=prepare.TERMINAL,operator=dr,namespace_fixture=fixture,
        guard_static=guard,output=str(c.RETRY/"v158"/c.BASE_NAME),log=str(observe.LOG),
        cadence_source=dict(path=str(OP/"cadence.py"),sha256=next(x["sha256"] for x in deployment["members"] if x["name"]=="cadence.py")))
    issuer.checked_inputs(row)
    return c.recorded(ROOT/"SCOPE.json",row)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("action",choices=("plan","scope"))
    cli.add_argument("--revision")
    cli.add_argument("--observed")
    cli.add_argument("--sources")
    args=cli.parse_args()
    answer=plan(args.revision,args.observed,json.loads(args.sources)) if args.action=="plan" else scope()
    print(json.dumps(answer))
