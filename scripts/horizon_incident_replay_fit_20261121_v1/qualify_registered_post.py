"""Exercise the released 136 route and the V12 price using sealed native dependencies."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from unittest.mock import Mock, patch

provider, scratch = map(Path, sys.argv[1:])
module = runpy.run_path(str(provider))
check = module["registered136"]
scope = check.__globals__
native = scope["fit"]
status = scope["s"]
original = scope["R"] / "epoch136-joint-writer-20261122-v6/controller"
seal, sr = status.read(original / "deployment-seal-receipt.json")
assert sr["sha256"] == "62ced18aed9e45e564bc01aebfc2c18639c7cf2125626bdda405b6ac0af976ba"
image = original / "admit136"
digest = next(x["sha256"] for x in seal["members"] if x["name"] == "admit136")
native.binary(image, digest)
# The real controller must refuse to verify a missing incident outside its writer.
if not (scope["H"] / "epoch136-actual-20261120-g1/prestart-intent.json").exists():
    neg = subprocess.run([image, "verify-release", str(original.parent / "production-plan.json"), "0"*64],
                         capture_output=True, timeout=45)
    assert neg.returncode != 0 and not neg.stdout

def write(p, value):
    p.parent.mkdir(parents=True, exist_ok=True)
    raw=(json.dumps(value,sort_keys=True)+"\n").encode()
    p.write_bytes(raw)
    return {"path":str(p),"sha256":hashlib.sha256(raw).hexdigest()}

def refused(fn):
    try:
        fn()
    except (AssertionError, ValueError, FileNotFoundError, subprocess.CalledProcessError):
        return
    raise AssertionError("foreign custody accepted")

with tempfile.TemporaryDirectory(dir=scratch) as temporary, ExitStack() as mocks:
    base = Path(temporary)
    root = base / "epoch136-actual-20261120-g1"
    root.mkdir()
    dispatch = scope["R"] / "epoch145-phase-dispatch-20261122-v1"
    selector = {"path":str(dispatch/"READY.json"),"sha256":"f"*64}
    plan = {"controller":status.ref(root/"controller/admit136",digest),"controller_deployment":sr}
    planref = write(base / "plan.json",plan)
    offer = {"selector":selector,"writer_plan":planref}
    intent = {"selector":selector,"writer_plan":planref,"writer":plan["controller"]}
    intent_path = root / "prestart-intent.json"
    release_path = root / "prestart-released.json"
    rows = []
    def read(path, sha=None):
        if path == dispatch / "OFFER.json":
            return offer, None
        return status.read(path,sha)
    def bound(ref,path):
        if path == dispatch/"READY.json":
            assert ref == selector
            return dict()
        return status.bound(ref,path)
    context = Mock(wraps=status)
    context.read.side_effect = read
    context.bound.side_effect = bound
    child = Mock(wraps=native)
    child.members.side_effect = lambda unit: tuple(rows)
    child.candidate136.return_value = dict(ordinary=True)
    run = Mock(wraps=subprocess)
    mocks.enter_context(patch.dict(scope, H=base,s=context,fit=child,subprocess=run))
    assert check({},None)==dict(ordinary=True)
    write(release_path,{})
    refused(lambda:check({},None))
    release_path.unlink()
    iref = write(intent_path,intent)
    refused(lambda:check({},None))
    rows.append(101)
    assert check({},None)==dict(ordinary=True)
    rows.clear()
    doc=dict(intent=iref,donor_restored=True,candidate_physically_drained=True,all_physical_outputs_retained=True,
             resource_credit_bytes=0)
    release=write(release_path,doc)
    run.check_output.return_value=json.dumps(release)
    expected=dict(occupied=False,cap=72<<30,remaining=72<<30,loan_micros=0,identity=None,verified_release=release)
    assert check({},None)==expected
    run.check_output.assert_called_once_with([image,"verify-release",planref["path"],planref["sha256"]],timeout=45)
    for field in ("donor_restored","candidate_physically_drained","all_physical_outputs_retained","resource_credit_bytes","intent"):
        write(release_path,dict(doc,**{field:1 if field=="resource_credit_bytes" else False}))
        refused(lambda:check({},None))
    write(release_path,doc)
    run.check_output.return_value=json.dumps(dict(release,sha256="0"*64))
    refused(lambda:check({},None))
    run.check_output.side_effect=subprocess.CalledProcessError(1, "verify-release")
    refused(lambda:check({},None))
    write(intent_path,dict(intent,selector={}))
    refused(lambda:check({},None))
    write(intent_path,dict(intent,writer={}))
    refused(lambda:check({},None))
print("Released-136 custody fixtures passed with full reservation and zero credit; sealed controller and its ordinary absent route checked.")
