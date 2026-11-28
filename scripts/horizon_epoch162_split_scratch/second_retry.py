"""Prepare interval two again after its first held gate closed before payload execution."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
OLD = RT/"epoch162-second-replay-20261128-v1"
NEW = RT/"epoch162-second-replay-20261128-v2"
OP = OLD/"issued-split-v2"
PREVIOUS = "0a4f55edf2b14df6a8a99a41d09834fc"
OLD_SCOPE = "220b9159270070057d3b44d5e0fce304606fd44c18b9348bf5e8cc45fcd9a9ea"
OLD_OP = "56a55825cbbf968f201a3dd80ce84de9de1919f515386f0e8e304527172342e2"
OLD_TERM = "da2221e9db60025435d8ef53c8750439a199de91e56e62d956cf30920fbaf5f0"
OLD_HELD = "122d7e7a4cb0230d4fff1c6487ac2f7727b1d134c6c0c123a1b05cdae4cf5298"
OLD_STOP = "6e824f38bfa5393a06d912dee38476add35209a72fbdf8291c93d9d37160375f"
UNIT = "horizon-qualify-162-second-replay-20261128-v2.service"

def checked(p, digest):
    raw = p.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("unexpected bytes "+str(p))
    return json.loads(raw)

def ref(p):
    return dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())

def translate(text):
    return (text.replace("162-second-replay-20261128-v1","162-second-replay-20261128-v2")
                .replace("/run/horizon-162-second-replay-v1","/run/horizon-162-second-replay-v2"))

def closure(l, op):
    term = checked(l.DATA/"TERMINAL.json", OLD_TERM)
    actor = checked(l.DATA/"HELD_OWNER.json", OLD_HELD)
    stop = checked(l.GUARDS/"stop-completion.json", OLD_STOP)
    assert Path(stop["intent"]) == l.GUARDS/"stop-intent.json"
    intent, iref = l.pinned(stop["intent"])
    assert intent["plan_sha256"] == stop["plan_sha256"] == actor["guard_plan"]["sha256"]
    sample = intent["sample"]
    assert sample == l.bound(term["guard"])
    end = op["native_end"](l, actor)
    assert term["pid1"] == end and term["disposition"] == "guard-stopped" and term["trip"] == "filesystem-floor"
    assert actor["producer_invocation_id"] == sample["producer_invocation_id"] == PREVIOUS
    assert op["SUCCESS"] == end["MESSAGE_ID"] and sample["trip_reason"] == "filesystem-floor"
    assert stop["terminal"]["pid"] == 0 and sample["available_bytes"] < sample["minimum_free_bytes"]
    assert not l.ALLOW.exists() and not (l.DATA/"GRANT.json").exists() and not l.CGROUP.exists()
    seen = [l.pinned(p)[0] for p in l.GUARDS.glob("sample-*.json")]
    assert seen and all(row["producer_invocation_id"] == PREVIOUS and row["workers"] == [] for row in seen)
    assert l.manager(l.UNIT)["MainPID"] == "0" and l.manager(l.TIMER)["ActiveState"] == "inactive"
    assert json.loads(subprocess.check_output(["/usr/sbin/losetup","--list","--json","--associated",l.IMAGE])) == {"loopdevices":[]}
    image = l.IMAGE.stat()
    assert image.st_uid == 0 and image.st_nlink == 1 and image.st_mode & 0o777 == 0o400 and [image.st_dev,image.st_ino,image.st_size] == term["image"]
    return dict(schema="horizon-162-second-unreleased-guard-closure-v1",old_unit=l.UNIT,invocation_id=PREVIOUS,
                held=ref(l.DATA/"HELD_OWNER.json"),terminal=ref(l.DATA/"TERMINAL.json"),stop=ref(l.GUARDS/"stop-completion.json"),
                stop_intent=iref,first_guard=actor["first_guard"],samples=len(seen),guard_floor=sample["minimum_free_bytes"],
                available_home=sample["available_bytes"],image_identity=l.identity(l.IMAGE),image_allocated=image.st_blocks*512,
                no_grant=True,no_worker=True,immutable_source=ref(l.HANDOFF),native_end=end,resource_credit_bytes=0)

def prepare(gate, guard, commit):
    assert os.geteuid() == 0 and __debug__
    from types import SimpleNamespace
    l = SimpleNamespace(**runpy.run_path(str(OP/"layout.py")))
    old = checked(OP/"deployment-seal-receipt.json",OLD_OP)
    scope = checked(l.HANDOFF,OLD_SCOPE)
    older = runpy.run_path(str(OP/"status162.py"))
    helper = runpy.run_path(str(HERE/"second_interval.py"))
    helper["seal"].__globals__["BASE"] = NEW
    s = NEW/"source"; NEW.mkdir(mode=0o700,exist_ok=True);s.mkdir(mode=0o700,exist_ok=True)
    for folder in (s,NEW):
        assert folder.resolve()==folder and folder.stat().st_uid==0 and folder.stat().st_mode&0o077==0
    closure_ref = l.save(NEW/"UNRELEASED_PREDECESSOR.json",closure(l,older),0o400)
    source = Path(__file__).resolve(); repo = HERE.parent.parent
    git = ["git","-c","safe.directory="+str(repo),"-C",str(repo)]
    subprocess.run([*git,"merge-base","--is-ancestor",commit,"origin/account-updates"],check=True)
    assert subprocess.check_output([*git,"show",commit+":"+str(source.relative_to(repo))])==source.read_bytes()
    for b,digest in ((gate,GATE_SHA),(guard,GUARD_SHA)):
        assert ref(b)["sha256"]==digest
    files = {}
    for name,p in (("hold-162-second",gate),("guard",guard)):
        dst=s/name
        l.save(dst,p.read_bytes(),0o555); files[name]=(dst,0o555)
    static = helper["seal"](files,NEW/"static-v2",l.save)
    new_scope = json.loads(translate(json.dumps(scope)))
    new_scope["gate_deployment"]=static
    new_scope["unreleased_predecessor"]=closure_ref
    new_scope["source_commit"]=commit
    new_scope["first_hourly_gate"]=ref(NEW/"static-v2/hold-162-second")
    new_scope["first_hourly_guard"]=ref(NEW/"static-v2/guard")
    for row in new_scope["profile"]["readonly_projections"]:
        if row["source"] == str(NEW/"static-v2/hold-162-second"): row["sha256"]=GATE_SHA
    sref=l.save(NEW/"SCOPE-V2.json",new_scope,0o400)
    need_fields=("layout.py","launch.py","status162.py","close.py","terminal_bank.py")
    payload={}
    for name in need_fields:
        prior=OP/name
        assert any(m["name"]==name and m["sha256"]==ref(prior)["sha256"] for m in old["members"])
        text=translate(prior.read_text()).replace(OLD_SCOPE,sref["sha256"]).replace(l.GUARD_SHA,GUARD_SHA)
        if name in ("launch.py","status162.py"):
            text=text.replace("second162_provider","second162_retry_provider").replace("second162_reader","second162_retry_reader").replace("second162_status.py","second162_retry_status.py")
        if name=="status162.py":
            text=text.replace('FIELD = "current_private162_second_hourly"', 'FIELD = "current_private162_second_retry"')
            anchor='    l.bound(l.scope()["previous"])'
            assert text.count(anchor)==1
            text=text.replace(anchor,anchor+'''
    closure = l.bound(l.scope()["unreleased_predecessor"])
    previous = fleet.get("current_private162_second_hourly")
    l.need(closure["no_grant"] and closure["no_worker"] and closure["invocation_id"] == "0a4f55edf2b14df6a8a99a41d09834fc"
           and (not previous or previous["phase"] == "terminal" and previous["held_owner"] == closure["held"]
                and previous["producer_invocation_id"] == closure["invocation_id"] and previous["terminal"] == closure["native_end"]),
           "earlier second gate does not have its native terminal")
''')
        compile(text,name,"exec")
        p=s/name;l.save(p,text.encode(),0o444);payload[name]=(p,0o444)
    origin=s/"ORIGIN.json";l.save(origin,dict(commit=commit,original=ref(OP/"deployment-seal-receipt.json"),source=ref(source),
                                          gate_rev=NATIVE,gate=GATE_SHA,guard=GUARD_SHA,scope=sref,closure=closure_ref))
    payload[origin.name]=(origin,0o444)
    released=helper["seal"](payload,NEW/"issued-split-v2",l.save)
    return l.save(NEW/"RETRY_INTERFACE.json",dict(provider=released,reader=ref(NEW/"issued-split-v2/status162.py"),scope=sref,closure=closure_ref,
        unit=UNIT,field="current_private162_second_retry",guard=new_scope["first_hourly_guard"],gate=new_scope["first_hourly_gate"],
        first_slot=new_scope["first_slot"],last_slot=new_scope["last_slot"],immutable_predecessor=l.scope()["previous"]),0o400)

NATIVE = "ab15f4c21921fa19f44237eb6c97c5c48a5ac639"
GATE_SHA = "0a94eb6302ba4756fe588093a6e3ad2a16795b53d811783856792e400d143dae"
GUARD_SHA = "984bd4333fb82963274f4ae9ece05d74cf99ea3e48dcf3ee022953c754af3640"

if __name__ == "__main__":
    print(json.dumps(prepare(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3])))
