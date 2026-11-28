"""Close the third 169 gate after the native guard reserved more floor than the disk could fund."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

ROOT=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-retry-20261128-v3")
OP=ROOT/"operator-v1"
IID="5d0455bad43742be89ee9711b460d1c0"
SCOPE="7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
CONTROL="bdb679419333a1a1aa0c0d744306aef44e76f18008ceae6dc10ffe26ced1db16"


def close():
    tool=OP/"contract.py"
    if hashlib.sha256(tool.read_bytes()).hexdigest()!=CONTROL:
        raise ValueError("different third evidence reader")
    c=runpy.run_path(str(tool))
    read,need=c["read"],c["need"]
    scope,sr=read(ROOT/"SCOPE.json",SCOPE)
    held,hr=read(ROOT/"HELD_GATE.json","65a388c8db36cfeb2558e961ccc54950c6f770dcd0f215e9792c03472dd65239")
    end,er=read(ROOT/"results/TERMINAL.json","a25522f69b21b42e6f353e6733dd7075844d02468e63f8c5d5ea15e87f4694b0")
    start,ir=read(ROOT/"START_INTENT.json","bf2d3d0b3767e13fe4c3b783f90386d6834e011fc5b2502b5ed35124fd87a001")
    initial,pr=read(Path(start["prestart"]["path"]),start["prestart"]["sha256"])
    guard,gr=read(Path(start["guard_plan"]["path"]),start["guard_plan"]["sha256"])
    post,qr=read(ROOT/"POST_GUARD_SCREEN.json","5a038a1c5559b159ec975d0f37a25e5622f06f9e023409043c6f832a125e9015")
    peer=post["whole_roster"]["base_169"]["native"]["independent_retry169"]
    need(end==dict(canonical_publication_authorized=False,disposition="private-payload-never-released")
         and pr == dict(path=str(ROOT/"PRESTART.json"),sha256="867bb8abffc792b1a0e3d4d87751d4f44276631e2c6c27112440e011b3861e4b")
         and gr == dict(path=str(ROOT/"GUARD_PLAN.json"),sha256="da078041223dbd5dacf3bf2e7e9da21d56ba54cf4657f63473b8bf62dcd01e56")
         and held["invocation_id"]==guard["invocation_id"]==start["producer_invocation_id"]==peer["invocation"]==IID
         and start["held"]==hr and start["scope"]==initial["scope"]==post["scope"]==sr
         and peer["phase"]=="held" and peer["guard_plan"]==gr and peer["floor"]==post["armed_floor"]==guard["minimum_free_bytes"]
         and initial["writer"]==post["writer"] and initial["whole_roster"]["fleet"]==post["whole_roster"]["fleet"]
         and post["fits"] and not post["preliminary"] and post["stage"]=="native-postguard"
         and [key for key,v in post["postguard_checks"].items() if not v]==["funded_output"]
         and post["guard_floor"]<=post["armed_floor"] and post["whole_roster"]["available_home"]-post["armed_floor"]
         -scope["quota"]["home_output"]==post["armed_home_margin"]==-598_995_877,"foreign held postguard stop")
    names=[scope["producer_unit"],scope["guard_timer"],scope["guard_timer"].replace(".timer",".service"),scope["watcher"]]
    states={}
    for name in names:
        keys="Id,ActiveState,SubState,Job,InvocationID"
        if name.endswith(".service"):
            keys+=",ControlGroup,MainPID,ControlPID"
        cmd=subprocess.run(["systemctl","show","--all","-p",keys,"--",name],text=True,capture_output=True,timeout=15)
        st=dict(line.split("=",1) for line in cmd.stdout.splitlines())
        need(cmd.returncode in (0,4) and st["Id"]==name and st["ActiveState"] in ("failed","inactive") and not st["Job"]
             and not st.get("ControlGroup") and st.get("MainPID","0")==st.get("ControlPID","0")=="0"
             and not (Path("/sys/fs/cgroup/system.slice")/name/"cgroup.procs").exists(),"undrained "+name)
        if name == scope["producer_unit"]:
            need(st["ActiveState"] == st["SubState"] == "failed" and st["InvocationID"] == IID,
                 "third producer lost its PID1 failure identity")
        else:
            need(st["ActiveState"] == "inactive" and st["SubState"] == "dead", "third guard or watcher still active")
        states[name]=st
    events=list(map(json.loads,subprocess.check_output(["journalctl","--no-pager","-q","-o","json","_PID=1",
        "UNIT="+scope["producer_unit"],"INVOCATION_ID="+IID,"_BOOT_ID="+held["boot_id"].replace("-","")],timeout=20).splitlines()))
    exitline,=[e for e in events if e.get("MESSAGE_ID")=="98e322203f7a4ed290d09fe03c09fe15"]
    failure,=[e for e in events if e.get("MESSAGE_ID")=="d9b373ed55a64feb8242e02dbe79a49c"]
    need(exitline["EXIT_CODE"]=="exited" and exitline["EXIT_STATUS"]=="1" and failure["UNIT_RESULT"]=="exit-code","different gate exit")
    samples=[]
    for p in sorted((c["RETRY"]/"hourly-guard-receipts").glob("sample-*.json")):
        sample,ref=read(p,sealed=False)
        need(sample["producer_invocation_id"]==IID and sample["plan_sha256"]==gr["sha256"] and sample["producer_stop_enabled"]
             and not sample["workers"] and sample["trip_reason"] is None,"different held guard sample")
        samples.append(ref)
    log,body=c["stable"](Path(scope["log"]),keep_bytes=True)
    need(len(samples)==17 and start["first_guard"] in samples and body.endswith(b"TimeoutError: expired before the first guard and postguard grant\n")
         and b"progress slot " not in body,"different gate interval")
    for p in (ROOT/"GRANT.json",ROOT/"POST_GUARD_PRICE.json",c["BARRIER"]/"allow.json",Path(scope["output"]),
              Path(scope["output"]+".segment.json")):
        need(not os.path.lexists(p),"unexpected third output or release "+str(p))
    return c["recorded"](ROOT/"UNRELEASED_OUTPUT_MARGIN.json",dict(schema="horizon-169-third-unreleased-output-margin-v1",
        invocation_id=IID,scope=sr,held=hr,intent=ir,prestart=pr,guard=gr,guard_samples=samples,terminal=er,
        retained_log=log,postguard=qr,armed_home_margin=post["armed_home_margin"],pid1=[exitline,failure],states=states,
        proof=scope["guard_projection_qualification"],first_replay_slot_observed=False,resource_credit_bytes=0,
        canonical_publication_authorized=False))


if __name__=="__main__":
    print(json.dumps(close()))
