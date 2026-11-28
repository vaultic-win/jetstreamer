"""Qualify the completed operator artifact from all six original PID1 lifecycles."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

here=Path(__file__).resolve().parent
b=runpy.run_path(str(here/"bootstrap.py"))
f=b["fit"]
need=f["need"]
start_id="39f53479d3a045ac8e11786248231fbf"
done_id="7ad2d189f7e94e70a38c781354912448"


def events(rows, unit, earliest, latest):
    starts=[r for r in rows if r.get("MESSAGE_ID")==start_id]
    ends=[r for r in rows if r.get("MESSAGE_ID")==done_id]
    need(len(starts)==len(ends)==1,"missing or ambiguous PID1 start/success")
    a,z=starts[0],ends[0]
    need(a["_PID"]==z["_PID"]=="1" and a["UNIT"]==z["UNIT"]==unit
         and a["INVOCATION_ID"]==z["INVOCATION_ID"] and len(a["INVOCATION_ID"])==32
         and a["_BOOT_ID"]==z["_BOOT_ID"] and a["JOB_RESULT"]=="done" and
         a["JOB_TYPE"]=="start" and z["MESSAGE"]==unit+": Deactivated successfully." and
         earliest*1_000_000<=int(a["__REALTIME_TIMESTAMP"])<=int(z["__REALTIME_TIMESTAMP"])<=latest*1_000_000
         and int(a["__MONOTONIC_TIMESTAMP"])<int(z["__MONOTONIC_TIMESTAMP"]), "wrong PID1 lifecycle")
    return dict(invocation_id=a["INVOCATION_ID"],boot=a["_BOOT_ID"],start=a["__CURSOR"],success=z["__CURSOR"],
                start_usec=int(a["__MONOTONIC_TIMESTAMP"]),end_usec=int(z["__MONOTONIC_TIMESTAMP"]))


def native(unit,g):
    args=["/usr/bin/journalctl","-b","-o","json","--no-pager","--since=@"+str(g["created"]),
          "--until=@"+str(g["deadline"]+10),"_PID=1","UNIT="+unit]
    raw=subprocess.check_output(args,timeout=10)
    result=events([json.loads(row) for row in raw.splitlines()],unit,g["created"],g["deadline"]+10)
    props=dict(row.split("=",1) for row in subprocess.check_output(["/usr/bin/systemctl","show","-p",
        "ActiveState,MainPID,ControlPID,Job,NRestarts",unit],text=True,timeout=10).splitlines())
    cg=f["SLICE_DIR"]/unit/"cgroup.procs"
    need(props["ActiveState"]=="inactive" and props["MainPID"]==props["ControlPID"]==props["NRestarts"]=="0"
         and not props["Job"] and (not cg.exists() or not cg.read_text().strip()),"scope remains occupied")
    return result


def finish():
    need(os.geteuid()==0 and sys.flags.isolated and __debug__,"root isolated finalization required")
    grant=b["BASE"]/"bootstrap-grant.json"
    binding={"path":str(grant),"sha256":b["file_sha"](grant)}
    g=f["checked"](binding)
    b["mounted"](g)
    complete_path=b["WORK"]/"complete.json"
    done=f["checked"]({"path":str(complete_path),"sha256":b["file_sha"](complete_path)})
    source=b["SOURCE"]
    b["package"](source,g["source_sha256"],["main.rs","phase.rs","PROTOCOL.json","consumer_capacity.rs"])
    b["package"](b["PACKAGE"],g["package_sha256"],["bootstrap.py","bootstrap_fit.py"])
    recipe,original=f["recipe"]()
    need(done["source"]==g["source_sha256"] and done["grant"]==binding and done["original_commands"]==original
         and done["inherited_original_tests"]==11 and not done["consumer_phases_started"] and not done["restore_started"],
         "different execution proof")
    root=native(b["ROOT_UNIT"],g)
    prior=root["start_usec"]
    proofs={}
    for label in b["STAGES"]:
        record=native(b["unit"](label),g)
        need(record["boot"]==root["boot"] and prior<=record["start_usec"]<record["end_usec"]<=root["end_usec"]
             and record["end_usec"]-record["start_usec"]<=50_000_000,"overlapping or late bootstrap")
        prior=record["end_usec"]
        argv=b["WORK"]/(label+".argv")
        expected=b["child_argv"](recipe,label,binding)
        need(json.loads(argv.read_bytes())==expected and argv.stat().st_uid==0 and not argv.stat().st_mode&0o222,
             "changed original child command")
        log=b["WORK"]/(label+".log")
        need(log.stat().st_uid==0 and 0<=log.stat().st_size<=256<<10,"invalid original child log")
        if label=="ordinary-tests":
            need("11 passed; 0 failed" in log.read_text(),"incomplete original fixture run")
        else:
            p=b["WORK"]/label
            f["pin"](p,done["products"][label])
        proofs[label]=dict(pid1=record,argv_sha256=b["file_sha"](argv),log_sha256=b["file_sha"](log))
    need(len({r["pid1"]["invocation_id"] for r in proofs.values()})==5 and
         root["end_usec"]-root["start_usec"]<=310_000_000,"forked or late root")
    evidence=dict(schema="horizon-native163-operator-source-bootstrap-qualification-v1",producer_authorized=False,
                  consumer_admission_authorized=False,source_commit=g["commit"],source_seal=g["source_sha256"],
                  tools_seal=g["package_sha256"],actual_ROOT=root,original_five_stages=proofs,grant=binding,
                  sha256=done["products"]["production"],complete=b["file_sha"](complete_path),resource_credit_bytes=0)
    proof=b["WORK"]/"qualified.json"
    if not proof.exists():
        b["write"](proof,(json.dumps(evidence,sort_keys=True)+"\n").encode())
    need(json.loads(proof.read_bytes())==evidence,"changed qualification")
    dest=b["BASE"]/"operator"
    members=[dict(name=name,source=str(src),mode=mode,sha256=b["file_sha"](src))
             for name,src,mode in [("run",b["WORK"]/"production",0o555),("qualification.json",proof,0o444)]]
    need(sum(Path(m["source"]).stat().st_size for m in members)+2*1024*1024 < 16*1024*1024,"outside allowance")
    plan=b["WORK"]/"operator-install.json"
    data=(json.dumps(dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(dest),members=members),
                     sort_keys=True)+"\n").encode()
    if not plan.exists():
        b["write"](plan,data)
    need(plan.read_bytes()==data,"different installation plan")
    sealer=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
    f["pin"](sealer,b["SEALER"])
    if not dest.exists():
        subprocess.run([sealer,plan,"--plan-sha256",b["file_sha"](plan),"--self-sha256",b["SEALER"]],check=True,timeout=20)
    seal=dest/"deployment-seal-receipt.json"
    saved=f["checked"]({"path":str(seal),"sha256":b["file_sha"](seal)})
    need(saved["plan_sha256"]==b["file_sha"](plan) and saved["destination"]==str(dest) and
         {m["name"]:m["sha256"] for m in saved["members"]}=={m["name"]:m["sha256"] for m in members},
         "different installed application")
    print(json.dumps(dict(seal=str(seal),sha256=b["file_sha"](seal),program=done["products"]["production"],
                          compiler_closed=True,restore_started=False)))


if __name__=="__main__":
    finish()
