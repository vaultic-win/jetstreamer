"""Read-only witness for the chronological audit's clean v10 -> v11 cut."""
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

UNIT="horizon-r2-chronological-plugin-audit-20261118-v1.service"
CG="/system.slice/"+UNIT
BASE=Path("/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1")
STATE=Path("/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1")
READERS=Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1")
TRANS=BASE/"range-v11-transition"
OLD_IID="7204441a3de34846a079875d564838dc"
OLD_PID=2464769
OLD_TICKS=349524833
OLD_IMAGE="408703e0c58c738a55d30742e01e348e3720a1ec62357f555dbc887926de7435"
OLD_SEAL="f0fe063020f459c5f44ad36f2c7629bbe198050e5105648420289ab11e618cd9"
OLD_STARTED="4e8085614ad96a018bde71d3f582b993e6f0a2f8f5de8d755da7b0db66a16246"
HOME_START="c043d9d42a50bd2aac7b1ab0c865f3a0ee1759fe6adc6da657aed4d5b5ad2257"
CONFIG="5d7d09bfb1ffdb08ac5aa04b228e9cd3827a6ef3bbb700723d7b777d2261e177"
FAILURE="d05c0f397a4b4c96a16454869bb0834135735a931136ee9a0ce3ba88393daa9c"
INVENTORY="d38d5146d50b7788cf5866fa0f7f5aeefade92fbf0496398fee334b480b7084e"
SEALER="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
NEW_IMAGE="6273535cb5f313253e89428ee28811e68c97a56fe5c7abd07f084125c6e43a3b"
NEW_SEAL="27f8565027a12035158065cc9b00e7407399dfa40ea66cbd0606e26e4e402bd5"
HANDOFF_SEAL="d244bee2aae964e188eb021b8fc4f3181967300f21b13691611849530f002957"
REPAIR="7916c7cf62be04481ed7deace1dbe3d31d9ed6c6"
LIMITS={"MemoryMax":str(24<<30),"MemorySwapMax":"0","TasksMax":"512","CPUQuotaPerSecUSec":"4s","ControlGroup":CG}
FIELDS=("Id","ActiveState","SubState","MainPID","InvocationID","MemoryMax","MemoryHigh","MemorySwapMax","CPUQuotaPerSecUSec","TasksMax","ControlGroup","NRestarts","Job","FreezerState")
LEGACY_FIELDS=("MainPID","ActiveState","SubState","InvocationID","NRestarts","Job")
RESERVE=6796908511026
MAX_ARCHIVE=385290386716

class TransitionPending(ValueError):
    pass

def need(condition, reason):
    if not condition: raise ValueError(reason)

def run(args):
    return subprocess.check_output(args,timeout=15,stderr=subprocess.PIPE).decode()

def native():
    raw=run(["/usr/bin/systemctl","show",UNIT,"-p"+",".join(FIELDS)])
    row=dict(line.split("=",1) for line in raw.splitlines())
    need(set(row)==set(FIELDS),"unexpected audit native fields")
    return row

def legacy(row):
    return {k:row[k] for k in LEGACY_FIELDS}

def read(path, expected=None, mode=None, kind="json"):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path,"noncanonical witness file "+str(path))
    def identity(m):
        return m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as fh:
        m=os.fstat(fh.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_dev==Path("/home/sol").stat().st_dev and m.st_uid==0 and m.st_nlink==1 and not m.st_mode&0o022 and m.st_size<=128<<20,"unsafe HOME witness file "+str(path))
        if mode is not None: need(stat.S_IMODE(m.st_mode)==mode,"unexpected sealed mode "+str(path))
        if kind=="json":
            need(m.st_size<=8<<20,"oversized receipt")
            raw=fh.read();digest=hashlib.sha256(raw).hexdigest();value=json.loads(raw)
        else:
            digest=hashlib.file_digest(fh,"sha256").hexdigest();value=None
        need(identity(m)==identity(os.fstat(fh.fileno()))==identity(path.lstat()),"audit witness changed while reading "+str(path))
    if expected is not None: need(digest==expected,"different audit evidence "+str(path))
    return value,{"path":str(path),"sha256":digest}

def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])

def validate_limits(row):
    need(all(row[k]==v for k,v in LIMITS.items()) and row["SubState"]=="running" and row["Job"]=="" and row["NRestarts"]=="0","audit limits or running owner differ")

def validate_config(cfg):
    need(cfg["reserve_bytes"]==RESERVE and cfg["max_archive_bytes"]==MAX_ARCHIVE and cfg["build_reserve_bytes"]==16<<30 and cfg["threads"]==4 and cfg["build_jobs"]==2
         and cfg["state_directory"]==str(STATE) and cfg["cargo_home"]=="/home/sol/.cargo" and cfg.get("external_scratch") is None,"changed HOME/CPU/Cargo configuration")

def check_obligation(o):
    need(o["additional_memory_bytes"]==24<<30 and o["additional_cpu_quota_micros"]==4000000 and o["tasks_max"]==512 and o["DATA_storage_filesystem"]=="/home/sol"
         and o["configured_free_floor_bytes"]==RESERVE and o["working_allocation_cap_bytes"]==16<<30 and o["cargo_growth_allowance_bytes"]==2<<30
         and o["archive_acceptance_ceiling_bytes"]==MAX_ARCHIVE and o["archive_cap_is_acceptance_ceiling_not_reservation"] is True and o["per_epoch_capacity_reserves_exact_archive_bytes"] is True
         and o["old166scratch_DATA_obligation_retained"]==309237645312 and o["original_promises_ended"] is False,"changed fleet audit allocation")

def bind_process(row,pkg,image):
    validate_limits(row)
    pid=int(row["MainPID"]);start=ticks(pid);proc=Path("/proc")/str(pid);exe=pkg/"audit"
    need(pid>1 and start>0 and row["ActiveState"]=="active" and row["FreezerState"]=="running" and row["MemoryHigh"]==str(20<<30) and row["Id"]==UNIT,"audit process not running under the accepted envelope")
    need((proc/"cgroup").read_text().strip()=="0::"+CG and (proc/"exe").readlink()==exe and (proc/"exe").samefile(exe)
         and (proc/"cmdline").read_bytes()==b"\0".join([os.fsencode(exe),b"run",os.fsencode(pkg/"config.json"),b""]), "audit native image, config or cgroup changed")
    need("frozen 0" in (Path("/sys/fs/cgroup")/CG.lstrip("/")/"cgroup.events").read_text().splitlines(),"actual audit cgroup remains frozen")
    _,image_ref=read(exe,image,0o555,"binary")
    need(native()==row and ticks(pid)==start and (proc/"exe").samefile(exe),"audit owner changed while reading its image")
    return start,image_ref

def verify_group(old,stopped,started):
    validate_limits(old);validate_limits(started)
    need(old["InvocationID"]==OLD_IID and old["MainPID"]==str(OLD_PID) and old["FreezerState"]=="frozen","foreign incumbent freeze")
    need(stopped["MainPID"]=="0" and stopped["Job"]=="" and stopped["SubState"] in ("dead","failed") and stopped["InvocationID"] in ("",OLD_IID),"old audit still active at handoff")
    need(re.fullmatch("[0-9a-f]{32}",started["InvocationID"]) and started["InvocationID"] not in ("0"*32,OLD_IID) and int(started["MainPID"])>1 and started["FreezerState"]=="running","invalid successor admission")

def clean_boundary(clean):
    epoch=clean["clean_epoch"];need(type(epoch) is int and epoch>=91,"unexpected clean cut epoch")
    result,r=read(STATE/"results"/f"epoch-{epoch}.json",clean["result_sha256"])
    attempt=Path(result["attempt"])
    need(attempt.parent==STATE/"attempts" and re.fullmatch(f"epoch-{epoch}-[0-9]+",attempt.name),"foreign boundary attempt")
    cleanup,c=read(attempt/"cleanup.json",clean["cleanup_sha256"])
    play=result["playback"];download=result["download"];path=Path(play["native_report_path"])
    need(path.parent==attempt and path==Path(clean["native_report"]) and clean["native_report_sha256"]==play["native_report_sha256"],"native full playback report mismatch")
    _,p=read(path,play["native_report_sha256"])
    need(clean["result"]==r["path"] and clean["cleanup"]==c["path"] and cleanup["epoch"]==epoch and cleanup["removed_only_owned_audit_copy"] is True
         and result["epoch"]==epoch and result["status"]=="passed" and result["remote_mutations"] is False and result["invocation"] and play["clean_process_exit"] is True
         and play["epoch"]==epoch and play["first_slot"]==epoch*432000 and play["last_slot"]==(epoch+1)*432000-1 and play["counters"]["slots"]==432000
         and download["object"]==result["object"] and 0<download["bytes"]==result["object"]["bytes"] and re.fullmatch("[a-f0-9]{64}",download["sha256"]), "incomplete boundary playback or cleanup")
    return {"epoch":epoch,"result":r,"cleanup":c,"playback":p}

def deployment(pkg,image,seal_sha,source):
    seal,s=read(pkg/"deployment-seal-receipt.json",seal_sha,0o444)
    need(seal["schema"]=="jetstreamer-sealed-deployment-receipt-v1" and seal["destination"]==str(pkg) and seal["remote_mutations"] is False and seal["sealer_sha256"]==SEALER,"wrong runtime deployment")
    members={x["name"]:x for x in seal["members"]}
    need(len(members)==len(seal["members"]) and members["audit"]["sha256"]==image and members["audit"]["mode"]=="0555" and members["config.json"]["sha256"]==CONFIG and members["config.json"]["mode"]=="0444","incorrect runtime seal members")
    cfg,c=read(pkg/"config.json",CONFIG,0o444);validate_config(cfg)
    proof_ref=None
    if source:
        need(re.fullmatch("[0-9a-f]{40}",source) and members["artifact-proof.json"]["mode"]=="0444","invalid build source or qualification")
        proof,proof_ref=read(pkg/"artifact-proof.json",members["artifact-proof.json"]["sha256"],0o444)
        need(proof["git"]==source and proof["artifact_sha256"]==image and proof["predecessor_terminal"]==FAILURE and proof["full_playback_required"] is True,"wrong repair build")
        git=["/usr/bin/git","--no-replace-objects","-c","safe.directory=/home/sol/workspace/jetstreamer","-C","/home/sol/workspace/jetstreamer","merge-base","--is-ancestor"]
        run([*git,REPAIR,source]);run([*git,source,"refs/remotes/origin/account-updates"])
    return c,s,proof_ref

def clean_tool():
    pkg=BASE/"epoch90-clean-handoff-v1"
    seal,ref=read(pkg/"deployment-seal-receipt.json",HANDOFF_SEAL,0o444)
    need(seal["destination"]==str(pkg) and seal["sealer_sha256"]==SEALER and seal["remote_mutations"] is False,"foreign handoff package")
    members={m["name"]:m for m in seal["members"]}
    tool=members["handoff90"]
    _,image=read(pkg/"handoff90",tool["sha256"],0o555,"binary")
    proof,qual=read(pkg/"artifact-proof.json",members["artifact-proof.json"]["sha256"],0o444)
    need(proof["predecessor_terminal"]==FAILURE and proof["artifact_sha256"]==image["sha256"] and proof["full_playback_required"] is True,"different clean-cut helper")
    return {"seal":ref,"image":image,"qualification":qual}

def capture():
    row=native()
    start_path=TRANS/"STARTED.json"
    inc=(row["InvocationID"],row["MainPID"])==(OLD_IID,str(OLD_PID))
    if inc and row["FreezerState"] in ("freezing","frozen") and not start_path.exists():
        raise TransitionPending("original audit temporarily frozen at its scheduled clean handoff")
    if not inc and not start_path.exists() and (TRANS/"STOP_INTENT.json").exists():
        raise TransitionPending("clean-cut successor has not yet recorded STARTED.json")
    _,home_start=read(BASE/"range-v9-transition/START_EVENT.json",HOME_START)
    past,old_start=read(BASE/"range-v10-transition/STARTED.json",OLD_STARTED)
    need(past["InvocationID"]==OLD_IID and past["MainPID"]==str(OLD_PID),"incumbent start proof changed")
    need(all(p.stat().st_dev==Path("/home/sol").stat().st_dev for p in (STATE,READERS,Path("/home/sol/.cargo"))),"audit work moved from HOME")
    if inc:
        need(not start_path.exists() and not (TRANS/"STOPPED.json").exists(),"closed audit invocation reappeared")
        pkg=BASE/"runtime-v10";cfg,seal,_=deployment(pkg,OLD_IMAGE,OLD_SEAL,None)
        tick,img=bind_process(row,pkg,OLD_IMAGE)
        need(tick==OLD_TICKS,"incumbent PID was reused")
        return dict(native=row,start_ticks=tick,image=img,config=cfg,seal=seal,home_storage_start_event=home_start,incumbent_start=old_start)
    intent,intent_ref=read(TRANS/"STOP_INTENT.json")
    stopped,stop_ref=read(TRANS/"STOPPED.json")
    started,start_ref=read(start_path)
    clean=intent["verified_clean_boundary"]
    verify_group(clean["old_owner"],stopped,started)
    need(all(row[k]==v for k,v in started.items() if k in FIELDS) and row["InvocationID"]==started["InvocationID"] and row["MainPID"]==started["MainPID"],"uncaptured successor invocation")
    try: retired=ticks(OLD_PID)
    except (FileNotFoundError,ProcessLookupError): retired=None
    need(retired!=OLD_TICKS and intent["old_image"]==OLD_IMAGE and intent["frozen_inventory"]==INVENTORY and intent["epoch90_original"]==FAILURE,"old process or mismatching cut")
    read(STATE/"inventory.json",INVENTORY)
    old,_=read(STATE/"results/epoch-90.json",FAILURE)
    need(old["epoch"]==90 and old["status"]=="failed" and old["playback"] is None,"invalid original transfer failure")
    boundary=clean_boundary(clean)
    image=intent["next_image"];seal_sha=intent["next_seal"];source=intent["required_source"]
    need(image==NEW_IMAGE and seal_sha==NEW_SEAL and source==REPAIR,"invalid successor seal/image binding")
    pkg=BASE/"runtime-v11";cfg,seal,proof=deployment(pkg,image,seal_sha,source)
    tick,img=bind_process(row,pkg,image)
    if "start_ticks" in started: need(int(started["start_ticks"])==tick,"successor tick mismatch")
    need(tick>OLD_TICKS and read(start_path)[1]==start_ref,"successor changed while binding")
    return dict(native=row,start_ticks=tick,image=img,config=cfg,seal=seal,home_storage_start_event=home_start,
                epoch90_handoff=dict(intent=intent_ref,stopped=stop_ref,started=start_ref,incumbent_start=old_start,closed_start_ticks=OLD_TICKS,boundary=boundary,artifact_proof=proof,source=source,handoff_tool=clean_tool()))

def continuity(previous,receipt,witness):
    present=legacy(witness["native"])
    if receipt is not None:
        if previous["InvocationID"]==present["InvocationID"]:
            need(receipt==witness and previous==present,"audit owner changed without a new clean cut")
            return
        need(receipt["native"]["InvocationID"]==OLD_IID and receipt["start_ticks"]==OLD_TICKS and receipt["image"]["sha256"]==OLD_IMAGE,"unrecognized prior witness")
    if previous==present:
        need(present["InvocationID"]==OLD_IID,"successor lacks preceding capacity witness")
    else:
        need(previous=={"InvocationID":OLD_IID,"MainPID":str(OLD_PID),"ActiveState":"active","SubState":"running","NRestarts":"0","Job":""}
             and "epoch90_handoff" in witness,"uncertified audit turnover")

if __name__=="__main__":
    print(json.dumps(capture(),sort_keys=True))
