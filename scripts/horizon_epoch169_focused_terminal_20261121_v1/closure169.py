"""Resolve, authenticate and retire the original focused 169 invocation."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import struct
import subprocess
import sys

o=runpy.run_path(str(Path(__file__).resolve().with_name("original169.py")))
R,T,A,UNIT,IID,TIMER,TIMER_IID,GUARD,LOG,OUT,LOCK,MANIFEST=(o[k] for k in ("R","T","A","UNIT","IID","TIMER","TIMER_IID","GUARD","LOG","OUT","LOCK","MANIFEST"))
shared=o["shared"]
document,once,need=(shared[k] for k in ("document","once","need"))
FIELD="focused169_terminal"
DONE=T/"TERMINAL_GUARD_DRAINED.json"
TERM=T/"TERMINAL.json"
LIVE="60b076b21cae35dbc206bc782fb596f782df4039d7d22a1113acf2e06483c779"
OK="7ad2d189f7e94e70a38c781354912448"
FAIL="d9b373ed55a64feb8242e02dbe79a49c"
EXIT="98e322203f7a4ed290d09fe03c09fe15"
STOPPING="de5b426a63be47a7b6ac3eaac82e2f6f"
PRIVATE="completed-private-span"
MISMATCH="diagnosed-target-mismatch"
INTERRUPTED="interrupted-or-unclassified"
TIME=rb"\[\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,9}Z "
BANK=re.compile(rb"epoch169 diagnostic bank feature at slot 73239086 entry 164: per_byte_logging_cost active=(true|false) activated_slot=(None|Some\(\d{1,20}\))")
EXPECTED=b"Some(InstructionError { instruction_index: 2, error: ProgramFailedToComplete })"
DIFF=(rb"historical worker batch failed from slot \d+ entry \d+ through slot \d+ entry \d+: entry response consumer failed: historical execution mismatch at slot 73239086 entry 164 transaction 205 signature "
      +o["SIG"].encode()+rb": expected "+re.escape(EXPECTED)+rb", got (None|Some\(InstructionError \{ instruction_index: \d{1,3}, error: [A-Za-z][A-Za-z0-9]*(?:\(\d{1,10}\))? \}\))")
WARN=re.compile(TIME+rb"WARN  jetstreamer_node\] replay failure: ("+DIFF+rb")")
ERROR=re.compile(rb"error: ("+DIFF+rb")")
MARK=re.compile(TIME+rb"INFO  jetstreamer_node::historical_replay\] historical checkpoint slot=73245218 bank_hash=[1-9A-HJ-NP-Za-km-z]{32,44} accounts_hash="+o["HASH"].encode()+rb" last_blockhash=[1-9A-HJ-NP-Za-km-z]{32,44} capitalization=\d+ transactions=\d+ tick_height=\d+ complete=true writes=\d+ next_write_version=\d+")
ARCHIVE=re.compile(TIME+rb"INFO  jetstreamer_node::horizon\] horizon archive complete: slots=237219 blocks=\d+ txs=\d+ tx_updates=\d+ orphan_updates=\d+ epochs=\d+ buckets=\d+ bytes=(\d+) \(payload \d+ uncompressed\)")
PUBLISHED=re.compile(TIME+rb"INFO  jetstreamer_node\] published verified historical segment evidence "+re.escape(os.fsencode(MANIFEST)))

def manager_events(rows,boot):
    keys=("_PID","_BOOT_ID","UNIT","INVOCATION_ID","MESSAGE_ID","COMMAND","EXIT_CODE","EXIT_STATUS","UNIT_RESULT","__REALTIME_TIMESTAMP","__MONOTONIC_TIMESTAMP","__CURSOR")
    relevant=[]
    for r in rows:
        mid=r.get("MESSAGE_ID")
        if mid not in {OK,FAIL,EXIT,STOPPING}:continue
        need((r.get("_PID"),r.get("_BOOT_ID"),r.get("UNIT"),r.get("INVOCATION_ID"))==("1",boot.replace("-",""),UNIT,IID),"foreign PID 1 exit")
        relevant.append({k:r[k] for k in keys if k in r})
    ends=[r for r in relevant if r["MESSAGE_ID"] in {OK,FAIL}]
    need(len(ends)==1 and ends[0]==relevant[-1], "no unique original PID 1 terminal")
    exits=[r for r in relevant if r["MESSAGE_ID"]==EXIT and r.get("COMMAND")=="ExecStart"]
    need(len(exits)<=1, "conflicting original process exits")
    end=ends[0]; requested=any(r["MESSAGE_ID"]==STOPPING for r in relevant)
    normal=not requested and end["MESSAGE_ID"]==OK and not exits
    mismatch=not requested and end["MESSAGE_ID"]==FAIL and end.get("UNIT_RESULT")=="exit-code" and len(exits)==1 and exits[0].get("EXIT_CODE")=="exited" and exits[0].get("EXIT_STATUS")=="1"
    return dict(events=relevant,normal=normal,ordinary_failure=mismatch,terminal_usec=int(end["__REALTIME_TIMESTAMP"]))

def event(boot):
    fields="_PID,_BOOT_ID,MESSAGE_ID,UNIT,INVOCATION_ID,COMMAND,EXIT_CODE,EXIT_STATUS,UNIT_RESULT"
    out=subprocess.check_output(["/usr/bin/journalctl","--no-pager","-o","json","--output-fields="+fields,
                                 "_BOOT_ID="+boot.replace("-",""),"_PID=1","UNIT="+UNIT,"INVOCATION_ID="+IID,"-n","100"],timeout=15)
    return manager_events([json.loads(r) for r in out.splitlines()],boot)

def stopped_guard():
    base=A/"guard-receipts"
    files={p.name:p for p in base.glob("stop-*.json")}
    if not files:return {}
    need(set(files)=={"stop-intent.json","stop-completion.json"},"incomplete original guard stop")
    intent,ir=document(files["stop-intent.json"],0o600)
    done,dr=document(files["stop-completion.json"],0o600)
    plan="3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58"
    need(intent["schema"]=="jetstreamer-horizon-standalone-stop-intent-v1" and done["schema"]=="jetstreamer-horizon-standalone-stop-completion-v1"
         and intent["producer_invocation_id"]==done["producer_invocation_id"]==IID and intent["plan_sha256"]==done["plan_sha256"]==plan
         and done["intent"]==ir["path"] and all(done[k] is False for k in ("remote_mutations","r2_mutations","scratch_deleted")), "foreign guard stop")
    s=intent["sample"]
    need(s["producer_invocation_id"]==IID and s["plan_sha256"]==plan and s["trip_reason"]==intent["reason"] and s["producer_stop_enabled"],"foreign original stop sample")
    terminal=done["terminal"]
    need(terminal["invocation_id"]==IID and terminal["pid"]==0 and terminal["active"] in ("inactive","failed"),"foreign guard completion")
    sample_path=base/("sample-"+s["guard_invocation_id"]+".json")
    need(re.fullmatch(r"sample-[0-9a-f]{32}\.json",sample_path.name) and sample_path.parent==base,"foreign stop sample path")
    actual,sr=document(sample_path,0o600)
    need(s==actual,"original guard sample changed")
    return dict(intent=ir,completion=dr,sample=sr,reason=intent["reason"])

def classify(lines,event,guard,segment):
    found={k:[] for k in ("feature","warn","error","checkpoint","archive","manifest")}
    last=b""
    for i,line in enumerate(lines):
        need(len(line)<=1<<20 and line.endswith(b"\n"),"incomplete or oversized append log")
        line=line[:-1];last=line
        for k,pattern in (("feature",BANK),("warn",WARN),("error",ERROR),("checkpoint",MARK),("archive",ARCHIVE),("manifest",PUBLISHED)):
            m=pattern.fullmatch(line)
            if m and len(found[k])<2:found[k].append((i,m))
    def one(k):return len(found[k])==1
    status=INTERRUPTED;detail={}
    if one("feature") and not guard:
        b,feature=found["feature"][0]
        active,activation=feature.groups()
        valid=(active==b"true")==activation.startswith(b"Some(")
        if valid and activation.startswith(b"Some("):valid=int(activation[5:-1])<=73239086
        if valid:
            detail=dict(per_byte_logging_cost_active=active==b"true",activated_slot=int(activation[5:-1]) if activation.startswith(b"Some(") else None)
            if event["ordinary_failure"] and one("warn") and one("error") and not segment:
                wi,warn=found["warn"][0];ei,error=found["error"][0]
                if b<wi<ei and error[0]==last and warn[1]==error[1] and error[2]!=EXPECTED and not found["archive"] and not found["manifest"]:
                    status=MISMATCH;detail.update(expected=EXPECTED.decode(),actual=error[2].decode())
            if event["normal"] and segment and all(one(k) for k in ("checkpoint","archive","manifest")) and not found["error"] and not found["warn"]:
                ck,_=found["checkpoint"][0];ak,archive=found["archive"][0];mk,_=found["manifest"][0]
                if b<ck<mk and b<ak<mk and int(archive[1])==segment["size"]:status=PRIVATE
    return status,detail

def meta(p):
    m=p.lstat()
    need(p.resolve(strict=True)==p and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and (m.st_uid,m.st_gid)==(1001,1003) and not (m.st_mode&0o022),"unsafe private member")
    return dict(path=str(p),device=m.st_dev,inode=m.st_ino,size=m.st_size,mtime_ns=m.st_mtime_ns,ctime_ns=m.st_ctime_ns)

def artifact(size):
    if not MANIFEST.exists():return None
    mf=meta(MANIFEST);need(mf["size"]<=1<<20,"oversized segment manifest")
    with MANIFEST.open("rb") as f:raw=f.read()
    v=json.loads(raw)
    need(meta(MANIFEST)==mf and v["epoch"]==169 and v["schema_version"]==1 and v["output_slot_start"]==73008000 and v["output_slot_count"]==237219
         and v["bootstrap"]["slot"]==73007829 and v["terminal"]["slot"]==73245218 and v["terminal"]["slot_complete"] is True and v["terminal"]["accounts_hash"]==o["HASH"]
         and v["runtime"]["runtime_profile"]=="solana-v1.5.8" and v["runtime"]["runtime_admission"]=="candidate" and v["worker_executable_sha256"]==o["WORKER"]
         and re.fullmatch(r"[0-9a-f]{64}",v["archive_sha256"]) and int(v["archive_sha256"],16)>0,"wrong private segment")
    with OUT.open("rb") as fd:
        need(fd.read(8)==b"JSHZN1\0\0" and size>=56,"wrong private archive")
        fd.seek(-48,os.SEEK_END)
        offset,length,buckets,_,reserved,end=struct.unpack("<5Q8s",fd.read(48))
        need(end==b"\0\0NZHSJ1" and reserved==0 and 8<offset and length>0 and offset+length+48==size and buckets>0,"incomplete private archive footer")
    return dict(size=size,archive_sha256=v["archive_sha256"],manifest=mf,manifest_sha256=hashlib.sha256(raw).hexdigest())

def live():
    w,wr=document(T/"LIVE.json",0o400,LIVE)
    refs,row=o["original"]()
    need(w["original"]==refs and w["boot_id"]==o["boot"]() and w["producer_invocation_id"]==IID and w["timer_invocation_id"]==TIMER_IID
         and w["prefix"]==row["native_preworker_log"] and w["worker"]==row["native_worker_at_consumption"],"foreign original live witness")
    return w,wr

def drained_original():
    m=shared["drained"](UNIT)
    need(m["InvocationID"] in ("",IID),"different producer generation")
    return m

@contextlib.contextmanager
def custody(w):
    drained_original()
    def verify():
        layout=o["layout"]()
        need(all(w[k]==v for k,v in layout.items()),"private 169 inode or lease replaced")
    verify()
    with LOCK.open("rb") as lease:
        fcntl.flock(lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
        need(os.path.samestat(os.fstat(lease.fileno()),LOCK.lstat()),"foreign private lease")
        yield
        verify();drained_original()

def exact_exit():
    fields="InvocationID,ExecMainCode,ExecMainStatus,ExecMainExitTimestampMonotonic,Result"
    raw=subprocess.run(["/usr/bin/systemctl","show","-p",fields,UNIT],capture_output=True,text=True,timeout=8).stdout
    row=dict(line.split("=",1) for line in raw.splitlines())
    if row.get("InvocationID")==IID and int(row.get("ExecMainExitTimestampMonotonic") or "0")>0:
        return dict(binding="original-manager",invocation=IID,exited=row["ExecMainCode"]=="1",status=row["ExecMainStatus"],result=row["Result"])
    # PID 1 passes these variables only to the original OnSuccess/OnFailure target.
    kind={"success":"success"}.get(os.environ.get("MONITOR_SERVICE_RESULT"),"failure")
    name="horizon-focused169-terminal-event@"+kind+".service"
    me=shared["manager"](name)
    if (me["InvocationID"]==os.environ.get("INVOCATION_ID") and me["MainPID"]==str(os.getpid()) and
        Path("/proc/self/cgroup").read_text().strip()=="0::/system.slice/"+name and
        os.environ.get("MONITOR_UNIT")==UNIT and os.environ.get("MONITOR_INVOCATION_ID")==IID):
        return dict(binding="original-manager-monitor",invocation=IID,exited=os.environ.get("MONITOR_EXIT_CODE")=="exited",
                    status=os.environ.get("MONITOR_EXIT_STATUS"),result=os.environ.get("MONITOR_SERVICE_RESULT"))
    return None

def terminal():
    w,wr=live()
    with custody(w):
        e=event(w["boot_id"]);guard=stopped_guard();exit_status=exact_exit()
        classified=dict(e,normal=bool(e["normal"] and exit_status and exit_status["exited"] and exit_status["status"]=="0" and exit_status["result"]=="success"))
        archive=meta(OUT);log=meta(LOG)
        bound=e["terminal_usec"]*1000+999
        need(max(archive["ctime_ns"],log["ctime_ns"])<=bound and log["size"]<=256<<20,"original bytes changed after PID 1 termination")
        segment=artifact(archive["size"])
        need(not segment or segment["manifest"]["ctime_ns"]<=bound,"segment manifest postdates process exit")
        prefix=w["prefix"];h=hashlib.sha256()
        with LOG.open("rb") as f:
            need(hashlib.sha256(f.read(prefix["prefix_bytes"])).hexdigest()==prefix["prefix_sha256"],"startup log changed")
            f.seek(0)
            def lines():
                while chunk:=f.readline((1<<20)+1):
                    h.update(chunk);yield chunk
            try: disposition,detail=classify(lines(),classified,guard,segment)
            except ValueError:
                while chunk:=f.read(1<<20):h.update(chunk)
                disposition,detail=INTERRUPTED,{}
        need(meta(LOG)==log and meta(OUT)==archive,"terminal bytes changed")
        return dict(schema="focused169-private-terminal-v1",epoch=169,producer_unit=UNIT,producer_invocation_id=IID,
                    live=wr,**w["original"],manager_terminal=e,original_exit=exit_status,guard_stop=guard,disposition=disposition,detail=detail,closed_log=log,log_sha256=h.hexdigest(),
                    private_output=archive,private_segment=segment,archive_publication_authorized=False,canonical_replay_claimed=False,new_producer_authorized=False,
                    resource_credit_bytes=0,reservation_ending_bytes=0)

def committed():
    w,wr=live();record,tr=document(TERM,0o400)
    with custody(w):
        guard=stopped_guard()
        need(record["schema"]=="focused169-private-terminal-v1" and record["epoch"]==169 and record["producer_invocation_id"]==IID and record["producer_unit"]==UNIT
             and record["live"]==wr and all(record[k]==v for k,v in w["original"].items())
             and manager_events(record["manager_terminal"]["events"],w["boot_id"])==record["manager_terminal"] and record["guard_stop"]==guard
             and record["closed_log"]==meta(LOG) and record["private_output"]==meta(OUT)
             and record["private_segment"]==artifact(record["private_output"]["size"])
             and record["disposition"] in (PRIVATE,MISMATCH,INTERRUPTED) and (not guard or record["disposition"]==INTERRUPTED)
             and record["resource_credit_bytes"]==record["reservation_ending_bytes"]==0 and
             all(record[k] is False for k in ("archive_publication_authorized","canonical_replay_claimed","new_producer_authorized")), "changed private terminal")
    return dict(terminal=tr,live=wr,admission=record["admission"],first_guard=record["first_guard"],actual_guard_plan=record["actual_guard_plan"],
                disposition=record["disposition"],producer_invocation_id=IID,timer_unit=TIMER,timer_invocation_id=TIMER_IID,guard_unit=GUARD,resource_credit_bytes=0)

class FocusedGuard(shared["GuardClosure"]):
    def committed(self):return committed()

guard=FocusedGuard(169,T,A,UNIT,IID,TIMER,TIMER_IID,LIVE,"",0o400,"","")
inspect,retire=guard.inspect,guard.retire

def settle():
    if not TERM.exists():once(TERM,terminal())
    return retire()

if __name__=="__main__":
    need(sys.flags.isolated and __debug__ and os.geteuid()==0 and len(sys.argv)==2 and sys.argv[1] in ("settle","inspect"),"invalid terminal call")
    print(json.dumps(settle() if sys.argv[1]=="settle" else inspect(),sort_keys=True))
