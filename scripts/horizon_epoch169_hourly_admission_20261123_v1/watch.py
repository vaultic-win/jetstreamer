"""Inspect a single registered hourly invocation. No worker manipulation or public writes."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

UNIT = "horizon-qualify-169-focused-hourly-20261123-v1.service"
BASE = Path("/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1")
OUTPUT = BASE / "v158/epoch-169-through-73245218.jet"
MANIFEST = OUTPUT.with_suffix(".jet.segment.json")
LOG = BASE / "hourly-run/producer.log"
WORKER = "9665351525b7a6a8b67e985fc35ad896a5adbcb7aeda0cab379be16cf693796a"
BOOT_HASH = "GDXFwepRMYKGWDv947uUN9cfoMpunPFDLJHn4cgJx5A5"
TERMINAL_HASH = "5aXCD1ZXBe3fPYtrxvFkDvSvz8x68XiRmWfoEnLVLPif"
SIG = "267mkJuiWWjRVYmTUjAEcLu9K3BmLos5h7tBkpXkYTyyJffVJ6Wn89cFrQvuEYXU8vASqvWkF1Mni7RSi1gGTG5c"
EXPECTED = "Some(InstructionError { instruction_index: 2, error: ProgramFailedToComplete })"
TARGET = "historical execution mismatch at slot 73239086 entry 164 transaction 205 signature "+SIG+": expected "+EXPECTED+", got "
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAIL = "d9b373ed55a64feb8242e02dbe79a49c"
EXIT = "98e322203f7a4ed290d09fe03c09fe15"
STOPPING = "de5b426a63be47a7b6ac3eaac82e2f6f"


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def identity(path):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
         st.st_uid in (0,1001) and not st.st_mode & 0o022, "unsafe private file")
    return dict(device=st.st_dev,inode=st.st_ino,size=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)


def auth_manifest(m):
    need(m["schema_version"]==1 and m["epoch"]==169 and
         (m["output_slot_start"],m["output_slot_count"])==(73_238_441,6778) and
         (m["bootstrap"]["slot"],m["bootstrap"]["accounts_hash"])==(73_238_440,BOOT_HASH) and
         (m["terminal"]["slot"],m["terminal"]["accounts_hash"],m["terminal"]["slot_complete"])==
         (73_245_218,TERMINAL_HASH,True) and m["runtime"]["runtime_profile"]=="solana-v1.5.8" and
         m["runtime"]["runtime_admission"]=="candidate" and m["worker_executable_sha256"]==WORKER and
         re.fullmatch("[0-9a-f]{64}",m["archive_sha256"]) and int(m["archive_sha256"],16)>0,
         "wrong hourly manifest, slot count, checkpoint or worker")


def classify(log, manager, stopped, size=None):
    if stopped:
        return "interrupted-or-unclassified"
    feature = []
    failures = []
    ends = []
    archived = []
    committed = []
    for num, raw in enumerate(log):
        need(len(raw)<=1<<20 and raw.endswith(b"\n"),"truncated or oversized producer log")
        row = raw[:-1].decode("utf-8",errors="replace")
        if re.search(r"epoch169 diagnostic bank feature at slot 73239086 entry 164: per_byte_logging_cost active=(?:false activated_slot=None|true activated_slot=Some\(\d+\))$",row):
            feature.append(num)
        if TARGET in row:
            detail = row.split(TARGET,1)[1]
            kind = "warn" if "WARN  jetstreamer_node] replay failure: historical worker batch failed from slot " in row else (
                   "error" if row.startswith("error: historical worker batch failed from slot ") else "unrecognized")
            failures.append((num,detail,kind))
        if "historical checkpoint slot=73245218 bank_hash=" in row and f" accounts_hash={TERMINAL_HASH} " in row and " complete=true " in row:
            ends.append(num)
        if "horizon archive complete: slots=6778 " in row and re.search(r" bytes="+str(size)+r" \(payload \d+ uncompressed\)$",row):
            archived.append(num)
        if row.endswith("published verified historical segment evidence "+str(MANIFEST)):
            committed.append(num)
    if len(feature)!=1:
        return "interrupted-or-unclassified"
    if manager=="failure" and len(failures)==2 and failures[0][0]>feature[0] and failures[0][1]==failures[1][1] and failures[0][1]!=EXPECTED and [k for _,_,k in failures]==["warn","error"] and re.fullmatch(r"None|Some\(InstructionError \{ instruction_index: \d{1,3}, error: [A-Za-z][A-Za-z0-9]*(?:\(\d{1,10}\))? \}\)",failures[0][1]):
        return "diagnosed-target-mismatch"
    if manager=="success" and not failures and size is not None and len(ends)==len(archived)==len(committed)==1 and feature[0]<ends[0]<committed[0] and feature[0]<archived[0]<committed[0]:
        return "completed-private-span"
    return "interrupted-or-unclassified"


def manager_result(rows, iid, boot):
    related=[r for r in rows if r.get("MESSAGE_ID") in (SUCCESS,FAIL,EXIT,STOPPING)]
    need(all((r["_PID"],r["_BOOT_ID"],r["UNIT"],r["INVOCATION_ID"])==("1",boot,UNIT,iid) for r in related),
         "manager events from different generation")
    ends=[r for r in related if r["MESSAGE_ID"] in (SUCCESS,FAIL)]
    need(len(ends)==1 and ends[0]==related[-1],"private worker has no unique terminal yet")
    exit_events=[r for r in related if r["MESSAGE_ID"]==EXIT and r.get("COMMAND")=="ExecStart"]
    if any(r["MESSAGE_ID"]==STOPPING for r in related):
        return "interrupted"
    if ends[0]["MESSAGE_ID"]==SUCCESS and not exit_events:
        return "success"
    if ends[0].get("UNIT_RESULT")=="exit-code" and len(exit_events)==1 and exit_events[0].get("EXIT_CODE")=="exited" and exit_events[0].get("EXIT_STATUS")=="1":
        return "failure"
    return "interrupted"


def receipt(path, digest):
    raw=path.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==digest,"different registered owner")
    return json.loads(raw)


def inspect(grant_ref, digest):
    grant=receipt(grant_ref,digest)
    iid,boot=grant["invocation_id"],grant["boot_id"].replace("-","")
    need(grant["unit"]==UNIT and re.fullmatch("[0-9a-f]{32}",iid) and int(iid,16) and
         re.fullmatch("[0-9a-f]{32}",boot) and grant["canonical_publication_authorized"] is False,
         "foreign hourly grant")
    rows=subprocess.check_output(["/usr/bin/journalctl","--no-pager","-o","json","_PID=1",
                                  "UNIT="+UNIT,"_BOOT_ID="+boot,"INVOCATION_ID="+iid],timeout=30)
    manager=manager_result([json.loads(v) for v in rows.splitlines()],iid,boot)
    original=identity(LOG)
    need(original["inode"]==grant["log_inode"] and original["device"]==grant["log_device"],"foreign log")
    actual=None
    archive=None
    if manager=="success" and MANIFEST.exists():
        mi=identity(MANIFEST)
        need(mi["size"]<=1<<20,"oversized private manifest")
        m=json.loads(MANIFEST.read_bytes());auth_manifest(m)
        archive=identity(OUTPUT)
        with OUTPUT.open("rb") as fd:
            need(fd.read(8)==b"JSHZN1\0\0" and archive["size"]>=56,"private archive header")
            fd.seek(-48,os.SEEK_END)
            offset,length,buckets,_,reserved,magic=struct.unpack("<5Q8s",fd.read(48))
            need(magic==b"\0\0NZHSJ1" and reserved==0 and 8<offset and length>0 and
                 offset+length+48==archive["size"] and buckets>0,"private archive footer")
            fd.seek(0)
            need(hashlib.file_digest(fd,"sha256").hexdigest()==m["archive_sha256"], "private archive SHA-256 differs")
        need(mi==identity(MANIFEST) and archive==identity(OUTPUT),"private archive changed")
        actual=archive["size"]
    stopped=(BASE/"hourly-guard-receipts/stop-intent.json").exists()
    with LOG.open("rb") as file:
        result=classify(file,manager,stopped,actual)
    need(original==identity(LOG),"private log changed during terminal inspection")
    return dict(disposition=result,unit=UNIT,invocation_id=iid,boot_id=boot,log=original,archive=archive,
                private_span=result=="completed-private-span",canonical_publication_authorized=False,
                resource_credit_bytes=0)


def terminal_event():
    control=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-admission-20261123-v1")
    directory=control/"results"
    if not (control/"GRANT.json").exists():
        # No grant means no payload was authorized. A prestart failure may still have a PID1 journal.
        result=dict(disposition="private-payload-never-released",canonical_publication_authorized=False)
    else:
        p=control/"GRANT.json";m=p.lstat()
        need(p.resolve(strict=True)==p and stat.S_ISREG(m.st_mode) and m.st_uid==0 and not m.st_mode&0o222 and m.st_nlink==1,
             "untrusted terminal grant")
        digest=hashlib.sha256(p.read_bytes()).hexdigest()
        result=inspect(p,digest)
        result["grant_sha256"]=digest
    output=directory/"TERMINAL.json"
    payload=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
    if output.exists():
        need(output.read_bytes()==payload,"different terminal already recorded")
        return result
    temp=directory/(".terminal-"+str(os.getpid())+".tmp")
    try:
        with temp.open("xb") as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        temp.chmod(0o400)
        try:
            os.link(temp,output)
        except FileExistsError:
            need(output.read_bytes()==payload,"conflicting private terminal")
    finally:
        temp.unlink(missing_ok=True)
    fd=os.open(directory,os.O_DIRECTORY|os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return result


if __name__=="__main__":
    import argparse
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("--terminal-event",action="store_true")
    cli.add_argument("grant",nargs="?",type=Path)
    cli.add_argument("sha256",nargs="?")
    args=cli.parse_args()
    if args.terminal_event and args.grant is None and args.sha256 is None:
        result=terminal_event()
    elif not args.terminal_event and args.grant is not None and args.sha256 is not None:
        result=inspect(args.grant,args.sha256)
    else:
        cli.error("supply the terminal event switch or an explicit grant and digest")
    print(json.dumps(result,indent=2,sort_keys=True))
