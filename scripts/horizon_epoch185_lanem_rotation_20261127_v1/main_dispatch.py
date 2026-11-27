"""Operator for the original lane-M partial. Run a mutation only when assigned the serial turn."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
STATE = ROOT / "epoch185-lanem-main-holding-20261127-v1"
PACKAGE = STATE / "package"
RECOVERY = STATE / "restore-tools-v1"
RETIRE = STATE / "retirement-tools-v1"
SIX = ROOT / "epoch141-foundation-sixth-bootstrap-20261127-v1"
SERIAL = ROOT / "epoch185-lanem-holding-20261127-v1/PARK_ADMISSION.json"
OPLOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
HOLDING = Path("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1")
COLD = Path("/usr/local/lib/jetstreamer/horizon-holding-candidate-20261023-v1/jetstreamer-r2")
SEAL = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
PRICE_PROGRAM = Path("/home/sol/.jetstreamer-private/epoch170-terminal-continuation-20261127.dnssfYJW/build/five-owner-price-v2.py")
NATIVE = {phase: f"horizon-closed185-lanem-main-{phase}-20261127-v1.service" for phase in ("park","retire","restore","review")}
METADATA = 2 << 20
RESTORE_META = 16 << 20
LENGTH = 54_996_291_524
SLOT = 123_350_028_052


def ref(path):
    with path.open("rb") as f:
        return {"path":str(path),"sha256":hashlib.file_digest(f,"sha256").hexdigest()}


def read(path):
    return json.loads(path.read_bytes())


def put(path,data):
    """Reuse identical durable records. Hard-link an fsynced temporary without overwriting."""
    raw=(json.dumps(data,indent=2,sort_keys=True)+"\n").encode()
    if path.exists():
        assert read(path)==data,path
        return ref(path)
    stage=path.with_name("."+path.name+"."+str(os.getpid())+"."+str(time.time_ns()))
    try:
        with stage.open("xb") as f:
            os.fchmod(f.fileno(),0o400)
            f.write(raw);f.flush();os.fsync(f.fileno())
        os.link(stage,path)
    finally:
        stage.unlink(missing_ok=True)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return ref(path)


@contextmanager
def locked(path):
    with path.open("rb") as f:
        fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


def native(unit):
    result=subprocess.run(["systemctl","show","--all","-p","Id,MainPID,InvocationID,ActiveState,SubState,ControlPID,Job,LoadState,ControlGroup",unit],capture_output=True,text=True,timeout=15)
    assert result.returncode in (0,4)
    return dict(s.split("=",1) for s in result.stdout.splitlines())


def completed(unit,iid,pid):
    if pid:
        try:fd=os.pidfd_open(pid)
        except ProcessLookupError:fd=None
        if fd is not None:
            try:
                state=native(unit)
                assert state["MainPID"]=="0" or (state["InvocationID"]==iid and state["MainPID"]==str(pid))
                poll=select.poll();poll.register(fd,select.POLLIN);poll.poll()
            finally:os.close(fd)
    for _ in range(60):
        st=native(unit)
        if st["MainPID"]==st["ControlPID"]=="0" and not st["Job"]:
            lines=subprocess.check_output(["journalctl","-b","-q","--no-pager","-o","json","_PID=1","_UID=0","UNIT="+unit,"INVOCATION_ID="+iid],text=True,timeout=15)
            for entry in reversed([json.loads(s) for s in lines.splitlines()]):
                settled=entry.get("MESSAGE_ID")=="7ad2d189f7e94e70a38c781354912448"
                if settled or "EXIT_CODE" in entry:
                    return dict(unit=unit,invocation=iid,done_usec=entry["__REALTIME_TIMESTAMP"],success=settled,native=st)
        time.sleep(.2)
    raise RuntimeError("missing native terminal "+unit)


def props(*values):
    return ["--property="+v for v in values]


def service(phase,argv,write=(),network=False,blocking=True,unit=None):
    memory,quota,timeout={"park":("2G","200%","2h"),"retire":("1G","100%","20min"),"restore":("2G","100%","2h"),"review":("512M","100%","4min"),"identity":("256M","25%","80s")}[phase]
    args=["systemd-run","--quiet","--service-type=exec","--unit="+(unit or NATIVE[phase])]
    if blocking:args+=["--wait","--pipe","--collect"]
    args+=props("MemoryMax="+memory,"CPUQuota="+quota,"RuntimeMaxSec="+timeout,"MemorySwapMax=0","TasksMax=256","UMask=0077","ProtectSystem=strict","ProtectHome=read-only","NoNewPrivileges=yes","Restart=no")
    if write:args+=props("ReadWritePaths="+" ".join(map(str,write)))
    args+=props("EnvironmentFile=/etc/jetstreamer/horizon-r2.env" if network else "PrivateNetwork=yes")
    return subprocess.check_output([*args,"--",*map(str,argv)],text=True)


def identity(phase):
    result=json.loads(service("identity",["/usr/bin/python3","-IB",RETIRE/"holding_identity.py",phase,"--main-partial"],network=True,unit="horizon-185-main-identity-"+str(time.time_ns())))
    assert result["authenticated"] and not result["remote_mutations"] and result["owner"]["status"]==200
    return result


def fit():
    code=PRICE_PROGRAM.read_bytes()
    assert hashlib.sha256(code).hexdigest()=="a1a1b4ee5e904d4568126e29d4d78a09af1c598b131b4a0e78d6db684e5c16f1"
    scope={"__file__":str(PRICE_PROGRAM),"__name__":"quoted_operator"}
    exec(compile(code,str(PRICE_PROGRAM),"exec"),scope)
    q=scope["quote"]()
    sixth=read(SIX/"ANZA_SERIAL_HANDBACK.json")
    assert sixth["return_to"]=="campaign controller" and sixth["temporary_payloads"]==sixth["retained_tmpfs_bytes"]==0
    assert Path(sixth["local_copy"]).stat().st_blocks*512==sixth["local_occupied_bytes"]
    assert read(SERIAL)["restore_overlap_bytes"]==SLOT
    # Reserve the campaign controls and any later independently admitted bootstrap.
    # This exact five-owner price must be rebound by the controller when the profile changes.
    latest=sorted(ROOT.glob("epoch141-foundation-*-bootstrap-20261127-v1/ANZA_SERIAL_HANDBACK.json"),key=lambda f:f.stat().st_mtime_ns)
    assert latest and latest[-1].parent==SIX,"update the serial/auxiliary roster for newer input custody"
    current=q["home"]; floor=max(q["required_home"],q["max_guard_floor"])+sixth["local_occupied_bytes"]+(128<<20)+(32<<20)
    home=min(q["home_margin"],current-floor)
    ram=q["ram_margin"]-(2<<30)-(256<<20)-(512<<20)
    return dict(recorded=time.time(),fleet=q["fleet"],source_price=ref(PRICE_PROGRAM),complete_price=q,serial_handback=ref(SIX/"ANZA_SERIAL_HANDBACK.json"),sixth_local_allocated=sixth["local_occupied_bytes"],home_margin=home,ram_margin=ram,floor_bytes=floor,single_copy_peak=LENGTH+RESTORE_META,two_copy_peak=2*LENGTH+RESTORE_META,serial_restore_reservation=SLOT,new_selected_source_credit=0)


def review():
    exe=RETIRE/"retire-main"
    result=json.loads(service("review",[exe,"--check-source",ref(exe)["sha256"]]))
    assert result["live_and_staged_check"] and result["unfinished"] and result["inode"]==104005633
    return result


def observed(phase,source,metrics):
    required={"park":2<<30,"retire":1<<30,"restore":2<<30}[phase]
    assert time.time()-metrics["recorded"]<=25
    need=metrics["single_copy_peak"] if phase=="restore" and not source.exists() else METADATA
    assert metrics["home_margin"]>=need and metrics["ram_margin"]>=required,(metrics["home_margin"],need,metrics["ram_margin"],required)
    return put(STATE/f"{phase.upper()}_FIT_{time.time_ns()}.json",metrics)


def retire_plan(expected, remote, proof, admission):
    saved=STATE/"RETIREMENT_REMOTE_IDENTITY.json"
    if saved.exists():
        earlier=read(saved)
        assert all(earlier[k]["etag"]==remote[k]["etag"] for k in ("blob","manifest","owner"))
    else:put(saved,remote)
    path=STATE/"retirement-plan-v1/plan.json"
    if not path.exists():
        raw=STATE/"RETIREMENT_PLAN_SOURCE.json"
        if not raw.exists():put(raw,dict(schema="horizon-lanem185-main-retirement-plan-v1",source=expected["source"],expected=ref(PACKAGE/"EXPECTED.json"),remote=ref(saved),park=ref(proof),admission=admission))
        spec=STATE/"RETIREMENT_SEAL_PLAN.json"
        put(spec,dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(path.parent),members=[dict(source=str(raw),name="plan.json",sha256=ref(raw)["sha256"],mode=0o400)]))
        assert ref(SEAL)["sha256"]=="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
        subprocess.run([SEAL,spec,"--plan-sha256",ref(spec)["sha256"],"--self-sha256",ref(SEAL)["sha256"]],check=True,stdout=subprocess.DEVNULL)
    return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase",choices=["quote","park","retire","restore"])
    phase=parser.parse_args().phase
    if not __debug__ or os.geteuid()!=0:
        raise RuntimeError("operator requires root with Python assertions enabled")
    expected=read(PACKAGE/"EXPECTED.json");src=Path(expected["source"]);custody=Path(expected["custody_path"])
    if phase=="quote":
        print(json.dumps(fit(),indent=2))
        return
    unit=NATIVE[phase];prefix=phase.upper()
    with locked(OPLOCK):
        final={"park":STATE/"PARK_CUSTODY.json","retire":STATE/"MEASURED_LOCAL_RECLAMATION.json"}.get(phase)
        if final is not None and final.exists():
            assert read(final)["native_custody"]==ref(custody)
            identity("accepted")
            if phase=="retire":
                assert not src.exists() and not Path(read(STATE/"LOCAL_RETIREMENT_COMPLETE.json")["operation"]["quarantine"]).exists()
            print(json.dumps(ref(final)))
            return
        current=native(unit)
        # A controller may have exited after the native operation but before its final receipt.
        # Recover that exact invocation before deciding to dispatch another worker.
        previous=sorted(STATE.glob(prefix+"_START_*.json"),key=lambda item:item.stat().st_mtime_ns)
        recovering=False
        if current["MainPID"]=="0" and previous:
            start=read(previous[-1]);old=start["native"]
            prior=completed(unit,old["InvocationID"],0)
            if prior["success"] and (phase!="restore" or not (STATE/("RESTORED_"+old["InvocationID"]+".json")).exists()):
                current=dict(InvocationID=old["InvocationID"],MainPID="0");recovering=True
        if recovering:pass
        elif current["MainPID"]!="0":
            assert current["ActiveState"]=="active" and re.fullmatch("[0-9a-f]{32}",current["InvocationID"])
            start=read(STATE/(prefix+"_START_"+current["InvocationID"]+".json"))
            assert start["unit"]==unit and start["native"]["MainPID"]==current["MainPID"]
        else:
            with locked(HOLDING/"transition.lock"):pass
            metrics=fit()
            assert metrics["two_copy_peak"]<SLOT
            if phase=="park":
                checked=review();remote=identity("precheck")
                assert checked["source"]==str(src) and remote["blob"]["key"]==expected["object_key"] and remote["manifest"]["key"]==expected["manifest_key"]
                assert ref(COLD)["sha256"]=="909248d8e4c1db4c3cd89e1a4f15205b4a59d442494f35b7635038152025bb7e"
                exe=COLD;plan=PACKAGE/"plan.json";argv=[exe,"holding-park",plan,"--spec-sha256",ref(plan)["sha256"],"--self-sha256",ref(exe)["sha256"]]
                write=[HOLDING]
            else:
                assert read(custody)["remote_sha256_readback"] and read(custody)["local_source_revalidated"]
                proof=STATE/"PARK_CUSTODY.json"
                assert read(proof)["native_custody"]==ref(custody)
                remote=identity("accepted")
                assert remote["blob"]["etag"].strip('"')==read(custody)["object_etag"].strip('"')
                if phase=="retire" and src.exists() and not (STATE/"LOCAL_RETIREMENT_INTENT.json").exists():review()
            metrics=fit()
            admission=observed(phase,src,metrics)
            if phase=="retire":
                # Merely test the prospective post-retirement fit. Credit remains zero until
                # the native measured reclamation exists, and future restore needs a fresh fit.
                if src.exists():
                    assert metrics["home_margin"]+min(src.stat().st_blocks*512,54_996_418_560)>=metrics["single_copy_peak"]
                plan=retire_plan(expected,remote,proof,admission)
                exe=RETIRE/"retire-main"
                argv=[exe,ref(plan)["sha256"],ref(exe)["sha256"]]
                write=[STATE,src.parent,HOLDING/"transition.lock",Path("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock")]
            elif phase=="restore":
                assert read(STATE/"LOCAL_RETIREMENT_COMPLETE.json")["source_absent"]
                rr=put(STATE/f"RESTORE_REMOTE_{time.time_ns()}.json",remote)
                plan=STATE/f"RESTORE_ADMISSION_{time.time_ns()}.json"
                put(plan,dict(schema="horizon-lanem185-main-restore-admission-v1",source=str(src),sha256=expected["sha256"],length=LENGTH,serial_restore_reservation=SLOT,two_copy_peak=metrics["two_copy_peak"],single_copy_peak=metrics["single_copy_peak"],restore_before_consumer=True,recorded_unix_seconds=int(time.time()),floor_bytes=metrics["floor_bytes"],fleet=metrics["fleet"],expected=ref(PACKAGE/"EXPECTED.json"),custody=ref(custody),retirement=ref(STATE/"LOCAL_RETIREMENT_COMPLETE.json"),remote=rr,fit=admission))
                exe=RECOVERY/"restore-main"; argv=[exe,plan,ref(plan)["sha256"],ref(exe)["sha256"]];write=[src.parent]
            if current["ActiveState"]=="failed":subprocess.run(["systemctl","reset-failed",unit],check=True)
            service(phase,argv,write,network=phase!="retire",blocking=False)
            current=native(unit);iid=current["InvocationID"]
            assert re.fullmatch("[0-9a-f]{32}",iid) and current["MainPID"]!="0"
            start=dict(unit=unit,native=current,plan=ref(plan),image=ref(exe),fit=admission)
            put(STATE/(prefix+"_START_"+iid+".json"),start)
    terminal=completed(unit,current["InvocationID"],int(current["MainPID"]))
    terminal_ref=put(STATE/(prefix+"_TERMINAL_"+terminal["invocation"]+".json"),terminal)
    assert terminal["success"],terminal
    if phase=="park":
        receipt=read(custody);assert all(receipt[k]==expected[k] for k in ("source","length","sha256","manifest","manifest_key","object_key","manifest_sha256"))
        assert receipt["remote_sha256_readback"] and receipt["local_source_revalidated"] and src.stat().st_ino==104005633
        post=identity("accepted")
        final=STATE/"PARK_CUSTODY.json"
        if not final.exists():put(final,dict(native_custody=ref(custody),native_terminal=terminal_ref,authenticated_identity=post,restore_reservation_bytes=SLOT,resource_credit_bytes=0))
    elif phase=="retire":
        document=read(STATE/"LOCAL_RETIREMENT_COMPLETE.json");assert not src.exists() and not Path(document["operation"]["quarantine"]).exists()
        post=identity("accepted")
        assert document["allocated_bytes_removed"]==54_996_418_560 and document["authenticated_custody_revalidated"]
        final=STATE/"MEASURED_LOCAL_RECLAMATION.json"
        if not final.exists():put(final,dict(native_terminal=terminal_ref,completion=ref(STATE/"LOCAL_RETIREMENT_COMPLETE.json"),native_custody=ref(custody),remote=post,allocated_bytes_removed=document["allocated_bytes_removed"],measured_net_free_bytes=document["measured_freed_bytes"],conservative_capacity_bytes=max(0,min(document["allocated_bytes_removed"],document["measured_freed_bytes"])),restore_before_original_path_consumer=True))
    else:
        assert src.stat().st_size==LENGTH and src.stat().st_uid==1001 and src.stat().st_gid==1003
        final=STATE/("RESTORED_"+terminal["invocation"]+".json")
        put(final,dict(native_terminal=terminal_ref,verified_destination=str(src),length=LENGTH,sha256=expected["sha256"],evidence=start))
    print(json.dumps(ref(final)))


if __name__=="__main__":
    main()
