"""Start the qualified held-source uploader after the accepted recovered-166 status."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import closure
import terminal_event as event

D=event.R/"epoch166-retry10-delivery-20261121-v1"
LAUNCH=D/"controller-tools/run-committed.sh"
FIT=D/"capacity-tools/publication-fit"
UNIT="horizon-publish-166-retry10-committed.service"
STATE=D/"event-state"

def status(fleet,report,terminal):
    ref=report["receipts"]["166"]
    row,actual=event.document(Path(ref["path"]),0o600)
    observed=fleet["observer"]
    event.need(actual==ref==fleet["effective_status_receipts"]["166"] and row["epoch"]==166 and
               row["key"]=="epoch-166.epoch-status.json" and row["observer"]==observed and
               row["authenticated_readback"] is True and row["conditional_header"]=="If-Match" and
               row["current_repair_owner"]=="/root" and row["producer_invocation_id"] is None and
               row[closure.FIELD]==terminal and row["after_status"]["phase"]=="verification" and
               row["archive_sample"]==closure.document(closure.T/"TERMINAL_SUCCESS.json",0o400)[0]["local_archive"] and
               row["after_status"]["jet_size_bytes"]==row["archive_sample"]["size"] and row["after_etag"],
               "cadence did not read back the committed local source")
    return ref

def head(fleet):
    current,_=event.document(Path(fleet["path"]),0o600)
    timer=current["sole_next_timer"];name=timer if isinstance(timer,str) else timer["unit"]
    mo=re.fullmatch(r"horizon-observer-(root[0-9]{6}-live166167170-[0-9]{8}-v1)\.timer",name)
    event.need(mo is not None,"foreign scheduled successor")
    if (event.R/mo.group(1)/event.FLEET_NAME).exists():return None
    return event.document(Path(fleet["path"]),0o600)[1]

def main():
    event.need(os.geteuid()==0 and __debug__ and sys.flags.isolated,"isolated root required")
    bindings,_=event.document(HERE/"programs.json",0o444)
    for p in (FIT,LAUNCH):
        event.need(event.member(p,0o555)[1]==bindings[p.name],"changed qualified program")
    fit_sha=bindings[FIT.name]["sha256"]
    original=closure.retire()["terminal"]
    m=STATE.lstat()
    event.need(STATE.resolve(strict=True)==STATE and m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o700,"untrusted event state")
    with (STATE/"event.lock").open("a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (STATE/"INTENT.json").exists():
            old,_=event.document(STATE/"INTENT.json",0o400)
            event.need(old["terminal"]==original and old["unit"]==UNIT,"uncertain original submission differs")
            print(json.dumps(dict(disposition="existing-intent",manager=event.manager(UNIT))))
            return
        changes=event.Changes()
        try:
            def accepted():
                return event.accepted(event.R,event.REPORTS,original,changes,head,time.time(),closure.FIELD,status)
            while True:
                proof=accepted()
                if proof:
                    socket=event.agents()
                    event.need(closure.inspect()["terminal"]==original,"terminal changed before submission")
                    if accepted()!=proof:continue
                    def launch(fleet,socket):
                        subprocess.run([LAUNCH,"sync",fleet["path"],fleet["sha256"],socket,fit_sha],check=True,timeout=45)
                        return event.manager(UNIT)
                    print(event.submit(STATE,original,proof,socket,launch,lambda t:event.previous(t,D,UNIT),UNIT,LAUNCH,fit_sha),flush=True)
                    return
                changes.wait()
        finally:
            changes.close()

if __name__=="__main__":main()
