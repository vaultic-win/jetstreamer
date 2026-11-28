"""Validate the stable verifier's protected 168 admission window and retired original peers."""
import hashlib
import os
from pathlib import Path
import stat

import status168 as s
import same_five

BASE=s.ROOT/"epoch145-semantic-continuity-20261121-v1"
IMAGE=BASE/"tools-v3/export145"
# The v3 verifier checks both original epoch 172 executable inodes.
IMAGE_SHA="e731a521cbcec391ceff90ace6a3b17095a6c771a9a5224be7d850ec5967f01f"
SEAL_SHA="e048a2694aebe57fd9018fd9cc22fd3047c397102efa394c1fa7f589be29ac53"
BUILD_SHA="6a90bb92f8353737d82ab752a2059a1b8eeeb6d111df1634717510cc01a48926"
HISTORY=s.ref(s.ROOT/"root084959-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json",
              "350020d2dcef311ec3a469250273b8a8bc79286d8bf4b96a6c2db8f7c994ee57")
ROOT=Path("/home/sol/.jetstreamer-private")
SOURCE=ROOT/"epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet"
MANIFEST=SOURCE.with_suffix(".jet.segment.json")
OUTPUT=ROOT/"epoch145-prefix-extract-funded-20261121-v1"
OLD="5dfb817906f74b73a27f61a386751d75"


def leases(pid,objects):
    actual={}
    proc=Path(f"/proc/{pid}")
    for fd in (proc/"fd").iterdir():
        try:
            m=fd.stat()
            if (m.st_dev,m.st_ino) not in objects: continue
            for line in (proc/"fdinfo"/fd.name).read_text().splitlines():
                fields=line.split()
                if len(fields)>=7 and fields[0]=="lock:" and fields[2:5]==["LEASE","ACTIVE","READ"]:
                    actual[m.st_ino]=int(fd.name)
        except FileNotFoundError:
            continue
    s.need(set(actual)=={ino for _,ino in objects},"original recovery read lease absent")
    return actual


def qualified_image(profile=None):
    image,image_sha,seal_sha,build_sha=profile or (IMAGE,IMAGE_SHA,SEAL_SHA,BUILD_SHA)
    seal,sealref=s.read(image.parent/"deployment-seal-receipt.json",seal_sha)
    build,buildref=s.read(image.parent/"build-proof.json",build_sha)
    members={row["name"]:row["sha256"] for row in seal["members"]}
    s.need(seal["destination"]==str(image.parent) and members.get("export145")==image_sha
           and members.get("build-proof.json")==build_sha, "foreign 145 continuity seal or build")
    if profile is None:
        s.need(build["content_hashes"]["export145"]["sha256"]==image_sha,"different post-terminal verifier build")
    with image.open("rb") as f:
        s.need(hashlib.file_digest(f,"sha256").hexdigest()==image_sha,"different available 145 executable")
    return sealref,buildref


def inspect(stable,manager,unit,children):
    same = None
    if str(IMAGE)!=stable["exe"]:
        same=same_five.profile(stable["exe"])
        if same is None: return None
    image,image_sha=(same or (IMAGE,IMAGE_SHA))[:2]
    if len(stable["argv"])!=5 or stable["argv"][1]!="recover-full-output":
        return None
    who=manager["InvocationID"];pid=int(manager["MainPID"]);proc=Path(f"/proc/{pid}")
    s.need(s.iid(who) and who!=OLD and manager["Id"]==unit and manager["ControlGroup"]=="/system.slice/"+unit
           and manager["ActiveState"]=="active" and manager["SubState"]=="running" and manager["NRestarts"]=="0"
           and not manager["Job"] and manager["ControlPID"]=="0" and manager["CPUQuotaPerSecUSec"]=="1s"
           and manager["MemoryMax"]==str(2<<30) and manager["MemorySwapMax"]=="0"
           and s.same_file(proc/"exe",image) and s.process(pid)[1:]==(stable["start_ticks"],"0::/system.slice/"+unit)
           and (stable["holding_lock"]["device"],stable["holding_lock"]["inode"])==(64512,95818311)
           and stable["holding_lock"]["fds"],"different recovery manager")
    sealref,buildref=qualified_image(same)
    if len(children)!=2 or pid not in children: return None
    child=next(p for p in children if p!=pid);cproc=Path(f"/proc/{child}")
    ppid,ticks,group=s.process(child)
    cargv=(cproc/"cmdline").read_bytes().split(b"\0")[:-1]
    if cargv!=[os.fsencode(image),b"recover-worker",str(pid).encode(),image_sha.encode()]: return None
    s.need(ppid==pid and group=="0::/system.slice/"+unit and s.same_file(cproc/"exe",image)
           and all(("INVOCATION_ID="+who).encode() in (p/"environ").read_bytes().split(b"\0") for p in (proc,cproc)),
           "different native 145 recovery child")
    state=s.ROOT/"epoch145-guarded-export-20261121-v1/state"/who
    started,startref=s.read(state/"recovery-started.json")
    fleetref=started["fresh_fit"]["fleet"]
    predecessor=started["prior_frozen_recovery"]
    s.need(stable["argv"]==[str(image),"recover-full-output",fleetref["path"],fleetref["sha256"],image_sha]
           and started["iid"]==who and started["image"]==image_sha and started["r2_mutations"] is False
           and started["fresh_fit"]["joint136_enabled"] is True
           and predecessor["append"]["sha256"]=="9d8fc46ba227c4875f516d2318b2e397caa8884d058ccb217313ec3ae9071fc4"
           and not any((state/n).exists() for n in ("failed.json","verified-frozen.json","complete.json")),
           "145 has left verified recovery or has different provenance")
    if same is None:
        closed=started["fresh_fit"]["joint_closed166"]
        s.need(isinstance(closed,dict) and closed["unit"]=="horizon-qualify-independent-cold166-20261120-v1.service"
               and closed["invocation_id"]=="fa16ee2f14fe44ecbc37c59e197553ac" and closed["pid1_success"] is True
               and closed["resource_credit_bytes"]==0,"different post-terminal 166 owner")
        terminal=s.bound(closed["terminal"],s.ROOT/"epoch166-terminal-20261121-v1/TERMINAL_SUCCESS.json")
        s.need(terminal["producer_invocation_id"]==closed["invocation_id"] and terminal["resource_credit_bytes"]==0
               and terminal["committed_receipt"]==closed["batch"] and terminal["transaction_id"]==closed["transaction"],"different post-terminal 166 evidence")
        failed=None
    else:
        failed=same_five.predecessor(predecessor,started["fresh_fit"],unit)
    candidate=Path(started["file"])
    s.need(candidate.parent==OUTPUT and candidate.name in (".tmp36MvkN","epoch-145.jet"),"different frozen output")
    objects={}
    for path,ino,length in ((SOURCE,100214450,105633748687),(MANIFEST,100214429,1809),(candidate,103237059,105610995833)):
        m=path.lstat()
        s.need(path.resolve(strict=True)==path and stat.S_ISREG(m.st_mode) and
               (m.st_dev,m.st_ino,m.st_size,m.st_nlink,m.st_uid,stat.S_IMODE(m.st_mode))==(64512,ino,length,1,0,0o400),
               "wrong frozen original 145 object")
        objects[(m.st_dev,m.st_ino)]=str(path)
    a=leases(pid,objects);b=leases(child,objects)
    s.need(s.process(child)==(ppid,ticks,group) and s.process(pid)[1]==stable["start_ticks"],"145 census changed")
    return dict(mode="recover-full-output",native_child=dict(pid=child,start_ticks=ticks),
                recovery=startref,original_five_peer_failure=failed,continuity_seal=sealref,continuity_build=buildref,
                leases_parent=a,leases_worker=b)


def retired(epoch,anchor,manager,children):
    original=s.bound(HISTORY,Path(HISTORY["path"]))
    rows=[x for k in ("actual_executing_replays","actual_active_private_diagnostics") for x in original[k] if x["epoch"]==epoch]
    s.need(len(rows)==1,"original peer absent from paid historical census")
    who=anchor["iid"];unit=anchor["unit"]
    path=BASE/"peer-terminals"/f"epoch-{epoch}-{who}.json"
    value,termref=s.read(path)
    v=value["peer"];initial=rows[0];event=v["terminal"]
    expected=[p[:2] for p in anchor["processes"]]
    s.need(value["schema"]=="horizon-145-qualified-original-peer-terminal-v1" and value["history_sha256"]==HISTORY["sha256"]
           and value["boot"]==Path("/proc/sys/kernel/random/boot_id").read_text().strip()
           and v["epoch"]==epoch and v["unit"]==initial["unit"]["Id"]==unit and v["invocation"]==who==initial["unit"]["InvocationID"]
           and v["processes"]==expected and v["admission"]==initial["admission"] and v["resource_credit_bytes"]==0
           and v["archive_publication_authorized"] is False and event["UNIT"]==unit and event["INVOCATION_ID"]==who
           and manager["ActiveState"] in ("inactive","failed") and not manager["Job"] and not children,
           "different retired peer lineage")
    for pid,ticks in expected:
        try: same=s.process(pid)[1]==ticks
        except (FileNotFoundError,ProcessLookupError): same=False
        s.need(not same,"original supposedly terminal peer remains alive")
    if epoch==169:
        s.need(v["source"]["diagnostic_only"] is True and v["source"]["archive_ready"] is False and
               event["MESSAGE_ID"] in ("7ad2d189f7e94e70a38c781354912448","98e322203f7a4ed290d09fe03c09fe15"),
               "unqualified original diagnostic disposition")
    else:
        z=v["source"]
        s.need(event["MESSAGE_ID"]=="7ad2d189f7e94e70a38c781354912448" and z["native_sha256"]==
               "dea7acbfa01d0beae046549823ebce48e7086a7276349b4530ed35c04a2d4efb" and z["committed"]["uid"]==1001
               and Path(z["committed"]["archive"]).name==f"epoch-{epoch}.jet"
               and len(z["committed"]["sha256"])==64,"unqualified original singleton disposition")
    return termref
