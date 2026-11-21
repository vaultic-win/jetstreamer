"""Authenticate the conditional 96-GiB extension of the original epoch 170 booking."""
import hashlib
import os
from pathlib import Path
import stat

R=Path("/var/lib/jetstreamer/horizon_runtime_data")
D=R/"epoch170-retry10-recovery-20261121-v1"
G=R/"epoch170-retry10-guard384-20261121-v1"
OLD=R/"epoch170-ancestor-accounts-20261121-v1"
IMAGE_SOURCE="e72ae5b535920079d665a11a088bd76e90447f2a"
UNIT="horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
ORIGINAL="8d120ed88adc4afb9485fb3f61dfa29c"
CAP=384<<30
EXTRA=96<<30

def guard(s):
    q,qr=s.read(G/"GUARD_QUALIFIED.json")
    s.need(q["schema"]=="horizon-170-384-native-guard-qualified-v1" and not q["physical_launch"] and
           set(q["static_controls"])=={"positive","wrong-cap","wrong-epoch","wrong-root","missing-witness"},"foreign extended guard controls")
    build=s.bound(q["build"],G/"BUILD.json")
    seal=s.bound(q["seal"],G/"tools/deployment-seal-receipt.json")
    sha=q["guard"]["sha256"];exe=G/"tools/guard"
    s.need(build["commit"]==IMAGE_SOURCE and s.iid(build["build_iid"]) and build["test_count"]==102 and
           build["artifact"]["sha256"]==sha and q["guard"]["path"]==str(exe) and seal["destination"]==str(exe.parent) and
           any(v["name"]=="guard" and v["sha256"]==sha for v in seal["members"]),"foreign 170 guard build")
    with exe.open("rb") as f:
        st=os.fstat(f.fileno())
        s.need(exe.resolve(strict=True)==exe and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o555 and
               hashlib.file_digest(f,"sha256").hexdigest()==sha,"changed 170-only image")
    witness=s.bound(q["witness"],G/"NATIVE_WITNESS.json")
    binding=q["contract"];contract=s.bound(binding["contract"],G/"contract/contract.json")
    cs=s.bound(binding["deployment_seal"],G/"contract/deployment-seal-receipt.json")
    s.need(witness["native_identity"]["executable_sha256"]==sha and witness["native_identity"]["executable"]==str(exe) and
           len(witness["allocation"]["first"])==12 and witness["allocation"]["first"]==witness["allocation"]["second"] and
           contract["qualified_native_witness"]==q["witness"] and cs["destination"]==str(G/"contract") and
           any(v["name"]=="contract.json" and v["sha256"]==binding["contract"]["sha256"] for v in cs["members"]),"extended native DATA witness changed")
    return dict(image=sha,qualification=qr,contract=binding)

def funding(s,epoch):
    accepted=D/"ACCEPTED_384_BOOKING.json"
    if epoch!=170 and not accepted.exists():
        s.need(s.show(UNIT)["ActiveState"] in ("inactive","failed"),"unexpected unbooked 170 generation")
        return None
    final,retirement=s.read(OLD/"CLOSED_6_7_RETIRED.json","c246bb365dd59d234fd389d7dfcaed30910cbab36dfeeacff62cd2e9d64196dc")
    s.need(final["net_removed_bytes"]==65619279872 and final["resource_credit_bytes"]==0,"unbound cleanup total")
    result={}
    for n,size,inode in [(6,32506998784,109772806),(7,33112289280,110902340)]:
        label="local3retry"+str(n);p=OLD/"post-stop-state"/label
        c,cr=s.read(p/"COMPLETE.json");check,_=s.read(p/"CHECK.json",c["check_sha256"])
        intent,_=s.read(p/"INTENT.json",c["intent_sha256"])
        target=Path(c["scope"]);m=target.lstat()
        s.need(c["schema"]=="horizon170-closed-accounts-complete-v1" and c["attempt"]==label and c["original_iid"]==ORIGINAL
               and c["scope_empty"] and c["archive_or_snapshot_removed"] is False and c["resource_credit_bytes"]==0 and
               c["retired_tree_before_bytes"]==size and check["target"]==intent["scope"]==str(target) and
               check["inode"]==intent["inode"]==inode and check["anchors"]["closed_retry9"]["successor_inode"]==113710084 and
               target.resolve(strict=True)==target and target.name=="accounts-state" and (m.st_dev,m.st_ino)==(64512,inode) and
               m.st_blocks*512==c["scope_root_remaining_bytes"] and not any(target.iterdir()),"170 closed extent or custody differs")
        s.need(final["completions"][str(n)]["completion"]==cr,"foreign closed scope")
        result[str(n)]=cr
    g=guard(s)
    if accepted.exists():
        a,ar=s.read(accepted)
        s.need(a["epoch"]==170 and a["cap_bytes"]==CAP and a["extra_bytes"]==EXTRA and a["retired"]==result and
               a["guard"]==g["qualification"] and a["prestart"]["fits"] is True and a["prestart"]["epoch"]==170 and
               a["prestart"]["bookings"]["170"]["cap_bytes"]==CAP,"foreign accepted 170 extension")
    else:ar=None
    return dict(cap_bytes=CAP,extra_bytes=EXTRA,retired=result,guard=g["qualification"],retirement=retirement,accepted=ar)

def held(s,unit,run,pid,proc,intent):
    profile,pref=s.read(D/"profile.json")
    prep=s.bound(intent["prepared"],D/"PREPARED.json");s.need(prep["profile"]==pref,"unbound held profile")
    tools=D/"controller";seal=s.bound(intent["controller"],tools/"deployment-seal-receipt.json")
    src=tools/"gate.py";members={v["name"]:v["sha256"] for v in seal["members"]}
    args=[os.fsdecode(a) for a in (proc/"cmdline").read_bytes().split(b"\0") if a]
    expected=["/usr/bin/python3","-IB","/run/horizon-recovered170/gate.py",*profile["normal_argv"]]
    path=proc/"root/run/horizon-recovered170";env=(proc/"environ").read_bytes().split(b"\0")
    status=dict((l.split(":",1)[0],l.split(":",1)[1].split()) for l in (proc/"status").read_text().splitlines() if ":" in l)
    s.need(unit==UNIT and s.same_file(proc/"exe",Path("/usr/bin/python3")) and status["Uid"]==["1001"]*4 and status["Gid"]==["1003"]*4 and
           args==expected and hashlib.sha256(src.read_bytes()).hexdigest()==members["gate.py"] and s.same_file(path/"gate.py",src) and
           s.same_file(path/"profile.json",D/"profile.json") and s.same_file(path/"barrier",D/"barrier") and
           ("HORIZON_REPLAY170_PROFILE_SHA256="+pref["sha256"]).encode() in env and not (D/"barrier/allow").exists(),"foreign 170 held gate")
