#!/usr/bin/python3 -I
"""Render the normal gated producer and standalone guard commands from their qualified inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

STATE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1")
TEMPLATE = STATE.parent/"epoch172-full-half-core-20261120-v1"
PKG = STATE/"inputs-v1"
TREE = Path("/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1")
RUN = TREE/"full-metered-20261121-v1"
ALIAS = Path("/run/horizon-full168-metered")
PAYLOAD_SHA = "6c56c0cad87c9d22ca72ad8e2cf97cb0cc0c5e1b4d1d01e4f051dfc01875b240"
MINIMUM_FLOOR = 8297502499408


def need(condition, message):
    if not condition:
        raise ValueError(message)


def verified(path, sha):
    data=path.read_bytes()
    need(hashlib.sha256(data).hexdigest()==sha, f"wrong sealed input: {path}")
    return json.loads(data)


def complete_offline():
    real=STATE/"qa-f8fd52e48d7e4aeab815c5c12fc622c6/native-controls.jsonl"
    data=real.read_bytes()
    need(hashlib.sha256(data).hexdigest()=="a37616b133b53c750d7e218e4acbb584a1dc85bc7193fb9457eda3616d6de3b2",
         "wrong native control evidence")
    wrong,positive=map(json.loads,data.splitlines())
    need(wrong["exit"]==positive["exit"]==1 and "cohort manifest fingerprint mismatch" in wrong["stderr"]
         and "generation 1634787413893700 at slot 72575704" in positive["stderr"]
         and "bound its bootstrap and 1 root checkpoint(s) through epoch 168" in positive["stderr"]
         and "historical worker startup failed" in positive["stderr"] and "deliberately-absent-worker" in positive["stderr"],
         "original node preflight stopped outside the intended gate")
    return str(real)


def projection(j):
    files = {RUN/"runtime"/name:Path(p) for name,(p,_) in j["members"].items()}
    files[RUN/"runtime/payload.json"] = PKG/"payload.json"
    files[ALIAS/"jetstreamer-node"] = Path(j["members"]["jetstreamer-node"][0])
    files[ALIAS/"gate.py"] = STATE/"controller/gate.py"
    files[ALIAS/"barrier"] = STATE/"barrier"
    files[RUN/"ledger/genesis.tar.bz2"] = Path(j["genesis"]["path"])
    for item in j["indexes"]:
        files[Path(item["target"])] = Path(item["source"]["path"])
    return files


def normal_spec():
    complete_offline()
    seal=verified(PKG/"deployment-seal-receipt.json","e00db5e753a2cc37af403933f54bcb3216594d1fac3d91cc8984623999295a93")
    need(any(m["name"]=="payload.json" and m["sha256"]==PAYLOAD_SHA for m in seal["members"]),
         "missing qualified payload")
    j=verified(PKG/"payload.json",PAYLOAD_SHA)
    old=verified(TEMPLATE/"PRODUCER_ARGV.json","9792ffdb44ceb5051c70e6f0b57f091a944277e633078c4548ff2f3b7ca1a690")
    props=dict(x.removeprefix("--property=").split("=",1) for x in old if x.startswith("--property="))
    need(props["User"]=="sol" and props["Group"]=="horizon" and props["MemorySwapMax"]=="0"
         and props["MemoryMax"]==str(68<<30) and props["ReadWritePaths"].endswith("full-metered-20261120-v1"),
         "original full production template changed")
    binds=projection(j)
    props.update(CPUQuota="900%",WorkingDirectory=str(RUN/"runtime"),RuntimeMaxSec="604800",
        ExecPaths=f"{RUN} {ALIAS}/jetstreamer-node",ReadWritePaths=str(RUN),
        BindReadOnlyPaths=" ".join(str(src)+":"+str(dst) for dst,src in binds.items()),
        StandardOutput="append:"+str(RUN/"producer.log"),StandardError="append:"+str(RUN/"producer.log"))
    env={**j["environment"],"HORIZON_FULL168_PAYLOAD_SHA256":PAYLOAD_SHA}
    producer=["/usr/bin/systemd-run","--unit="+j["producer_unit"],"--description=guarded-full168-metered",
        *["--property="+k+"="+v for k,v in props.items()],*["--setenv="+k+"="+v for k,v in env.items()],
        "/usr/bin/python3","-IB",str(ALIAS/"gate.py"),*j["regular_node_argv"]]
    need(not any("172-" in x for x in producer if "BindReadOnlyPaths=" not in x),
         "foreign epoch in the producer command")
    return j,producer


def guard(j,generation,floor):
    need(re.fullmatch("[a-f0-9]{32}",generation) and int(generation,16) and floor>=MINIMUM_FLOOR,
         "standalone guard needs the producer's actual invocation and complete protected floor")
    original=verified(TEMPLATE/"GUARD_ARGV.json","485a87012acf96a0523fa931415525b53bce6aec71d6adfb8f93ea3dd0a8e45e")
    plan={"schema":"jetstreamer-horizon-standalone-guard-plan-v1","filesystem":"/home/sol",
        "invocation_id":generation,"maximum_root_physical_bytes":j["whole_root_cap"],
        "maximum_worker_vmas":3500000,"minimum_free_bytes":floor,
        "receipt_directory":str(STATE/"guard-receipts"),"unit":j["producer_unit"],"worker_root":str(TREE)}
    # The normal deployment sealer supplies this exact plan as an immutable file.
    raw=(json.dumps(plan,indent=2,sort_keys=True)+"\n").encode()
    substitutions={str(TEMPLATE):str(STATE),"horizon-guard-172-full-half-core-20261120-v1":j["guard_unit"],
        "horizon-qualify-172-full-half-core-20261120-v1.service":j["producer_unit"]}
    argv=[]
    for value in original:
        for before,after in substitutions.items():
            value=value.replace(before,after)
        argv.append(value)
    argv[argv.index("--plan-sha256")+1]=hashlib.sha256(raw).hexdigest()
    need(argv[-2:]==["--self-sha256","b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"]
         and "--property=MemorySwapMax=0" in argv and "--property=CPUQuota=25%" in argv,"foreign standalone guard")
    return plan,argv


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--invocation")
    p.add_argument("--protected-home-floor",type=int)
    a=p.parse_args()
    j,producer=normal_spec()
    out={"producer_argv":producer,"materialize_under_new_root":str(RUN),"readonly_projections":
        {str(target):str(source) for target,source in projection(j).items()},
        "guard_maximum_whole_tree_bytes":j["whole_root_cap"],"offline_native":complete_offline()}
    if a.invocation or a.protected_home_floor:
        need(a.invocation and a.protected_home_floor,"supply both actual guard fields")
        out["guard_plan"],out["guard_argv"]=guard(j,a.invocation,a.protected_home_floor)
    print(json.dumps(out,indent=2,sort_keys=True))
