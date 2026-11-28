"""Derive and preflight V72 from V71. Activation belongs to the existing writer owner."""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import compact_adjacent_operator as c
import compact_adjacent_writer as w
WRITER=HERE.parent/"horizon_epoch143_bounded_entry_20261126_v1/writer"
sys.path.insert(0,str(WRITER))
from derive143_bootstrap_retry import read_package
from derive69 import following_block

a=c.a
ROOT=a.RT/"survivor172-cadence-20261122-v1"
OLD=ROOT/"tools-cold168-retry5-failed166-v71-entry146"
NEW=OLD.with_name("tools-cold168-retry5-failed166-v72-entry146")
PIN="0c48be5c716513e7de5eb41b61894a39bcffb576cf90f1433443a91dff5ef809"
ACTIVE="1d9087ae207f193876a0d3e289141e0b21852a9e9b6012344fe4d0871970b463"
one=c.one


def cycle(source):
    normal,commands=source.split("def main():",1)
    normal=normal.replace(", 70, 71)",", 70, 71, 72)")
    for line in normal.splitlines():
        if line.strip().startswith(("71: (transition_v71.","71: 'fb9db4e77")):
            addition=line.replace("71:","72:",1).replace("transition_v71.V70","transition_v72.V71")
            normal=one(normal,line,line+"\n"+addition)
    normal=following_block(normal,"import transition_v71",["if FAILED166_VERSION >= 72:","    import transition_v72"])
    entry="modules.extend([ram_retry143, ram_retry143_scope, held143_ram_terminal, transition_v71])"
    normal=following_block(normal,entry,["if FAILED166_VERSION >= 72:","    modules.append(transition_v72)"])
    anchor="    elif FAILED166_VERSION == 71:\n        transition_v71.validate(globals(), ready, receipt)"
    normal=one(normal,anchor,anchor.replace("71","72")+"\n"+anchor)
    blocks=list(re.finditer(r"^    if FAILED166_VERSION == 71 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+",commands,re.M))
    a.need(len(blocks)==5,"different V71 command boundary")
    for b in reversed(blocks):
        addition=b[0].replace("== 71","== 72").replace("v71","v72").replace("V71","V72")
        commands=commands[:b.start()]+addition+commands[b.start():]
    return normal+"def main():"+commands


def cutover(text):
    text=re.sub(r"(cutover|[vV])(70|71)",lambda m:m[1]+str(int(m[2])+1),text)
    text=one(text,'ORIGINAL_SEAL = "838bfc4a45f355e086bc85f2188d6ee8baf12c5b444a5522d7afd43db59ad987"',f'ORIGINAL_SEAL = "{PIN}"')
    return one(text,'OLD_OWNER = "6aef2af6a4c8332e9af577ee55fa27bf44f88cfe39d9d67a32d4056faf008c3f"',f'OLD_OWNER = "{ACTIVE}"')


def files():
    old=read_package(OLD,PIN)
    old.pop("SHA256SUMS",None)
    changes=w.members()
    changes.update({"transition_v72.py":(HERE/"transition_v72.py").read_bytes(),
                    "status_cycle.py":cycle(old["status_cycle.py"][0].decode()).encode(),
                    "cutover72.py":cutover(old["cutover71.py"][0].decode()).encode()})
    for name,count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        data=old[name][0].decode()
        ending=repr(OLD.name)+")"
        a.need(data.count(ending)==count,"different source of "+name)
        changes[name]=data.replace(ending,repr(OLD.name)+", "+repr(NEW.name)+")").encode()
    for n,data in changes.items():
        if n.endswith(".py"):
            ast.parse(data,filename=n)
        elif n.endswith(".json"):
            json.loads(data)
    return old,changes


def stage(revision):
    c.published(revision,[Path(__file__).resolve(),HERE/"transition_v72.py",HERE/"compact_adjacent_writer.py",
        HERE/"compact_adjacent_operator.py",WRITER/"derive143_bootstrap_retry.py",WRITER/"derive69.py"])
    old,changes=files()
    _,l=c.original()
    save=l["save"]
    stage=a.BASE/"writer-v72-source"
    stage.mkdir(mode=0o700,exist_ok=True)
    a.need(stage.resolve()==stage and stage.stat().st_uid==0 and not stage.stat().st_mode & 0o077,"wrong writer staging")
    members={n:(OLD/n,mode) for n,(_,mode) in old.items()}
    for n,body in changes.items():
        if n in old and body==old[n][0]:
            continue
        save(stage/n,body)
        members[n]=stage/n,0o444
    a.shared.BASE=a.BASE
    return a.shared.seal(members,NEW,save)


def preflight():
    seal=a.reference(NEW/"deployment-seal-receipt.json")
    fleet=a.reference(max(a.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns))
    args=["/usr/bin/python3","-IB",str(NEW/"status_cycle.py"),"--check-v72-handoff",fleet["path"],fleet["sha256"]]
    result=json.loads(subprocess.check_output(args))
    a.need(result["package"]==seal and result["fleet"]==fleet and result["adjacent169_interface"]==w.INTERFACE
           and result["old_owner"]["sha256"]==ACTIVE,"different V72 handoff")
    _,l=c.original()
    return l["save"](a.BASE/("PENDING_V72_"+fleet["sha256"][:10]+".json"),result,0o400)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seal")
    p.add_argument("--preflight",action="store_true")
    args=p.parse_args()
    if args.seal:
        print(json.dumps(stage(args.seal)))
    elif args.preflight:
        print(json.dumps(preflight()))
    else:
        original,changes=files()
        print(json.dumps([k for k,v in changes.items() if k not in original or v!=original[k][0]]))
