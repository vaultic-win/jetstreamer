"""Extend the running V67 package with the independently sealed third 162 operator."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import derive_third162_writer as third

ROOT=third.WRITER.parent
OLD=ROOT/"tools-cold168-retry5-failed166-v67-entry146"
NEW=ROOT/"tools-cold168-retry5-failed166-v68-entry146"
SEAL="44451395c11f4de72d6768818e58bd00ac298191746e5167516a375cf24eb3b5"
ACTIVE="4748bd09457b12e876763e012bb67371142bc1194349df7def25301ef5967c83"
INTERFACE=dict(path=str(third.BASE/"INTERFACE.json"),sha256="0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3")


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 67)",", 67, 68)")
    for line in ordinary.splitlines():
        if line.strip().startswith(("67: (transition_v67.", "67: 'fb9db4e77")):
            ordinary=third.one(ordinary,line,line+"\n"+line.replace("67:","68:",1).replace("transition_v67.V66","transition_v68.V67"))
    for anchor, addition in (("import forecast166","import transition_v68"),
                             ("modules += [transition_v67, forecast166]","modules.append(transition_v68)")):
        line, = [v for v in ordinary.splitlines() if v.strip()==anchor]
        indent=line[:len(line)-len(line.lstrip())]
        ordinary=third.one(ordinary,line,line+"\n"+indent+"if FAILED166_VERSION >= 68:\n"+indent+"    "+addition)
    old="    elif FAILED166_VERSION == 67:\n        transition_v67.validate(globals(), ready, receipt)"
    ordinary=third.one(ordinary,old,old.replace("== 67","== 68").replace("v67.validate","v68.validate")+"\n"+old)
    blocks=list(re.finditer(r"^    if FAILED166_VERSION == 67 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+",commands,re.M))
    if len(blocks)!=5:raise ValueError("unexpected V67 handoff commands")
    for m in reversed(blocks):
        nxt=m[0].replace("== 67","== 68").replace("v67","v68").replace("V67","V68")
        commands=commands[:m.start()]+nxt+commands[m.start():]
    return third.cycle(ordinary+"def main():"+commands,68)


def stage(folder):
    pkg=(OLD/"deployment-seal-receipt.json").read_bytes()
    if sha256(pkg).hexdigest()!=SEAL or json.loads(pkg)["destination"]!=str(OLD):
        raise ValueError("different V67 package")
    folder.mkdir(mode=0o700)
    members={}
    for row in json.loads(pkg)["members"]:
        name=row["name"]; p=OLD/name
        if p.parent!=OLD or name in members or p.resolve()!=p or sha256(p.read_bytes()).hexdigest()!=row["sha256"]:
            raise ValueError("changed V67 member "+name)
        if name!="SHA256SUMS":
            members[name]=dict(name=name,source=str(p),sha256=row["sha256"],mode=int(row["mode"],8))

    def add(name,raw):
        if name.endswith(".py"):ast.parse(raw,filename=name)
        else:json.loads(raw)
        p=folder/name
        p.write_bytes(raw)
        p.chmod(0o444)
        members[name]=dict(name=name,source=str(p),sha256=sha256(raw).hexdigest(),mode=0o444)

    add("status_cycle.py",cycle((OLD/"status_cycle.py").read_text()).encode())
    for name,raw in third.members(INTERFACE).items():add(name,raw)
    add("transition_v68.py",(HERE/"transition_v68.py").read_bytes())
    cutover=(OLD/"cutover67.py").read_text()
    cutover=re.sub(r"(cutover|[vV])(66|67)",lambda m:m[1]+str(int(m[2])+1),cutover)
    cutover=cutover.replace("05a0b11ac5eb14c53aa0bd0773479b9c4d76e616d9e6c03d8508f2b3311171cb",SEAL)
    cutover=cutover.replace("b4d26a441e41758d31cb797d746d608b27ecda582126cf58fb5cceac67815dd7",ACTIVE)
    add("cutover68.py",cutover.encode())
    for name,count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        raw=(OLD/name).read_text()
        needle=repr(OLD.name)+")"
        if raw.count(needle)!=count:raise ValueError("different reader root list in "+name)
        add(name,raw.replace(needle,repr(OLD.name)+", "+repr(NEW.name)+")").encode())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(NEW),members=list(members.values()))


if __name__=="__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()),indent=2))
