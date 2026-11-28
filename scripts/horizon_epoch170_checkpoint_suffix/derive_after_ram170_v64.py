"""Prepare V64 from the exact deployed V63 presenter, receiver and cadence."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import re

import derive_after_ram170_writer as receiver
from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
RT = receiver.ROOT.parent
WRITERS = RT/"survivor172-cadence-20261122-v1"
OLD = WRITERS/"tools-cold168-retry5-failed166-v63-entry146"
NEW = OLD.with_name(OLD.name.replace("v63","v64"))
OLD_OWNER = "426de90d6f3a62d83c08b95e682cf55566744992b984259ec989726d815f4a08"
OLD_SEAL = "18c6d258eca8596d2ae90729314b21dfc6413a22b9ddb2ea9a28deb3ca5ae101"
AFTER_SEAL = "9d2fffc08e26af3a84e8fda30cf8e1d72fe29b905ef5b9fddc5f9cd7590c8ac2"


def cycle(source):
    ordinary, commands = source.split("def main():",1)
    old_validator = "    elif FAILED166_VERSION == 63:\n        transition_v63.validate(globals(), ready, receipt)"
    ordinary = once(ordinary,old_validator,"EXISTING_V63_VALIDATOR")
    ordinary = ordinary.replace(", 63)",", 63, 64)").replace("FAILED166_VERSION == 63","FAILED166_VERSION in (63, 64)")
    ordinary = once(ordinary,"EXISTING_V63_VALIDATOR",old_validator.replace("63","64")+"\n"+old_validator)
    for anchor, tail in (
        ("                                    import transition_v63", "                                    if FAILED166_VERSION == 64:\n                                        import transition_v64"),
        ("                                                                modules += [second_hourly143, second_hourly143_scope, transition_v63]",
         "                                                                if FAILED166_VERSION == 64:\n                                                                    modules += [transition_v64]"),
        ("                63: (transition_v63.V62_SHA, transition_v63.V62_SEAL),",
         "                64: (transition_v64.V63_SHA, transition_v64.V63_SEAL),"),
        ("                    63: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "                    64: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        ordinary = once(ordinary,anchor,anchor+"\n"+tail)
    lines = commands.splitlines(keepends=True)
    starts = [i for i,line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 63 and len(sys.argv) == 4")]
    if len(starts) != 5:
        raise ValueError("different V63 control commands")
    for start in reversed(starts):
        end = next(i for i in range(start+1,len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        lines.insert(start,"".join(lines[start:end]).replace("== 63","== 64").replace("V63","V64").replace("v63","v64"))
    return receiver.cycle(ordinary+"def main():"+"".join(lines),64)


def plan(stage):
    members = {}
    def include(path,name,digest,mode):
        if path.resolve(strict=True) != path or sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("changed source file " + str(path))
        members[name] = dict(name=name,source=str(path),sha256=digest,mode=mode)
    def package(directory,digest):
        path = directory/"deployment-seal-receipt.json"
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != digest:
            raise ValueError("different package " + str(directory))
        manifest = json.loads(raw)
        if manifest["destination"] != str(directory):
            raise ValueError("different package directory")
        for item in manifest["members"]:
            name = item["name"]
            if directory/name != directory/Path(name).name or name in members:
                raise ValueError("duplicate or indirect package member")
            if name != "SHA256SUMS":
                include(directory/name,name,item["sha256"],int(item["mode"],8))
    package(OLD,OLD_SEAL)
    package(receiver.ROOT/"after-ram-observer-v1",AFTER_SEAL)
    stage.mkdir(mode=0o700)
    def add(name,source):
        ast.parse(source,filename=name)
        path=stage/name
        path.write_text(source)
        include(path,name,sha256(source.encode()).hexdigest(),0o444)
    add("status_cycle.py",cycle((OLD/"status_cycle.py").read_text()))
    add("transition_v64.py",(HERE/"after_ram170_transition.py").read_text())
    cutover = re.sub(r"(cutover|[vV])(62|63)",lambda m:m[1]+str(int(m[2])+1),(OLD/"cutover63.py").read_text())
    cutover = once(cutover,"7901076dbe284118014b0d37483368fc5c8b50bc340c8bc181cc33a9f4dcaf99",OLD_SEAL)
    cutover = once(cutover,"be7681e7d92c6617147239e3e534ab008341599e198c1183cbe4f007802fc3cb",OLD_OWNER)
    add("cutover64.py",cutover)
    for name,count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        text=(OLD/name).read_text()
        marker=repr(OLD.name)+")"
        if text.count(marker)!=count:
            raise ValueError("different qualified package set in " + name)
        add(name,text.replace(marker,repr(OLD.name)+", "+repr(NEW.name)+")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(NEW),members=list(members.values()))
