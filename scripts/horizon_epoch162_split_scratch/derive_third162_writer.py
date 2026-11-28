"""Bind the third 162 interval to the existing cadence and preserve its predecessor readers."""
import ast
import hashlib
import json
from pathlib import Path

from third_inputs import BASE, PREVIOUS, PREVIOUS_SHA

HERE = Path(__file__).resolve().parent
WRITER = BASE.parent/"survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v66-entry146"
PROGRESS_SHA = "7be4a82a249a3c5f0e24400b56ec5fee83fde6673cedd8930617fbf6a32fdaea"


def one(src, old, new):
    if src.count(old) != 1:
        raise ValueError("different writer near " + old[:95])
    return src.replace(old,new)


def read(ref, path):
    data = path.read_bytes()
    if path.resolve() != path or ref != dict(path=str(path),sha256=hashlib.sha256(data).hexdigest()):
        raise ValueError("changed exact 162 input "+str(path))
    return data


def cycle(source, version):
    if type(version) is not int or version < 68:
        raise ValueError("the third 162 replay follows the 170 writer enrollment")
    line, = [s for s in source.splitlines() if s.strip() == "import second162_reserved_route as second162_route"]
    indent = line[:len(line)-len(line.lstrip())]
    source = one(source, line, line+"\n"+indent+"reserved162_route = second162_route\n"+indent+f"if FAILED166_VERSION >= {version}:\n"
                 +indent+"    import third162_route as second162_route")
    line, = [s for s in source.splitlines() if "modules += [transition_v62, second162_route," in s]
    indent = line[:len(line)-len(line.lstrip())]
    source = one(source, line, line.replace("second162_route", "reserved162_route")+"\n"+indent+f"if FAILED166_VERSION >= {version}:\n"
                 +indent+"    modules += [second162_route, second162_route.third, second162_route.progress]\n"
                 +indent+"    import third162_bindings\n"+indent+"    modules.append(third162_bindings)")
    ast.parse(source)
    return source


def members(interface):
    info = json.loads(read(interface, BASE/"INTERFACE.json"))
    scope = json.loads(read(info["scope"], BASE/"SCOPE.json"))
    seal = json.loads(read(info["provider"], BASE/"operator-v1/deployment-seal-receipt.json"))
    reader = read(info["reader"], BASE/"operator-v1/status162.py")
    if not (scope["previous"] == info["previous"] == dict(path=str(PREVIOUS),sha256=PREVIOUS_SHA)
            and info["field"] == "current_private162_third_hourly" and info["first_slot"] == 69_998_120 and info["last_slot"] == 70_004_937
            and seal["destination"] == str(BASE/"operator-v1") and any(m["name"] == "status162.py" and m["sha256"] == info["reader"]["sha256"] for m in seal["members"])):
        raise ValueError("different third 162 interface")
    p = WRITER/"second162_reserved_progress.py"
    progress = read(dict(path=str(p), sha256=PROGRESS_SHA),p).decode()
    if progress.count("162-second-replay-20261128-v3") != 2:
        raise ValueError("previous 162 progress source changed")
    progress = progress.replace("162-second-replay-20261128-v3","162-third-replay-20261128-v1")
    progress = one(progress,"69_991_077 <= slot <= 69_998_119","69_998_120 <= slot <= 70_004_937")
    progress = one(progress,"c6049e1161b1a54b2d7193faac077242c24b2f52543e986dfb9c958d47698d72",info["guard"]["sha256"])
    refs = dict(INTERFACE=interface,SCOPE=info["scope"],OPERATOR=info["provider"],READER=info["reader"])
    bindings = "".join(f"{k} = {v!r}\n" for k,v in refs.items())
    return {"third162_route.py":(HERE/"third162_route.py").read_bytes(), "third162_status.py":reader,
            "third162_provider.json":(json.dumps(info["provider"],sort_keys=True)+"\n").encode(),
            "third162_progress.py":progress.encode(), "third162_bindings.py":bindings.encode()}
