"""Project the narrow epoch 140 reader onto the sealed V40 writer."""
import ast
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v40-entry146"
NEW = OLD.replace("v40", "v41")
V40_SEAL = "eb9c4380a8aad5d44a21b91c0feca8d9475d31c1fea4a201cb3bac75b143ccb7"


def one(body, old, new):
    if body.count(old) != 1:
        raise ValueError(f"unexpected V40 text at {old.strip().splitlines()[0]}")
    return body.replace(old, new)


def cycle(body):
    body = body.replace(", 40)", ", 40, 41)")
    old = "        if FAILED166_VERSION == 40:\n            import transition_v40\n"
    body = one(body, old, old.replace("== 40", ">= 40") + "        if FAILED166_VERSION == 41:\n"
               "            import transition_v41\n            import recording140_status\n")
    old = "    if getattr(cold_workers, 'cold168', None):\n        cold_workers.cold168.census"
    body = one(body, old, """    if FAILED166_VERSION == 41:
        active140 = bound(ROOT/'FAILED166_CADENCE_V41_ACTIVE.json')
        c.recording140 = recording140_status.observe(c, active140)
        if recording140_status.active(c.recording140):
            native_owners = dict(native_owners, recording140=c.recording140)
""" + old)
    old = "    if held170:\n        from full170_status import native\n"
    body = one(body, old, "    if FAILED166_VERSION == 41:\n"
               "        recording140_status.recheck(c.recording140)\n" + old)
    old = "    cap['historical_prior_owner_observations']="
    body = one(body, old, "    if FAILED166_VERSION == 41:\n"
               "        cap[recording140_status.RESERVATION] = c.recording140 and c.recording140['reservation']\n" + old)
    old = "        prefix162_status.install(fleet, c.first162)\n"
    body = one(body, old, old + "    if FAILED166_VERSION == 41:\n"
               "        recording140_status.install(fleet, c.recording140)\n")
    old = "            if FAILED166_VERSION == 40:\n                modules.append(transition_v40)\n"
    body = one(body, old, old.replace("== 40", ">= 40") + "            if FAILED166_VERSION == 41:\n"
               "                modules += [transition_v41, recording140_status]\n")
    old = "    elif FAILED166_VERSION == 40:\n        transition_v40.validate"
    body = one(body, old, "    elif FAILED166_VERSION == 41:\n"
               "        transition_v41.validate(globals(), ready, receipt)\n" + old)
    old = "                40: (transition_v40.V39_SHA, transition_v40.V39_SEAL),\n"
    body = one(body, old, old + "                41: (transition_v41.V40_SHA, transition_v41.V40_SEAL),\n")
    old = "                    40: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',\n"
    body = one(body, old, old + old.replace("40:", "41:"))
    old = "    if FAILED166_VERSION == 40 and len(sys.argv) == 4 and sys.argv[1] == '--check-v40-handoff':"
    return one(body, old, """    if FAILED166_VERSION == 41 and len(sys.argv) == 4 and sys.argv[1] == '--check-v41-handoff':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        print(json.dumps(transition_v41.ready(globals(), head, receipt)))
        return
""" + old)


def stage(old, new):
    raw = (old / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != V40_SEAL:
        raise ValueError("different V40 seal")
    receipt = json.loads(raw)
    new.mkdir(mode=0o700)
    rows = []

    def add(name, data, mode):
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = new / name
        path.write_bytes(data)
        path.chmod(mode)
        rows.append(dict(name=name, source=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=mode))

    for member in receipt["members"]:
        name = member["name"]
        if name == "SHA256SUMS":
            continue
        data = (old / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError(f"V40 {name} changed")
        if name == "status_cycle.py":
            data = cycle(data.decode()).encode()
        elif name in ("full170_status.py", "joint168_status.py", "cold170_status.py"):
            data = data.replace(f"'{OLD}')".encode(), f"'{OLD}', '{NEW}')".encode())
        add(name, data, int(member["mode"], 8))
    for name in ("transition_v41.py", "recording140_status.py"):
        add(name, (HERE / name).read_bytes(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",
                destination=str(Path(receipt["destination"]).with_name(NEW)), members=rows)


if __name__ == "__main__":
    print(json.dumps(stage(*map(Path, sys.argv[1:])), indent=2, sort_keys=True))
