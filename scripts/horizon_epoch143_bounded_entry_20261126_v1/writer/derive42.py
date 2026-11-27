"""Project the bounded epoch 170 receiver onto the exact sealed V41 writer."""
import ast
import hashlib
import json
from pathlib import Path
import sys

from derive41 import one

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v41-entry146"
NEW = OLD.replace("v41", "v42")
V41_SEAL = "245dda3f40bc976ff0a293b3256291a351aecc1473528694b00126bf9b1573aa"


def cycle(body):
    body = body.replace(", 41)", ", 41, 42)")
    old = "        if FAILED166_VERSION == 41:\n            import transition_v41\n            import recording140_status\n"
    body = one(body, old, old.replace("== 41", ">= 41") + """        if FAILED166_VERSION == 42:
            import transition_v42
            import successor170_status
""")
    old = "    bridge_prior = bridge170_status.retained_population(c.fleet, c.cfg) if FAILED166_VERSION >= 34 else None"
    body = one(body, old, """    bridge_prior = bridge170_status.retained_population(c.fleet, c.cfg) if FAILED166_VERSION >= 34 else None
    successor_prior = successor170_status.retained_population(c.fleet, c.cfg) if FAILED166_VERSION == 42 else None
    need(not (bridge170_status.active(bridge_prior) and successor_prior),
         'overlapping bridge and successor epoch 170 populations')""")
    body = one(body, "private_successor=bridge_prior)", "private_successor=successor_prior or bridge_prior)")
    body = one(body, "    c.bridge170_prior = bridge_prior", "    c.bridge170_prior = successor_prior or bridge_prior")
    old = "        bridge170_status.project(c, c.bridge170)\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 42:
        c.successor170 = successor170_status.observe(c, successor_prior, cycle.observed_lane)
        if successor170_status.active(c.successor170):
            need(c.bridge170 and not bridge170_status.active(c.bridge170)
                 and '170' not in native_owners and 170 not in c.new_rows and c.stopped170,
                 'private epoch 170 successor overlaps an incumbent owner')
            if c.successor170['phase'] != 'held':
                native_owners = dict(native_owners, successor170=c.successor170)
        successor170_status.project(c, c.successor170)
""")
    for line in [
        "        active140 =",
        "        recording140_status.recheck",
        "        cap[recording140_status.RESERVATION]",
        "        recording140_status.install",
    ]:
        old = "    if FAILED166_VERSION == 41:\n" + line
        body = one(body, old, old.replace("== 41", ">= 41"))
    old = "        bridge170_status.recheck(c.bridge170)\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 42:
        successor170_status.recheck(c.successor170)
""")
    old = "            cap[bridge170_status.FIELD] = c.bridge170\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 42 and c.successor170:
        cap[successor170_status.FIELD] = c.successor170
""")
    old = "        diagnostic_count += int(bridge170_status.active(c.bridge170))\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 42:
        diagnostic_count += int(successor170_status.active(c.successor170))
""")
    old = "        bridge170_status.install(fleet, c.bridge170)\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 42:
        successor170_status.install(fleet, c.successor170)
""")
    old = "            if FAILED166_VERSION == 41:\n                modules += [transition_v41, recording140_status]\n"
    body = one(body, old, old.replace("== 41", ">= 41") + """            if FAILED166_VERSION == 42:
                modules += [transition_v42, successor170_status]
""")
    old = "        cold_workers.full170.historical_diagnostic(fleet, private_successor=prior)"
    body = one(body, old, """        if FAILED166_VERSION == 42:
            prior = successor170_status.retained_population(fleet, sealed(ready['config'])) or prior
""" + old)
    old = "    elif FAILED166_VERSION == 41:\n        transition_v41.validate"
    body = one(body, old, """    elif FAILED166_VERSION == 42:
        transition_v42.validate(globals(), ready, receipt)
""" + old)
    old = "                41: (transition_v41.V40_SHA, transition_v41.V40_SEAL),\n"
    body = one(body, old, old + "                42: (transition_v42.V41_SHA, transition_v42.V41_SEAL),\n")
    old = "                    41: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',\n"
    body = one(body, old, old + old.replace("41:", "42:"))
    old = "    if FAILED166_VERSION == 41 and len(sys.argv) == 4 and sys.argv[1] == '--check-v41-handoff':"
    return one(body, old, """    if FAILED166_VERSION == 42 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v42-handoff':
            print(json.dumps(transition_v42.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-bounded-170':
            writer_ref = bound(ROOT/'FAILED166_CADENCE_V42_ACTIVE.json')
            print(json.dumps(successor170_status.enroll(globals(), head, writer_ref)))
            return
""" + old)


def bridge(body):
    # The newer private row has its own validator. Preserve the bridge row and its terminal proof.
    old = 'assigned = [row for row in cfg["diagnostic_replays"] if row["range"] == "170"]'
    body = one(body, old, old[:-1] + ' and row["producer_unit"] == UNIT]')
    old = 'row["epoch"] == 170]'
    body = one(body, old, 'row["epoch"] == 170 and row["unit"]["Id"] == UNIT]')
    old = 'item["range"] == "170"'
    return body.replace(old, old + ' and item["producer_unit"] == UNIT')


def stage(old, new):
    raw = (old / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != V41_SEAL:
        raise ValueError("different V41 seal")
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
            raise ValueError(f"V41 {name} changed")
        if name == "status_cycle.py":
            data = cycle(data.decode()).encode()
        elif name == "bridge170_status.py":
            data = bridge(data.decode()).encode()
        elif name in ("full170_status.py", "joint168_status.py", "cold170_status.py"):
            data = data.replace(f"'{OLD}')".encode(), f"'{OLD}', '{NEW}')".encode())
        add(name, data, int(member["mode"], 8))
    for name in ("transition_v42.py", "successor170_status.py", "cutover42.py", "cutover41.py"):
        add(name, (HERE / name).read_bytes(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",
                destination=str(Path(receipt["destination"]).with_name(NEW)), members=rows)


if __name__ == "__main__":
    print(json.dumps(stage(*map(Path, sys.argv[1:])), indent=2, sort_keys=True))
