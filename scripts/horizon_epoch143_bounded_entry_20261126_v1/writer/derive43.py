"""Bind the 141 and 143 hourly reader to the sealed V42 writer."""

import ast
import hashlib
import json
from pathlib import Path
import sys

from derive41 import one

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v42-entry146-r3"
NEW = "tools-cold168-retry5-failed166-v43-entry146"
V42_SEAL = "7400a14e6af29e19f9880afdc9976da4528cd607d1d77da54cd48be76b47e0db"


def cycle(body):
    body = body.replace(", 42)", ", 42, 43)")
    old = "        if FAILED166_VERSION == 42:\n            import transition_v42\n            import successor170_status\n"
    body = one(body, old, old.replace("== 42", ">= 42") + """        if FAILED166_VERSION == 43:
            import transition_v43
            import first_hourly143
            import hourly_population
""")
    for line in [
        "    successor_prior =",
        "        c.successor170 =",
        "        successor170_status.recheck",
        "        cap[successor170_status.FIELD]",
        "        diagnostic_count += int(successor170_status.active",
        "        successor170_status.install",
        "                modules += [transition_v42, successor170_status]",
        "            prior = successor170_status.retained_population",
    ]:
        lines = body.splitlines(keepends=True)
        index, = (index for index, value in enumerate(lines) if value.startswith(line))
        clause = index if "== 42" in lines[index] else index - 1
        if "== 42" not in lines[clause]:
            raise ValueError(f"missing successor version gate at {line}")
        lines[clause] = lines[clause].replace("== 42", ">= 42")
        body = "".join(lines)
    old = "    if getattr(cold_workers, 'cold168', None):\n        cold_workers.cold168.census"
    body = one(body, old, """    if FAILED166_VERSION == 43:
        c.first_hourly = hourly_population.census(c)
        for profile, row in c.first_hourly:
            if hourly_population.active(row) and row['phase'] != 'held':
                need(str(profile.epoch) not in native_owners and profile.epoch not in c.new_rows,
                     'first-hourly replay overlaps an incumbent owner')
                native_owners = dict(native_owners, **{f'hourly{profile.epoch}': row})
        hourly_population.project_all(c, c.first_hourly)
""" + old)
    old = "        successor170_status.recheck(c.successor170)\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 43:
        hourly_population.recheck_all(c.first_hourly)
""")
    old = "        cap[successor170_status.FIELD] = c.successor170\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 43:
        cap[hourly_population.CAPACITY_FIELD] = hourly_population.capacity(c.first_hourly)
""")
    old = "        diagnostic_count += int(successor170_status.active(c.successor170))\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 43:
        diagnostic_count += sum(hourly_population.active(row) for _, row in c.first_hourly)
""")
    old = "        successor170_status.install(fleet, c.successor170)\n"
    body = one(body, old, old + """    if FAILED166_VERSION == 43:
        hourly_population.install(fleet, c.first_hourly)
""")
    old = "                modules += [transition_v42, successor170_status]\n"
    body = one(body, old, old + """            if FAILED166_VERSION == 43:
                modules += [transition_v43, first_hourly143, hourly_population]
""")
    old = "    elif FAILED166_VERSION == 42:\n        transition_v42.validate"
    body = one(body, old, """    elif FAILED166_VERSION == 43:
        transition_v43.validate(globals(), ready, receipt)
""" + old)
    old = "                42: (transition_v42.V41_SHA, transition_v42.V41_SEAL),\n"
    body = one(body, old, old + "                43: (transition_v43.V42_SHA, transition_v43.V42_SEAL),\n")
    old = "                    42: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',\n"
    body = one(body, old, old + old.replace("42:", "43:"))
    old = "    if FAILED166_VERSION == 42 and len(sys.argv) == 4:"
    return one(body, old, """    if FAILED166_VERSION == 43 and len(sys.argv) == 4 and sys.argv[1] == '--check-v43-handoff':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        print(json.dumps(transition_v43.ready(globals(), head, receipt)))
        return
""" + old)


def stage(old, new):
    raw = (old / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != V42_SEAL:
        raise ValueError("different V42 seal")
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
            raise ValueError(f"V42 {name} changed")
        if name == "status_cycle.py":
            data = cycle(data.decode()).encode()
        elif name == "successor170_status.py":
            data = (HERE / name).read_bytes()
        elif name in ("full170_status.py", "joint168_status.py", "cold170_status.py"):
            data = data.replace(f"'{OLD}')".encode(), f"'{OLD}', '{NEW}')".encode())
        add(name, data, int(member["mode"], 8))
    for name in ("transition_v43.py", "hourly_population.py", "cutover43.py"):
        add(name, (HERE / name).read_bytes(), 0o444)
    add("first_hourly143.py", (HERE.parent / "cadence/first_hourly143.py").read_bytes(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",
                destination=str(Path(receipt["destination"]).with_name(NEW)), members=rows)


if __name__ == "__main__":
    print(json.dumps(stage(*map(Path, sys.argv[1:])), indent=2, sort_keys=True))
