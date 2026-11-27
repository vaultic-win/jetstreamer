"""Preserve the failed 170 attempt and adopt its exact next private state."""

import ast
import hashlib
import json
from pathlib import Path
import sys

from derive41 import one

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v43-entry146"
NEW = OLD.replace("v43", "v44")
V43_SEAL = "5191b1fde1164f4da59fc09906c52b62be90668ec6564f0d0d260dcd73b91cd7"


def cycle(body):
    body = body.replace(", 43)", ", 43, 44)")
    old = """        if FAILED166_VERSION == 43:
            import transition_v43
            import first_hourly143
            import hourly_population
"""
    body = one(body, old, old.replace("== 43", ">= 43") + """        if FAILED166_VERSION == 44:
            import transition_v44
""")
    old = """            if FAILED166_VERSION == 43:
                modules += [transition_v43, first_hourly143, hourly_population]
"""
    body = one(body, old, old.replace("== 43", ">= 43") + """            if FAILED166_VERSION == 44:
                modules.append(transition_v44)
""")
    for start in (
        "        c.first_hourly = hourly_population.census(c)",
        "        hourly_population.recheck_all(c.first_hourly)",
        "        cap[hourly_population.CAPACITY_FIELD]",
        "        diagnostic_count += sum(hourly_population.active",
        "        hourly_population.install(fleet, c.first_hourly)",
    ):
        lines = body.splitlines(keepends=True)
        index, = (index for index, line in enumerate(lines) if line.startswith(start))
        if lines[index - 1] != "    if FAILED166_VERSION == 43:\n":
            raise ValueError(f"missing first-hourly version at {start}")
        lines[index - 1] = "    if FAILED166_VERSION >= 43:\n"
        body = "".join(lines)
    old = "    elif FAILED166_VERSION == 43:\n        transition_v43.validate"
    body = one(body, old, """    elif FAILED166_VERSION == 44:
        transition_v44.validate(globals(), ready, receipt)
""" + old)
    old = "                43: (transition_v43.V42_SHA, transition_v43.V42_SEAL),\n"
    body = one(body, old, old + "                44: (transition_v44.V43_SHA, transition_v44.V43_SEAL),\n")
    old = "                    43: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',\n"
    body = one(body, old, old + old.replace("43:", "44:"))
    old = "    if FAILED166_VERSION == 43 and len(sys.argv) == 4 and sys.argv[1] == '--check-v43-handoff':"
    return one(body, old, """    if FAILED166_VERSION == 44 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v44-handoff':
            print(json.dumps(transition_v44.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-bounded-170':
            writer_ref = bound(ROOT/'FAILED166_CADENCE_V44_ACTIVE.json')
            print(json.dumps(successor170_status.enroll(globals(), head, writer_ref)))
            return
""" + old)


def retry(body):
    old = 'ROOT = BASE / "epoch170-from-73726716-20261127-v1"'
    body = one(body, old, old + '\nROOT = ROOT / "attempt-2"')
    old = "30ba2b754885f8ba7cf9abc04d9453bb1b8a030b0534b31d1801543ea8c4906a"
    body = one(body, old, "b1977d6a8b65b654349b98a66748b77439b3539869bf1f4e758d2d76ea0851d3")
    old = '    return scope\n'
    body = one(body, old, """    failure = checked(scope["failed_predecessor"])
    preflight = checked(scope["private_state_native_preflight"])
    need(scope["attempt"] == 2 and failure["guard_drained"] is True
         and failure["node_exited_before_worker"] is True and bool(preflight),
         "retry lacks its original failure and native state qualification")
    return scope
""")
    old = '    if prior is None:\n        need(not assigned and not rows, "unregistered bounded epoch 170 fleet row")'
    body = one(body, old, """    if prior and prior["interface"] != INTERFACE:
        scope = interface()
        predecessor = checked(scope["failed_predecessor"])
        need(prior["interface"] == scope["original_interface"] and prior["phase"] == "terminal"
             and prior["actor_ref"] == predecessor["actor"] and prior["release"] == predecessor["release"]
             and not assigned and not rows, "retry overlaps a different 170 predecessor")
        return None
""" + old)
    old = '    if not ACTOR.exists():\n        need(prior is None and not RELEASE.exists(), "bounded epoch 170 actor evidence disappeared")\n        native.idle(UNIT)\n        return None'
    body = one(body, old, """    if not ACTOR.exists():
        need(prior is None and not RELEASE.exists(), "bounded epoch 170 actor evidence disappeared")
        native.idle(UNIT)
        scope = interface()
        predecessor = checked(scope["failed_predecessor"])
        need(manager["InvocationID"] in ("", predecessor["exit"]["InvocationID"]),
             "empty retry overlaps a different failed 170 invocation")
        return None""")
    old = "def install(fleet, row):\n"
    return one(body, old, old + '    fleet["retained_170_failed_successor"] = interface()["failed_predecessor"]\n')


def cutover(body):
    body = one(body, 'OLD = BASE / "tools-cold168-retry5-failed166-v42-entry146-r3"',
               f'OLD = BASE / "{OLD}"')
    body = one(body, f'NEW = BASE / "{OLD}"', f'NEW = BASE / "{NEW}"')
    body = body.replace("V43", "V44").replace("--check-v43-handoff", "--check-v44-handoff")
    body = one(body, "-v42-r3-entry146.conf", "-v43-entry146.conf")
    body = one(body, 'replace("-v42-r3-", "-v43-")', 'replace("-v43-", "-v44-")')
    body = one(body, 'need(protected_successor(live[SUCCESSOR], RELEASE.read_bytes())',
               'need(live[SUCCESSOR]["ActiveState"] == "failed"\n'
               '             and protected_successor(live[SUCCESSOR], RELEASE.read_bytes())')
    return body.replace("unexpected V42 service definition", "unexpected V43 service definition").replace(
        "V42 is no longer the current writer", "V43 is no longer the current writer").replace(
        "V42 did not release the writer service", "V43 did not release the writer service")


def stage(old, new):
    raw = (old / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != V43_SEAL:
        raise ValueError("different V43 seal")
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
            raise ValueError(f"V43 {name} changed")
        if name == "status_cycle.py":
            data = cycle(data.decode()).encode()
        elif name == "successor170_status.py":
            data = retry(data.decode()).encode()
        elif name in ("full170_status.py", "joint168_status.py", "cold170_status.py"):
            data = data.replace(f"'{OLD}')".encode(), f"'{OLD}', '{NEW}')".encode())
        add(name, data, int(member["mode"], 8))
    add("transition_v44.py", (HERE / "transition_v44.py").read_bytes(), 0o444)
    add("cutover44.py", cutover((old / "cutover43.py").read_text()).encode(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",
                destination=str(Path(receipt["destination"]).with_name(NEW)), members=rows)


if __name__ == "__main__":
    print(json.dumps(stage(*map(Path, sys.argv[1:])), indent=2, sort_keys=True))
