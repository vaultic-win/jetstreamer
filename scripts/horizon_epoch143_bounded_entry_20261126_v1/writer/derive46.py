"""Derive the joint 143 and 170 writer package from the exact active V45 seal."""

import ast
import hashlib
import json
from pathlib import Path
import sys

from derive41 import one

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v45-entry146"
NEW = OLD.replace("v45", "v46") + "-r2"
PREVIOUS_SEAL = "237ff74a47d9d3fce22399ea81ff268aa50b6ed09daa3a03bf102a228f09e0bb"


def cycle(text):
    text = text.replace(", 45)", ", 45, 46)")
    old = "    if version == 42:"
    text = one(text, old, '    if version == 46:\n        return name + "-entry146-r2"\n' + old)
    old = "            import rolling170_status as successor170_status"
    text = one(text, old, old + """
            import transition_v46
        if FAILED166_VERSION == 46:
            import rolling170_retry_status as successor170_status""")
    old = "                            import_module('continuation170_contract')]"
    text = one(text, old, old + """
            if FAILED166_VERSION == 46:
                modules += [transition_v46, successor170_status.retry, successor170_status.contract,
                            successor170_status.history, successor170_status.history.previous,
                            successor170_status.history.following, import_module('continuation170_contract')]""")
    old = "    elif FAILED166_VERSION == 45:"
    text = one(text, old, """    elif FAILED166_VERSION == 46:
        transition_v46.validate(globals(), ready, receipt)
""" + old)
    old = "                45: (transition_v45.V44_SHA, transition_v45.V44_SEAL),"
    text = one(text, old, old + "\n                46: (transition_v46.V45_SHA, transition_v46.V45_SEAL),")
    # The dispatch table evaluates every tuple even when the new version takes one branch.
    text = one(text, "        if FAILED166_VERSION == 45:\n            import transition_v45",
               "        if FAILED166_VERSION >= 45:\n            import transition_v45")
    old = "                    45: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    text = one(text, old, old + "\n" + old.replace("45:", "46:"))
    old = "    if FAILED166_VERSION == 45 and len(sys.argv) == 4:"
    return one(text, old, """    if FAILED166_VERSION == 46 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v46-handoff':
            print(json.dumps(transition_v46.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-next-bounded-170':
            os.umask(0o077)
            writer_ref = bound(ROOT/'FAILED166_CADENCE_V46_ACTIVE.json')
            print(json.dumps(successor170_status.enroll(globals(), head, writer_ref)))
            return
""" + old)


def tail167(text):
    start = text.index('    samples = sorted((ROOT/"guard-receipts")')
    end = text.index('    return dict(plan=first["plan"]', start)
    witness = one(text[start:end],
                  'walked[key]["vanished_entries"] == 0 and 0 < walked[key]["physical_bytes"] <= cap',
                  '0 < walked[key]["physical_bytes"] <= cap')
    return (text[:start] + '    deadline = time.monotonic() + 40\n    while True:\n'
            + ''.join('    ' + line if line.strip() else line for line in witness.splitlines(keepends=True))
            + '        if all(walked[key]["vanished_entries"] == 0 for key in ("first", "second")):\n            break\n        need(time.monotonic() < deadline, "bounded 167 guard still saw entries vanish")\n        time.sleep(2)\n' + text[end:])


def stage(old, staging):
    raw = (old / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != PREVIOUS_SEAL:
        raise ValueError("different V45 deployment")
    seal = json.loads(raw)
    staging.mkdir(mode=0o700)
    members = []

    def add(name, data, mode):
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = staging / name
        path.write_bytes(data)
        path.chmod(mode)
        members.append(dict(name=name, source=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=mode))

    native = None
    for row in seal["members"]:
        name = row["name"]
        if name == "SHA256SUMS":
            continue
        data = (old / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("changed V45 member " + name)
        if name == "status_cycle.py":
            data = cycle(data.decode()).encode()
        if name in {"full170_status.py", "cold170_status.py", "joint168_status.py"}:
            data = data.replace(f"'{OLD}')".encode(), f"'{OLD}', '{NEW}')".encode())
        if name == "tail167_status.py":
            data = tail167(data.decode()).encode()
        if name == "continuation170_native.py":
            native = one(data.decode(), "from continuation170_contract import ",
                         "from continuation170_retry_contract import ").encode()
        add(name, data, int(row["mode"], 8))
    add("continuation170_retry_native.py", native, 0o444)
    for name in ("continuation170_retry_contract.py", "rolling170_retry_status.py", "transition_v46.py", "cutover46.py"):
        add(name, (HERE / name).read_bytes(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",
                destination=str(Path(seal["destination"]).with_name(NEW)), members=members)


if __name__ == "__main__":
    print(json.dumps(stage(*map(Path, sys.argv[1:])), indent=2))
