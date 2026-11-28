"""Stage the V33 observer from the verified, immutable V32 deployment."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
V32_SEAL = "a6399f6c67ae2c5e70e98ebfeea9c79955b0e91bdc134db2795f8eb0c99035f0"
OLD = "tools-cold168-retry5-failed166-v32-entry146"
NEW = "tools-cold168-retry5-failed166-v33-entry146"


def change(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"unexpected V32 baseline near {old.strip().splitlines()[0]}")
    return text.replace(old, new)


def status_cycle(text):
    text = re.sub(r", 32\)", ", 32, 33)", text)
    text = text.replace("FAILED166_VERSION == 32", "FAILED166_VERSION >= 32")
    text = change(text, "    import transition as v32_transition",
                  "    import transition as v32_transition\n\nif FAILED166_VERSION == 33:\n    import transition_v33")
    text = change(text, "        for module in (bounded167_status, bounded167_status.route, v32_transition):",
                  """        modules = [bounded167_status, bounded167_status.route, v32_transition]
        if FAILED166_VERSION == 33:
            import bounded167_operator
            modules += [bounded167_operator, transition_v33]
        for module in modules:""")
    text = change(text, "    elif FAILED166_VERSION >= 32:\n        v32_transition.validate",
                  "    elif FAILED166_VERSION == 33:\n        transition_v33.validate(globals(), ready, receipt)\n"
                  "    elif FAILED166_VERSION == 32:\n        v32_transition.validate")
    text = change(text, "                32: (v32_transition.V31_SHA, v32_transition.V31_SEAL_SHA),",
                  "                33: (transition_v33.V32_SHA, transition_v33.V32_SEAL_SHA),\n"
                  "                32: (v32_transition.V31_SHA, v32_transition.V31_SEAL_SHA),")
    predecessor = "                    32: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    text = change(text, predecessor, predecessor.replace("32:", "33:")+"\n"+predecessor)
    return change(text, "    if FAILED166_VERSION >= 32 and len(sys.argv) == 4 and sys.argv[1] == '--check-v32-handoff':",
                  """    if FAILED166_VERSION == 33 and len(sys.argv) == 4 and sys.argv[1] == '--check-v33-handoff':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        print(json.dumps(transition_v33.ready(globals(), head, receipt)))
        return
    if FAILED166_VERSION == 32 and len(sys.argv) == 4 and sys.argv[1] == '--check-v32-handoff':""")


def bounded_status(text):
    start = text.index("def launched_intent(reference):")
    end = text.index("def assigned(cfg):", start)
    text = text[:start] + text[end:]
    text = change(text, "from importlib import util\n", "")
    return change(text, "import bounded167_admission as route",
                  "import bounded167_admission as route\nfrom bounded167_operator import OPERATOR_SEAL, launched_intent, operator_image")


def joint_status(text):
    text = change(text, f"'{OLD}')", f"'{OLD}', '{NEW}')")
    condition = f"Path(__file__).parent.name == '{OLD}'"
    if text.count(condition) != 2:
        raise ValueError("unexpected V32 joint exit branches")
    return text.replace(condition, f"Path(__file__).parent.name in ('{OLD}', '{NEW}')")


def cold170_status(text):
    text = change(text, f"V32_PACKAGE = '{OLD}'", f"V32_PACKAGE = '{OLD}'\nV33_PACKAGE = '{NEW}'")
    end = "V31_PACKAGE, V32_PACKAGE)"
    if text.count(end) != 5:
        raise ValueError("unexpected V32 epoch 170 receiver registrations")
    return text.replace(end, "V31_PACKAGE, V32_PACKAGE, V33_PACKAGE)")


def stage(baseline, staging):
    original = (baseline/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(original).hexdigest() != V32_SEAL:
        raise ValueError("expected actual immutable V32 package seal")
    receipt = json.loads(original)
    files = {}
    modes = {}
    for member in receipt["members"]:
        name = member["name"]
        if name in files or Path(name).name != name:
            raise ValueError("foreign V32 member")
        if name == "SHA256SUMS":
            continue
        data = (baseline/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError("V32 member digest changed: "+name)
        files[name] = data
        modes[name] = int(member["mode"], 8)
    for name, patch in (("status_cycle.py", status_cycle), ("bounded167_status.py", bounded_status),
                        ("joint168_status.py", joint_status), ("cold170_status.py", cold170_status),
                        ("full170_status.py", lambda text: change(text, f"'{OLD}')", f"'{OLD}', '{NEW}')"))):
        files[name] = patch(files[name].decode()).encode()
    for name in ("bounded167_operator.py", "transition_v33.py"):
        files[name] = (HERE/name).read_bytes()
        modes[name] = 0o444
    for name, data in files.items():
        if name.endswith(".py"):
            ast.parse(data, filename=name)
    staging.mkdir(mode=0o700)
    rows = []
    for name, data in sorted(files.items()):
        target = staging/name
        target.write_bytes(data)
        target.chmod(modes[name])
        rows.append(dict(name=name, source=str(target.resolve(strict=True)), mode=modes[name],
                         sha256=hashlib.sha256(data).hexdigest()))
    destination = str(Path(receipt["destination"]).with_name(NEW))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=destination, members=rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("staging", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.baseline, args.staging), indent=2))
