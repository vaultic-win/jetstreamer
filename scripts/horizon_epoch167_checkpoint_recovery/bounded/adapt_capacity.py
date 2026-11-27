"""Add the isolated held 167 census to an unsealed copy of the V31 provider."""

import argparse
import ast
import hashlib
import json
from pathlib import Path

PROVIDERS = Path("/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1")
ROUTE = "tools-homefloor-170-full-metered-independent-v20-joint168-v31-bounded167"


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"wrong V31 provider source for change: {old.strip().splitlines()[0]}")
    return text.replace(old, new)


def adapt(provider, full146):
    changes = [
        (
            'V31_JOINT168 = HERE == D / "tools-homefloor-170-full-metered-independent-v20-joint168-v31"',
            f'BOUNDED167 = HERE == D / "{ROUTE}"\n'
            'BOUNDED167_REQUEST = None\n'
            'V31_JOINT168 = BOUNDED167 or HERE == D / "tools-homefloor-170-full-metered-independent-v20-joint168-v31"',
        ),
        (
            '\n\ndef focused168_held():',
            '''

def bounded167_owner(ref):
    if BOUNDED167_REQUEST is None:
        return None
    s.need(BOUNDED167, "bounded 167 requires its exact provider")
    intent = bound(BOUNDED167_REQUEST)
    s.need(intent["prestart"]["fleet"] == ref, "bounded 167 crossed the fleet")
    seal, _ = s.read(HERE / "deployment-seal-receipt.json")
    program = HERE / "bounded167-admission.py"
    row, = (item for item in seal["members"] if item["name"] == program.name and item["mode"] == "0555")
    prepared = bound(intent["prepared"])
    s.need(seal["destination"] == str(HERE)
           and prepared["gate_source_sha256"] == row["sha256"],
           "bounded 167 callback differs from the sealed gate source")
    fit.binary(program, row["sha256"])
    return json.loads(subprocess.check_output(
        ["/usr/bin/python3", "-IB", program, "owner", BOUNDED167_REQUEST["path"],
         BOUNDED167_REQUEST["sha256"]], timeout=20))


def focused168_held():''',
        ),
        (
            'focused168=None, entry143=False, full146=None, joint168=None):',
            'focused168=None, entry143=False, full146=None, joint168=None, bounded167=None):',
        ),
        (
            '    if focused168 is not None:\n        unit = focused168_capacity["UNIT"]',
            '''    if bounded167 is not None:
        unit = "horizon-qualify-167-checkpoint-bounded-20261127-v1.service"
        s.need(BOUNDED167 and own == 145 and repro166 is None and bounded167["unit"] == unit
               and unit not in expect and len(bounded167["processes"]) == 1
               and bounded167["processes"][0][:2] == [bounded167["producer_pid"], bounded167["start_ticks"]],
               "different held bounded epoch 167 qualifier")
        expect[unit] = bounded167["processes"]
    if focused168 is not None:
        unit = focused168_capacity["UNIT"]''',
        ),
        (
            '    repro166 = reproduction166_owner(repro166_mode,ref)',
            '    repro166 = reproduction166_owner(repro166_mode,ref)\n    held167 = bounded167_owner(ref)',
        ),
        (
            'focused168, entry143, epoch146_actor, joint168_actor)\n    if closed169:',
            'focused168, entry143, epoch146_actor, joint168_actor, held167)\n    if closed169:',
        ),
        (
            'focused168, entry143, epoch146_actor, joint168_actor)==(population,qualification),',
            'focused168, entry143, epoch146_actor, joint168_actor, held167)==(population,qualification),',
        ),
        (
            '        native["reproduction166_owner"] = repro166\n    if FULL170_RETRY5:',
            '''        native["reproduction166_owner"] = repro166
    if BOUNDED167:
        s.need(bounded167_owner(ref) == held167, "bounded 167 process changed during native capture")
        native["bounded167_owner"] = held167
    if FULL170_RETRY5:''',
        ),
        (
            '                s.need(price["schema"] == joint168_capacity["OUTPUT_SCHEMA"]',
            '''                if held167 := native.get("bounded167_owner"):
                    want.add(held167["unit"])
                if BOUNDED167:
                    s.need(bounded167_owner(ref) == native["bounded167_owner"],
                           "bounded 167 process changed after complete repricing")
                s.need(price["schema"] == joint168_capacity["OUTPUT_SCHEMA"]''',
        ),
        (
            's.need(len(args) == 6 and args[1].startswith("/") and FULL146_REQUEST["mode"] == "active",',
            's.need(len(args) in ((6, 9) if BOUNDED167 else (6,)) and args[1].startswith("/")\n'
            '               and FULL146_REQUEST["mode"] == "active",',
        ),
        (
            '    repro166_mode = None\n    if args and args[0].startswith("--repro166="):',
            '''    if args[:1] == ["--bounded167-request"]:
        s.need(BOUNDED167 and len(args) == 6 and args[1].startswith("/") and JOINT168_REQUEST is not None,
               "usage: ... --joint168-request PATH SHA --bounded167-request INTENT SHA 145 FLEET SHA")
        BOUNDED167_REQUEST = s.ref(Path(args[1]), args[2])
        args = args[3:]
    repro166_mode = None
    if args and args[0].startswith("--repro166="):''',
        ),
    ]
    for old, new in changes:
        provider = replace(provider, old, new)
    full146 = replace(
        full146, "    old = native['retry5_complete_booking']",
        """    if held167 := native.get('bounded167_owner'):
        s.need(held166 is None and held167['unit'] not in expected
               and native['population'].get(held167['unit']) == [row[:2] for row in held167['processes']],
               'bounded epoch 167 changed the full 146 census')
        expected.add(held167['unit'])
    old = native['retry5_complete_booking']""",
    )
    return provider, full146


def stage(baseline_plan, staging):
    plan = json.loads(baseline_plan.read_bytes())
    if plan["schema"] != "jetstreamer-sealed-deployment-plan-v1" or Path(plan["destination"]) != PROVIDERS/ROUTE.removesuffix("-bounded167"):
        raise ValueError("matching V31 capacity seal plan required")
    members = {}
    modes = {}
    for member in plan["members"]:
        name = member["name"]
        if name in members or Path(name).name != name or name == "bounded167-admission.py":
            raise ValueError(f"foreign or duplicate V31 member {name}")
        if name == "SHA256SUMS":
            continue
        data = Path(member["source"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError(f"V31 member changed {name}")
        members[name] = data
        modes[name] = member["mode"]
    updated = adapt(members["post-stop-fit"].decode(), members["full146_capacity.py"].decode())
    for name, content in zip(("post-stop-fit", "full146_capacity.py"), updated):
        members[name] = content.encode()
    members["bounded167-admission.py"] = Path(__file__).with_name("replay167.py").read_bytes()
    modes["bounded167-admission.py"] = 0o555
    for name, data in members.items():
        if name == "post-stop-fit" or name.endswith(".py"):
            ast.parse(data, filename=name)
    staging.mkdir(mode=0o700, exist_ok=False)
    rows = []
    for name, data in sorted(members.items()):
        path = staging/name
        path.write_bytes(data)
        path.chmod(modes[name])
        rows.append(dict(source=str(path.resolve(strict=True)), name=name,
                         sha256=hashlib.sha256(data).hexdigest(), mode=modes[name]))
    return dict(schema=plan["schema"], destination=str(PROVIDERS/ROUTE), members=rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline_plan", type=Path)
    parser.add_argument("staging", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.baseline_plan, args.staging), indent=2))


if __name__ == "__main__":
    main()
