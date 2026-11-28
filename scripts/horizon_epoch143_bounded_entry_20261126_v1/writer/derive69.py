"""Enroll the epoch 143 held-gate retry while preserving the original 30-minute clock."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from derive63 import ROOT, SOURCE, one
from derive143_bootstrap_retry import read_package

OLD = ROOT / "tools-cold168-retry5-failed166-v68-entry146"
NEW = OLD.with_name(OLD.name.replace("-v68-", "-v69-"))
SEAL = "290592e137b70208701f11a6dbaba10a0c84551991cd0233024bacc0a60a687f"
ACTIVE = "747c3740e5beb31f4cc0a87fad47a143fc2337d664922535d156e75da5527355"
V3 = ROOT.parent / "epoch143-second-hourly-20261128-v3"
CLOSED = V3 / "held-stop-73b04c4b19644244a5880631da917425"
FROZEN_SHA = "8baa0d5367c8f7c8d9d563d06ca170fe7e781a4ecddf29f2cf00e0202c41a39a"
TERMINAL_SHA = "589128efd24df747003f08e7a683ce2d2f8a8cedd0d6d5193c5cd4ef195388a6"
V4 = ROOT.parent / "epoch143-second-hourly-20261128-v4"


def following_block(source, anchor, lines):
    line, = (v for v in source.splitlines() if v.strip() == anchor)
    indent = line[:len(line) - len(line.lstrip())]
    return one(source, line, line + "\n" + "\n".join(indent + v for v in lines))


def cycle(source):
    normal, commands = source.split("def main():", 1)
    normal = normal.replace(", 68)", ", 68, 69)")
    for line in normal.splitlines():
        if line.strip().startswith(("68: (transition_v68.", "68: 'fb9db4e77")):
            normal = one(normal,line,line + "\n" + line.replace("68:", "69:", 1).replace("transition_v68.V67","transition_v69.V68"))
    for anchor, lines in (
        ("import transition_v68", ["if FAILED166_VERSION >= 69:", "    import runway_retry143", "    import runway143_scope", "    import transition_v69"]),
        ("modules.append(transition_v68)", ["if FAILED166_VERSION >= 69:", "    modules.extend([runway_retry143, runway143_scope, transition_v69])"]),
    ):
        normal = following_block(normal, anchor, lines)
    for choice in ("status143", "forecaster"):
        anchor = choice + " = floor_retry143"
        normal = following_block(normal, anchor, ["if FAILED166_VERSION >= 69:", "    " + choice + " = runway_retry143"])
    anchor = "            hourly143_status.install(fleet, successor or fleet[hourly143_status.PROFILE.field])"
    normal = one(normal, anchor, "            if FAILED166_VERSION >= 69:\n"
                 "                successor = fleet.get(runway_retry143.PROFILE.field) or successor\n" + anchor)
    anchor = "    elif FAILED166_VERSION == 68:\n        transition_v68.validate(globals(), ready, receipt)"
    normal = one(normal,anchor,anchor.replace("68","69") + "\n" + anchor)
    blocks = list(re.finditer(r"^    if FAILED166_VERSION == 68 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+", commands, re.M))
    if len(blocks) != 5:
        raise ValueError("unexpected V68 command set")
    for block in reversed(blocks):
        addition = block[0].replace("== 68","== 69").replace("v68","v69").replace("V68","V69")
        commands = commands[:block.start()] + addition + commands[block.start():]
    return normal + "def main():" + commands


def stage(directory, contract_sha, guard_timer):
    bindings = {}
    originals = read_package(OLD, SEAL)
    originals.pop("SHA256SUMS",None)
    for name, (data, mode) in originals.items():
        bindings[name] = dict(name=name, source=str(OLD / name), sha256=hashlib.sha256(data).hexdigest(), mode=mode)
    directory.mkdir(mode=0o700)

    def add(name, contents):
        if name.endswith(".py"):
            ast.parse(contents, filename=name)
        p = directory / name
        p.write_text(contents)
        p.chmod(0o444)
        bindings[name] = dict(name=name,source=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),mode=0o444)

    def original(name):
        return originals[name][0].decode()

    frozen = CLOSED / "V68_NATIVE_CLOSED_ROW.json"
    closed = CLOSED / "TERMINAL.json"
    contract = V4 / "contract-v1/LAUNCH_PROFILE.json"
    for path, digest in ((frozen,FROZEN_SHA),(closed,TERMINAL_SHA),(contract,contract_sha)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest or path.stat().st_uid != 0 or path.stat().st_mode & 0o222:
            raise ValueError("different retained input " + str(path))
    value = json.loads(contract.read_bytes())
    match = re.fullmatch(r"horizon-qualify-143-second-hourly-20261128-v(\d+)\.service", value["unit"])
    if (not match or not re.fullmatch(r"horizon-guard-143-second-hourly-20261128-v\d+\.timer", guard_timer)
            or value.get("held_stop") != {"path":str(closed),"sha256":TERMINAL_SHA}):
        raise ValueError("unexpected 143 retry unit or closure")
    terms = dict(CONTRACT_SHA=contract_sha, NODE=value["node"]["path"], FROZEN=dict(path=str(frozen),sha256=FROZEN_SHA),
                 EVIDENCE_BASE=V4.name,GUARD_TIMER=guard_timer,UNIT_VERSION=int(match[1]))
    add("runway143_scope.py", "".join(f"{k} = {v!r}\n" for k,v in terms.items()))
    for name in ("runway_retry143.py","transition_v69.py"):
        add(name,(SOURCE / name).read_text())
    add("status_cycle.py",cycle(original("status_cycle.py")))
    census = one(original("hourly_population.py"), "import floor_retry143 as following",
                 "import floor_retry143 as following\nimport runway_retry143 as runway")
    census = one(census, "prior, replacement = following.census(", "prior, replacement, current = runway.census(")
    census = one(census, "    rows.append((following.PROFILE, replacement))",
                 "    rows.append((following.PROFILE, replacement))\n    rows.append((runway.PROFILE, current))")
    census = one(census, "            following.previous({profile.field: row})",
                 "            following.previous({profile.field: row})\n        elif profile is following.PROFILE:\n            runway.previous({profile.field: row})")
    add("hourly_population.py", census)
    # The previous 170 reader sees the observer assignment for its own interval.
    # Authenticate and project the newly recorded successor through its native adapter first.
    before = '    config = checked(fleet["sole_next_observer"])\n    if fleet.get(following.FIELD):'
    after = ('    config = checked(fleet["sole_next_observer"])\n'
             '    import after_floor170_status as latest170\n'
             '    config = latest170.history_config(fleet, config)\n'
             '    if fleet.get(following.FIELD):')
    add("transition_v58.py", one(original("transition_v58.py"), before, after))
    # Only the second-162 adapter interprets that single historical 162 diagnostic slot.
    # Later adapters must continue checking the original fleet pointer and its full roster.
    prev = one(original("transition_v62.py"),"def native_assignments(fleet):\n    earlier =",
               "def native_assignments(fleet):\n    from third162_route import earlier_fleet\n    fleet = earlier_fleet(fleet)\n    earlier =")
    add("transition_v62.py",prev)
    prev = one(original("transition_v67.py"),"prior, row = retry.census(context,",
               "from runway_retry143 import retained_census\n    prior, row = retained_census(context,")
    add("transition_v67.py",prev)
    prev = one(original("transition_v68.py"),'actor["terminal"]["INVOCATION_ID"] == iid',
               'checked(actor["held_owner"]) == actor["actor"] and actor["actor"]["producer_invocation_id"] == iid\n'
               '                 and actor["terminal"] == route.third.native_end(route.third.api(), actor["actor"])')
    add("transition_v68.py",prev)
    cutover = re.sub(r"(cutover|[vV])(67|68)",lambda m: m[1] + str(int(m[2]) + 1),original("cutover68.py"))
    cutover = one(cutover, "44451395c11f4de72d6768818e58bd00ac298191746e5167516a375cf24eb3b5", SEAL)
    cutover = one(cutover, "4748bd09457b12e876763e012bb67371142bc1194349df7def25301ef5967c83", ACTIVE)
    add("cutover69.py",cutover)
    for name, count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        data = original(name)
        final = repr(OLD.name) + ")"
        if data.count(final) != count:
            raise ValueError("different reader package bindings in " + name)
        add(name,data.replace(final,repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(bindings.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3]), indent=2))
