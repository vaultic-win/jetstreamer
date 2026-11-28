"""Seal a compatible V63 writer with a separate second-hourly epoch 143 census."""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

V62_SHA = "be7681e7d92c6617147239e3e534ab008341599e198c1183cbe4f007802fc3cb"
V62_SEAL = "7901076dbe284118014b0d37483368fc5c8b50bc340c8bc181cc33a9f4dcaf99"

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = BASE / "survivor172-cadence-20261122-v1"
OLD = ROOT / "tools-cold168-retry5-failed166-v62-entry146"
NEW = OLD.with_name(OLD.name.replace("v62", "v63"))
SECOND = BASE / "epoch143-second-hourly-20261128-v1"
SOURCE = Path(__file__).resolve().parent


def one(source, before, after):
    if source.count(before) != 1:
        raise ValueError("different source anchor: " + before)
    return source.replace(before, after)


def original(path, sha256):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("changed preceding deployment member: " + str(path))
    return raw


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 62)", ", 62, 63)")
    ordinary = ordinary.replace("                            if FAILED166_VERSION == 62:",
                                "                            if FAILED166_VERSION in (62, 63):")
    foreign = "                                import transition_v62"
    ordinary = one(ordinary, foreign, foreign + """
                                if FAILED166_VERSION == 63:
                                    import second_hourly143
                                    import second_hourly143_scope
                                    import transition_v63""")
    modules = "                                                            modules += [transition_v62, second162_route, second162_route.second, second162_route.progress]"
    ordinary = one(ordinary, modules, modules + """
                                                            if FAILED166_VERSION == 63:
                                                                modules += [second_hourly143, second_hourly143_scope, transition_v63]""")
    validation = "    elif FAILED166_VERSION == 62:\n        transition_v62.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, validation.replace("62", "63") + "\n" + validation)
    origin = "        c.status143 = hourly143_status.baseline(refs.pop('143', None))"
    ordinary = one(ordinary, origin, origin.replace("hourly143_status.baseline", "status143.baseline").replace(
        "        c.status143", "        status143 = second_hourly143 if FAILED166_VERSION == 63 else hourly143_status\n        c.status143"))
    point = """            row, = (row for profile, row in c.first_hourly if profile.epoch == 143)
            after,extra = hourly143_status.forecast(c, row, old)"""
    ordinary = one(ordinary, point, """            if FAILED166_VERSION == 63:
                row = second_hourly143.status_row(c.first_hourly)
                after,extra = second_hourly143.forecast(c, row, old)
            else:
                row, = (row for profile, row in c.first_hourly if profile.epoch == 143)
                after,extra = hourly143_status.forecast(c, row, old)""")
    install = "            hourly143_status.install(fleet, fleet[hourly143_status.PROFILE.field])"
    ordinary = one(ordinary, install, """            successor = fleet.get(second_hourly143.PROFILE.field) if FAILED166_VERSION == 63 else None
            hourly143_status.install(fleet, successor or fleet[hourly143_status.PROFILE.field])
            if successor:
                entry, = (entry for entry in fleet['epochs'] if entry['epoch'] == 143)
                entry['current_status_scope'] = 'Private second-hourly interval and canonical delivery planning.'""")
    for line in ordinary.splitlines():
        if line.strip().startswith(("62: (transition_v62.", "62: 'fb9db4e77")):
            ordinary = one(ordinary, line, line + "\n" + line.replace("62:", "63:", 1)
                           .replace("transition_v62.V61", "transition_v63.V62"))
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 62 and len(sys.argv) == 4")]
    if len(starts) != 5:
        raise ValueError("different V62 handoff commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 62", "== 63").replace("v62", "v63").replace("V62", "V63"))
    return ordinary + "def main():" + "".join(lines)


def stage(folder, contract_ref):
    test = json.loads(original(OLD / "deployment-seal-receipt.json", V62_SEAL))
    contract = json.loads(original(Path(contract_ref["path"]), contract_ref["sha256"]))
    if (test["destination"] != str(OLD) or contract["unit"] != "horizon-qualify-143-second-hourly-20261128-v1.service"
            or Path(contract_ref["path"]) != SECOND / "contract-v1/LAUNCH_PROFILE.json"):
        raise ValueError("different V62 package or epoch 143 route")
    folder.mkdir(mode=0o700)
    members = {}
    for item in test["members"]:
        name = item["name"]
        path = OLD / name
        if path.parent != OLD or name in members:
            raise ValueError("invalid V62 deployment member")
        original(path, item["sha256"])
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(path), sha256=item["sha256"], mode=int(item["mode"], 8))

    def add(name, source):
        ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), mode=0o444)

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    for name in ("transition_v63.py", "second_hourly143.py", "hourly143_status.py"):
        add(name, (SOURCE / name).read_text())
    add("second_hourly143_scope.py", "\n".join([
        f"CONTRACT_SHA = {contract_ref['sha256']!r}", f"NODE = {contract['node']['path']!r}",
        f"PREFIX = {contract['prefix_acceptance']!r}", f"TERMINAL = {contract['native_terminal']!r}",
    ]) + "\n")
    add("first_hourly143.py", (SOURCE.parent / "cadence/first_hourly143.py").read_text())
    population = (OLD / "hourly_population.py").read_text()
    population = one(population, "PROFILES = (EPOCH141, EPOCH143)", """import second_hourly143 as second

PROFILES = (EPOCH141, EPOCH143)""")
    population = one(population, "    live = [row", """    successor = second.census(context, rows[1][1])
    rows.append((second.PROFILE, successor))
    live = [row""")
    add("hourly_population.py", population)
    cutover = (OLD / "cutover62.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(61|62)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    cutover = cutover.replace("71d71c0d6b635e60e6a009090a94159ea47dbfe3061bd8885982050d3ecd553c", V62_SEAL)
    cutover = cutover.replace("2c3903ff7579026e93c659c57cc8cb7b0342cd838c7fb6be85b77e033515ebb5", V62_SHA)
    add("cutover63.py", cutover)
    for name, count in (("full170_status.py", 1), ("cold170_status.py", 5), ("joint168_status.py", 3)):
        source = (OLD / name).read_text()
        marker = repr(OLD.name) + ")"
        if source.count(marker) != count:
            raise ValueError("different installed package list in " + name)
        add(name, source.replace(marker, repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    folder, contract, digest = sys.argv[1:]
    print(json.dumps(stage(Path(folder).resolve(), dict(path=contract, sha256=digest)), indent=2))
