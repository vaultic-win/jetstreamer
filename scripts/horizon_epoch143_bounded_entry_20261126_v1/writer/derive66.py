"""Thread the guarded floor-stop replacement into the existing writer."""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

from derive63 import ROOT, SOURCE, one, original

OLD = ROOT / "tools-cold168-retry5-failed166-v65-entry146"
NEW = OLD.with_name(OLD.name.replace("v65", "v66"))
V65_SEAL = "53f0d5e2181341b51779c2e91672b61f1b06bfd0c4d493708e2524ab54f2e1c3"
V65_SHA = "53397543058f6c75319bd7e68bf587cf991bf4c984ea155096c34d90a4bb74ac"


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 65)", ", 65, 66)")
    ordinary = ordinary.replace("                                        if FAILED166_VERSION == 65:",
                                "                                        if FAILED166_VERSION >= 65:")
    anchor = "                                            import transition_v65"
    ordinary = one(ordinary, anchor, anchor + """
                                            if FAILED166_VERSION == 66:
                                                import floor_retry143
                                                import floor_retry143_scope
                                                import transition_v66""")
    ordinary = ordinary.replace("                                                                    if FAILED166_VERSION == 65:",
                                "                                                                    if FAILED166_VERSION >= 65:")
    anchor = "                                                                                    second143_terminal, transition_v65]"
    ordinary = one(ordinary, anchor, anchor + """
                                                                        if FAILED166_VERSION == 66:
                                                                            modules += [floor_retry143, floor_retry143_scope, transition_v66]""")
    validation = "    elif FAILED166_VERSION == 65:\n        transition_v65.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, validation.replace("65", "66") + "\n" + validation)
    baseline = "            status143 = retry_second_hourly143"
    ordinary = one(ordinary, baseline, baseline + "\n        if FAILED166_VERSION == 66:\n            status143 = floor_retry143")
    forecast = "                after,extra = forecaster.forecast(c, row, old)"
    ordinary = one(ordinary, forecast, """                if FAILED166_VERSION == 66:
                    forecaster = floor_retry143
""" + forecast)
    install = "            hourly143_status.install(fleet, successor or fleet[hourly143_status.PROFILE.field])"
    ordinary = one(ordinary, install, """            if FAILED166_VERSION == 66:
                successor = (fleet.get(floor_retry143.PROFILE.field)
                             or fleet.get(retry_second_hourly143.PROFILE.field) or successor)
""" + install)
    for line in ordinary.splitlines():
        if line.strip().startswith(("65: (transition_v65.", "65: 'fb9db4e77")):
            ordinary = one(ordinary, line, line + "\n" + line.replace("65:", "66:", 1)
                           .replace("transition_v65.V64", "transition_v66.V65"))
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 65 and len(sys.argv) == 4")]
    if len(starts) < 2:
        raise ValueError("different V65 handoff commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 65", "== 66").replace("v65", "v66").replace("V65", "V66"))
    return ordinary + "def main():" + "".join(lines)


def stage(folder, contract_ref):
    predecessor = json.loads(original(OLD / "deployment-seal-receipt.json", V65_SEAL))
    contract = json.loads(original(Path(contract_ref["path"]), contract_ref["sha256"]))
    if predecessor["destination"] != str(OLD) or not contract.get("floor_stop"):
        raise ValueError("different V65 package or epoch 143 route")
    folder.mkdir(mode=0o700)
    members = {}
    for item in predecessor["members"]:
        name = item["name"]
        path = OLD / name
        if path.parent != OLD or name in members:
            raise ValueError("invalid V65 deployment member")
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
    for name in ("transition_v66.py", "floor_retry143.py", "second143_floor_terminal.py"):
        add(name, (SOURCE / name).read_text())
    add("floor_retry143_scope.py", f"CONTRACT_SHA = {contract_ref['sha256']!r}\nNODE = {contract['node']['path']!r}\n")
    add("first_hourly143.py", (SOURCE.parent / "cadence/first_hourly143.py").read_text())
    population = (OLD / "hourly_population.py").read_text()
    population = one(population, "import retry_second_hourly143 as retry",
                     "import retry_second_hourly143 as retry\nimport floor_retry143 as following")
    population = one(population, """    repaired = retry.census(context, rows[1][1], successor)
    rows.append((retry.PROFILE, repaired))""", """    prior, replacement = following.census(context, rows[1][1], successor)
    rows.append((retry.PROFILE, prior))
    rows.append((following.PROFILE, replacement))""")
    population = one(population, "        recheck(row, profile)", """        if profile is retry.PROFILE:
            following.previous({profile.field: row})
        else:
            recheck(row, profile)""")
    add("hourly_population.py", population)
    cutover = (OLD / "cutover65.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(64|65)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    cutover = cutover.replace("3e29cb4264fa554c688e5c18a81a0651bc053000d8856d848b8872d94cae949f", V65_SEAL)
    cutover = cutover.replace("986f2778ca9f025b778c5a188d88ecdeaa1c18ae042924429e8d201aece77d29", V65_SHA)
    add("cutover66.py", cutover)
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
