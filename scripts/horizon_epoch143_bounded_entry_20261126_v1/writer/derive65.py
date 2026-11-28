"""Carry the native 143 retry into the existing cadence without losing its failed owner."""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

from derive63 import ROOT, SOURCE, one, original

OLD = ROOT / "tools-cold168-retry5-failed166-v64-entry146"
NEW = OLD.with_name(OLD.name.replace("v64", "v65"))
V64_SEAL = "3e29cb4264fa554c688e5c18a81a0651bc053000d8856d848b8872d94cae949f"
V64_SHA = "986f2778ca9f025b778c5a188d88ecdeaa1c18ae042924429e8d201aece77d29"


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 64)", ", 64, 65)")
    ordinary = ordinary.replace("                                    if FAILED166_VERSION == 64:",
                                "                                    if FAILED166_VERSION >= 64:")
    marker = "                                        import transition_v64"
    ordinary = one(ordinary, marker, marker + """
                                        if FAILED166_VERSION == 65:
                                            import retry_second_hourly143
                                            import retry_second_hourly143_scope
                                            import second143_terminal
                                            import transition_v65""")
    module = "                                                                    modules += [transition_v64]"
    ordinary = ordinary.replace("                                                                if FAILED166_VERSION == 64:",
                                "                                                                if FAILED166_VERSION >= 64:")
    ordinary = one(ordinary, module, module + """
                                                                    if FAILED166_VERSION == 65:
                                                                        modules += [retry_second_hourly143, retry_second_hourly143_scope,
                                                                                    second143_terminal, transition_v65]""")
    validation = "    elif FAILED166_VERSION == 64:\n        transition_v64.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, validation.replace("64", "65") + "\n" + validation)
    baseline = "        status143 = second_hourly143 if FAILED166_VERSION in (63, 64, 65) else hourly143_status"
    ordinary = one(ordinary, baseline, baseline + "\n        if FAILED166_VERSION == 65:\n            status143 = retry_second_hourly143")
    foreground = "                after,extra = second_hourly143.forecast(c, row, old)"
    ordinary = one(ordinary, foreground, """                forecaster = retry_second_hourly143 if FAILED166_VERSION == 65 else second_hourly143
                after,extra = forecaster.forecast(c, row, old)""")
    install = "            hourly143_status.install(fleet, successor or fleet[hourly143_status.PROFILE.field])"
    ordinary = one(ordinary, install, """            if FAILED166_VERSION == 65:
                successor = fleet.get(retry_second_hourly143.PROFILE.field) or successor
""" + install)
    for line in ordinary.splitlines():
        if line.strip().startswith(("64: (transition_v64.", "64: 'fb9db4e77")):
            ordinary = one(ordinary, line, line + "\n" + line.replace("64:", "65:", 1)
                           .replace("transition_v64.V63", "transition_v65.V64"))
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 64 and len(sys.argv) == 4")]
    if len(starts) < 2:
        raise ValueError("different V64 handoff commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 64", "== 65").replace("v64", "v65").replace("V64", "V65"))
    return ordinary + "def main():" + "".join(lines)


def stage(folder, contract_ref):
    predecessor = json.loads(original(OLD / "deployment-seal-receipt.json", V64_SEAL))
    contract = json.loads(original(Path(contract_ref["path"]), contract_ref["sha256"]))
    if predecessor["destination"] != str(OLD) or contract["unit"] != "horizon-qualify-143-second-hourly-20261128-v2.service":
        raise ValueError("different V64 package or epoch 143 route")
    folder.mkdir(mode=0o700)
    members = {}
    for item in predecessor["members"]:
        name = item["name"]
        path = OLD / name
        if path.parent != OLD or name in members:
            raise ValueError("invalid V64 deployment member")
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
    older = (OLD / "transition_v58.py").read_text()
    anchor = '    config = third_ram.history_config(fleet, checked(fleet["sole_next_observer"]))'
    older = one(older, anchor, """    import after_ram170_status as following
    config = checked(fleet["sole_next_observer"])
    if fleet.get(following.FIELD):
        config = following.history_config(fleet, config)
    config = third_ram.history_config(fleet, config)""")
    add("transition_v58.py", older)
    add("transition_v64.py", one((OLD / "transition_v64.py").read_text(),
        'second["native_terminal"]["INVOCATION_ID"]', 'second["native_terminal"]["invocation_id"]'))
    for name in ("transition_v65.py", "second_hourly143.py", "retry_second_hourly143.py", "second143_terminal.py"):
        add(name, (SOURCE / name).read_text())
    add("retry_second_hourly143_scope.py", "\n".join([
        f"CONTRACT_SHA = {contract_ref['sha256']!r}", f"NODE = {contract['node']['path']!r}",
        f"TERMINAL = {contract['failed_second_hourly']!r}",
    ]) + "\n")
    add("first_hourly143.py", (SOURCE.parent / "cadence/first_hourly143.py").read_text())
    population = (OLD / "hourly_population.py").read_text()
    population = one(population, "import second_hourly143 as second", "import second_hourly143 as second\nimport retry_second_hourly143 as retry")
    population = one(population, "    live = [row", """    repaired = retry.census(context, rows[1][1], successor)
    rows.append((retry.PROFILE, repaired))
    live = [row""")
    add("hourly_population.py", population)
    cutover = (OLD / "cutover64.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(63|64)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    cutover = cutover.replace("18c6d258eca8596d2ae90729314b21dfc6413a22b9ddb2ea9a28deb3ca5ae101", V64_SEAL)
    cutover = cutover.replace("426de90d6f3a62d83c08b95e682cf55566744992b984259ec989726d815f4a08", V64_SHA)
    add("cutover65.py", cutover)
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
