"""Derive the epoch 143 RAM retry writer from the exact adjacent 169 writer."""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

from derive63 import ROOT, SOURCE, one
from derive69 import following_block
from derive143_bootstrap_retry import read_package
from held143_ram_terminal import TERMINAL


OLD = ROOT / "tools-cold168-retry5-failed166-v70-entry146"
NEW = OLD.with_name("tools-cold168-retry5-failed166-v71-entry146")
OLD_SHA = "6aef2af6a4c8332e9af577ee55fa27bf44f88cfe39d9d67a32d4056faf008c3f"
OLD_SEAL = "838bfc4a45f355e086bc85f2188d6ee8baf12c5b444a5522d7afd43db59ad987"
V5 = ROOT.parent / "epoch143-second-hourly-20261128-v5"
CONTRACT_SHA = "9ffb82089d6053616def391ac8714e0ba57d808ee151a60b88499b5a53248d57"
FROZEN_SHA = "64aef203d81be0b40fd88159ca58e7a28e0b5716cc6e31f4950f9a567ac61643"


def cycle(source):
    normal, commands = source.split("def main():", 1)
    normal = normal.replace(", 69, 70)", ", 69, 70, 71)")
    for line in normal.splitlines():
        if line.strip().startswith(("70: (transition_v70.", "70: 'fb9db4e77")):
            addition = line.replace("70:", "71:", 1).replace("transition_v70.V69", "transition_v71.V70")
            normal = one(normal, line, line + "\n" + addition)
    normal = following_block(normal, "import transition_v70",
                             ["if FAILED166_VERSION >= 71:", "    import ram_retry143", "    import ram_retry143_scope",
                              "    import held143_ram_terminal", "    import transition_v71"])
    normal = following_block(normal, "modules.append(transition_v70)", ["if FAILED166_VERSION >= 71:",
        "    modules.extend([ram_retry143, ram_retry143_scope, held143_ram_terminal, transition_v71])"])
    for choice in ("status143", "forecaster"):
        normal = following_block(normal, choice + " = runway_retry143",
                                 ["if FAILED166_VERSION >= 71:", "    " + choice + " = ram_retry143"])
    normal = following_block(normal, "successor = fleet.get(runway_retry143.PROFILE.field) or successor",
                             ["if FAILED166_VERSION >= 71:",
                              "    successor = fleet.get(ram_retry143.PROFILE.field) or successor"])
    anchor = "    elif FAILED166_VERSION == 70:\n        transition_v70.validate(globals(), ready, receipt)"
    normal = one(normal, anchor, anchor.replace("70", "71") + "\n" + anchor)
    blocks = list(re.finditer(r"^    if FAILED166_VERSION == 70 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+",
                              commands, re.M))
    if len(blocks) != 5:
        raise ValueError("unexpected V70 command set")
    for block in reversed(blocks):
        addition = block[0].replace("== 70", "== 71").replace("v70", "v71").replace("V70", "V71")
        commands = commands[:block.start()] + addition + commands[block.start():]
    return normal + "def main():" + commands


def population(source):
    source = one(source, "import runway_retry143 as runway", "import runway_retry143 as runway\nimport ram_retry143 as ram")
    source = one(source, "prior, replacement, current = runway.census(",
                 "prior, replacement, held_ram, current = ram.census(")
    source = one(source, "    rows.append((runway.PROFILE, current))",
                 "    rows.append((runway.PROFILE, held_ram))\n    rows.append((ram.PROFILE, current))")
    return one(source, "            runway.previous({profile.field: row})",
               "            runway.previous({profile.field: row})\n"
               "        elif profile is runway.PROFILE:\n            ram.previous({profile.field: row})")


def retained_transition(source):
    source = one(source, "from types import SimpleNamespace\n", "")
    source = one(source, "import runway_retry143 as following",
                 "import runway_retry143 as following\nfrom ram_retry143 import previous as held_ram_refusal")
    return one(source, '''    context = SimpleNamespace(fleet=fleet, fleet_ref=fleet_ref, sample_ref=fleet["observer"])
    _, _, row = following.census(context, fleet[following.second.EPOCH143.field], fleet[following.second.PROFILE.field])''',
               "    row = held_ram_refusal(fleet)")


def cutover(source):
    result = re.sub(r"(cutover|[vV])(69|70)", lambda m: m[1] + str(int(m[2]) + 1), source)
    result = one(result, 'OLD = BASE / "tools-cold168-retry5-failed166-v70-entry146-r2"', f'OLD = BASE / "{OLD.name}"')
    result = one(result, 'ORIGINAL_SEAL = "5e340efd8997049cc8000a06feaf666c00605ad81ad384387b375981aaeb3f58"',
                 f'ORIGINAL_SEAL = "{OLD_SEAL}"')
    return one(result, 'OLD_OWNER = "eabc10a834d15a0e9558872fb79c94074f53b76c13a52ca99c4533a17106805f"',
               f'OLD_OWNER = "{OLD_SHA}"')


def bound_input(path, digest):
    raw = path.read_bytes()
    st = path.lstat()
    if path.resolve(strict=True) != path or st.st_uid != 0 or st.st_mode & 0o222 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("different epoch 143 input " + str(path))
    return json.loads(raw)


def stage(directory):
    old = read_package(OLD, OLD_SEAL)
    old.pop("SHA256SUMS", None)
    files = {name: dict(name=name, source=str(OLD / name), sha256=hashlib.sha256(data).hexdigest(), mode=mode)
             for name, (data, mode) in old.items()}
    directory.mkdir(mode=0o700)

    def write(name, data):
        ast.parse(data, filename=name)
        path = directory / name
        path.write_bytes(data)
        path.chmod(0o444)
        files[name] = dict(name=name, source=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=0o444)

    terminal = Path(TERMINAL["path"])
    frozen = terminal.with_name("V69_NATIVE_CLOSED_ROW.json")
    closure = bound_input(terminal, TERMINAL["sha256"])
    history = bound_input(frozen, FROZEN_SHA)
    contract = bound_input(V5 / "contract-v1/LAUNCH_PROFILE.json", CONTRACT_SHA)
    if (contract["held_ram_stop"] != TERMINAL or contract["unit"] != closure["unit"]
            or history["held_owner"] != closure["prior_held"]
            or history["native_terminal"]["cursor"] != closure["pid1_cursor"]):
        raise ValueError("different epoch 143 RAM retry or frozen terminal")
    write("ram_retry143_scope.py", (f"CONTRACT_SHA = {CONTRACT_SHA!r}\n"
        f"NODE = {contract['node']['path']!r}\nFROZEN = {{'path': {str(frozen)!r}, 'sha256': {FROZEN_SHA!r}}}\n").encode())
    for name in ("ram_retry143.py", "held143_ram_terminal.py", "transition_v71.py"):
        write(name, (SOURCE / name).read_bytes())
    for name, transform in (("status_cycle.py", cycle), ("hourly_population.py", population),
                            ("transition_v69.py", retained_transition)):
        write(name, transform(old[name][0].decode()).encode())
    write("cutover71.py", cutover(old["cutover70.py"][0].decode()).encode())
    for name, count in (("full170_status.py", 1), ("cold170_status.py", 5), ("joint168_status.py", 3)):
        source = old[name][0].decode()
        ending = repr(OLD.name) + ")"
        if source.count(ending) != count:
            raise ValueError("different origin of the current " + name)
        write(name, source.replace(ending, repr(OLD.name) + ", " + repr(NEW.name) + ")").encode())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(files.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
