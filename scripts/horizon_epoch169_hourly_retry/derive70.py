"""Add the adjacent epoch 169 reader to the sole registered cadence writer."""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / "horizon_epoch143_bounded_entry_20261126_v1/writer")]
import derive_adjacent_writer as receiver
from derive69 import following_block, NEW as OLD
from derive63 import one
from derive143_bootstrap_retry import read_package


NEW = OLD.with_name("tools-cold168-retry5-failed166-v70-entry146")
OLD_SEAL = "5e340efd8997049cc8000a06feaf666c00605ad81ad384387b375981aaeb3f58"
OLD_ACTIVE = "eabc10a834d15a0e9558872fb79c94074f53b76c13a52ca99c4533a17106805f"


def cycle(source):
    normal, commands = source.split("def main():", 1)
    normal = normal.replace(", 68, 69)", ", 68, 69, 70)")
    for line in normal.splitlines():
        if line.strip().startswith(("69: (transition_v69.", "69: 'fb9db4e77")):
            additional = line.replace("69:", "70:", 1).replace("transition_v69.V68", "transition_v70.V69")
            normal = one(normal, line, line + "\n" + additional)
    normal = following_block(normal, "import transition_v69",
                             ["if FAILED166_VERSION >= 70:", "    import transition_v70"])
    normal = following_block(normal, "modules.extend([runway_retry143, runway143_scope, transition_v69])",
                             ["if FAILED166_VERSION >= 70:", "    modules.append(transition_v70)"])
    anchor = "    elif FAILED166_VERSION == 69:\n        transition_v69.validate(globals(), ready, receipt)"
    normal = one(normal, anchor, anchor.replace("69", "70") + "\n" + anchor)
    blocks = list(re.finditer(r"^    if FAILED166_VERSION == 69 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+", commands, re.M))
    if len(blocks) != 5:
        raise ValueError("unexpected V69 command set")
    for block in reversed(blocks):
        new = block[0].replace("== 69", "== 70").replace("v69", "v70").replace("V69", "V70")
        commands = commands[:block.start()] + new + commands[block.start():]
    return receiver.cycle(normal + "def main():" + commands, 70)


def cutover(source):
    result = re.sub(r"(cutover|[vV])(68|69)", lambda m: m[1] + str(int(m[2]) + 1), source)
    result = one(result, 'OLD = BASE / "tools-cold168-retry5-failed166-v69-entry146"', f'OLD = BASE / "{OLD.name}"')
    result = one(result, 'NEW = BASE / "tools-cold168-retry5-failed166-v70-entry146-r2"', f'NEW = BASE / "{NEW.name}"')
    result = one(result, 'ORIGINAL_SEAL = "290592e137b70208701f11a6dbaba10a0c84551991cd0233024bacc0a60a687f"',
                 f'ORIGINAL_SEAL = "{OLD_SEAL}"')
    return one(result, 'OLD_OWNER = "747c3740e5beb31f4cc0a87fad47a143fc2337d664922535d156e75da5527355"',
               f'OLD_OWNER = "{OLD_ACTIVE}"')


def stage(directory):
    old = read_package(OLD, OLD_SEAL)
    old.pop("SHA256SUMS", None)
    files = {n: dict(name=n, source=str(OLD / n), sha256=hashlib.sha256(data).hexdigest(), mode=mode)
             for n, (data, mode) in old.items()}
    directory.mkdir(mode=0o700)

    def write(name, data):
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = directory / name
        path.write_bytes(data)
        path.chmod(0o444)
        files[name] = dict(name=name, source=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=0o444)

    for name, data in receiver.members().items():
        write(name, data)
    write("transition_v70.py", (HERE / "transition_v70.py").read_bytes())
    previous = one(old["transition_v69.py"][0].decode(), "def native_assignments(fleet):",
                   "def native_assignments(fleet, fleet_ref=None):")
    previous = one(previous, 'SimpleNamespace(fleet=fleet, sample_ref=fleet["observer"])',
                   'SimpleNamespace(fleet=fleet, fleet_ref=fleet_ref, sample_ref=fleet["observer"])')
    write("transition_v69.py", previous.encode())
    write("status_cycle.py", cycle(old["status_cycle.py"][0].decode()).encode())
    write("cutover70.py", cutover(old["cutover69.py"][0].decode()).encode())
    write("split_wire.py", receiver.wire(old["split_wire.py"][0].decode()).encode())
    for name, count in (("full170_status.py", 1), ("cold170_status.py", 5), ("joint168_status.py", 3)):
        data = old[name][0].decode()
        end = repr(OLD.name) + ")"
        if data.count(end) != count:
            raise ValueError("unexpected package binding in " + name)
        write(name, data.replace(end, repr(OLD.name) + ", " + repr(NEW.name) + ")").encode())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(files.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
