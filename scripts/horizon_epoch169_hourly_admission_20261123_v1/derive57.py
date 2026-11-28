"""Enroll the epoch 169 and 170 guard replacements on the existing Anza observation clock."""
import ast
import hashlib
import json
from pathlib import Path
import runpy
import sys

import derive56
from derive49 import one

OLD = derive56.NEW
NEW = OLD.with_name(OLD.name.replace("v56", "v57"))
OWNER = "b827747955e1f5287696189bb6ee89c3dc454e0431e7332864ee810a1dcfac5d"
SEAL = "fc5cc84b6af3f36b31aba78ffc3a51e49859588053a6ea2c310994aac45fa722"
WIRE = "136b26ac78fe67c0ff9324080ba72bea852a45165dd9ab587c456cf845d21509"
HERE = Path(__file__).resolve().parent
RAM = OLD.parent.parent / "epoch170-from-73760367-ram-20261128-v2/observer-modules-v1"
RAM_SEAL = "5c8d82782a94087bb5622ee35a0daa5b71a3904973308647833750528e062f25"


def cycle(source, extend_ram):
    # The new executable inherits the predecessor's ordinary replay, inventory,
    # clock and status paths. CLI enrollment still binds a single exact owner.
    source = source.replace(", 56)", ", 56, 57)")
    main = source.index("def main():")
    ordinary, commands = source[:main], source[main:]
    validation = "    elif FAILED166_VERSION == 56:\n        transition_v56.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, "V57_VALIDATION")
    ordinary = ordinary.replace("FAILED166_VERSION == 56", "FAILED166_VERSION in (56, 57)")
    ordinary = one(ordinary, "V57_VALIDATION", validation.replace("56", "57") + "\n" + validation)
    ordinary = one(ordinary, "                                import second169_status as retry169_status",
                   """                                import second169_status as retry169_status
                                if FAILED166_VERSION == 57:
                                    import transition_v57
                                    import third169_status as retry169_status""")
    ordinary = one(ordinary, "                                    modules += [transition_v56, transition_v55.retry]",
                   """                                    modules += [transition_v56, transition_v55.retry]
                                    if FAILED166_VERSION == 57:
                                        modules += [transition_v57, transition_v56.retry]""")
    for field, added in (
        ("                56: (transition_v56.V55_SHA, transition_v56.V55_SEAL),",
         "                57: (transition_v57.V56_SHA, transition_v57.V56_SEAL),"),
        ("                    56: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "                    57: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        ordinary = one(ordinary, field, field + "\n" + added)
    expanded = extend_ram(ordinary + commands)
    main = expanded.index("def main():")
    ordinary, commands = expanded[:main], expanded[main:]
    # Keep each enrolled CLI route on both versions and update only the owner
    # and module identifiers. The independent sha256 evidence fields stay exact.
    lines = commands.splitlines(keepends=True)
    copied = 0
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 56 and len(sys.argv) == 4")]
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 56", "== 57").replace("v56", "v57").replace("V56", "V57"))
        copied += 1
    if copied != 3:
        raise ValueError("different epoch 170 enrollment and writer check commands")
    commands = "".join(lines)
    return ordinary + commands


def transition(source):
    source = one(source, "from transition_v55 import native_assignments", "from transition_v56 import native_assignments")
    source = one(source, "import second169_status as retry", "import third169_status as retry")
    source = one(source, "import ram170_status as ram", "import ram170_status as ram\nimport ram170_second_status as second_ram")
    source = source.replace("V55_", "V56_").replace("FAILED166_CADENCE_V55", "FAILED166_CADENCE_V56")
    source = one(source, 'package"](55)', 'package"](56)')
    source = source.replace(derive56.OWNER, OWNER).replace(derive56.SEAL, SEAL)
    anchor = "    retry.receiver()"
    source = one(source, anchor, """    stop_ref = checked(retry.SCOPE)["second_guard_stop"]
    stop = checked(stop_ref)
    prior = fleet["current_private169_retry2"]
    need(prior["phase"] == "terminal" and prior["invocation_id"] == stop["invocation_id"]
         and prior["held"] == stop["held"] and prior["terminal"] == stop["terminal"],
         "different second epoch 169 terminal or held invocation")
""" + anchor)
    source = one(source, "    older = ram.history_config(fleet, cfg)", """    second_ram.contract.stopped_owner(fleet)
    older = ram.history_config(fleet, second_ram.history_config(fleet, cfg))""")
    return one(source, "private169_retry2_scope=retry.SCOPE, private169_retry2_cadence=retry.CADENCE,",
               """private169_retry3_scope=retry.SCOPE, private169_retry3_cadence=retry.CADENCE,
                                   retained_169_second_guard_stop=stop_ref,
                                   second_ram_gap170_interface=second_ram.INTERFACE,
                                   second_ram_gap170_receiver=bound(current / "ram170_second_status.py"),
                                   retained_170_first_ram_stop=second_ram.contract.STOP,
                                   retained_170_first_ram_drain=second_ram.contract.DRAIN,""")


def stage(folder):
    wire_path = HERE.parent / "horizon_epoch169_hourly_retry/third_wire.py"
    derive56.verified(wire_path, WIRE)
    wire = runpy.run_path(str(wire_path))
    ram_sources = HERE.parent / "horizon_epoch170_checkpoint_suffix"
    ram_derive = ram_sources / "derive_second_ram_writer.py"
    derive56.verified(ram_derive, "ed81412c4c6c2e051ddd5dfee2c5f39f5ec73b8c852a4fda3c4b9d07db21d99b")
    derive56.verified(ram_sources / "derive_ram170_writer.py", "322d9eeae9eef89a3a7a672e69f1a9e4fad75a62d8bf3e1ac5ca38d92d8de7bd")
    sys.path.insert(0, str(ram_sources))
    try:
        extend_ram = runpy.run_path(str(ram_derive))["cycle"]
    finally:
        sys.path.pop(0)
    folder.mkdir(mode=0o700)
    members = {}
    for directory, digest in ((OLD, SEAL), (RAM, RAM_SEAL)):
        seal = json.loads(derive56.verified(directory / "deployment-seal-receipt.json", digest))
        if Path(seal["destination"]) != directory:
            raise ValueError("unexpected package directory")
        for item in seal["members"]:
            name = item["name"]
            path = directory / name
            if path.parent != directory or name in members:
                raise ValueError("overlapping or out-of-scope package member")
            derive56.verified(path, item["sha256"])
            if name != "SHA256SUMS":
                members[name] = dict(name=name, source=str(path), mode=int(item["mode"], 8), sha256=item["sha256"])

    def add(name, source):
        ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), mode=0o444, sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text(), extend_ram))
    add("third169_status.py", wire["status"]((OLD / "second169_status.py").read_text()))
    add("split_wire.py", wire["wire"]((OLD / "split_wire.py").read_text()))
    add("transition_v57.py", transition((OLD / "transition_v56.py").read_text()))
    cutover = (OLD / "cutover56.py").read_text()
    for prefix in ("cutover", "v", "V"):
        cutover = cutover.replace(prefix + "56", prefix + "57").replace(prefix + "55", prefix + "56")
    add("cutover57.py", cutover.replace(derive56.OWNER, OWNER).replace(derive56.SEAL, SEAL))
    for name, count in (("full170_status.py", 1), ("cold170_status.py", 5), ("joint168_status.py", 3)):
        original = (OLD / name).read_text()
        marker = "'" + OLD.name + "')"
        if original.count(marker) != count:
            raise ValueError("different receiver list in " + name)
        add(name, original.replace(marker, "'" + OLD.name + "', '" + NEW.name + "')"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
