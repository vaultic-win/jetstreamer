"""Enroll the second private 169 gate and the RAM-backed 170 gap on the incumbent clock."""
import ast
import hashlib
import json
from pathlib import Path
import runpy
import sys

import derive55
from derive49 import one

HERE = Path(__file__).resolve().parent
OLD = derive55.NEW
NEW = OLD.with_name(OLD.name.replace("v55", "v56"))
SEAL = "3dec320015200b7714764f8b6615341ff041c9a41383da041609cc05a1851d0d"
OWNER = "991f2e7c65ebb299f14c6af9e9053ed6a0d1b2422a420df44f0b1eb4e07aaa91"
RAM = OLD.parent.parent / "epoch170-from-73760367-ram-20261128-v1/observer-modules-v1"
RAM_SEAL = "e94b0211cfa973e0ca708259c3ec7e611b5cfd6b831d27c9530167d96b3c8bee"
WIRE = "8ee51ed4f9ff16922b63952e0dee082b05a8dcffabc9757fe5fd7f7c3b88de67"


def verified(path, expected):
    raw = path.read_bytes()
    if path.resolve(strict=True) != path or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("changed input " + str(path))
    return raw


def cycle(source, ram):
    source = source.replace(", 55)", ", 55, 56)")
    begin = source.index("    if FAILED166_VERSION == 55 and len(sys.argv) == 4:")
    end = source.index("    if FAILED166_VERSION == 54 and len(sys.argv) == 4:", begin)
    original = source[begin:end]
    source = source[:begin] + "V56_ENTRIES\n" + source[end:]
    validation = "    elif FAILED166_VERSION == 55:\n        transition_v55.validate(globals(), ready, receipt)"
    source = one(source, validation, "V56_VALIDATION")
    source = source.replace("FAILED166_VERSION == 55", "FAILED166_VERSION in (55, 56)")
    source = one(source, "V56_ENTRIES\n", original.replace("55", "56") + original)
    source = one(source, "V56_VALIDATION", validation.replace("55", "56") + "\n" + validation)
    anchor = "                            import retry169_status"
    source = one(source, anchor, anchor + """
                            if FAILED166_VERSION == 56:
                                import transition_v56
                                import second169_status as retry169_status""")
    anchor = "                                modules += [transition_v55, retry169_status]"
    source = one(source, anchor, anchor + """
                                if FAILED166_VERSION == 56:
                                    modules += [transition_v56, transition_v55.retry]""")
    for anchor, added in [
        ("                55: (transition_v55.V54_SHA, transition_v55.V54_SEAL),",
         "                56: (transition_v56.V55_SHA, transition_v56.V55_SEAL),"),
        ("                    55: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "                    56: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ]:
        source = one(source, anchor, anchor + "\n" + added)
    return ram["cycle"](source)


def transition(source):
    source = one(source, "from transition_v53 import native_assignments as earlier_assignments",
                 "from transition_v55 import native_assignments as earlier_assignments")
    source = one(source, "import retry169_status as retry", "import second169_status as retry\nimport ram170_status as ram")
    source = source.replace("V54_", "V55_").replace("FAILED166_CADENCE_V54", "FAILED166_CADENCE_V55")
    source = source.replace('package"](54)', 'package"](55)').replace(derive55.V54_OWNER, OWNER).replace(derive55.V54_SEAL, SEAL)
    anchor = '    config = fleet["sole_next_observer"]'
    source = one(source, anchor, '''    first_stop = checked(checked(retry.SCOPE)["first_gate_closure"])
    first_gate = fleet["current_private169_retry"]
    need(first_gate["phase"] == "terminal" and first_gate["terminal"] == first_stop["terminal"]
         and first_gate["invocation_id"] == first_stop["invocation_id"], "unmatched first 169 gate")
    retry.receiver()
    ram.contract.stopped_owner(fleet)
''' + anchor)
    source = one(source, '    api["successor170_status"].retained_population(fleet, api["gap170_status"].history_config(fleet, cfg))',
                 '''    older = ram.history_config(fleet, cfg)
    api["successor170_status"].retained_population(fleet, api["gap170_status"].history_config(fleet, older))''')
    source = one(source, "private169_retry_scope=retry.SCOPE, private169_retry_cadence=retry.CADENCE,",
                 """private169_retry2_scope=retry.SCOPE, private169_retry2_cadence=retry.CADENCE,
                                   retained_169_first_gate=checked(retry.SCOPE)["first_gate_closure"],
                                   ram_gap170_interface=ram.INTERFACE, ram_gap170_receiver=bound(current / "ram170_status.py"),""")
    return source


def stage(folder, wire_path):
    verified(wire_path, WIRE)
    second = runpy.run_path(str(wire_path))
    ram = runpy.run_path(str(HERE.parent / "horizon_epoch170_checkpoint_suffix/derive_ram170_writer.py"))
    folder.mkdir(mode=0o700)
    members = {}
    for directory, digest in [(OLD, SEAL), (RAM, RAM_SEAL)]:
        meta = json.loads(verified(directory / "deployment-seal-receipt.json", digest))
        if meta["destination"] != str(directory):
            raise ValueError("foreign sealed directory")
        for item in meta["members"]:
            name = item["name"]
            path = directory / name
            if path.parent != directory:
                raise ValueError("invalid member")
            verified(path, item["sha256"])
            if name != "SHA256SUMS":
                members[name] = dict(name=name, source=str(path), mode=int(item["mode"], 8), sha256=item["sha256"])

    def add(name, source):
        ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), mode=0o444, sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text(), ram))
    cutover = (OLD / "cutover55.py").read_text()
    for prefix in ("cutover", "v", "V"):
        cutover = cutover.replace(prefix + "55", prefix + "56").replace(prefix + "54", prefix + "55")
    add("cutover56.py", cutover.replace(derive55.V54_OWNER, OWNER).replace(derive55.V54_SEAL, SEAL))
    add("transition_v56.py", transition((OLD / "transition_v55.py").read_text()))
    add("second169_status.py", second["status"]((OLD / "retry169_status.py").read_text()))
    add("split_wire.py", second["wire"]((OLD / "split_wire.py").read_text()))
    for name, count in (("full170_status.py", 1), ("cold170_status.py", 5), ("joint168_status.py", 3)):
        original = (OLD / name).read_text()
        anchor = "'" + OLD.name + "')"
        if original.count(anchor) != count:
            raise ValueError("different receiver list in " + name)
        add(name, original.replace(anchor, "'" + OLD.name + "', '" + NEW.name + "')"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()), indent=2))
