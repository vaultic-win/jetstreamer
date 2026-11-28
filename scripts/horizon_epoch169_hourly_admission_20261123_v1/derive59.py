"""Enroll the fourth private epoch 169 attempt on the V58 observation clock."""
import ast
import hashlib
import json
from pathlib import Path
import re
import runpy
import sys

import derive58
from derive49 import one
from derive56 import verified

OLD = derive58.NEW
NEW = OLD.with_name(OLD.name.replace("v58", "v59"))
OWNER = "9de8300faf6c23becf091d8031596e1dfa2ffc6ab8ff6e7d845902c3a33db074"
SEAL = "6bf38918e0bdba1849ccbd4a4d1969395ff44230da7ac83f9f860c07dde67754"
WIRE = "b181071a88bb2cd79aa73710b905f37e611e636ef3a64116dad6a3b689663de1"


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 58)", ", 58, 59)")
    validation = "    elif FAILED166_VERSION == 58:\n        transition_v58.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, "INCUMBENT_VALIDATION")
    ordinary = ordinary.replace("FAILED166_VERSION == 58", "FAILED166_VERSION in (58, 59)")
    ordinary = one(ordinary, "INCUMBENT_VALIDATION", validation.replace("58", "59") + "\n" + validation)
    marker = "                import transition_v58\n"
    ordinary = one(ordinary, marker, marker + """                if FAILED166_VERSION == 59:
                    import transition_v59
                    import fourth169_status as retry169_status
""")
    marker = "                                                        second162_route.second162_progress]"
    ordinary = one(ordinary, marker, marker + """
                                            if FAILED166_VERSION == 59:
                                                modules += [transition_v59, transition_v58.retry]""")
    for anchor, addition in (
        ("58: (transition_v58.V57_SHA, transition_v58.V57_SEAL),",
         "59: (transition_v59.V58_SHA, transition_v59.V58_SEAL),"),
        ("58: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "59: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        line, = (line for line in ordinary.splitlines() if line.strip() == anchor)
        ordinary = one(ordinary, line, line + "\n" + line.replace(anchor, addition))
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 58 and len(sys.argv) == 4")]
    if len(starts) != 4:
        raise ValueError("different V58 handoff or enrollment commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 58", "== 59").replace("v58", "v59").replace("V58", "V59"))
    return ordinary + "def main():" + "".join(lines)


def transition(source):
    source = one(source, "from transition_v57 import native_assignments as earlier_assignments",
                 "from transition_v58 import native_assignments as earlier_assignments\nimport fourth169_status as fourth")
    source = source.replace("V57_", "V58_").replace("FAILED166_CADENCE_V57", "FAILED166_CADENCE_V58")
    source = one(source, 'package"](57)', 'package"](58)')
    source = source.replace(derive58.OWNER, OWNER).replace(derive58.SEAL, SEAL)
    start, end = source.index("def native_assignments("), source.index("def ready(")
    source = source[:start] + """def native_assignments(fleet):
    observed = fourth.receiver()["observe"]
    parent, custody = observed.closed_parent(fleet)
    need(custody == checked(fourth.SCOPE)["third_unreleased"]
         and parent["phase"] == "terminal", "different third 169 closure")
    active, closed = earlier_assignments(observed.predecessor_view(fleet))
    need(closed.get(retry.UNIT) == parent["invocation_id"], "third 169 owner missing from protected roster")
    row = observed.current(fleet)
    if row and row["phase"] == "terminal":
        closed[fourth.UNIT] = row["invocation_id"]
    elif row:
        active[fourth.UNIT] = dict(unit=fourth.UNIT, iid=row["invocation_id"],
                                   pid=str(row["actor"]["producer_pid"]), intent=row["intent"])
    return active, closed


""" + source[end:]
    marker = "private169_retry3_scope=retry.SCOPE, private169_retry3_cadence=retry.CADENCE,"
    return one(source, marker, marker + """
                                   private169_retry4_scope=fourth.SCOPE, private169_retry4_cadence=fourth.CADENCE,
                                   retained_169_third_unreleased=checked(fourth.SCOPE)["third_unreleased"],""")


def stage(folder):
    plan = json.loads(verified(OLD / "deployment-seal-receipt.json", SEAL))
    if Path(plan["destination"]) != OLD:
        raise ValueError("different V58 writer")
    path = Path(__file__).resolve().parent.parent / "horizon_epoch169_hourly_retry" / "fourth_wire.py"
    verified(path, WIRE)
    wire = runpy.run_path(str(path))
    folder.mkdir(mode=0o700)
    members = {}
    for member in plan["members"]:
        name = member["name"]
        p = OLD / name
        if p.parent != OLD or name in members:
            raise ValueError("invalid V58 package member")
        verified(p, member["sha256"])
        if name != "SHA256SUMS":
            members[name] = dict(name=name, mode=int(member["mode"], 8), source=str(p), sha256=member["sha256"])

    def add(name, source):
        ast.parse(source, filename=name)
        dst = folder / name
        dst.write_text(source)
        dst.chmod(0o444)
        members[name] = dict(name=name, mode=0o444, source=str(dst), sha256=hashlib.sha256(dst.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("fourth169_status.py", wire["status"]((OLD / "third169_status.py").read_text()))
    add("split_wire.py", wire["wire"]((OLD / "split_wire.py").read_text()))
    add("transition_v59.py", transition((OLD / "transition_v58.py").read_text()))
    cutover = (OLD / "cutover58.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(57|58)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    add("cutover59.py", cutover.replace(derive58.OWNER, OWNER).replace(derive58.SEAL, SEAL))
    for name, count in (("full170_status.py",1), ("cold170_status.py",5), ("joint168_status.py",3)):
        source = (OLD / name).read_text()
        marker = repr(OLD.name) + ")"
        if source.count(marker) != count:
            raise ValueError("unexpected installed writer list in " + name)
        add(name, source.replace(marker, repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
