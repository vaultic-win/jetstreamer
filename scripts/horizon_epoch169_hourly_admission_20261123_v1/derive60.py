"""Enroll the replacement for the stopped second epoch 162 gate on the V59 clock."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import derive59
from derive49 import one
from derive56 import verified

OLD = derive59.NEW
NEW = OLD.with_name(OLD.name.replace("v59", "v60"))
OWNER = "40de245ea6f29f9b8fb7a9f603fdb5a7fbb2e5d45be1ec8b8f3d5175f935b638"
SEAL = "6dc55b32864dddb27365e15d0160b771c5e7bd31b640fee556ce9ce7d0f65f93"
SECOND = OLD.parent.parent / "epoch162-second-replay-20261128-v2"
INTERFACE = "c010fe101d3edafb732bbf87f7f8de7fd41a11d9b8b967e14ac5a4f372a8e279"


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 59)", ", 59, 60)")
    validation = "    elif FAILED166_VERSION == 59:\n        transition_v59.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, "PRIOR_TRANSITION")
    ordinary = ordinary.replace("FAILED166_VERSION == 59", "FAILED166_VERSION in (59, 60)")
    ordinary = one(ordinary, "PRIOR_TRANSITION", validation.replace("59", "60") + "\n" + validation)
    marker = "                import second162_route\n"
    ordinary = one(ordinary, marker, marker + "                original162_route = second162_route\n")
    marker = "                    import fourth169_status as retry169_status"
    ordinary = one(ordinary, marker, marker + """
                    if FAILED166_VERSION == 60:
                        import second162_retry_route as second162_route
                        import transition_v60""")
    ordinary = one(ordinary, "modules += [transition_v58, second162_route, second162_route.second,\n                                                        second162_route.second162_progress]",
                   "modules += [transition_v58, original162_route, original162_route.second,\n                                                        original162_route.second162_progress]")
    marker = "modules += [transition_v59, transition_v58.retry]"
    ordinary = one(ordinary, marker, marker + """
                                                if FAILED166_VERSION == 60:
                                                    modules += [transition_v60, second162_route, second162_route.second, second162_route.progress]""")
    ordinary = one(ordinary, "or epoch == 162 and second162_route.receiver(row) is second162_route.second\n                and old.get('private162_second_held') != row['held_owner']",
                   "or epoch == 162 and second162_route.changed_turnover(row, old)")
    for anchor, addition in (
        ("59: (transition_v59.V58_SHA, transition_v59.V58_SEAL),", "60: (transition_v60.V59_SHA, transition_v60.V59_SEAL),"),
        ("59: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "60: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        line, = (line for line in ordinary.splitlines() if line.strip() == anchor)
        ordinary = one(ordinary, line, line + "\n" + line.replace(anchor, addition))
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 59 and len(sys.argv) == 4")]
    if len(starts) != 4:
        raise ValueError("unexpected predecessor handoff commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 59", "== 60").replace("v59", "v60").replace("V59", "V60"))
    return ordinary + "def main():" + "".join(lines)


def transition(source):
    source = one(source, "from transition_v58 import native_assignments as earlier_assignments",
                 "from transition_v59 import native_assignments as earlier_assignments\nimport second162_retry_route as retry162")
    source = source.replace("V58_", "V59_").replace("FAILED166_CADENCE_V58", "FAILED166_CADENCE_V59")
    source = one(source, 'package"](58)', 'package"](59)')
    source = source.replace(derive59.OWNER, OWNER).replace(derive59.SEAL, SEAL)
    start, end = source.index("def native_assignments("), source.index("def ready(")
    source = source[:start] + """def native_assignments(fleet):
    earlier = retry162.previous(fleet)
    active, closed = earlier_assignments(retry162.earlier_fleet(fleet))
    need(closed.get(route.SECOND) == earlier["producer_invocation_id"] == retry162.PRIOR,
         "earlier 162 closure is missing from native owners")
    row = retry162.second.current(fleet)
    if row:
        unit, iid = row["unit"]["Id"], row["producer_invocation_id"]
        need(retry162.receiver(row) is retry162.second, "wrong retry unit")
        if row["phase"] == "terminal":
            closed[unit] = iid
        else:
            active[unit] = dict(unit=unit, iid=iid, pid=str(row["actor"]["producer_pid"]), intent=row["held_owner"])
    return active, closed


""" + source[end:]
    marker = "    assignments, closed = native_assignments(fleet)"
    source = one(source, marker, """    interface = checked(retry162.INTERFACE)
    retry_layout = retry162.second.api()
    need(interface["scope"] == retry162.SCOPE and interface["closure"] == retry162.CLOSED
         and interface["immutable_predecessor"] == route.CUSTODY and retry_layout.scope()["unreleased_predecessor"] == retry162.CLOSED
         and retry_layout.UNIT == interface["unit"] == retry162.SECOND
         and interface["provider"] == api["read_ref"](current / "second162_retry_provider.json")
         and interface["reader"]["sha256"] == bound(current / "second162_retry_status.py")["sha256"],
         "unregistered retry for the second 162 interval")
""" + marker)
    marker = "                                   second162_progress=bound(current / \"second162_progress.py\"),"
    return one(source, marker, marker + """
                                   second162_retry_provider=interface["provider"], second162_retry_reader=bound(current / "second162_retry_status.py"),
                                   second162_retry_scope=retry162.SCOPE, second162_retry_predecessor=retry162.CLOSED,
                                   second162_retry_wire=bound(current / "second162_retry_route.py"),
                                   second162_retry_progress=bound(current / "second162_retry_progress.py"),""")


def stage(folder):
    plan = json.loads(verified(OLD / "deployment-seal-receipt.json", SEAL))
    interface = json.loads(verified(SECOND / "RETRY_INTERFACE.json", INTERFACE))
    if Path(plan["destination"]) != OLD or interface["unit"] != "horizon-qualify-162-second-replay-20261128-v2.service":
        raise ValueError("wrong V59 or interval-two retry")
    folder.mkdir(mode=0o700)
    members = {}
    for member in plan["members"]:
        name = member["name"]
        p = OLD / name
        if p.parent != OLD or name in members:
            raise ValueError("invalid V59 package member")
        verified(p, member["sha256"])
        if name != "SHA256SUMS":
            members[name] = dict(name=name, mode=int(member["mode"], 8), source=str(p), sha256=member["sha256"])

    def add(name, source):
        if name.endswith(".py"):
            ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, mode=0o444, source=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("transition_v60.py", transition((OLD / "transition_v59.py").read_text()))
    add("second162_retry_route.py", Path(__file__).with_name("second162_retry_route.py").read_text())
    reader = interface["reader"]
    add("second162_retry_status.py", verified(Path(reader["path"]), reader["sha256"]).decode())
    add("second162_retry_provider.json", json.dumps(interface["provider"], sort_keys=True) + "\n")
    progress = (OLD / "second162_progress.py").read_text()
    if progress.count("162-second-replay-20261128-v1") != 2:
        raise ValueError("different interval guard or scratch")
    progress = progress.replace("162-second-replay-20261128-v1", "162-second-replay-20261128-v2")
    add("second162_retry_progress.py", one(progress, "55f4db7ab1e892f193704af39d7f3ace9f8fe5179983f10f1fcf18ac50919053", interface["guard"]["sha256"]))
    cutover = (OLD / "cutover59.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(58|59)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    add("cutover60.py", cutover.replace(derive59.OWNER, OWNER).replace(derive59.SEAL, SEAL))
    for name, count in (("full170_status.py",1), ("cold170_status.py",5), ("joint168_status.py",3)):
        source = (OLD / name).read_text()
        marker = repr(OLD.name) + ")"
        if source.count(marker) != count:
            raise ValueError("unexpected installed package list in " + name)
        add(name, source.replace(marker, repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
