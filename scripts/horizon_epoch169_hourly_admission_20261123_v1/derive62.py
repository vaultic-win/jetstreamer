"""Enroll the replacement for the stopped second epoch 162 gate on the V61 clock."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import derive61
from derive49 import one
from derive56 import verified

OLD = derive61.NEW
NEW = OLD.with_name(OLD.name.replace("v61", "v62"))
OWNER = "2c3903ff7579026e93c659c57cc8cb7b0342cd838c7fb6be85b77e033515ebb5"
SEAL = "71d71c0d6b635e60e6a009090a94159ea47dbfe3061bd8885982050d3ecd553c"
SECOND = OLD.parent.parent / "epoch162-second-replay-20261128-v3"
INTERFACE = "ff09a7c8a45f6135b64bb25ce7fdea65e78ea71331afd29503baf8c3ad393dcb"


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 61)", ", 61, 62)")
    validation = "    elif FAILED166_VERSION == 61:\n        transition_v61.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, "PRIOR_TRANSITION")
    ordinary = ordinary.replace("FAILED166_VERSION == 61", "FAILED166_VERSION in (61, 62)")
    ordinary = one(ordinary, "PRIOR_TRANSITION", validation.replace("61", "62") + "\n" + validation)
    marker = "                        import second162_retry_route as second162_route"
    ordinary = one(ordinary, marker, marker + "\n                        retry162_route = second162_route")
    marker = "                            import ram170_third_status"
    ordinary = one(ordinary, marker, marker + """
                            if FAILED166_VERSION == 62:
                                import second162_reserved_route as second162_route
                                import transition_v62""")
    ordinary = one(ordinary, "[transition_v60, second162_route, second162_route.second, second162_route.progress]",
                   "[transition_v60, retry162_route, retry162_route.second, retry162_route.progress]")
    marker = "modules += [transition_v61, ram170_third_status, ram170_third_status.contract, ram170_third_status.gap, ram170_third_status.gap.workspace]"
    ordinary = one(ordinary, marker, marker + """
                                                        if FAILED166_VERSION == 62:
                                                            modules += [transition_v62, second162_route, second162_route.second, second162_route.progress]""")
    for anchor, addition in (
        ("61: (transition_v61.V60_SHA, transition_v61.V60_SEAL),", "62: (transition_v62.V61_SHA, transition_v62.V61_SEAL),"),
        ("61: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "62: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        line, = (line for line in ordinary.splitlines() if line.strip() == anchor)
        ordinary = one(ordinary, line, line + "\n" + line.replace(anchor, addition))
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 61 and len(sys.argv) == 4")]
    if len(starts) != 5:
        raise ValueError("unexpected predecessor handoff commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        lines.insert(start, block.replace("== 61", "== 62").replace("v61", "v62").replace("V61", "V62"))
    return ordinary + "def main():" + "".join(lines)


def transition(source):
    source = one(source, "from transition_v60 import native_assignments as earlier_assignments",
                 "from transition_v61 import native_assignments as earlier_assignments\nimport second162_reserved_route as reserved")
    source = source.replace("V60_", "V61_").replace("FAILED166_CADENCE_V60", "FAILED166_CADENCE_V61")
    source = one(source, 'package"](60)', 'package"](61)')
    source = source.replace(derive61.OWNER, OWNER).replace(derive61.SEAL, SEAL)
    a,b = source.index("def native_assignments("), source.index("def ready(")
    source = source[:a] + """def native_assignments(fleet):
    earlier = reserved.previous(fleet)
    before = reserved.earlier_fleet(fleet)
    active, closed = earlier_assignments(before)
    need(closed.get(retry162.SECOND) == earlier["producer_invocation_id"] == reserved.PRIOR,
         "earlier 162 postguard closure is missing from native owners")
    row = reserved.second.current(fleet)
    if row:
        unit, iid = row["unit"]["Id"], row["producer_invocation_id"]
        need(reserved.receiver(row) is reserved.second, "wrong 162 reserved attempt")
        if row["phase"] == "terminal":
            closed[unit] = iid
        else:
            active[unit] = dict(unit=unit, iid=iid, pid=str(row["actor"]["producer_pid"]), intent=row["held_owner"])
    gap = third_ram.gap
    if gap.ACTOR.exists():
        actor_ref, actor = gap.read_actor()
        manager = gap.native.props(gap.UNIT, gap.PROPS)
        iid = actor["producer_invocation_id"]
        if manager["ActiveState"] in ("inactive", "failed"):
            need(gap.terminal(actor)["INVOCATION_ID"] == iid, "third 170 lacks its own closure")
            active.pop(gap.UNIT, None)
            closed[gap.UNIT] = iid
        else:
            scope = third_ram.interface()
            _, grant = gap.release(scope, actor_ref, actor, third_ram.contract.checkpoint(scope))
            need(grant, "third 170 is crossing release")
            _, worker, _ = gap.live(scope, manager, actor, True)
            gap.guard(scope, actor, worker, grant)
            active[gap.UNIT] = dict(unit=gap.UNIT, iid=iid, pid=manager["MainPID"], intent=actor_ref)
    return active, closed


""" + source[b:]
    marker = "    assignments, closed = native_assignments(fleet)"
    source = one(source, marker, """    fresh = checked(reserved.INTERFACE)
    layouts = reserved.second.api()
    need(fresh["scope"] == reserved.SCOPE and layouts.scope()["postguard_predecessor"] == fresh["closure"] == reserved.CLOSED
         and layouts.scope()["previous"] == reserved.CUSTODY and fresh["previous_interface"] == retry162.INTERFACE
         and layouts.UNIT == fresh["unit"] == reserved.SECOND
         and fresh["provider"] == api["read_ref"](current / "second162_reserved_provider.json")
         and fresh["reader"]["sha256"] == bound(current / "second162_reserved_status.py")["sha256"],
         "unregistered reserved 162 issuer")
""" + marker)
    anchor = '                                   second162_retry_progress=bound(current / "second162_retry_progress.py"),'
    return one(source, anchor, anchor + """
                                   second162_reserved_provider=fresh["provider"], second162_reserved_reader=bound(current / "second162_reserved_status.py"),
                                   second162_reserved_scope=reserved.SCOPE, second162_reserved_predecessor=reserved.CLOSED,
                                   second162_reserved_progress=bound(current / "second162_reserved_progress.py"), second162_reserved_wire=bound(current / "second162_reserved_route.py"),""")


def stage(folder):
    plan = json.loads(verified(OLD / "deployment-seal-receipt.json", SEAL))
    interface = json.loads(verified(SECOND / "INTERFACE.json", INTERFACE))
    if Path(plan["destination"]) != OLD or interface["unit"] != "horizon-qualify-162-second-replay-20261128-v3.service":
        raise ValueError("wrong V61 or interval-two retry")
    validation = interface["guard_validation"]
    actual = json.loads(verified(Path(validation["path"]), validation["sha256"]))
    if (actual["guard"] != interface["guard"]["sha256"]
            or [case["exit"] for case in actual["cases"]] != [0, 1, 1, 1]):
        raise ValueError("unqualified service guard")
    folder.mkdir(mode=0o700)
    members = {}
    for member in plan["members"]:
        name = member["name"]
        p = OLD / name
        if p.parent != OLD or name in members:
            raise ValueError("invalid V61 package member")
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
    add("transition_v62.py", transition((OLD / "transition_v61.py").read_text()))
    add("second162_reserved_route.py", Path(__file__).with_name("second162_reserved_route.py").read_text())
    reader = interface["reader"]
    add("second162_reserved_status.py", verified(Path(reader["path"]), reader["sha256"]).decode())
    add("second162_reserved_provider.json", json.dumps(interface["provider"], sort_keys=True) + "\n")
    progress = (OLD / "second162_retry_progress.py").read_text()
    if progress.count("162-second-replay-20261128-v2") != 2:
        raise ValueError("different interval guard or scratch")
    progress = progress.replace("162-second-replay-20261128-v2", "162-second-replay-20261128-v3")
    add("second162_reserved_progress.py", one(progress, "6c66c053a29cf45e5b17715aeba3ee263c7324e16bcd41494956599ffd6724e6", interface["guard"]["sha256"]))
    cutover = (OLD / "cutover61.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(60|61)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    add("cutover62.py", cutover.replace(derive61.OWNER, OWNER).replace(derive61.SEAL, SEAL))
    for name, count in (("full170_status.py",1), ("cold170_status.py",5), ("joint168_status.py",3)):
        source = (OLD / name).read_text()
        marker = repr(OLD.name) + ")"
        if source.count(marker) != count:
            raise ValueError("unexpected installed package list in " + name)
        add(name, source.replace(marker, repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
