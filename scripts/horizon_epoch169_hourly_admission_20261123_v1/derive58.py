"""Carry the two enrolled 169/170 successors and add the second private epoch 162 interval."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import derive57
from derive49 import one
from derive56 import verified

OLD = derive57.NEW
NEW = OLD.with_name(OLD.name.replace("v57", "v58"))
OWNER = "f10024629bad19e4b9672c7f9179046b7945495c631aed6f83ba77d49066ebab"
SEAL = "1f036fc8b252edd3e8c43ba71a81195052d38757992978853d55504a5574a1a2"
SECOND = OLD.parent.parent / "epoch162-second-replay-20261128-v1"
OPERATOR = SECOND / "issued-split-v2"
ISSUED = "56a55825cbbf968f201a3dd80ce84de9de1919f515386f0e8e304527172342e2"
STATUS = "3bc86f44e200738558318e849a754220288a7429eb73b8f70f649f0168b1413a"
INTERFACE = "d9a729d6de6c940de696b1856ad148e41dcee00cbed91ee8b79afc5124c1df1c"
HERE = Path(__file__).resolve().parent


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 57)", ", 57, 58)")
    validation = "    elif FAILED166_VERSION == 57:\n        transition_v57.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, "V57_TRANSITION_VALIDATION")
    ordinary = ordinary.replace("FAILED166_VERSION == 57", "FAILED166_VERSION in (57, 58)")
    s = one(ordinary, "V57_TRANSITION_VALIDATION", validation.replace("57", "58") + "\n" + validation)
    s = one(s, "            import status162\n", """            import status162
            if FAILED166_VERSION == 58:
                import second162_route
                import transition_v58
""")
    s = one(s, "modules += [transition_v57, transition_v56.retry]", """modules += [transition_v57, transition_v56.retry]
                                        if FAILED166_VERSION == 58:
                                            modules += [transition_v58, second162_route, second162_route.second,
                                                        second162_route.second162_progress]""")
    for anchor, add in (
        ("                57: (transition_v57.V56_SHA, transition_v57.V56_SEAL),",
         "                58: (transition_v58.V57_SHA, transition_v58.V57_SEAL),"),
        ("                    57: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "                    58: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',")):
        s = one(s, anchor, anchor + "\n" + add)
    # This sealed program belongs to the V58 directory. Preserve the predecessor's
    # source modules by calling the appropriate receiver at its handful of dispatch points.
    for before, after in (
        ("c.split162 = frozen['capacity'].get(status162.FIELD)", "c.split162 = second162_route.frozen(frozen['capacity'])"),
        ("c.split162 = status162.observe(c, callback162)", "c.split162 = second162_route.observe(c, callback162)"),
        ("c.split162 = progress162.reconcile(c.split162, c.sample)", "c.split162 = second162_route.reconcile(c.split162, c.sample)"),
        ("status162.project(c, c.split162)", "second162_route.receiver(c.split162).project(c, c.split162)"),
        ("status162.recheck(c.fleet, c.split162)", "second162_route.recheck(c.fleet, c.split162)"),
        ("cap[status162.FIELD] = c.split162", "second162_route.save(cap, c.fleet, c.split162)"),
        ("status162.install(fleet, c.split162)", "second162_route.install(fleet, c.fleet, c.split162)"),
        ("initial162.baseline(c, refs.pop('162', None))", "second162_route.baseline(c, refs.pop('162', None))"),
        ("extra.update(status162.status_fields(c.split162))", "extra.update(second162_route.fields(c.fleet, c.split162))"),
        ("row['phase'] != 'terminal' or old.get('producer_invocation_id') is not None):",
         """row['phase'] != 'terminal' or old.get('producer_invocation_id') is not None
                or epoch == 162 and second162_route.receiver(row) is second162_route.second
                and old.get('private162_second_held') != row['held_owner']):"""),
        ("            forecast_row = progress162.wire_row(row) if FAILED166_VERSION in (52, 53, 54, 55, 56, 57, 58) and epoch == 162 else row\n            after,extra=split_wire.forecast(c,forecast_row,prior,old,original,delivery_eta.estimate)",
         "            forecast = second162_route.forecast if epoch == 162 else split_wire.forecast\n            after, extra = forecast(c, row, prior, old, original, delivery_eta.estimate)"),
    ):
        s = one(s, before, after)
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 57 and len(sys.argv) == 4")]
    if len(starts) != 4:
        raise ValueError("different 170 enrollment or V57 handoff commands")
    for start in reversed(starts):
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        lines.insert(start, "".join(lines[start:end]).replace("== 57", "== 58").replace("v57", "v58").replace("V57", "V58"))
    return s + "def main():" + "".join(lines)


def transition(source):
    s = one(source, "from transition_v56 import native_assignments as earlier_assignments",
            "from transition_v57 import native_assignments as earlier_assignments\nimport second162_route as route")
    a, b = s.index("def native_assignments("), s.index("def ready(")
    s = s[:a] + """def native_assignments(fleet):
    active, closed = earlier_assignments(route.earlier_fleet(fleet))
    # A 170 replacement can acquire its guarded process between scheduled fleets.
    gap = second_ram.gap
    prior_ram = second_ram.retained_population(fleet, checked(fleet["sole_next_observer"]))
    if not gap.ACTOR.exists():
        need(not prior_ram and not gap.RELEASE.exists(), "missing second 170 actor")
        gap.native.idle(gap.UNIT)
    else:
        ref, actor = gap.read_actor()
        need(not prior_ram or prior_ram["actor_ref"] == ref, "second 170 changed its held owner")
        manager = gap.native.props(gap.UNIT, gap.PROPS)
        iid = actor["producer_invocation_id"]
        if manager["ActiveState"] in ("inactive", "failed"):
            need(gap.terminal(actor)["INVOCATION_ID"] == iid, "second 170 terminal lacks its owner")
            closed[gap.UNIT] = iid
        else:
            scope = second_ram.interface()
            _, grant = gap.release(scope, ref, actor, second_ram.contract.checkpoint(scope))
            need(grant, "second 170 is between its gate and guarded release")
            _, worker, _ = gap.live(scope, manager, actor, True)
            gap.guard(scope, actor, worker, grant)
            active[gap.UNIT] = dict(unit=gap.UNIT, iid=iid, pid=manager["MainPID"], intent=ref)
    row = route.current(fleet)
    if route.receiver(row) is route.second:
        unit, iid = route.SECOND, row["producer_invocation_id"]
        if row["phase"] == "terminal":
            closed[unit] = iid
        else:
            active[unit] = dict(unit=unit, iid=iid, pid=str(row["actor"]["producer_pid"]), intent=row["held_owner"])
    return active, closed


""" + s[b:]
    s = s.replace("V56_", "V57_").replace("FAILED166_CADENCE_V56", "FAILED166_CADENCE_V57")
    s = one(s, 'package"](56)', 'package"](57)')
    s = s.replace(derive57.OWNER, OWNER).replace(derive57.SEAL, SEAL)
    anchor = "    assignments, closed = native_assignments(fleet)"
    s = one(s, anchor, """    scope = checked(route.SCOPE)
    second_operator = api["read_ref"](current / "second162_provider.json")
    native = route.second.api()
    need(native.scope() == scope and scope["previous"] == route.CUSTODY
         and scope["first_slot"] == 69991077 and scope["last_slot"] == 69998119,
         "second interval violates its retained first checkpoint")
    route.baseline(SimpleNamespace(fleet=fleet), checked(fleet["complete_active_status_audit"])["receipts"]["162"])
""" + anchor)
    s = one(s, "from pathlib import Path", "from pathlib import Path\nfrom types import SimpleNamespace")
    return one(s, "completed_sample=done, protected_private_assignments=assignments,",
               """completed_sample=done, protected_private_assignments=assignments,
                                   second162_provider=second_operator, second162_reader=bound(current / "second162_status.py"),
                                   second162_scope=route.SCOPE, second162_predecessor=route.CUSTODY,
                                   second162_wire=bound(current / "second162_route.py"),
                                   second162_progress=bound(current / "second162_progress.py"),""")


def stage(folder):
    plan = json.loads(verified(OLD / "deployment-seal-receipt.json", SEAL))
    issued = json.loads(verified(OPERATOR / "deployment-seal-receipt.json", ISSUED))
    interface = json.loads(verified(SECOND / "WRITER_INTERFACE_V2_CUSTODY.json", INTERFACE))
    if (Path(plan["destination"]) != OLD or Path(issued["destination"]) != OPERATOR
        or interface["operator"] != dict(path=str(OPERATOR / "deployment-seal-receipt.json"), sha256=ISSUED)
        or interface["second162_reader"] != dict(path=str(OPERATOR / "status162.py"), sha256=STATUS)
        or not any(m["name"] == "status162.py" and m["sha256"] == STATUS for m in issued["members"])):
        raise ValueError("unregistered writer or second operator")
    folder.mkdir(mode=0o700)
    members = {}
    for m in plan["members"]:
        name = m["name"]
        p = OLD / name
        if p.parent != OLD or name in members:
            raise ValueError("invalid incumbent member")
        verified(p, m["sha256"])
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(p), mode=int(m["mode"],8), sha256=m["sha256"])

    def add(name, source):
        if name.endswith(".py"):
            ast.parse(source, filename=name)
        p = folder / name
        p.write_text(source)
        p.chmod(0o444)
        members[name] = dict(name=name, source=str(p), mode=0o444, sha256=hashlib.sha256(p.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("transition_v58.py", transition((OLD / "transition_v57.py").read_text()))
    cut = (OLD / "cutover57.py").read_text()
    cut = re.sub(r"(cutover|[vV])(56|57)", lambda m: m[1] + str(int(m[2])+1), cut)
    add("cutover58.py", cut.replace(derive57.OWNER, OWNER).replace(derive57.SEAL, SEAL))
    for name, count in (("full170_status.py",1), ("cold170_status.py",5), ("joint168_status.py",3)):
        text = (OLD / name).read_text()
        anchor = repr(OLD.name) + ")"
        if text.count(anchor) != count:
            raise ValueError("unexpected receiver list in " + name)
        add(name, text.replace(anchor, repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    add("second162_status.py", verified(OPERATOR / "status162.py", STATUS).decode())
    add("second162_provider.json", json.dumps(interface["operator"],sort_keys=True) + "\n")
    add("second162_route.py", (HERE / "second162_route.py").read_text())
    prog = (OLD / "progress162.py").read_text()
    for before, after in (("horizon-qualify-162-first-hourly-completion-20261127-v2.service",interface["producer_unit"]),
                          ("/home/sol/.jetstreamer-private/epoch162-first-hourly-completion-20261127-v2/scratch",interface["scratch_path"]),
                          ("5be30fba437e03fc26f009247714986dfdc6670426650532b5ec166d67fc9183",interface["native_guard"]["sha256"]),
                          ("69_984_000 <= slot <= 69_991_076", "69_991_077 <= slot <= 69_998_119")):
        prog = one(prog, before, after)
    add("second162_progress.py", prog)
    wire = (OLD / "split_wire.py").read_text()
    wire = one(wire, "status_key=None, archive_reader=archive):",
               "status_key=None, archive_reader=archive, bounds=None, closed_predecessor=None):")
    wire = one(wire, "first, end = BOUNDS[epoch]", "first, end = bounds or BOUNDS[epoch]")
    wire = one(wire, "(previous['phase'] != 'replay' or same)", "(previous['phase'] != 'replay' or same or closed_predecessor is not None)")
    add("split_wire.py", wire)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
