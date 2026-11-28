"""Carry both stopped RAM recordings forward and enroll the third private epoch 170 scope."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import derive60
from derive49 import one
from derive56 import verified


OLD = derive60.NEW
NEW = OLD.with_name(OLD.name.replace("v60", "v61"))
ROOT = OLD.parent.parent / "epoch170-from-73760367-ram-20261128-v3"
INTERFACE = "b148b13e8ef0bfff8bb40992eb267068668dac71590908806fe6ded15dff7151"
MODULES = "1eac71ad427b6f67421199403e8f6782823d0052e98aec9793b7a7497f3ae0e3"
OWNER = "b76c15f318f3ed7ecc8eec98bc35f1eee88afe92e203f0b74e614dcfb41c0d6c"
SEAL = "1b9bcdd883e2ce78d33573eafc7a458f7a61c4f5f192fbef5fac1f0817fccc9b"


def cycle(source):
    ordinary, commands = source.split("def main():", 1)
    ordinary = ordinary.replace(", 60)", ", 60, 61)")
    validation = "    elif FAILED166_VERSION == 60:\n        transition_v60.validate(globals(), ready, receipt)"
    ordinary = one(ordinary, validation, "EXISTING_V60_VALIDATOR")
    ordinary = ordinary.replace("FAILED166_VERSION == 60", "FAILED166_VERSION in (60, 61)")
    ordinary = one(ordinary, "EXISTING_V60_VALIDATOR", validation.replace("60", "61") + "\n" + validation)

    def after(anchor, addition):
        nonlocal ordinary
        ordinary = one(ordinary, anchor, anchor + "\n" + addition)

    after("                        import transition_v60", """                        if FAILED166_VERSION == 61:
                            import transition_v61
                            import ram170_third_status""")
    for old, new in (
        ("60: (transition_v60.V59_SHA, transition_v60.V59_SEAL),", "61: (transition_v61.V60_SHA, transition_v61.V60_SEAL),"),
        ("60: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "61: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        anchor, = (line for line in ordinary.splitlines() if line.strip() == old)
        after(anchor, anchor.replace(old, new))
    after("            extra.update(ram170_second_status.status_fields(c.second_ram_gap170))", """        if FAILED166_VERSION == 61 and epoch == 170 and c.third_ram_gap170:
            extra.update(ram170_third_status.status_fields(c.third_ram_gap170))""")
    ordinary = one(ordinary, "    second_ram_prior = None\n    ram_prior = None", "    third_ram_prior = None\n    second_ram_prior = None\n    ram_prior = None")
    ordinary = one(ordinary, "                second_ram_prior = ram170_second_status.retained_population(c.fleet,ram_cfg)", """                if FAILED166_VERSION == 61:
                    third_ram_prior = ram170_third_status.retained_population(c.fleet,ram_cfg)
                    ram_cfg = ram170_third_status.history_config(c.fleet,ram_cfg)
                second_ram_prior = ram170_second_status.retained_population(c.fleet,ram_cfg)""")
    ordinary = one(ordinary, "private_successor=second_ram_prior or", "private_successor=third_ram_prior or second_ram_prior or")
    ordinary = one(ordinary, "c.bridge170_prior = second_ram_prior or", "c.bridge170_prior = third_ram_prior or second_ram_prior or")
    after("        ram170_second_status.project(c,c.second_ram_gap170)", """    if FAILED166_VERSION == 61:
        c.third_ram_gap170 = ram170_third_status.observe(c,third_ram_prior,cycle.observed_lane)
        if ram170_third_status.active(c.third_ram_gap170):
            need(c.second_ram_gap170 and c.second_ram_gap170['phase']=='terminal' and c.ram_gap170 and c.ram_gap170['phase']=='terminal'
                 and c.gap170 and c.gap170['phase']=='terminal' and not bridge170_status.active(c.bridge170)
                 and not successor170_status.active(c.successor170) and '170' not in native_owners and 170 not in c.new_rows
                 and c.stopped170,'third 170 overlaps another private producer')
            if c.third_ram_gap170['phase'] != 'held':
                native_owners = dict(native_owners, third_ram_gap170=c.third_ram_gap170)
        ram170_third_status.project(c,c.third_ram_gap170)""")
    for anchor in ("ram170_second_status.recheck(c.second_ram_gap170)",
                   "if c.second_ram_gap170: cap[ram170_second_status.FIELD] = c.second_ram_gap170",
                   "diagnostic_count += int(ram170_second_status.active(c.second_ram_gap170))",
                   "ram170_second_status.install(fleet,c.second_ram_gap170)"):
        after("        " + anchor, "    if FAILED166_VERSION == 61:\n        " + anchor.replace("second", "third"))
    anchor = "modules += [transition_v60, second162_route, second162_route.second, second162_route.progress]"
    line, = (line for line in ordinary.splitlines() if line.strip() == anchor)
    after(line, line.replace(anchor, "if FAILED166_VERSION == 61:\n" + line[:line.index("modules")] +
                             "    modules += [transition_v61, ram170_third_status, ram170_third_status.contract, ram170_third_status.gap, ram170_third_status.gap.workspace]"))
    ordinary = one(ordinary, "            second_ram_prior = None\n            ram_prior = None", """            third_ram_prior = None
            second_ram_prior = None
            ram_prior = None
            if FAILED166_VERSION == 61:
                need(ready['third_ram_gap170_interface']==ram170_third_status.INTERFACE,'unregistered third RAM gap')
                third_ram_prior=ram170_third_status.retained_population(fleet,previous_cfg)
                previous_cfg=ram170_third_status.history_config(fleet,previous_cfg)""")
    ordinary = one(ordinary, "prior = second_ram_prior or ram_prior or gap_prior or older or prior",
                   "prior = third_ram_prior or second_ram_prior or ram_prior or gap_prior or older or prior")
    lines = commands.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("    if FAILED166_VERSION == 60 and len(sys.argv) == 4")]
    if len(starts) != 4:
        raise ValueError("unexpected V60 commands")
    for start in reversed(starts):
        end = next(i for i in range(start+1, len(lines)) if lines[i].strip() and not lines[i].startswith("        "))
        block = "".join(lines[start:end])
        new = block.replace("== 60", "== 61").replace("v60", "v61").replace("V60", "V61")
        lines.insert(start, new)
        if "--enroll-second-ram-gap-170" in block:
            lines.insert(start, new.replace("second-ram", "third-ram").replace("ram170_second_status", "ram170_third_status"))
    updated = ordinary + "def main():" + "".join(lines)
    ast.parse(updated)
    return updated


def transition(source):
    source = one(source, "from transition_v59 import native_assignments as earlier_assignments",
                 "from transition_v60 import native_assignments as earlier_assignments\nimport ram170_third_status as third_ram")
    source = source.replace("V59_", "V60_").replace("FAILED166_CADENCE_V59", "FAILED166_CADENCE_V60")
    source = one(source, 'package"](59)', 'package"](60)')
    source = source.replace(derive60.OWNER, OWNER).replace(derive60.SEAL, SEAL)
    start, finish = source.index("def native_assignments("), source.index("def ready(")
    source = source[:start] + """def native_assignments(fleet):
    active, closed = earlier_assignments(fleet)
    prior = third_ram.contract.stopped_owner(fleet)
    closed[second_ram.UNIT] = prior['actor']['producer_invocation_id']
    row = fleet.get(third_ram.FIELD)
    if row:
        need(row['unit']['Id'] == third_ram.UNIT and row['interface'] == third_ram.INTERFACE
             and row['actor_ref'] == bound(third_ram.gap.ACTOR), 'different third 170 assignment')
        iid = row['actor']['producer_invocation_id']
        if row['phase'] == 'terminal':
            need(row['native_terminal']['INVOCATION_ID'] == iid, 'different third 170 terminal')
            closed[third_ram.UNIT] = iid
        else:
            active[third_ram.UNIT] = dict(unit=third_ram.UNIT, iid=iid, pid=str(row['actor']['producer_pid']), intent=row['actor_ref'])
    return active, closed


""" + source[finish:]
    source = one(source, '    api["bridge170_status"].retained_population(fleet, cfg)',
                 '    effective = third_ram.history_config(fleet, cfg)\n    api["bridge170_status"].retained_population(fleet, effective)')
    source = one(source, "second_ram.history_config(fleet, cfg)", "second_ram.history_config(fleet, effective)")
    anchor = '                                   second_ram_gap170_interface=second_ram.INTERFACE,'
    return one(source, anchor, anchor + """
                                   third_ram_gap170_interface=third_ram.INTERFACE,
                                   third_ram_gap170_receiver=bound(current / "ram170_third_status.py"),
                                   retained_170_second_ram_stop=third_ram.contract.STOP,
                                   retained_170_second_ram_drain=third_ram.contract.DRAIN,""")


def stage(folder):
    price = json.loads(verified(ROOT / "RAM_GAP170_WRITER_INTERFACE.json", INTERFACE))
    directory = ROOT / "observer-modules-v1"
    modules = json.loads(verified(directory / "deployment-seal-receipt.json", MODULES))
    original = json.loads(verified(OLD / "deployment-seal-receipt.json", SEAL))
    if original["destination"] != str(OLD) or modules["destination"] != str(directory) or price["expected_producer_unit"] != "horizon-qualify-170-from-73760367-ram-20261128-v3.service":
        raise ValueError("unregistered cadence or epoch 170 receiver")
    folder.mkdir(mode=0o700)
    members = {}
    for member in original["members"]:
        name = member["name"]
        path = OLD / name
        if path.parent != OLD or name in members:
            raise ValueError("foreign V60 member")
        verified(path, member["sha256"])
        if name != "SHA256SUMS":
            members[name] = dict(name=name, mode=int(member["mode"],8), source=str(path), sha256=member["sha256"])
    for member in modules["members"]:
        name = member["name"]
        path = directory / name
        if path.parent != directory or name in members:
            raise ValueError("unexpected third receiver module")
        verified(path, member["sha256"])
        members[name] = dict(name=name, mode=0o444, source=str(path), sha256=member["sha256"])

    def add(name, source):
        ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, mode=0o444, source=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("transition_v61.py", transition((OLD / "transition_v60.py").read_text()))
    cutover = (OLD / "cutover60.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(59|60)", lambda m:m[1] + str(int(m[2])+1), cutover)
    add("cutover61.py", cutover.replace(derive60.OWNER, OWNER).replace(derive60.SEAL, SEAL))
    for name, count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        source = (OLD / name).read_text()
        marker = repr(OLD.name) + ")"
        if source.count(marker) != count:
            raise ValueError("unexpected package alternatives in " + name)
        add(name, source.replace(marker, repr(OLD.name) + ", " + repr(NEW.name) + ")"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(NEW),members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
