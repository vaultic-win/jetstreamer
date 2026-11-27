"""Stage the V34 cadence from verified V33 while retaining its original receipted attempt."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
V33_SEAL = "7bd9c52b4b4aaa213be55937b5855ccff3057b873c1ecb245e46ea135643dee7"
OLD = "tools-cold168-retry5-failed166-v33-entry146"
NEW = "tools-cold168-retry5-failed166-v34-entry146"


def change(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"unexpected V33 baseline near {old.strip().splitlines()[0]}")
    return text.replace(old, new)


def status_cycle(text):
    text = re.sub(r", 33\)", ", 33, 34)", text)
    text = change(text, """if FAILED166_VERSION >= 32:
    import bounded167_status
    import transition as v32_transition

if FAILED166_VERSION == 33:
    import transition_v33""",
                  """if FAILED166_VERSION >= 32:
    import transition as v32_transition

if FAILED166_VERSION >= 33:
    import transition_v33

if FAILED166_VERSION == 34:
    import bounded167_status_v2 as bounded167_status
    import bounded167_v2_operator
    import transition_v34
    import bridge170_status
elif FAILED166_VERSION >= 32:
    import bounded167_status""")
    text = change(text, "    if FAILED166_VERSION >= 30:\n        bounded_prior =",
                  "    if FAILED166_VERSION == 34:\n"
                  "        c.bounded167_v1_terminal = bounded167_v2_operator.historical_terminal(c.fleet, c.cfg)\n"
                  "    if FAILED166_VERSION >= 30:\n        bounded_prior =")
    text = change(text, """    if FAILED166_VERSION >= 32 and c.bounded167:
        cap[bounded167_status.FIELD] = c.bounded167""",
                  """    if FAILED166_VERSION >= 32 and c.bounded167:
        cap[bounded167_status.FIELD] = c.bounded167
    if FAILED166_VERSION == 34:
        cap["retained_bounded167_v1_guard_terminal"] = c.bounded167_v1_terminal""")
    text = change(text, """    if FAILED166_VERSION >= 32:
        bounded167_status.install(fleet, c.bounded167)
    return fleet""",
                  """    if FAILED166_VERSION >= 32:
        bounded167_status.install(fleet, c.bounded167)
    if FAILED166_VERSION == 34:
        history = bounded167_v2_operator.HISTORY_FIELD
        fleet[history] = c.fleet[history]
        fleet["retained_bounded167_v1_guard_terminal"] = c.bounded167_v1_terminal
    return fleet""")
    text = change(text, """        modules = [bounded167_status, bounded167_status.route, v32_transition]
        if FAILED166_VERSION == 33:
            import bounded167_operator
            modules += [bounded167_operator, transition_v33]""",
                  """        modules = [bounded167_status, v32_transition]
        if FAILED166_VERSION == 34:
            modules += [bounded167_v2_operator, bounded167_v2_operator.historical,
                        transition_v33, transition_v34]
        else:
            modules.append(bounded167_status.route)
            if FAILED166_VERSION == 33:
                import bounded167_operator
                modules += [bounded167_operator, transition_v33]""")
    text = change(text, "    elif FAILED166_VERSION == 33:\n        transition_v33.validate",
                  "    elif FAILED166_VERSION == 34:\n        transition_v34.validate(globals(), ready, receipt)\n"
                  "    elif FAILED166_VERSION == 33:\n        transition_v33.validate")
    text = change(text, '    if FAILED166_VERSION >= 31:\n        c.stopped170 = full170_terminal.observe(c, v31_ready()[\'full170_terminal\'])',
                  """    bridge_prior = bridge170_status.retained_population(c.fleet, c.cfg) if FAILED166_VERSION == 34 else None
    if FAILED166_VERSION >= 31:
        c.stopped170 = full170_terminal.observe(c, v31_ready()['full170_terminal'], private_successor=bridge_prior)""")
    text = change(text, """        need(all(row['range'] != '170' for row in c.cfg['diagnostic_replays']),
             'settled epoch 170 diagnostic remained in the schedule')""",
                  """        if FAILED166_VERSION != 34:
            need(all(row['range'] != '170' for row in c.cfg['diagnostic_replays']),
                 'settled epoch 170 diagnostic remained in the schedule')""")
    text = change(text, """            native_owners = dict(native_owners, bounded167=c.bounded167)
        bounded167_status.project(c, c.bounded167)
    if getattr(cold_workers,""",
                  """            if c.bounded167['phase'] != 'held':
                native_owners = dict(native_owners, bounded167=c.bounded167)
        bounded167_status.project(c, c.bounded167)
    if FAILED166_VERSION == 34:
        c.bridge170 = bridge170_status.observe(c, bridge_prior, cycle.observed_lane)
        if bridge170_status.active(c.bridge170):
            need('170' not in native_owners and 170 not in c.new_rows and c.stopped170,
                 'private bridge and canonical epoch 170 owners overlap')
            if c.bridge170['phase'] != 'held':
                native_owners = dict(native_owners, bridge170=c.bridge170)
        bridge170_status.project(c, c.bridge170)
    if getattr(cold_workers,""")
    text = change(text, """        bounded167_status.recheck(c.bounded167)
    if held170:""", """        bounded167_status.recheck(c.bounded167)
    if FAILED166_VERSION == 34:
        bridge170_status.recheck(c.bridge170)
    if held170:""")
    text = change(text, """        cap["retained_bounded167_v1_guard_terminal"] = c.bounded167_v1_terminal""",
                  """        cap["retained_bounded167_v1_guard_terminal"] = c.bounded167_v1_terminal
        if c.bridge170:
            cap[bridge170_status.FIELD] = c.bridge170""")
    text = change(text, """        diagnostic_count += int(bounded167_status.active(c.bounded167))""",
                  """        diagnostic_count += int(bounded167_status.active(c.bounded167))
    if FAILED166_VERSION == 34:
        diagnostic_count += int(bridge170_status.active(c.bridge170))""")
    text = change(text, """        fleet["retained_bounded167_v1_guard_terminal"] = c.bounded167_v1_terminal""",
                  """        fleet["retained_bounded167_v1_guard_terminal"] = c.bounded167_v1_terminal
        bridge170_status.install(fleet, c.bridge170)""")
    text = change(text, """                        transition_v33, transition_v34]""",
                  """                        transition_v33, transition_v34, bridge170_status]""")
    row = "                33: (transition_v33.V32_SHA, transition_v33.V32_SEAL_SHA),"
    text = change(text, row, "                34: (transition_v34.V33_SHA, transition_v34.V33_SEAL_SHA),\n"+row)
    row = "                    33: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    text = change(text, row, row.replace("33:", "34:")+"\n"+row)
    cli = "    if FAILED166_VERSION == 33 and len(sys.argv) == 4 and sys.argv[1] == '--check-v33-handoff':"
    return change(text, cli, """    if FAILED166_VERSION == 34 and len(sys.argv) == 4 and sys.argv[1] == '--check-v34-handoff':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        print(json.dumps(transition_v34.ready(globals(), head, receipt)))
        return
"""+cli)


def retry167_status(text):
    text = change(text, """import bounded167_admission as route
from bounded167_operator import OPERATOR_SEAL, launched_intent, operator_image

FIELD = "current_bounded167_checkpoint"
""", """from bounded167_v2_operator import OPERATOR_SEAL, admitted_caps, launched_intent, load

route = load(bound(OPERATOR_SEAL))
FIELD = "current_bounded167_checkpoint_v2"
""")
    text = change(text, """    need(prior["bounded_cap_bytes"] == doc["bounded_cap_bytes"]
         and prior["armed_floor"] == doc["armed_floor"], "private 167 lost its original protection")""",
                  """    outside, baseline, run_cap, cap = admitted_caps(doc)
    need(prior["bounded_cap_bytes"] == cap and prior["run_guard_cap_bytes"] == run_cap
         and prior["retained_outside_run_bytes"] == outside and prior["run_baseline_physical_bytes"] == baseline
         and prior["armed_floor"] == doc["armed_floor"], "private 167 lost its original protection")""")
    text = change(text, """    floor, cap = intent["armed_floor"], intent["bounded_cap_bytes"]
""", """    outside, baseline, cap, whole_cap = admitted_caps(intent)
    floor = intent["armed_floor"]
""")
    text = change(text, 'and plan["worker_root"] == str(route.LANE)',
                  'and plan["worker_root"] == str(route.RUN)')
    text = change(text, """                 for key in ("first","second"))
         and (not protected""", """                 for key in ("first","second"))
         and lower >= baseline and outside+lower <= whole_cap
         and (not protected""")
    text = change(text, """                floor=floor, physical_bytes=lower, bounded_cap_bytes=cap), protected""",
                  """                floor=floor, physical_bytes=outside+lower, run_physical_bytes=lower,
                retained_outside_run_bytes=outside, run_baseline_physical_bytes=baseline,
                run_guard_cap_bytes=cap, bounded_cap_bytes=whole_cap), protected""")
    text = change(text, """    row = dict(epoch=167, unit=manager, actor=actor, intent=intent, release=release, observer=c.sample_ref,""",
                  """    outside, baseline, run_cap, whole_cap = admitted_caps(doc)
    row = dict(epoch=167, unit=manager, actor=actor, intent=intent, release=release, observer=c.sample_ref,""")
    return change(text, """               bounded_cap_bytes=doc["bounded_cap_bytes"], armed_floor=doc["armed_floor"],""",
                  """               bounded_cap_bytes=whole_cap, armed_floor=doc["armed_floor"],
               run_guard_cap_bytes=run_cap, retained_outside_run_bytes=outside, run_baseline_physical_bytes=baseline,""")


def joint_status(text):
    original = f"('tools-cold168-retry5-failed166-v32-entry146', '{OLD}')"
    if text.count(original) != 2:
        raise ValueError("unexpected V33 joint exit branches")
    text = text.replace(original, original[:-1]+f", '{NEW}')")
    # This tuple also admits complete V33 predecessor rows to V34.
    return change(text, f"                   'tools-cold168-retry5-failed166-v32-entry146', '{OLD}')",
                  f"                   'tools-cold168-retry5-failed166-v32-entry146', '{OLD}', '{NEW}')")


def cold170_status(text):
    text = change(text, f"V33_PACKAGE = '{OLD}'", f"V33_PACKAGE = '{OLD}'\nV34_PACKAGE = '{NEW}'")
    end = "V32_PACKAGE, V33_PACKAGE)"
    if text.count(end) != 5:
        raise ValueError("unexpected V33 epoch 170 receiver registrations")
    return text.replace(end, "V32_PACKAGE, V33_PACKAGE, V34_PACKAGE)")


def prior170_terminal(text):
    text = change(text, "def observe(c, ref):", "def observe(c, ref, *, private_successor=None):")
    return change(text, """            for row in c.fleet[key] if row['epoch'] == 170]""",
                  """            for row in c.fleet[key] if row['epoch'] == 170
            and not (key == 'actual_active_private_diagnostics' and row == private_successor)]""")


def stage(baseline, staging):
    original = (baseline/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(original).hexdigest() != V33_SEAL:
        raise ValueError("expected actual immutable V33 package seal")
    receipt = json.loads(original)
    files = {}
    modes = {}
    for member in receipt["members"]:
        name = member["name"]
        if name in files or Path(name).name != name:
            raise ValueError("foreign V33 member")
        if name == "SHA256SUMS":
            continue
        data = (baseline/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError("V33 member digest changed: "+name)
        files[name] = data
        modes[name] = int(member["mode"], 8)
    for name, patch in (("status_cycle.py", status_cycle), ("joint168_status.py", joint_status),
                        ("cold170_status.py", cold170_status), ("full170_terminal.py", prior170_terminal),
                        ("full170_status.py", lambda text: change(text, f"'{OLD}')", f"'{OLD}', '{NEW}')"))):
        files[name] = patch(files[name].decode()).encode()
    name = "bounded167_status_v2.py"
    files[name] = retry167_status(files["bounded167_status.py"].decode()).encode()
    modes[name] = 0o444
    for name in ("bounded167_v2_operator.py", "transition_v34.py", "bridge170_status.py"):
        files[name] = (HERE/name).read_bytes()
        modes[name] = 0o444
    for name, data in files.items():
        if name.endswith(".py"):
            ast.parse(data, filename=name)
    staging.mkdir(mode=0o700)
    rows = []
    for name, data in sorted(files.items()):
        target = staging/name
        target.write_bytes(data)
        target.chmod(modes[name])
        rows.append(dict(name=name, source=str(target.resolve(strict=True)), mode=modes[name],
                         sha256=hashlib.sha256(data).hexdigest()))
    destination = str(Path(receipt["destination"]).with_name(NEW))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=destination, members=rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("staging", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.baseline, args.staging), indent=2))
