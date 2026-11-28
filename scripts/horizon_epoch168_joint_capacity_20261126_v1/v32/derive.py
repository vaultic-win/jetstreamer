"""Stage the V32 receiver from exact V31 sealed source and the merged 167 gate."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
V31_SEAL = "fce9080d3190e16d9353a594113d9ebb785d7f0be6f22c9e5c56f31e40f3240e"
GATE_SHA = "765935bd063d74b4aca3f3fe148dce72521b3749a787e77e10d8dbb680ddce9d"
OLD = "tools-cold168-retry5-failed166-v31-entry146"
NEW = "tools-cold168-retry5-failed166-v32-entry146"


def change(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"unexpected V31 baseline near {old.strip().splitlines()[0]}")
    return text.replace(old,new)


def status_cycle(text):
    text = re.sub(r", 31\)", ", 31, 32)", text)
    text = change(text, "if FAILED166_VERSION == 31:\n    import full170_terminal",
                  "if FAILED166_VERSION >= 31:\n    import full170_terminal\n\n"
                  "if FAILED166_VERSION == 32:\n    import bounded167_status\n    import transition as v32_transition")
    text = change(text,
                  "        c.failed167 = cold167_status.failed_route(c, cycle.observed_lane)\n    if FAILED166_VERSION == 31:",
                  """        bounded_prior = bounded167_status.retained_population(c.fleet, c.cfg) if FAILED166_VERSION == 32 else None
        c.failed167 = cold167_status.failed_route(c, cycle.observed_lane, private_successor=bounded_prior)
    if FAILED166_VERSION >= 31:""")
    text = change(text, "    if getattr(cold_workers, 'cold168', None):\n        cold_workers.cold168.census",
                  """    if FAILED166_VERSION == 32:
        c.bounded167 = bounded167_status.observe(c, cycle.observed_lane)
        if bounded167_status.active(c.bounded167):
            need('167' not in native_owners and 167 not in c.new_rows and c.failed167,
                 'private and canonical epoch 167 owners overlap')
            native_owners = dict(native_owners, bounded167=c.bounded167)
        bounded167_status.project(c, c.bounded167)
    if getattr(cold_workers, 'cold168', None):
        cold_workers.cold168.census""")
    text = change(text, "    if held170:\n        from full170_status import native",
                  """    if FAILED166_VERSION == 32:
        bounded167_status.recheck(c.bounded167)
    if held170:
        from full170_status import native""")
    text = change(text, "        cap[joint168_status.FIELD] = c.joint168\n    durable(path,witness)",
                  """        cap[joint168_status.FIELD] = c.joint168
    if FAILED166_VERSION == 32 and c.bounded167:
        cap[bounded167_status.FIELD] = c.bounded167
    durable(path,witness)""")
    text = change(text, "        diagnostic_count += int(c.joint168['phase'] != 'terminal')\n    original",
                  """        diagnostic_count += int(c.joint168['phase'] != 'terminal')
    if FAILED166_VERSION == 32:
        diagnostic_count += int(bounded167_status.active(c.bounded167))
    original""")
    text = change(text, "        joint168_status.install(fleet, c.joint168)\n    return fleet",
                  """        joint168_status.install(fleet, c.joint168)
    if FAILED166_VERSION == 32:
        bounded167_status.install(fleet, c.bounded167)
    return fleet""")
    text = change(text, "        if FAILED166_VERSION == 31:\n            names170 +=",
                  "        if FAILED166_VERSION >= 31:\n            names170 +=")
    text = change(text, "    return receipt\n\n", """    if FAILED166_VERSION == 32:
        for module in (bounded167_status, bounded167_status.route, v32_transition):
            source = Path(module.__file__)
            member, = (item for item in seal['members'] if item['name'] == source.name)
            need(source.parent == CURRENT.parent and member['mode'] == '0444'
                 and bound(source)['sha256'] == member['sha256'], 'unsealed V32 receiver member')
    return receipt

""")
    text = change(text, "        need(not timer_names(), 'retire the stale V30 recovery timer before V31 takes the clock')\n    else:",
                  """        need(not timer_names(), 'retire the stale V30 recovery timer before V31 takes the clock')
    elif FAILED166_VERSION == 32:
        v32_transition.validate(globals(), ready, receipt)
    else:""")
    text = change(text, "                31: ('ed73", """                32: (v32_transition.V31_SHA, v32_transition.V31_SEAL_SHA),
                31: ('ed73""")
    text = change(text, "                    31: 'fb9db", """                    32: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',
                    31: 'fb9db""")
    text = change(text, "    if FAILED166 and sys.argv[1:] == ['--check-failed166']:", """    if FAILED166_VERSION == 32 and len(sys.argv) == 4 and sys.argv[1] == '--check-v32-handoff':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        print(json.dumps(v32_transition.ready(globals(), head, receipt)))
        return
    if FAILED166 and sys.argv[1:] == ['--check-failed166']:""")
    text = change(text, "        replacement_ref=config(replacement,project(cfg,stamp(due),fleet['observer']))",
                  """        original = joint168_status.after_genuine_exit(fleet,cfg) if FAILED166_VERSION == 32 else cfg
        replacement_ref=config(replacement,project(original,stamp(due),fleet['observer']))""")
    return text


def joint_status(text):
    text = change(text, f"                   '{OLD}')", f"                   '{OLD}',\n                   '{NEW}')")
    text = change(text, "def retained_population(fleet, cfg):", """def after_genuine_exit(fleet, cfg):
    prior = fleet.get(FIELD)
    if not prior or prior['phase'] == 'terminal' or not TERMINAL.is_file():
        return cfg
    ref = prior['enrollment']
    terminal(ref, bound_at(ref,lane.ENROLLMENT), prior)
    assignments = cfg['diagnostic_replays']
    observed = [row for row in assignments if lane.UNIT in (row.get('producer_unit'),row.get('controller_unit'))]
    need(observed == ([prior['observer_config']] if prior['observer_config'] else []),
         'genuine joint exit differs from its immutable scheduled diagnostic')
    return dict(cfg, diagnostic_replays=[row for row in assignments if row not in observed])


def retained_population(fleet, cfg):""")
    text = change(text, """    need(prior['observer_config'] == expected and schedule == ([expected] if expected else []),""",
                  """    excluded_after_exit = (Path(__file__).parent.name == 'tools-cold168-retry5-failed166-v32-entry146'
                           and not schedule and expected is not None and TERMINAL.is_file())
    if excluded_after_exit:
        terminal(prior['enrollment'], enrolled, prior)
    need(prior['observer_config'] == expected and (excluded_after_exit or schedule == ([expected] if expected else [])),""")
    text = change(text, """    if manager['ActiveState'] in ('inactive','failed'):
        row.update(phase='terminal',terminal=terminal(ref,e,prior))""",
                  """    if manager['ActiveState'] in ('inactive','failed'):
        if Path(__file__).parent.name == 'tools-cold168-retry5-failed166-v32-entry146':
            deadline = time.monotonic()+90
            while not TERMINAL.is_file() and time.monotonic() < deadline:
                time.sleep(1)
        row.update(phase='terminal',terminal=terminal(ref,e,prior))""")
    return text


def cold167(text):
    text = change(text, "def failed_route(c, observed_lane):", "def failed_route(c, observed_lane, *, private_successor=None):")
    return change(text, """    rows = [row for key in ('actual_executing_replays','actual_active_bootstraps','actual_active_private_diagnostics')
            for row in c.fleet[key] if row['epoch'] == EPOCH]""",
                  """    rows = [row for key in ('actual_executing_replays','actual_active_bootstraps','actual_active_private_diagnostics')
            for row in c.fleet[key] if row['epoch'] == EPOCH
            and not (key == 'actual_active_private_diagnostics' and row == private_successor)]""")


def derive(members):
    members["status_cycle.py"] = status_cycle(members["status_cycle.py"].decode()).encode()
    members["cold167_status.py"] = cold167(members["cold167_status.py"].decode()).encode()
    members["joint168_status.py"] = joint_status(members["joint168_status.py"].decode()).encode()
    for name in ("full170_status.py","cold170_status.py"):
        data = members[name].decode()
        if name == "full170_status.py":
            data = change(data,f"'{OLD}')",f"'{OLD}', '{NEW}')")
        else:
            data = change(data,f"V31_PACKAGE = '{OLD}'",f"V31_PACKAGE = '{OLD}'\nV32_PACKAGE = '{NEW}'")
            data = data.replace("V31_PACKAGE)", "V31_PACKAGE, V32_PACKAGE)")
            data = data.replace("LOCAL.name == V31_PACKAGE", "LOCAL.name in (V31_PACKAGE, V32_PACKAGE)")
        members[name] = data.encode()
    return members


def stage(baseline, gate, staging):
    original = (baseline/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(original).hexdigest() != V31_SEAL:
        raise ValueError("expected actual immutable V31 package seal")
    receipt = json.loads(original)
    files = {}
    modes = {}
    for member in receipt["members"]:
        name = member["name"]
        if name in files or Path(name).name != name:
            raise ValueError("foreign V31 member")
        if name == "SHA256SUMS":
            continue
        data = (baseline/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError("V31 member digest changed: "+name)
        files[name] = data
        modes[name] = int(member["mode"],8)
    files = derive(files)
    if hashlib.sha256(gate.read_bytes()).hexdigest() != GATE_SHA:
        raise ValueError("different custody helper from the merged bounded 167 gate")
    for name, path in (("bounded167_status.py", HERE/"bounded167_status.py"),
                       ("transition.py", HERE/"transition.py"), ("bounded167_admission.py", gate)):
        files[name] = path.read_bytes()
        modes[name] = 0o444
    for name in files:
        if name.endswith(".py"):
            ast.parse(files[name], filename=name)
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
    parser.add_argument("gate", type=Path)
    parser.add_argument("staging", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.baseline,args.gate,args.staging),indent=2))
