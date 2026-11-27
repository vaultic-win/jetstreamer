"""Exercise the native entry checks and writer transition without taking the real lock."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace

NAME = "tools-cold168-retry5-failed166-v32-entry146"


def materialize(plan, private):
    baseline = json.loads(plan.read_bytes())
    local = private/NAME
    local.mkdir(mode=0o700)
    members = []
    for item in baseline["members"]:
        file = local/item["name"]
        data = Path(item["source"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"]
        file.write_bytes(data)
        file.chmod(item["mode"])
        members.append(dict(item, mode=f"{item['mode']:04o}", bytes=len(data)))
    receipt = local/"deployment-seal-receipt.json"
    receipt.write_text(json.dumps(dict(schema="jetstreamer-sealed-deployment-receipt-v1",
                                      destination=str(local),members=members)))
    receipt.chmod(0o444)
    return local


def load(package, private):
    source = package/"status_cycle.py"
    tree = ast.parse(source.read_text(),filename=str(source))
    select = next(node for node in tree.body if isinstance(node,ast.Assign)
                  and isinstance(node.targets[0],ast.Name) and node.targets[0].id == "FAILED166_VERSION")
    rule = ast.unparse(select.value)
    assert "CURRENT.parent == ROOT / failed166_package(version)" in rule
    select.value = ast.parse(rule.replace("CURRENT.parent == ROOT / failed166_package(version)",
                                         "CURRENT.parent.name == failed166_package(version)"), mode="eval").body
    module = ModuleType("private_v32_probe")
    module.__file__ = str(source)
    exec(compile(ast.fix_missing_locations(tree),str(source),"exec"),module.__dict__)
    assert module.FAILED166_VERSION == 32 and module.JOINT168_CADENCE and module.FULL146_CADENCE
    original = module.ROOT
    module.ROOT = private
    try:
        receipt = module.entry()
    finally:
        module.ROOT = original
    return module,receipt


def waiting_and_rejoin(module, receipt, private):
    api = vars(module)
    v32 = module.v32_transition
    accepted = module.BASE/"root031808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
    head = module.bound(accepted)
    assert head["sha256"] == v32.HEAD_SHA
    fleet = module.checked(head)
    original = module.bound(module.ROOT/"FAILED166_CADENCE_V31_ACTIVE.json")
    old = module.checked(original)["new"]
    config_ref = fleet["sole_next_observer"]
    config = module.sealed(config_ref)
    scheduled = fleet["sole_next_timer"]
    original_show = module.owners.show
    original_names = module.timer_names
    original_ticks = module.owners.ticks
    original_bound = module.bound
    original_durable = module.durable
    original_glob = module.BASE

    def show(unit, fields):
        if unit == scheduled:
            return dict(Id=scheduled, InvocationID="9"*32, ActiveState="active", SubState="waiting", Job="",
                        Triggers=scheduled.replace(".timer",".service"),
                        TimersCalendar=module.utc(config["not_before_utc"]).strftime("%F %T UTC"))
        if unit == scheduled.replace(".timer",".service"):
            return dict(ExecStart=f"{module.race166.NATIVE} {config_ref['path']} ")
        return original_show(unit,fields)

    def clocks():
        return [scheduled]

    module.owners.show = show
    module.timer_names = clocks
    try:
        ready = v32.ready(api,head,receipt)
        assert ready["config"] == config_ref and ready["completed_sample"] is None
        rejected = 0
        for field,value in (("timer","foreign.timer"),("config",head),("old_owner",receipt),
                            ("bounded167_admission",receipt),("full170_terminal",head)):
            try:
                v32.validate(api,dict(ready,**{field:value}),receipt)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError(field)
        module.timer_names = lambda: [scheduled,"foreign.timer"]
        try:
            v32.ready(api,head,receipt)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("second timer")
        module.timer_names = clocks

        # The installed fleet may have advanced since 03:18. Restrict only the
        # newest-head lookup to the fixture while retaining real receipt reads.
        class FleetFixture(type(original_glob)):
            def glob(self, pattern):
                assert pattern == "root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
                return iter([accepted])
        module.BASE = FleetFixture(original_glob)
        ready_path = private/"READY.json"
        active_path = private/"ACTIVE.json"
        module.durable(ready_path,ready)
        module.bound = lambda path: original_bound(ready_path if path == module.ROOT/"FAILED166_CADENCE_V32_READY.json" else path)
        def dry_durable(path, row):
            assert path == module.ROOT/"FAILED166_CADENCE_V32_ACTIVE.json"
            return original_durable(active_path,row)
        module.durable = dry_durable
        module.owners.ticks = lambda p: original_ticks(p) if p != old["pid"] else -1
        fd = os.open(old["lock"]["path"],os.O_RDONLY)
        try:
            state = dict(Id=module.CONTROLLER,ActiveState="active",Job="",InvocationID="v32-fixture")
            resumed = module.rejoin_failed166_cadence(state,receipt,fd)
        finally:
            os.close(fd)
        assert resumed == ready and module.checked(original_bound(active_path))["old"] == old
    finally:
        module.owners.show = original_show
        module.timer_names = original_names
        module.owners.ticks = original_ticks
        module.bound = original_bound
        module.durable = original_durable
        module.BASE = original_glob
    return fleet,rejected,ready


def coexist(module, fleet):
    receiver = module.bounded167_status
    joint = module.joint168_status
    prior = fleet[joint.FIELD]
    retained = fleet[module.cold167_status.TERMINAL_FIELD]
    cfg = module.sealed(fleet["sole_next_observer"])
    assert joint.retained_population(fleet,cfg) == prior
    for phase in ("held","bootstrap","worker","terminal"):
        row = dict(epoch=167,unit={"Id":receiver.UNIT},phase=phase,
                   observer_config={"range":"167","producer_unit":receiver.UNIT} if phase=="worker" else None)
        context = SimpleNamespace(next_cfg=dict(cfg))
        receiver.project(context,row)
        assert [x["range"] for x in context.next_cfg["replays"]] == [x["range"] for x in cfg["replays"]]
        fit = dict(fleet)
        fit["actual_active_private_diagnostics"] = list(fleet["actual_active_private_diagnostics"])
        receiver.install(fit,row)
        native = phase != "terminal"
        assert len(fit["actual_active_private_diagnostics"]) == len(fleet["actual_active_private_diagnostics"]) + native
        assert fit["active_producer_count"] == fleet["active_producer_count"] + native
        assert fit[module.cold167_status.TERMINAL_FIELD] == retained
        assert fit[joint.FIELD] == prior
    return list(cfg["replays"])


def joint_exit(module,fleet,private):
    joint = module.joint168_status
    prior = fleet[joint.FIELD]
    ref = prior["enrollment"]
    enrolled = module.checked(ref)
    actor = enrolled["actor"]
    cfg = module.sealed(fleet["sole_next_observer"])
    native = {
        "_PID":"1","_UID":"0","UNIT":joint.lane.UNIT,"INVOCATION_ID":actor["invocation_id"],
        "_BOOT_ID":actor["boot_id"].replace("-",""), "MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448",
        "__REALTIME_TIMESTAMP":str((actor["ready_at"]+1)*1_000_000),
    }
    proof = dict(schema="horizon-epoch168-joint-reduced-terminal-v1",enrollment=ref,
                 producer_invocation_id=actor["invocation_id"],producer_pid=actor["pid"],
                 producer_start_ticks=actor["start_ticks"],disposition="checkpoint-complete",
                 resource_credit_bytes=0,archive_publication_authorized=False,remote_mutations=False,
                 private_output_preserved=True,pid1_terminal_event=native,independent_archive_scan_pending=True)
    old_terminal,old_idle,old_ticks = joint.TERMINAL,joint.lane.require_idle,joint.ticks
    root = private/"terminal-fixtures"
    root.mkdir(mode=0o700)
    good, wrong = root/"terminal.json", root/"crossed.json"
    module.durable(good,proof)
    module.durable(wrong,dict(proof,pid1_terminal_event=dict(native,INVOCATION_ID="f"*32)))
    joint.lane.require_idle = lambda reader: None
    joint.ticks = lambda pid: -1
    try:
        joint.TERMINAL = wrong
        try:
            joint.after_genuine_exit(fleet,cfg)
        except ValueError:
            pass
        else:
            raise AssertionError("joint terminal crossed producer invocation")
        joint.TERMINAL = good
        after = joint.after_genuine_exit(fleet,cfg)
        assert after["replays"] == cfg["replays"]
        assert after["previous_sample"] == cfg["previous_sample"]
        assert after["not_before_utc"] == cfg["not_before_utc"]
        assert after["output"] == cfg["output"]
        assert len(after["diagnostic_replays"]) == len(cfg["diagnostic_replays"])-1
        assert all(item["producer_unit"] != joint.lane.UNIT for item in after["diagnostic_replays"])
        assert joint.retained_population(fleet,after) == prior
        context = SimpleNamespace(next_cfg=dict(cfg))
        terminal = dict(prior,phase="terminal",observer_config=None,terminal=module.bound(good))
        joint.project(context,terminal)
        assert context.next_cfg["diagnostic_replays"] == after["diagnostic_replays"]
        installed = dict(fleet, actual_active_private_diagnostics=[])
        joint.install(installed,terminal)
        assert installed[joint.FIELD]["terminal"] == module.bound(good)
        assert not installed["actual_active_private_diagnostics"]
        assert installed["active_producer_count"] == fleet["active_producer_count"]
    finally:
        joint.TERMINAL,joint.lane.require_idle,joint.ticks = old_terminal,old_idle,old_ticks
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plan",type=Path)
    parser.add_argument("private",type=Path)
    args = parser.parse_args()
    args.private = args.private.resolve()
    args.private.mkdir(mode=0o700)
    package = materialize(args.plan,args.private)
    module,receipt = load(package,args.private)
    fleet,rejected,ready = waiting_and_rejoin(module,receipt,args.private)
    preserved = [row["range"] for row in coexist(module,fleet)]
    terminal = joint_exit(module,fleet,args.private)
    current = max(module.BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda path: path.stat().st_mtime_ns)
    native = module.v32_transition.ready(vars(module),module.bound(current),receipt)
    print(json.dumps(dict(entry=receipt, ready=ready["config"], timer=ready["timer"],
                          negative_handoffs=rejected, ordinary_replays=preserved,
                          checked_historical_167=True, private_phases_checked=4, joint_terminal_checked=terminal,
                          native_ready_clock=native["timer"],native_ready_fleet=native["fleet"],production_clock_changes=0),sort_keys=True))


if __name__ == "__main__":
    main()
