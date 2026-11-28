"""Price the clean restart while preserving both earlier epoch 143 terminals."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_v53 import member_plan

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
OLD = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v25"
NEW = OLD.with_name("issued-price-v26")
SEAL = "048aeffb71c0f777f60e4f131696f8f503e344d3b516ea375a4f057b574e2dc2"


def derive(stage, revision):
    files = read_package(OLD, SEAL)
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        raw, mode = files[name]
        source = raw.decode()
        if source.count(str(OLD)) != count:
            raise ValueError("different V25 self references for " + name)
        files[name] = (source.replace(str(OLD), str(NEW)).encode(), mode)

    raw, mode = files["shared_hourly143.py"]
    source = raw.decode().replace('SECOND = RT / "epoch143-second-hourly-20261128-v2"',
                                  'SECOND = RT / "epoch143-second-hourly-20261128-v3"')
    source = source.replace('GUARD = "horizon-guard-143-second-hourly-20261128-v2"',
                            'GUARD = "horizon-guard-143-second-hourly-20261128-v3"')
    source = change(source, '''    native = state(UNIT)
    if native["ActiveState"] == "inactive":
        need(native["MainPID"] == native["ControlPID"] == "0" and not native["Job"],
             "next epoch 143 has a pending native launch")
        if (SECOND / "HELD_OWNER.json").exists():
            floor_stop = runpy.run_path(str(Path(__file__).with_name("second143_floor_terminal.py")))
            return dict(closure, second_retry_floor_terminal=floor_stop["closed"](core)), None
        return closure, None''', '''    native = state(UNIT)
    floor_stop = runpy.run_path(str(Path(__file__).with_name("second143_floor_terminal.py")))
    previous = floor_stop["closed"](core, require_unit_drain=native["ActiveState"] != "active")
    closure = dict(closure, second_retry_floor_terminal=previous)
    stopped = bound(previous)
    saved = fleet["current_private143_second_hourly_retry"]
    need(saved["phase"] == "terminal" and saved["native_terminal"]["invocation_id"] == stopped["invocation_id"]
         and saved["native_terminal"]["cursor"] == stopped["pid1_cursor"]
         and saved["held_owner"] == stopped["prior_held"],
         "floor stop differs from the ordinary writer's retained invocation")
    if native["ActiveState"] == "inactive":
        need(native["MainPID"] == native["ControlPID"] == "0" and not native["Job"]
             and not (SECOND / "HELD_OWNER.json").exists(), "next epoch 143 requires an independent floor terminal")
        return closure, None''')
    source = change(source, 'and booking["failed_second_hourly"] == terminal',
                    'and booking["failed_second_hourly"] == terminal and booking["floor_stop"] == previous\n'
                    '         and iid != stopped["invocation_id"]')
    files["shared_hourly143.py"] = (source.encode(), mode)
    raw, mode = files["capacity.py"]
    source = change(raw.decode(), "'second143_floor_terminal.py'}",
                    "'second143_floor_terminal.py','price143_floor_retry.py'}")
    line = "    return runpy.run_path(str(STOPPED.parent / 'serial157_operator.py'))['account'](booked, core)"
    source = change(source, line, """    custody = runpy.run_path(str(STOPPED.parent / 'serial157_operator.py'))['account'](booked, core)
    return runpy.run_path(str(STOPPED.parent / 'price143_floor_retry.py'))['protect'](core, custody)""")
    files["capacity.py"] = (source.encode(), mode)
    files["price143_floor_retry.py"] = (Path(__file__).with_name("price143_floor_retry.py").read_bytes(), 0o444)
    metadata = json.loads(files["SOURCE.json"][0])
    metadata.update(revision=revision, prior_shared_price=dict(
        path=str(OLD / "deployment-seal-receipt.json"), sha256=SEAL))
    files["SOURCE.json"] = ((json.dumps(metadata, indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, NEW)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]), sys.argv[2]), indent=2))
