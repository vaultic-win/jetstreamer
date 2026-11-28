"""Seal the next epoch 143 operator and common price from their exact predecessors."""

import ast
import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_v53 import member_plan


RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
SOURCE = Path(__file__).resolve().parent
OLD = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v29"
NEW = OLD.with_name("issued-price-v30")
OLD_SEAL = "67222929efde49b26a60c64a67c1f36b25f1d04524155048eb26b8273b3e3e1c"
V3 = RT / "epoch143-second-hourly-20261128-v3"
V4 = V3.with_name("epoch143-second-hourly-20261128-v4")
OPERATOR_SEAL = "a7376b0b72439a3c2d9567a930d846e994a12f3ea17fc1403812cd2703f38fd7"


def edit(files, name, transform):
    raw, mode = files[name]
    source = transform(raw.decode())
    ast.parse(source, filename=name)
    files[name] = (source.encode(), mode)


def price(stage, revision, scope):
    files = read_package(OLD, OLD_SEAL)
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        def move(source):
            if source.count(str(OLD)) != count:
                raise ValueError("different V29 self references for " + name)
            return source.replace(str(OLD), str(NEW))
        edit(files, name, move)

    def owner(source):
        source = source.replace(V3.name, V4.name).replace(
            "horizon-guard-143-second-hourly-20261128-v3", "horizon-guard-143-second-hourly-20261128-v4")
        source = change(source, '    stopped = bound(previous)', '''    held_stop = runpy.run_path(str(Path(__file__).with_name("held143_terminal.py")))
    unreleased = held_stop["closed"](core, require_unit_drain=native["ActiveState"] != "active")
    closure = dict(closure, second_held_floor_terminal=unreleased)
    stopped = bound(previous)''')
        source = change(source, 'and iid != stopped["invocation_id"]',
                        'and booking["held_stop"] == unreleased\n'
                        '         and iid not in (stopped["invocation_id"], held_stop["IID"])')
        return source

    def capacity(source):
        source = change(source, "'third162_price.py'}",
                        "'third162_price.py','held143_terminal.py','price143_held_tree.py'}")
        return change(source, """    protected = runpy.run_path(str(STOPPED.parent / 'price143_floor_retry.py'))['protect'](core, custody)""",
                      f"""    dormant = None
    if not prep143 and not base["native"]["raw"]["replacement143"]:
        tree = runpy.run_path(str(STOPPED.parent / 'price143_held_tree.py'))
        dormant = tree["prestart"](core, {scope!r})
    protected = runpy.run_path(str(STOPPED.parent / 'price143_floor_retry.py'))['protect'](core, custody, dormant)""")

    def protect(source):
        source = change(source, "def protect(core, quote):", "def protect(core, quote, dormant=None):")
        line = '    guards = {unit: core.bound(ref) for unit, ref in raw["joint"]["guard_samples"].items()}'
        return change(source, line, """    if dormant is not None:
        core.need(candidate is None and 0 < dormant["physical_bytes"] < booked,
                  "dormant epoch 143 census cannot replace a live guard")
        remaining -= dormant["physical_bytes"]
    quote["epoch143_dormant_tree"] = dormant
""" + line)

    edit(files, "shared_hourly143.py", owner)
    edit(files, "capacity.py", capacity)
    edit(files, "price143_floor_retry.py", protect)
    for name in ("held143_terminal.py", "price143_held_tree.py"):
        files[name] = ((SOURCE / name).read_bytes(), 0o444)
    metadata = json.loads(files["SOURCE.json"][0])
    metadata.update(revision=revision, prior_shared_price=dict(
        path=str(OLD / "deployment-seal-receipt.json"), sha256=OLD_SEAL), epoch143_dormant_census=scope)
    files["SOURCE.json"] = ((json.dumps(metadata, indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, NEW)


def operator(stage):
    prior = V3 / "operator-v1"
    files = read_package(prior, OPERATOR_SEAL)

    def launch(source):
        source = source.replace(V3.name, V4.name).replace(
            "horizon-guard-143-second-hourly-20261128-v3", "horizon-guard-143-second-hourly-20261128-v4")
        source = source.replace("second_hourly143_floor_retry_contract", "second_hourly143_held_retry_contract")
        source = change(source, '    booking["floor_stop"] = contract["floor_stop"]',
                        '    booking["floor_stop"] = contract["floor_stop"]\n'
                        '    booking["held_stop"] = contract["held_stop"]')
        source = change(source, 'and closed["retained_ram"] == MEMORY + GIB',
                        'and closed["second_held_floor_terminal"] == booking["held_stop"]\n'
                        '         and closed["retained_ram"] == MEMORY + GIB')
        source = change(source, '''    floor = quote["epoch143_protected_sibling_floor"]
    need(0 < floor and quote["required_home"] <= floor + runway < quote["available_home"]
         and runway == TREE, "whole roster and the full candidate tree do not fit")''',
                        '''    occupied = quote["epoch143_dormant_tree"]["physical_bytes"]
    minimum = quote["epoch143_protected_sibling_floor"]
    floor = minimum + min(GIB, quote["home_margin"] // 4)
    need(0 < occupied < TREE and runway == TREE - occupied and 0 < minimum <= floor
         and quote["required_home"] <= minimum + runway <= floor + runway < quote["available_home"],
         "whole roster and the measured remaining candidate tree do not fit")
    booking["prestart_tree_physical_bytes"] = occupied
    booking["guard_floor_buffer_bytes"] = floor - minimum''')
        source = change(source, 'and not sample["root_physical_observation"]["exceeds_budget"], "protected held gate check failed")',
                        '''and not sample["root_physical_observation"]["exceeds_budget"], "protected held gate check failed")
        physical = sample["root_physical_observation"]
        need(physical["first"] == physical["second"] and not physical["first"]["vanished_entries"]
             and physical["conservative_physical_bytes"] == physical["first"]["physical_bytes"] == occupied,
             "native tree occupancy changed between dormant and protected held census")''')
        return change(source, 'and held["epoch143_protected_sibling_floor"] <= floor',
                      'and held["epoch143_protected_sibling_floor"] <= floor\n'
                      '             and held["epoch143_remaining_replay_home"] == runway')

    edit(files, "launch_second_hourly143.py", launch)
    return member_plan(files, stage, V4 / "operator-v1")


if __name__ == "__main__":
    mode, folder, *args = sys.argv[1:]
    if mode == "price":
        revision, scope_path = args
        result = price(Path(folder), revision, json.loads(Path(scope_path).read_bytes()))
    elif mode == "operator" and not args:
        result = operator(Path(folder))
    else:
        raise ValueError("expected price or operator derivation")
    print(json.dumps(result, indent=2))
