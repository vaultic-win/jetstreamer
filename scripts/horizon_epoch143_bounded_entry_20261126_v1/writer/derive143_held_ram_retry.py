"""Carry the held RAM terminal into V32 and the adjacent epoch 143 operator."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_held_retry import RT, V4, edit
from derive143_v53 import member_plan


SOURCE = Path(__file__).resolve().parent
V5 = V4.with_name("epoch143-second-hourly-20261128-v5")
OLD = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v31"
NEW = OLD.with_name("issued-price-v32")
OLD_SEAL = "0950cbf45b59881553fa21d5fac776b512746481f9e8c8365fe6e00342816f86"
OPERATOR_SEAL = "bc991de2a62de90045fd1c3dc74fcb57d658023b085d99f7ca8c89b0c6a0045f"


def scope(source):
    return source.replace(V4.name, V5.name).replace(
        "horizon-guard-143-second-hourly-20261128-v4", "horizon-guard-143-second-hourly-20261128-v5")


def price(stage, revision, new_census):
    files = read_package(OLD, OLD_SEAL)
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        def move(source):
            if source.count(str(OLD)) != count:
                raise ValueError("different V31 self references for " + name)
            return source.replace(str(OLD), str(NEW))
        edit(files, name, move)

    def owner(source):
        source = scope(source)
        source = change(source, "    stopped = bound(previous)", '''    ram_stop = runpy.run_path(str(Path(__file__).with_name("held143_ram_terminal.py")))
    refused = ram_stop["closed"](core, require_unit_drain=native["ActiveState"] != "active")
    closure = dict(closure, second_held_ram_terminal=refused)
    stopped = bound(previous)''')
        return change(source, 'and iid not in (stopped["invocation_id"], held_stop["IID"])',
                      'and booking["held_ram_stop"] == refused\n'
                      '         and iid not in (stopped["invocation_id"], held_stop["IID"], ram_stop["IID"])')

    metadata = json.loads(files["SOURCE.json"][0])
    old_census = metadata["epoch143_dormant_census"]

    def capacity(source):
        source = change(source, "'held143_terminal.py','price143_held_tree.py'}",
                        "'held143_terminal.py','price143_held_tree.py','held143_ram_terminal.py'}")
        return change(source, repr(old_census), repr(new_census))

    edit(files, "shared_hourly143.py", owner)
    edit(files, "capacity.py", capacity)
    files["held143_ram_terminal.py"] = ((SOURCE / "held143_ram_terminal.py").read_bytes(), 0o444)
    metadata.update(revision=revision, prior_shared_price=dict(
        path=str(OLD / "deployment-seal-receipt.json"), sha256=OLD_SEAL),
        epoch143_dormant_census=new_census)
    files["SOURCE.json"] = ((json.dumps(metadata, indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, NEW)


def operator(stage):
    files = read_package(V4 / "operator-v1", OPERATOR_SEAL)

    def launch(source):
        source = scope(source).replace("second_hourly143_held_retry_contract", "second_hourly143_held_ram_retry_contract")
        source = change(source, '    booking["held_stop"] = contract["held_stop"]',
                        '    booking["held_stop"] = contract["held_stop"]\n'
                        '    booking["held_ram_stop"] = contract["held_ram_stop"]')
        return change(source, 'and closed["second_held_floor_terminal"] == booking["held_stop"]',
                      'and closed["second_held_floor_terminal"] == booking["held_stop"]\n'
                      '         and closed["second_held_ram_terminal"] == booking["held_ram_stop"]')

    edit(files, "launch_second_hourly143.py", launch)
    return member_plan(files, stage, V5 / "operator-v1")


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
