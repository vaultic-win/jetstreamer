"""Use the same stable native tree census before and during the held release."""

import json
from pathlib import Path
import subprocess


TREE = 64 << 30
ROOT = "/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1"
UNIT = "horizon-qualify-143-second-hourly-20261128-v2.service"


def occupied(need, sample):
    first, second = sample["first"], sample["second"]
    physical = sample["conservative_physical_bytes"]
    need(first == second and not first["vanished_entries"] and first["entries"] > 0
         and sample["maximum_physical_bytes"] == TREE and not sample["exceeds_budget"]
         and type(physical) is int and 0 < physical == first["physical_bytes"] < TREE,
         "epoch 143 did not have a stable complete physical tree census")
    return physical


def prestart(core, scope):
    state = dict(Id=UNIT, ActiveState="inactive", MainPID="0", ControlPID="0", Job="")
    before = core.state(UNIT, "Id,ActiveState,MainPID,ControlPID,Job")
    core.need(before == state and not Path("/sys/fs/cgroup/system.slice", UNIT).exists(),
              "epoch 143 tree census requires the producer to be drained")
    plan, guard = scope["plan"], scope["guard"]
    result = subprocess.run([guard["path"], plan["path"], "--plan-sha256", plan["sha256"],
                             "--self-sha256", guard["sha256"], "--measure-root-only"],
                            check=True, capture_output=True, text=True, timeout=35)
    measured = json.loads(result.stdout)
    core.need(measured["schema"] == "horizon-epoch143-dormant-tree-measurement-v1"
              and measured["unit"] == UNIT and measured["root"] == ROOT
              and measured["plan_sha256"] == plan["sha256"] and measured["self_sha256"] == guard["sha256"]
              and core.state(UNIT, "Id,ActiveState,MainPID,ControlPID,Job") == before
              and not Path("/sys/fs/cgroup/system.slice", UNIT).exists(),
              "epoch 143 native tree scope changed around the prestart census")
    return measured | {"physical_bytes": occupied(core.need, measured["observation"])}
