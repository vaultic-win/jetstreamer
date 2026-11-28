"""Validate the unreleased epoch 143 invocation before reusing its native unit."""

from pathlib import Path


BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-hourly-20261128-v3")
UNIT = "horizon-qualify-143-second-hourly-20261128-v2.service"
GUARD = "horizon-guard-143-second-hourly-20261128-v3"
IID = "73b04c4b19644244a5880631da917425"
TERMINAL = dict(path=str(BASE / f"held-stop-{IID}/TERMINAL.json"),
                sha256="589128efd24df747003f08e7a683ce2d2f8a8cedd0d6d5193c5cd4ef195388a6")


def closed(core, require_unit_drain=True):
    need, state, checked = (core[key] for key in ("need", "state", "bound"))
    terminal = checked(TERMINAL)
    owner = checked(terminal["prior_held"])
    before = checked(terminal["prestart_screen"])
    after = checked(terminal["held_screen"])
    plan = checked(terminal["guard_plan"])
    need(terminal["schema"] == "horizon-epoch143-second-hourly-held-floor-refusal-v1"
         and terminal["unit"] == owner["unit"] == plan["unit"] == UNIT
         and terminal["invocation_id"] == owner["producer_invocation_id"] == plan["invocation_id"] == IID
         and terminal["booking"] == owner["booking"] and terminal["contract"] == owner["contract"]
         and terminal["release_absent"] and not terminal["replay_started"] and terminal["output_absent"]
         and terminal["segment_manifest_absent"] and not terminal["resource_credit_bytes"]
         and not terminal["archive_publication_authorized"] and not (BASE / "barrier/allow").exists()
         and before["fits"] and after["fits"]
         and after["base_169"]["native"]["raw"]["replacement143"]["mode"] == "gate"
         and before["epoch143_protected_sibling_floor"] == after["epoch143_installed_guard_floor"]
         == plan["minimum_free_bytes"] == terminal["installed_guard_floor"]
         and after["epoch143_protected_sibling_floor"] == terminal["held_required_floor"]
         and terminal["held_required_floor"] - terminal["installed_guard_floor"] == terminal["floor_increase"] > 0,
         "epoch 143 held floor refusal changed")
    units = {UNIT, GUARD + ".timer", GUARD + ".service"}
    need(set(terminal["drain"]) == units, "incomplete held epoch 143 drain roster")
    for unit in units:
        expected = dict(Id=unit, ActiveState="inactive", Job="")
        need(terminal["drain"][unit] == expected, "nonterminal held epoch 143 stop")
        if require_unit_drain or unit != UNIT:
            need(state(unit, "Id,ActiveState,Job") == expected
                 and not Path("/sys/fs/cgroup/system.slice", unit).exists(),
                 "held epoch 143 invocation still has a native owner")
    return TERMINAL
