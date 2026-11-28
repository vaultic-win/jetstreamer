"""Recheck the drained epoch 143 gate whose fresh held RAM screen refused it."""

from pathlib import Path


BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-hourly-20261128-v4")
UNIT = "horizon-qualify-143-second-hourly-20261128-v2.service"
GUARD = "horizon-guard-143-second-hourly-20261128-v4"
IID = "e38ddabfcde14b09b7d180f7108612d4"
TERMINAL = dict(path=str(BASE / f"held-stop-{IID}/TERMINAL.json"),
                sha256="9306f06cd9e920f10e4bd626c2a5cd1a254200e44af901e7ccbbc5b4eca1a422")


def closed(core, require_unit_drain=True):
    need, state, checked = (core[key] for key in ("need", "state", "bound"))
    terminal = checked(TERMINAL)
    owner = checked(terminal["prior_held"])
    plan = checked(terminal["guard_plan"])
    before = checked(terminal["prestart_screen"])
    after = checked(terminal["held_screen"])
    actor = after["base_169"]["native"]["raw"]["replacement143"]
    need(terminal["schema"] == "horizon-epoch143-second-hourly-held-ram-refusal-v1"
         and terminal["unit"] == owner["unit"] == plan["unit"] == UNIT
         and terminal["invocation_id"] == owner["producer_invocation_id"] == plan["invocation_id"] == actor["iid"] == IID
         and terminal["booking"] == owner["booking"] and terminal["contract"] == owner["contract"]
         and terminal["prior_held"] == actor["actor"] and actor["mode"] == "gate"
         and terminal["release_absent"] and not terminal["replay_started"] and terminal["output_absent"]
         and terminal["segment_manifest_absent"] and not terminal["resource_credit_bytes"]
         and not terminal["archive_publication_authorized"] and not (BASE / "barrier/allow").exists()
         and before["fits"] and not after["fits"] and before["home_margin"] > 0 and after["home_margin"] > 0
         and before["ram_margin"] == terminal["prestart_ram_margin"] > 0
         and after["ram_margin"] == terminal["held_ram_margin"] < 0
         and after["epoch143_protected_sibling_floor"] == terminal["held_required_floor"]
         <= after["epoch143_installed_guard_floor"] == terminal["installed_guard_floor"] == plan["minimum_free_bytes"]
         and before["epoch143_remaining_replay_home"] == after["epoch143_remaining_replay_home"],
         "epoch 143 held RAM refusal changed")
    units = {UNIT, GUARD + ".timer", GUARD + ".service"}
    need(set(terminal["drain"]) == units, "incomplete epoch 143 held RAM drain")
    for unit in units:
        expected = dict(Id=unit, ActiveState="inactive", Job="")
        need(terminal["drain"][unit] == expected, "nonterminal held RAM stop")
        if require_unit_drain or unit != UNIT:
            need(state(unit, "Id,ActiveState,Job") == expected
                 and not Path("/sys/fs/cgroup/system.slice", unit).exists(),
                 "held RAM invocation still has a native owner")
    return TERMINAL
