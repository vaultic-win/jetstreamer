"""Bind the next hourly epoch 170 receiver to the drained private predecessor."""
from pathlib import Path

from evidence import BASE, checked, need
import after_floor170_contract as previous

ROOT = BASE / "epoch170-from-73773645-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73773645-ram-20261128-v1.service"
PREVIOUS = "732e022b564c49e5890c4cd3a86b8169"
INTERFACE_DIGEST = None
INTERFACE = dict(path=str(ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json"), sha256=INTERFACE_DIGEST)
FIRST, LAST = 73_773_645, 73_780_397


def interface():
    scope = checked(INTERFACE)
    profile = scope["profile"]
    source = checked(scope["source_packet"])
    package = checked(profile["sealed_package"])
    layout = checked(scope["staged_layout"])
    preflight = checked(scope["source_preflight"])
    need(scope["schema"] == "horizon-170-next-hourly-writer-interface-v1"
         and scope["expected_producer_unit"] == profile["host_unit"] == UNIT
         and scope["expected_guard_unit"] == UNIT.replace("-qualify-", "-guard-")
         and scope["expected_guard_timer"] == scope["expected_guard_unit"].replace(".service", ".timer")
         and scope["bootstrap"] == source["endpoints"][0]["slot"] == FIRST
         and scope["first_new_slot"] == source["first"] == FIRST + 1
         and scope["last"] == source["last"] == LAST and source["positions"] == LAST - FIRST
         and scope["predecessor"] == layout["predecessor"] == source["predecessor"]
         and scope["retained_comparison"] == source["closed_comparison"]
         and scope["run"] == layout["directories"][2]["path"] == source["run"]
         and scope["previous_interface"] == previous.INTERFACE == source["previous"]
         and package["destination"] == str(ROOT/"package")
         and profile["sealed_package"] == scope["guard_seal"] == preflight["seal"]
         and profile["namespace"] == preflight["namespace"]
         and preflight["scope"] == [FIRST+1,LAST]
         and preflight["route_accepted"] and not preflight["worker_executed"]
         and scope["source_packet"] == preflight["source"]
         and scope["following_input"]["single_copy"]
         and scope["following_input"]["archive"] == source["bootstrap"]
         and scope["following_input"]["custody"] == source["bootstrap_custody"]
         and profile["producer_memory_bytes"] == 56 << 30
         and profile["scratch_noswap_tmpfs_bytes"] == 40 << 30
         and profile["new_home_total_bytes"] == 8 << 30
         and profile["new_control_bytes"] == 64 << 20
         and not scope["publication_authorized"], "different next-hourly source or qualification")
    return scope


def checkpoint(scope):
    ready = checked(scope["predecessor"])
    closure = checked(ready["custody"])
    drained = checked(ready["drain"])
    compare = checked(ready["closed_comparison"])
    point = compare["checkpoints"][-1]
    need(scope["retained_comparison"] == closure["comparison"] == ready["closed_comparison"]
         and drained["custody"] == ready["custody"]
         and drained["producer_drained"] and drained["guard_drained"] and drained["scratch_released"]
         and closure["bindings"]["invocation"] == PREVIOUS
         and closure["actual_terminal"] == point and point["slot"] == FIRST and point["slot_complete"]
         and all(point[key] == value for key,value in ready["actual_terminal"].items())
         and not drained["resource_credit_bytes"] and not closure["archive_publication_authorized"],
         "missing independently read and drained predecessor")
    return ready["closed_comparison"]


def stopped_owner(fleet):
    row = fleet["current_private170_after_floor"]
    scope = interface()
    closure = checked(checked(scope["predecessor"])["custody"])
    need(row["phase"] == "terminal" and row["interface"] == previous.INTERFACE
         and row["actor_ref"] == closure["bindings"]["actor"]
         and row["release"] == closure["bindings"]["release"]
         and row["unit"]["Id"] == previous.UNIT
         and row["native_terminal"] == closure["native_producer"]["producer"]
         and row["native_terminal"]["INVOCATION_ID"] == PREVIOUS
         and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"],
         "accepted fleet lost the drained predecessor")
    return row
