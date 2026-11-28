"""Bind the independently replayed tail to the signed checkpoint reached before the guard stop."""
from pathlib import Path

from evidence import BASE, checked, need

ROOT = BASE / "epoch170-from-73760367-20261128-v1"
UNIT = "horizon-qualify-170-from-73760367-20261128-v1.service"
INTERFACE = dict(path=str(ROOT / "GAP170_WRITER_INTERFACE.json"),
                 sha256="3f375caf9273b81cb84c5908695c27c0e4dbc6406f5ab53ebc1e1611ddf2a69f")
CHECKPOINT = dict(path=str(ROOT / "INDEPENDENT_CHECKPOINT.json"),
                  sha256="1031f72af7900560d972c0a4b0c50f5f42e0c548e883e0eafbe3eaa0dec1f4eb")
PREVIOUS = "c3ab30cfeb05428bb8f5c48a5a44822c"
PREVIOUS_FIELD = "current_private170_bounded_successor"


def interface():
    scope = checked(INTERFACE)
    proof = checked(CHECKPOINT)
    packet = checked(scope["source_packet"])
    preflight = checked(scope["source_preflight"])
    custody = checked(proof["bootstrap_payload"])
    stop = checked(proof["verified_original_stop"])
    need(scope["schema"] == "horizon-170-independent-hourly-gap-writer-interface-v1"
         and scope["independent_checkpoint"] == scope["handoff"] == CHECKPOINT
         and scope["expected_producer_unit"] == scope["profile"]["host_unit"] == UNIT
         and scope["expected_guard_unit"] == UNIT.replace("-qualify-", "-guard-")
         and scope["expected_guard_timer"] == scope["expected_guard_unit"].replace(".service", ".timer")
         and [scope["first_new_slot"], scope["last"]] == preflight["scope"] == [73760368, 73766969]
         and scope["bootstrap"] == proof["bootstrap_slot"] == 73760367
         and scope["profile"]["positions"] == packet["positions"] == 6602
         and scope["guard_seal"] == scope["profile"]["sealed_package"]
         and scope["guard_seal"]["sha256"] == "548549e25d74551f2705d084e8e9a674bb718dcc19daa7e2529867f225bb5deb"
         and scope["source_preflight"] == proof["native_preflight"]
         and scope["namespace"] == preflight["namespace"] and preflight["route_accepted"]
         and custody["sha256"] == packet["bootstrap_snapshot_sha256"] == "3e695997b1318c9e48c5da0f934bb55d21da47a254d3551a17ab3dec9745eda6"
         and scope["source_packet"] == proof["source_packet"]
         and scope["old_actor"] == proof["original_actor"] and scope["old_release"] == proof["original_release"]
         and stop["properties"]["InvocationID"] == PREVIOUS
         and (stop["properties"]["ExecMainCode"], stop["properties"]["ExecMainStatus"]) == ("2", "15")
         and proof["closed_segment"] is preflight["worker_executed"] is scope["publication_authorized"]
         is scope["admission_or_release"] is packet["predecessor_closed_segment_claimed"] is False,
         "different independent epoch 170 checkpoint or route")
    return scope


def checkpoint(scope):
    need(scope["independent_checkpoint"] == CHECKPOINT, "unregistered independent checkpoint")
    checked(CHECKPOINT)
    return CHECKPOINT


def stopped_owner(fleet):
    row = fleet[PREVIOUS_FIELD]
    scope = interface()
    need(row["phase"] == "terminal" and row["actor_ref"] == scope["old_actor"]
         and row["release"] == scope["old_release"]
         and row["actor"]["producer_invocation_id"] == row["native_terminal"]["INVOCATION_ID"] == PREVIOUS
         and row["native_terminal"]["UNIT"] == row["actor"]["unit"]
         and row["archive_publication_authorized"] is False,
         "epoch 170 gap needs its original retained guard stop")
    return row
