"""Bind the hourly recovery to its lost disk run and to the independently accepted previous segment."""
from pathlib import Path

from evidence import BASE, checked, need
import after_ram170_contract as previous

ROOT = BASE / "epoch170-from-73766969-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
PREVIOUS = "e589078414194de38fe902a9df0f5b0c"
INTERFACE_DIGEST = None
INTERFACE = dict(path=str(ROOT/"AFTER_FLOOR_WRITER_INTERFACE.json"), sha256=INTERFACE_DIGEST)
SOURCE = dict(path=str(ROOT/"package/hourly-source.json"),sha256="bccca71af4bf55f31aa9d1ed79dae2e2857167bbf26f77ae9e0bc96558df6491")
PACKAGE = dict(path=str(ROOT/"package/deployment-seal-receipt.json"),sha256="f7c2d3fa967b1a8a64fdaf04a13e4bca67e28917d5d8c887674109fb2b764edb")


def interface():
    scope = checked(INTERFACE)
    source = checked(SOURCE)
    stop, drain, retain = (checked(source[key]) for key in ("failed", "drain", "scratch_retirement"))
    entry, namespace = checked(scope["source_preflight"]), checked(scope["namespace"])
    profile = scope["profile"]
    original = previous.interface()
    first, last = source["endpoints"]
    need(scope["schema"] == "horizon-170-after-floor-hourly-writer-interface-v1"
         and scope["source_packet"] == SOURCE and scope["preceding_disk_interface"] == source["previous_scope"] == previous.INTERFACE
         and scope["stopped_custody"] == source["failed"] and scope["stopped_drain"] == source["drain"]
         and scope["scratch_retirement"] == source["scratch_retirement"] and scope["predecessor"] == source["predecessor"]
         and stop["producer_invocation_id"] == drain["invocation"] == retain["original_iid"] == PREVIOUS
         and stop["release"] == drain["release"] and stop["actor"] == drain["actor"] and drain["custody"] == source["failed"]
         and not stop["verified_complete_segment"] and not stop["terminal_checkpoint_accepted"]
         and drain["guard_drained"] and drain["producer_inactive"] and not drain["resource_credit_bytes"]
         and retain["scope_empty"] and not retain["archive_or_snapshot_removed"]
         and stop["partial"] == source["private_partial"] and stop["partial"]["bytes"] == 203066302
         and stop["partial"]["sha256"] == "8ffdbd7df6759ff9b6846b6325294898377afe71fcd7e0f8b10788c5d5662f45",
         "different stopped disk invocation, partial or retirement")
    need(scope["following_input"] == source["immutable_bootstrap"] == original["following_input"]
         and profile["bootstrap"] == scope["bootstrap"] == first["slot"] == 73766969
         and profile["first"] == scope["first_new_slot"] == source["first"] == first["slot"]+1
         and profile["last"] == scope["last"] == source["last"] == last["slot"] == 73773645
         and profile["positions"] == source["positions"] == last["slot"]-first["slot"]
         and profile["checkpoints"] == [last["name"]] and all(profile[k] == original["profile"][k] for k in
            ("node", "worker", "producer_cpu_quota_micros", "guard_cpu_quota_micros", "guard_memory_bytes"))
         and profile["host_unit"] == scope["expected_producer_unit"] == UNIT
         and scope["expected_guard_unit"] == UNIT.replace("-qualify-", "-guard-")
         and scope["expected_guard_timer"] == scope["expected_guard_unit"].replace(".service",".timer")
         and profile["sealed_package"] == entry["seal"] == namespace["seal"] == scope["guard_seal"] == PACKAGE
         and profile["producer_memory_bytes"] == 56<<30 and profile["scratch_noswap_tmpfs_bytes"] == 40<<30
         and profile["new_home_total_bytes"] == 8<<30 and profile["new_control_bytes"] == 64<<20
         and scope["namespace"] == entry["namespace"] == profile["namespace"] and namespace["unit"] == entry["service"]
         and scope["layout"] == namespace["layout"] == entry["layout"] and entry["scope"] == [source["first"],source["last"]]
         and not entry["worker_executed"] and entry["route_accepted"] and namespace["no_host_scratch_payload"]
         and namespace["report"]["limits"]["memory.max"] == str(56<<30) and namespace["report"]["scratch"]["bytes"] == 40<<30
         and not scope["admission_or_release"] and not scope["publication_authorized"], "different hourly worker or input")
    return scope


def checkpoint(scope):
    comparison = previous.closed_comparison(previous.interface())
    source = checked(SOURCE)
    terminal = checked(scope["predecessor"])["actual_terminal"]
    signed = checked(source["endpoints"][0]["vote"])
    need(comparison == scope["retained_comparison"] == checked(scope["predecessor"])["comparison"]
         and terminal == checked(scope["stopped_custody"])["matched_bootstrap"] and terminal["slot_complete"]
         and all(terminal[k] == signed[k] for k in ("slot", "bank_hash", "last_blockhash")),
         "invalid completed predecessor or bootstrap")
    return comparison


def stopped_owner(fleet):
    row = fleet["current_private170_after_ram"]
    previous.previous_owner(fleet)
    scope = interface()
    stopped = checked(scope["stopped_custody"])
    need(row["phase"] == "terminal" and row["interface"] == previous.INTERFACE
         and row["actor_ref"] == stopped["actor"] and row["release"] == stopped["release"]
         and row["unit"]["Id"] == row["native_terminal"]["UNIT"] == checked(stopped["actor"])["unit"]
         and row["native_terminal"]["INVOCATION_ID"] == PREVIOUS
         and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"],
         "accepted fleet does not retain the floor-stopped disk invocation")
    return row
