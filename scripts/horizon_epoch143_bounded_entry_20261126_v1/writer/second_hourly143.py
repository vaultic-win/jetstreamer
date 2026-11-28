"""Enroll and observe the next private epoch 143 interval on the existing clock."""

import math
from pathlib import Path

import delivery_eta
from evidence import bound, checked, need, utc
from first_hourly143 import EPOCH143, FirstHourlyProfile, active, observe, recheck
import hourly143_status as first
from second_hourly143_scope import CONTRACT_SHA, NODE, PREFIX, TERMINAL
import split_wire


PROFILE = FirstHourlyProfile(
    143, bootstrap=EPOCH143.terminal, terminal=61_794_627, tree_gib=64, producer_ram_gib=40,
    contract_sha=CONTRACT_SHA, node=NODE, worker_sha=EPOCH143.worker_sha,
    interval="second", date="20261128",
)
PROGRESS = PROFILE.base / "FIRST_PROTECTED_PROGRESS.json"
PROGRESS_FIELD = "private143_second_first_progress"
ACTOR_FIELD = "private143_second_held"


def check_prefix(first_row):
    accepted = checked(PREFIX)
    need(first_row["phase"] == "terminal" and first_row["held_owner"] == first.HELD
         and accepted["producer_invocation_id"] == first_row["actor"]["producer_invocation_id"]
         and accepted["terminal_slot"] == EPOCH143.terminal
         and accepted["bindings"]["actor"] == first_row["held_owner"]
         and accepted["native_terminal"] == TERMINAL
         and checked(TERMINAL)["properties"]["Result"] == "success"
         and not accepted["resource_credit_bytes"] and not accepted["publication_authorized"],
         "epoch 143 second interval lost its accepted predecessor")
    recheck(first_row, EPOCH143)


def census(context, first_row):
    row = observe(context, PROFILE)
    if row:
        check_prefix(first_row)
        need(row["actor"]["closure"] == checked(row["actor"]["booking"])["closure"] == PREFIX,
             "epoch 143 successor has a different closure")
    return row


def status_row(rows):
    return next(row for profile, row in reversed(rows) if profile.epoch == 143 and row is not None)


def baseline(previous, profiles=(PROFILE,)):
    latest = checked(previous) if previous else {}
    if ACTOR_FIELD not in latest:
        return first.baseline(previous)
    origin = first.baseline(None)
    actor = checked(latest[ACTOR_FIELD])
    need(latest["private143_origin"] == origin and latest["private143_held"] == first.HELD
         and latest["epoch"] == PROFILE.epoch and latest["key"] == first.KEY
         and latest["authenticated_readback"] and latest["conditional_header"] == "If-Match"
         and any(actor["contract"] == profile.contract and actor["unit"] == profile.unit for profile in profiles)
         and actor["closure"] == PREFIX,
         "different epoch 143 successor status chain")
    if latest.get(PROGRESS_FIELD):
        progress = checked(latest[PROGRESS_FIELD])
        need(progress["held_owner"] == latest[ACTOR_FIELD]
             and progress["producer_invocation_id"] == actor["producer_invocation_id"],
             "epoch 143 successor status names another worker")
    return previous


def forecast(c, row, old, profile=PROFILE):
    if row["unit"]["Id"] == EPOCH143.unit:
        return first.forecast(c, row, old)
    need(old and old["private143_held"] == first.HELD, "missing authenticated epoch 143 status predecessor")
    progress_path = profile.base / "FIRST_PROTECTED_PROGRESS.json"
    actor = row["actor"]
    iid = actor["producer_invocation_id"]
    is_worker = row["phase"] == "worker"
    has_progress = row.get("transaction_replay_claimed", False)
    predecessor = old["after_status"]
    age = round((c.now - utc(predecessor["sampled_at_utc"])).total_seconds() * 1000)
    need(age >= 0 and predecessor["epoch"] == profile.epoch and row["epoch"] == profile.epoch,
         "epoch 143 forecast crossed the accepted clock")
    evidence = old.get(PROGRESS_FIELD) if old.get(ACTOR_FIELD) == row["held_owner"] else None
    if has_progress:
        evidence = bound(progress_path)
        progress = checked(evidence)
        need(progress["held_owner"] == row["held_owner"] and progress["producer_invocation_id"] == iid
             and progress["worker_pid"] == row["worker"]["pid"]
             and progress["worker_start_ticks"] == row["worker"]["start_ticks"]
             and profile.bootstrap < progress["slot"] <= progress["last_requested_slot"] == profile.terminal,
             "epoch 143 protected progress belongs to another worker")
    if is_worker:
        part = split_wire.archive(row, Path(checked(profile.contract)["prepared_output_file"]))
    else:
        part = None
    size = part["size"] if part else predecessor["jet_size_bytes"]
    quote = delivery_eta.estimate(c, profile.epoch, size)
    planning = dict(old["planning_milliseconds"])
    planning["verified_delivery"] = quote["total_millis"]
    rate = old.get("recorded_rate")
    if has_progress:
        sample = first.recorded_pair(row, progress, c.now, profile=profile, first_path=progress_path)
        if sample:
            rate = sample
        slot = sample["slot"] if sample else progress["slot"]
        planning["current_interval"] = math.ceil((profile.terminal - slot) * 1000 / rate["slots_per_second"])
    elif row["phase"] == "terminal":
        planning["current_interval"] = 0
    phase = "replay" if is_worker and has_progress else "verification"
    report = dict(epoch=profile.epoch, phase=phase, jet_size_bytes=size, sampled_at_utc=c.stamp,
                  elapsed_execution_millis=predecessor["elapsed_execution_millis"] + age,
                  estimated_remaining_millis=sum(planning.values()))
    return report, {
        ACTOR_FIELD: row["held_owner"], PROGRESS_FIELD: evidence,
        "private143_held": first.HELD, "first_protected_recording": bound(first.FIRST),
        "recorded_rate": rate, "archive_sample": part,
        "producer_invocation_id": iid if active(row) else None,
        "current_repair_owner": "/root", "measured_canonical_progress": False,
        "planning_milliseconds": planning, "delivery_forecast": quote,
        "estimate_model": "Private second-hourly replay and the retained canonical replay and delivery budget.",
    }
