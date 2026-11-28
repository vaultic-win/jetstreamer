"""Observe a new epoch 143 invocation after the held RAM refusal."""

from evidence import checked, need
from first_hourly143 import FirstHourlyProfile, observe, terminal
from held143_ram_terminal import IID, TERMINAL
from ram_retry143_scope import CONTRACT_SHA, FROZEN, NODE
import runway_retry143 as runway


PROFILE = FirstHourlyProfile(
    143, bootstrap=runway.PROFILE.bootstrap, terminal=runway.PROFILE.terminal,
    tree_gib=64, producer_ram_gib=40, contract_sha=CONTRACT_SHA, node=NODE,
    worker_sha=runway.PROFILE.worker_sha, interval="second", date="20261128",
    version=2, run=runway.PROFILE.run, field="current_private143_second_hourly_ram_retry",
    evidence_base="epoch143-second-hourly-20261128-v5",
    guard_timer="horizon-guard-143-second-hourly-20261128-v5.timer",
)


def previous(fleet):
    closure = checked(TERMINAL)
    fallback = checked(FROZEN)
    saved = fleet.get(runway.PROFILE.field, fallback)
    actor = checked(closure["prior_held"])
    need(closure["unit"] == runway.PROFILE.unit == PROFILE.unit
         and closure["invocation_id"] == actor["producer_invocation_id"] == IID
         and closure["prior_held_stop"] == runway.CLOSURE
         and closure["release_absent"] and not closure["replay_started"]
         and closure["output_absent"] and closure["segment_manifest_absent"]
         and not closure["archive_publication_authorized"] and not closure["resource_credit_bytes"]
         and actor["contract"] == runway.PROFILE.contract and actor["booking"] == closure["booking"]
         and actor["guard_plan"] == closure["guard_plan"],
         "epoch 143 RAM refusal lost its held predecessor")
    need(saved["phase"] == "terminal" and saved["epoch"] == 143
         and saved["unit"]["Id"] == runway.PROFILE.unit and saved["held_owner"] == closure["prior_held"]
         and saved["actor"] == actor and saved["native_terminal"] == fallback["native_terminal"]
         and saved["native_terminal"]["cursor"] == closure["pid1_cursor"]
         and saved["native_terminal"] == terminal(actor, runway.PROFILE),
         "epoch 143 RAM refusal has a different native terminal")
    return saved


def census(context, first, predecessor):
    earlier, floor_refusal = runway.retained_census(context, first, predecessor)
    ram_refusal = previous(context.fleet)
    row = observe(context, PROFILE)
    if row:
        actor = row["actor"]
        booking = checked(actor["booking"])
        need(actor["producer_invocation_id"] not in (IID, runway.IID)
             and actor["contract"] == PROFILE.contract
             and actor["closure"] == booking["closure"] == runway.second.PREFIX
             and booking["held_ram_stop"] == checked(PROFILE.contract)["held_ram_stop"] == TERMINAL,
             "unbound epoch 143 RAM refusal successor")
    return earlier, floor_refusal, ram_refusal, row


def baseline(previous_status):
    return runway.second.baseline(previous_status, (runway.second.PROFILE, runway.older.old.PROFILE,
                                                     runway.older.PROFILE, runway.PROFILE, PROFILE))


def forecast(context, row, last):
    if row["actor"]["contract"] == PROFILE.contract:
        return runway.second.forecast(context, row, last, PROFILE)
    return runway.forecast(context, row, last)
