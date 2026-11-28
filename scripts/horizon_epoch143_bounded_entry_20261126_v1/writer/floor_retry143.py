"""Observe the restarted producer without reassigning its closed invocation."""

from evidence import bound, checked, need
from first_hourly143 import FirstHourlyProfile, observe
import retry_second_hourly143 as old
import second_hourly143 as hourly
from floor_retry143_scope import CONTRACT_SHA, NODE
from second143_floor_terminal import IID, TERMINAL


PROFILE = FirstHourlyProfile(
    143, bootstrap=old.PROFILE.bootstrap, terminal=old.PROFILE.terminal, tree_gib=64,
    producer_ram_gib=40, contract_sha=CONTRACT_SHA, node=NODE, worker_sha=old.PROFILE.worker_sha,
    interval="second", date="20261128", version=2, run=old.PROFILE.run,
    field="current_private143_second_hourly_floor_retry",
    evidence_base="epoch143-second-hourly-20261128-v3",
    guard_timer="horizon-guard-143-second-hourly-20261128-v3.timer",
)


def previous(fleet):
    row = fleet[old.PROFILE.field]
    terminal = checked(TERMINAL)
    need(row["phase"] == "terminal" and row["native_terminal"]["invocation_id"] == IID
         and row["held_owner"] == terminal["prior_held"] and row["native_terminal"]["cursor"] == terminal["pid1_cursor"]
         and terminal["unit"] == PROFILE.unit and terminal["invocation_id"] == row["actor"]["producer_invocation_id"]
         and terminal["disposition"] == "filesystem-floor-guard-stop-incomplete"
         and not terminal["completed_epoch"] and not terminal["resource_credit_bytes"]
         and not terminal["publication_authorized"], "floor stop has no accepted epoch 143 terminal")
    return row


def census(context, first, second):
    prior = previous(context.fleet)
    old.check_predecessor(second)
    row = observe(context, PROFILE)
    if row:
        hourly.check_prefix(first)
        booking = checked(row["actor"]["booking"])
        need(row["actor"]["producer_invocation_id"] != IID
             and row["actor"]["closure"] == booking["closure"] == hourly.PREFIX
             and booking["failed_second_hourly"] == old.TERMINAL and booking["floor_stop"] == TERMINAL,
             "different protected floor-stop replacement")
    return prior, row


def baseline(previous):
    return hourly.baseline(previous, (hourly.PROFILE, old.PROFILE, PROFILE))


def forecast(context, row, last):
    if row["actor"]["contract"] == PROFILE.contract:
        return hourly.forecast(context, row, last, PROFILE)
    return old.forecast(context, row, last)
