"""Observe the repaired replay while retaining the exact first second-hourly terminal."""

from evidence import bound, checked, need
from first_hourly143 import FirstHourlyProfile, observe
import second_hourly143 as earlier
from retry_second_hourly143_scope import CONTRACT_SHA, NODE, TERMINAL
import second143_terminal as drained


PROFILE = FirstHourlyProfile(
    143, bootstrap=earlier.PROFILE.bootstrap, terminal=earlier.PROFILE.terminal, tree_gib=64,
    producer_ram_gib=40, contract_sha=CONTRACT_SHA, node=NODE, worker_sha=earlier.PROFILE.worker_sha,
    interval="second", date="20261128", version=2, run=earlier.PROFILE.run,
    field="current_private143_second_hourly_retry",
)


def check_predecessor(row):
    terminal = checked(TERMINAL)
    need(row["phase"] == "terminal" and row["native_terminal"]["invocation_id"] == drained.IID
         and row["held_owner"] == terminal["held"] and terminal["native"]["InvocationID"] == drained.IID
         and not terminal["publication_authorized"] and not terminal["resource_credit_bytes"]
         and not terminal["elapsed_replay_slots"] and not terminal["zero_output_bytes"],
         "repaired epoch 143 lost its exact failed predecessor")


def census(context, first, second):
    row = observe(context, PROFILE)
    if row:
        earlier.check_prefix(first)
        check_predecessor(second)
        booking = checked(row["actor"]["booking"])
        need(row["actor"]["closure"] == booking["closure"] == earlier.PREFIX and
             booking["failed_second_hourly"] == TERMINAL, "replacement escaped its exact terminal and reservation")
    return row


def baseline(previous):
    return earlier.baseline(previous, (earlier.PROFILE, PROFILE))


def forecast(context, row, old):
    profile = PROFILE if row["unit"]["Id"] == PROFILE.unit else earlier.PROFILE
    return earlier.forecast(context, row, old, profile)
