"""Reprice the stopped epoch 166 when its previous publication estimate expires."""
from datetime import timedelta
from pathlib import Path

from evidence import bound, checked, need, utc

MODEL = dict(path="/home/sol/.jetstreamer-private/r2-status-receipts/event-166-retry11-write-version-terminal-20261124-v1/RECEIPT.json",
             sha256="0c865c06745480c9661326919afe813895a7c838e38f2c34713b1714e6a6b404")
DONOR = dict(path="/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2/SPLIT_AND_166_WATCHERS_1795819276953592886.json",
             sha256="64aa76de4fb179a650488d3d53c05050aff7b4fa97ef60c61d3726e42545133c")


def forecast(context, prior, prior_ref, status162):
    model = checked(MODEL)
    stopped = context.fleet["cold166_retry11_write_version_failure"]
    need(stopped["terminal"] == model["terminal"] and model["authenticated_readback"]
         and prior["phase"] == "verification" and prior["epoch"] == 166
         and checked(prior_ref)["producer_invocation_id"] is None
         and not any(row["epoch"] == 166 for row in context.fleet["actual_executing_replays"]
                     + context.fleet["actual_active_private_diagnostics"] + context.fleet["actual_active_bootstraps"]),
         "epoch 166 no longer has the same stopped producer")
    stop = checked(stopped["terminal"])
    need(stop["producer_invocation"] == stopped["producer_invocation_id"]
         and stop["error"] == "account write 36 has write version 51911220176, expected the contiguous version 51911220175",
         "different write-version repair")
    census_ref = bound(context.paths["out"]/"CYCLE_OBSERVATION.json")
    census = checked(census_ref)
    loan = census["capacity"]["current_private162_second_reserved"]
    dependency = checked(status162)
    estimate = dependency["after_status"]
    need(census["observer"] == context.sample_ref and loan["donor"] == DONOR
         and checked(DONOR)["donor"]["usable_166_ram"] == 63 * 2**30
         and dependency["epoch"] == 162 and dependency["authenticated_readback"]
         and estimate["epoch"] == 162 and dependency["sampled_at_utc"] == estimate["sampled_at_utc"]
         and utc(estimate["sampled_at_utc"]) <= context.now and estimate["estimated_remaining_millis"] > 0,
         "unbound compute loan or epoch 162 estimate")
    previous = model["estimate_model"]
    release_estimate = utc(estimate["sampled_at_utc"]) + timedelta(milliseconds=estimate["estimated_remaining_millis"])
    wait = max(0, round((release_estimate-context.now).total_seconds()*1000))
    age = round((context.now-utc(prior["sampled_at_utc"])).total_seconds()*1000)
    need(age >= prior["estimated_remaining_millis"] and previous["safe_resume_credit"] == 0
         and all(type(previous[k]) is int and previous[k] > 0 for k in
                 ("repair_allowance_millis", "full_replay_planning_millis", "delivery_tail_millis")),
         "forecast is still current or the previous work budget is incomplete")
    remaining = wait + previous["repair_allowance_millis"] + previous["full_replay_planning_millis"] + previous["delivery_tail_millis"]
    after = dict(prior, sampled_at_utc=context.stamp, elapsed_execution_millis=prior["elapsed_execution_millis"]+age,
                 estimated_remaining_millis=remaining)
    evidence = dict(previous, loan=DONOR, current_loan_observation=census_ref, prior_model=MODEL,
                    dependency_status=status162, assumed_wait_millis=wait,
                    scheduling_assumption="Use the current 162 publication estimate as a conservative proxy for return of the shared replay resources.")
    return after, dict(estimate_model=evidence, producer_invocation_id=None, measured_canonical_progress=False,
                       current_repair_owner="/root", terminal=stopped["terminal"])
