"""Observe one bounded epoch 170 retry and retain both former owners."""

from pathlib import Path

from evidence import bound, checked, need
import continuation170_retry_native as retry
import continuation170_retry_contract as contract
import rolling170_status as history

FIELD = history.FIELD
FAILED_FIELD = "retained_170_second_bounded_first_held_terminal"
INTERFACE = retry.INTERFACE
active = retry.active
project = retry.project
interface = retry.interface


def retained_population(fleet, config):
    prior = fleet.get(FIELD)
    if prior and prior["interface"] == INTERFACE:
        need(fleet[FAILED_FIELD] == contract.failed_owner(),
             "bounded 170 retry lost the first held terminal")
        return retry.retained_population(fleet, config)
    return history.retained_population(fleet, config)


def observe(context, prior, observed_lane):
    if not retry.ACTOR.exists():
        need(not prior or prior["interface"] != INTERFACE, "bounded 170 retry actor disappeared")
        need(not retry.RELEASE.exists() and not retry.ENROLLMENT.exists(),
             "bounded 170 retry has evidence without an actor")
        return history.observe(context, prior, observed_lane)
    history.previous.native.idle(history.previous.UNIT)
    if prior and prior["interface"] == INTERFACE:
        return retry.observe(context, prior, observed_lane)
    contract.require_failed_owner(prior)
    return retry.observe(context, None, observed_lane)


def recheck(row):
    if row and row["interface"] == INTERFACE:
        history.previous.native.idle(history.previous.UNIT)
        retry.recheck(row)
    else:
        history.recheck(row)


def install(fleet, row):
    if row and row["interface"] == INTERFACE:
        fleet[FAILED_FIELD] = contract.failed_owner()
        retry.install(fleet, row)
    else:
        history.install(fleet, row)


def enroll(api, head, writer_ref):
    ready = checked(checked(writer_ref)["ready"])
    need(ready["successor170_interface"] == INTERFACE
         and ready["unreleased_170_terminal"] == contract.FAILED
         and ready["prior_successor170_interface"] == history.INTERFACE,
         "writer has not adopted the bounded 170 retry")
    contract.require_failed_owner(checked(head).get(FIELD))
    scope = interface()
    actor_ref, actor = retry.read_actor()
    need(actor["producer_invocation_id"] != contract.FAILURE_IID
         and not Path(scope["barrier"]).exists(), "bounded 170 retry has a stale actor or permit")
    guard_plan = bound(Path(scope["plan_path"]))
    plan = checked(guard_plan)
    timer = retry.native.props(retry.GUARD_TIMER, ("Id", "ActiveState", "InvocationID"))
    need(timer["ActiveState"] == "active" and plan["unit"] == retry.UNIT
         and plan["invocation_id"] == actor["producer_invocation_id"]
         and plan["receipt_directory"] == scope["guard_receipts"],
         "incorrect invocation-bound 170 retry guard")
    _, workers = retry.guard(scope, actor, None,
                             dict(guard_plan=guard_plan, guard_timer_invocation_id=timer["InvocationID"]))
    need(not workers, "bounded 170 retry escaped its held gate")
    if retry.ENROLLMENT.exists():
        return retry.enrollment(actor_ref, retry.closed_comparison(scope))
    return retry.enroll(api, head, writer_ref)
