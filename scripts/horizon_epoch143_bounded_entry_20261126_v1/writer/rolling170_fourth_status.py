"""Move the sole diagnostic assignment from the closed V46 owner to the fourth window."""

from pathlib import Path

from evidence import bound, checked, need
import fourth170_contract as contract
import fourth170_native as following
import rolling170_retry_status as history

FIELD = history.FIELD
PREVIOUS_FIELD = "retained_170_73746883_73766969_terminal"
INTERFACE = following.INTERFACE
interface = following.interface
active = following.active
project = following.project


def retained_population(fleet, config):
    prior = fleet.get(FIELD)
    if prior and prior["interface"] == INTERFACE:
        contract.previous_owner(fleet[PREVIOUS_FIELD], interface(), terminal=True)
        need(
            fleet[history.FAILED_FIELD] == history.contract.failed_owner(),
            "fourth window lost the first held 170 terminal",
        )
        return following.retained_population(fleet, config)
    return history.retained_population(fleet, config)


def observe(context, prior, observed_lane):
    if prior and prior["interface"] == INTERFACE:
        history.retry.native.idle(history.retry.UNIT)
        return following.observe(context, prior, observed_lane)
    incumbent = history.observe(context, prior, observed_lane)
    if not following.ACTOR.exists():
        following.native.idle(following.UNIT)
        need(
            not following.RELEASE.exists() and not following.ENROLLMENT.exists(),
            "fourth epoch 170 release or enrollment lacks its actor",
        )
        return incumbent
    contract.previous_owner(incumbent, interface(), terminal=True)
    result = following.observe(context, None, observed_lane)
    result["preceding_terminal_owner"] = incumbent
    return result


def recheck(row):
    if row and row["interface"] == INTERFACE:
        history.retry.native.idle(history.retry.UNIT)
        following.recheck(row)
    else:
        history.recheck(row)
        following.native.idle(following.UNIT)


def install(fleet, row):
    if not row or row["interface"] != INTERFACE:
        return history.install(fleet, row)
    old = row.get("preceding_terminal_owner") or fleet.get(PREVIOUS_FIELD)
    fleet[PREVIOUS_FIELD] = contract.previous_owner(old, interface(), terminal=True)
    need(
        fleet[history.FAILED_FIELD] == history.contract.failed_owner(),
        "lost first held terminal",
    )
    following.install(fleet, row)


def enroll(api, head, writer_ref):
    ready = checked(checked(writer_ref)["ready"])
    need(
        ready["successor170_interface"] == INTERFACE
        and ready["prior_successor170_interface"] == history.INTERFACE,
        "writer has not adopted both bounded epoch 170 interfaces",
    )
    scope = interface()
    history.retry.native.idle(history.retry.UNIT)
    prior = checked(head).get(FIELD)
    if prior and prior["interface"] == INTERFACE:
        contract.previous_owner(checked(head)[PREVIOUS_FIELD], scope, terminal=True)
    else:
        contract.previous_owner(prior, scope)
    actor_ref, actor = following.read_actor()
    plan_ref = bound(Path(scope["plan_path"]))
    plan = checked(plan_ref)
    timer = following.native.props(
        following.GUARD_TIMER, ("Id", "ActiveState", "InvocationID")
    )
    need(
        timer["ActiveState"] == "active"
        and plan["unit"] == following.UNIT
        and plan["invocation_id"]
        == actor["producer_invocation_id"]
        != contract.PREVIOUS_IID
        and plan["receipt_directory"] == scope["guard_receipts"]
        and not Path(scope["barrier"]).exists()
        and not following.RELEASE.exists(),
        "foreign fourth held epoch 170 gate",
    )
    _, workers = following.guard(
        scope,
        actor,
        None,
        dict(guard_plan=plan_ref, guard_timer_invocation_id=timer["InvocationID"]),
    )
    need(not workers, "fourth epoch 170 started a worker before enrollment")
    if following.ENROLLMENT.exists():
        ref = following.enrollment(actor_ref, following.closed_comparison(scope))
        need(
            checked(ref)["writer_active"] == writer_ref,
            "fourth enrollment belongs to another writer",
        )
        return ref
    return following.enroll(api, head, writer_ref)
