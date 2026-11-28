"""Observe the staged service under its own enrollment after the third RAM segment closes."""
from pathlib import Path

from evidence import bound, checked, need
import after_ram170_contract as contract
import after_ram170_native as following
import fourth170_native as old

FIELD, UNIT, INTERFACE = following.FIELD, following.UNIT, following.INTERFACE
active, recheck = following.active, following.recheck


def legacy_idle():
    """The original fourth observer and the replacement share one still-unused service name."""
    if not following.ACTOR.exists():
        return old.native.idle(old.UNIT)
    need(not any(path.exists() for path in (old.ACTOR, old.RELEASE, old.ENROLLMENT)),
         "the old fourth-window contract also claimed the producer")
    actor_ref, actor = following.read_actor()
    row = following.native.props(UNIT, following.PROPS)
    if row["ActiveState"] in ("inactive", "failed"):
        following.terminal(actor)
    else:
        scope = contract.interface()
        comparison = contract.closed_comparison(scope)
        _, grant = following.release(scope, actor_ref, actor, comparison)
        following.live(scope, row, actor, grant is not None)


def retained_population(fleet, config):
    previous = contract.previous_owner(fleet)
    # The older third-RAM module validates its exact assignment on the same cycle.
    # Leave any different 170 assignment visible for the native checks to reject.
    assignments = config["diagnostic_replays"]
    if previous["observer_config"] is not None:
        need(not fleet.get(FIELD) and previous["observer_config"] in assignments,
             "simultaneous follow-on and RAM assignments")
        assignments = [row for row in assignments if row != previous["observer_config"]]
    return following.retained_population(fleet, dict(config, diagnostic_replays=assignments))


def history_config(fleet, config):
    prior = retained_population(fleet, config)
    if not prior or not prior["observer_config"]:
        return config
    return dict(config, diagnostic_replays=[
        item for item in config["diagnostic_replays"] if item != prior["observer_config"]
    ])


def observe(context, prior, observed_lane):
    contract.previous_owner(context.fleet)
    if following.ACTOR.exists():
        need(not any(path.exists() for path in (old.ACTOR, old.RELEASE, old.ENROLLMENT)),
             "the original fourth handoff also acquired the producer")
        need(context.third_ram_gap170["phase"] == "terminal"
             and context.third_ram_gap170["native_terminal"]["INVOCATION_ID"] == contract.IID
             and context.third_ram_gap170["native_terminal"]["MESSAGE_ID"] == following.SUCCESS,
             "preceding RAM producer is active or failed")
    return following.observe(context, prior, observed_lane)


def project(context, row):
    context.next_cfg["diagnostic_replays"] = [
        item for item in context.next_cfg["diagnostic_replays"] if item["producer_unit"] != UNIT
    ]
    following.project(context, row)


def install(fleet, row):
    if not row:
        return
    prior = contract.previous_owner(fleet)
    need(prior["phase"] == "terminal" and prior["native_terminal"]["MESSAGE_ID"] == following.SUCCESS,
         "the preceding clean RAM terminal was lost")
    following.install(fleet, row)
    epoch, = (item for item in fleet["epochs"] if item["epoch"] == 170)
    epoch.update(current_private_diagnostic=row,
                 current_status_scope="Private epoch 170 interval 73,766,970–73,787,145 " + row["phase"] + ".")
    if active(row):
        epoch.update(no_live_producer_claimed=False, current_repair_owner="/root",
                     state="executing" if row["phase"] == "worker" else "verification")


def status_fields(row):
    return dict(private170_following_phase=row["phase"], private170_following_actor=row["actor_ref"],
                private170_following_guard=row.get("guard"), private170_following_terminal=row.get("native_terminal"),
                private_transaction_progress=row["transaction_replay_claimed"], private170_canonical_progress=False)


def enroll(api, head, writer_ref):
    scope = contract.interface()
    ready = checked(checked(writer_ref)["ready"])
    need(ready["after_ram170_interface"] == INTERFACE
         and ready["third_ram_gap170_interface"] == scope["prior_ram_interface"],
         "writer lacks the successor or its RAM predecessor")
    contract.previous_owner(checked(head))
    following.native.idle(contract.previous.UNIT)
    comparison = contract.closed_comparison(scope)
    need(not any(path.exists() for path in (old.ACTOR, old.RELEASE, old.ENROLLMENT)),
         "original fourth handoff already used")
    actor_ref, actor = following.read_actor()
    plan_ref = bound(Path(scope["plan_path"]))
    plan = checked(plan_ref)
    timer = following.native.props(following.GUARD_TIMER, ("Id", "ActiveState", "InvocationID"))
    need(timer["Id"] == following.GUARD_TIMER and timer["ActiveState"] == "active"
         and plan["unit"] == UNIT and plan["invocation_id"] == actor["producer_invocation_id"] != contract.IID
         and plan["receipt_directory"] == scope["guard_receipts"] and not Path(scope["barrier"]).exists()
         and not following.RELEASE.exists(), "foreign or already-released successor guard")
    _, workers = following.guard(scope, actor, None, dict(guard_plan=plan_ref,
                                                           guard_timer_invocation_id=timer["InvocationID"]))
    need(not workers, "staged producer already released before enrollment")
    if following.ENROLLMENT.exists():
        ref = following.enrollment(actor_ref, comparison)
        need(checked(ref)["writer_active"] == writer_ref, "enrollment belongs to a different writer")
        return ref
    return following.enroll(api, head, writer_ref)
