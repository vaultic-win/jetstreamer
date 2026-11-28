"""Add the isolated 6,602-position gap to the existing writer's observation."""
from pathlib import Path

from evidence import bound, checked, need
import gap170_contract as contract
import gap170_native as gap

FIELD, INTERFACE, UNIT = gap.FIELD, gap.INTERFACE, gap.UNIT
active, recheck = gap.active, gap.recheck
interface = contract.interface


def retained_population(fleet, config):
    contract.stopped_owner(fleet)
    return gap.retained_population(fleet, config)


def history_config(fleet, config):
    # The older observer correctly refuses unknown 170 registrations. Remove
    # only this separately validated assignment from its private input view.
    prior = retained_population(fleet, config)
    if not prior or not prior["observer_config"]:
        return config
    return dict(config, diagnostic_replays=[
        row for row in config["diagnostic_replays"] if row != prior["observer_config"]
    ])


def observe(context, prior, observed_lane):
    contract.stopped_owner(context.fleet)
    return gap.observe(context, prior, observed_lane)


def project(context, row):
    context.next_cfg["diagnostic_replays"] = [
        item for item in context.next_cfg["diagnostic_replays"] if item["producer_unit"] != UNIT
    ]
    gap.project(context, row)


def status_fields(row):
    return dict(private170_gap_phase=row["phase"], private170_gap_actor=row["actor_ref"],
                private170_gap_guard=row.get("guard"), private170_gap_terminal=row.get("native_terminal"),
                private_transaction_progress=row["transaction_replay_claimed"],
                private170_canonical_progress=False)


def install(fleet, row):
    contract.stopped_owner(fleet)
    if row:
        gap.install(fleet, row)
        entry, = (record for record in fleet["epochs"] if record["epoch"] == 170)
        entry.update(current_private_diagnostic=row,
                     current_status_scope="Private epoch 170 checkpoint gap " + row["phase"] + ".")
        if active(row):
            entry.update(no_live_producer_claimed=False, current_repair_owner="/root",
                         state="executing" if row["phase"] == "worker" else "verification")


def enroll(api, head, writer_ref):
    ready = checked(checked(writer_ref)["ready"])
    need(ready["gap170_interface"] == INTERFACE, "writer lacks the independent epoch 170 interface")
    scope = interface()
    contract.stopped_owner(checked(head))
    actor_ref, actor = gap.read_actor()
    plan_ref = bound(Path(scope["plan_path"]))
    plan = checked(plan_ref)
    timer = gap.native.props(gap.GUARD_TIMER, ("Id", "ActiveState", "InvocationID"))
    need(timer["ActiveState"] == "active" and plan["unit"] == UNIT
         and plan["invocation_id"] == actor["producer_invocation_id"] != contract.PREVIOUS
         and plan["receipt_directory"] == scope["guard_receipts"]
         and not Path(scope["barrier"]).exists() and not gap.RELEASE.exists(),
         "independent epoch 170 gate was released or has a foreign guard")
    _, workers = gap.guard(scope, actor, None, dict(
        guard_plan=plan_ref, guard_timer_invocation_id=timer["InvocationID"]))
    need(not workers, "epoch 170 gap started a worker before the writer enrolled it")
    if gap.ENROLLMENT.exists():
        ref = gap.enrollment(actor_ref, contract.checkpoint(scope))
        need(checked(ref)["writer_active"] == writer_ref, "gap belongs to another writer")
        return ref
    return gap.enroll(api, head, writer_ref)
