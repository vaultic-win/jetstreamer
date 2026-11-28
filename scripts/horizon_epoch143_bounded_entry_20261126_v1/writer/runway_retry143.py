"""Keep the unreleased floor check alongside its successor in the epoch 143 history."""
from evidence import checked, need
from first_hourly143 import FirstHourlyProfile, observe, terminal
import floor_retry143 as older
import second_hourly143 as second
from runway143_scope import CONTRACT_SHA, NODE, FROZEN, EVIDENCE_BASE, GUARD_TIMER, UNIT_VERSION

IID = "73b04c4b19644244a5880631da917425"
CLOSURE = dict(path=str(older.PROFILE.base / ("held-stop-" + IID) / "TERMINAL.json"),
               sha256="589128efd24df747003f08e7a683ce2d2f8a8cedd0d6d5193c5cd4ef195388a6")
PROFILE = FirstHourlyProfile(
    143, bootstrap=older.PROFILE.bootstrap, terminal=older.PROFILE.terminal,
    tree_gib=64, producer_ram_gib=40, contract_sha=CONTRACT_SHA, node=NODE,
    worker_sha=older.PROFILE.worker_sha, interval="second", date="20261128",
    version=UNIT_VERSION, run=older.PROFILE.run,
    field="current_private143_second_hourly_held_retry",
    evidence_base=EVIDENCE_BASE, guard_timer=GUARD_TIMER,
)


def previous(fleet):
    """Verify the historical process independently of any new user of the producer unit."""
    closure = checked(CLOSURE)
    fallback = checked(FROZEN)
    saved = fleet.get(older.PROFILE.field, fallback)
    actor = checked(closure["prior_held"])
    need(closure["release_absent"] and closure["output_absent"] and closure["segment_manifest_absent"]
         and not closure["replay_started"] and not closure["archive_publication_authorized"]
         and not closure["resource_credit_bytes"] and closure["invocation_id"] == IID
         and closure["unit"] == older.PROFILE.unit and closure["prior_floor_stop"] == older.TERMINAL
         and actor["contract"] == older.PROFILE.contract and actor["producer_invocation_id"] == IID
         and actor["booking"] == closure["booking"] and actor["guard_plan"] == closure["guard_plan"],
         "unreleased epoch 143 custody changed")
    need(saved["phase"] == "terminal" and saved["epoch"] == older.PROFILE.epoch
         and saved["unit"]["Id"] == older.PROFILE.unit and saved["held_owner"] == closure["prior_held"]
         and saved["actor"] == actor and saved["native_terminal"] == fallback["native_terminal"]
         and saved["native_terminal"]["cursor"] == closure["pid1_cursor"]
         and saved["native_terminal"] == terminal(actor, older.PROFILE),
         "epoch 143 held gate has a different native terminal")
    return saved


def retained_census(context, first, predecessor):
    second.check_prefix(first)
    older.old.check_predecessor(predecessor)
    return older.previous(context.fleet), previous(context.fleet)


def census(context, first, predecessor):
    earlier, held = retained_census(context, first, predecessor)
    row = observe(context, PROFILE)
    if row:
        actor = row["actor"]
        booking = checked(actor["booking"])
        need(actor["producer_invocation_id"] != IID and actor["contract"] == PROFILE.contract
             and actor["closure"] == booking["closure"] == second.PREFIX
             and checked(PROFILE.contract)["held_stop"] == CLOSURE, "unbound epoch 143 successor")
    return earlier, held, row


def baseline(previous_status):
    return second.baseline(previous_status, (second.PROFILE, older.old.PROFILE, older.PROFILE, PROFILE))


def forecast(context, row, last):
    if row["actor"]["contract"] == PROFILE.contract:
        return second.forecast(context, row, last, PROFILE)
    return older.forecast(context, row, last)
