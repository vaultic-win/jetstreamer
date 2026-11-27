"""Bind the second held attempt to the closed comparison and original failed gate."""

from evidence import checked, need
import continuation170_contract as original

BASE = original.ROOT
ROOT = BASE / "attempt-2"
INTERFACE = dict(path=str(ROOT / "BOUNDED_SUCCESSOR_WRITER_INTERFACE.json"),
                 sha256="f5da8a618bfb147d98d2db1ec91526d9b711df014189c4e6485503f003e63dcd")
FAILED = dict(path=str(BASE / "FAILED_FIRST_HELD_ATTEMPT.json"),
              sha256="439e43bde3149307a327a125a7a783358adb9933adde3354e259280e687b821b")
FAILURE_IID = "ff79d77ab47d47c6bb2d468916c020d4"
closed_comparison = original.closed_comparison


def interface():
    scope = checked(INTERFACE)
    prior = original.interface()
    following = dict(prior,
                     actor_path=str(ROOT / "SUCCESSOR_ACTOR.json"),
                     plan_path=str(ROOT / "ACTUAL_GUARD_PLAN.json"),
                     release_path=str(ROOT / "SUCCESSOR_RELEASE.json"))
    for field in ("schema", "bootstrap", "first_new_slot", "last", "expected_producer_unit",
                  "expected_guard_timer", "expected_guard_unit", "actor_path", "plan_path", "release_path",
                  "run", "barrier", "guard_receipts", "guard_seal", "guard_sha", "profile", "handoff",
                  "source_preflight", "recording", "admission_or_release",
                  "closed_comparison", "old_actor", "old_release", "namespace", "fixture"):
        need(scope[field] == following[field], "bounded 170 retry changed " + field)
    need(scope["previous_interface"] == original.INTERFACE
         and scope["unreleased_failed_attempt"] == FAILED
         and scope["retained_guard_receipt_directory"] == prior["guard_receipts"]
         and scope["closed_terminal_handoff"] == prior["handoff"]
         and scope["log"] == prior["log"].removesuffix("producer.log") + "producer-attempt2.log"
         and scope["stdio_changed_only"] is True
         and scope["native_enrollment_needed"] is True
         and scope["publication_authorized"] is False,
         "different bounded 170 attempt-2 interface")
    return scope


def failed_owner():
    prior = checked(FAILED)
    actor = checked(prior["actor"])
    fleet = checked(prior["accepted_terminal_row"])
    row = fleet["current_private170_bounded_successor"]
    terminal = prior["terminal"]
    need(prior["schema"] == "horizon-170-unreleased-held-gate-terminal-v1"
         and prior["no_permit"] is prior["no_worker_or_archive"] is True
         and prior["resource_credit_bytes"] == prior["guard_samples"] == 0
         and terminal["ActiveState"] == "failed" and terminal["MainPID"] == "0"
         and terminal["InvocationID"] == actor["producer_invocation_id"] == FAILURE_IID
         and row["interface"] == original.INTERFACE and row["actor_ref"] == prior["actor"]
         and row["actor"] == actor and row["phase"] == "terminal" and row["release"] is None
         and row["observer_config"] is None and row["native_terminal"] == prior["pid1"],
         "different unreleased bounded 170 gate terminal")
    return row


def require_failed_owner(row):
    retained = failed_owner()
    need(row is not None
         and all(row[field] == retained[field] for field in
                 ("interface", "actor_ref", "actor", "phase", "release", "observer_config", "native_terminal")),
         "bounded 170 retry has no accepted terminal predecessor")
    return retained
