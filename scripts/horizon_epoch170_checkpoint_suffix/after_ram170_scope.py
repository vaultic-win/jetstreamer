"""Bind the original staged service to the third RAM attempt without amending the old handoff."""
import following_prepare as prep

STAGED = prep.DEST
ROOT = prep.ROOT / "epoch170-from-73766969-gap-20261128-v1"
PREPARATION = dict(path=str(ROOT / "THIRD_SOURCE_AND_ROTATION.json"),
                   sha256="9bab932302c64c59cd887e4a051855be3af79404579337952669a65bbac2fefe")
OLD_INTERFACE = dict(path=str(STAGED / "BOUNDED_SUCCESSOR_WRITER_INTERFACE.json"),
                     sha256="6b0e1674cb45059761c95b312fbbb478a80ed1a0ab22dcee22a55cbfc03efb40")
SCOPE_PATH = ROOT / "AFTER_RAM_WRITER_INTERFACE.json"


def document():
    receipt = prep.read(PREPARATION)
    source = prep.read(receipt["source"])
    staged = prep.read(OLD_INTERFACE)
    prior = prep.read(source["predecessor_release"])
    prep.need(source["registered_interface"] == OLD_INTERFACE
              and source["registered_handoff"] == staged["handoff"]
              and source["predecessor_actor"] == prior["actor"] != staged["old_actor"]
              and source["predecessor_scope"] == prior["interface"]
              and receipt["predecessor_release"] == source["predecessor_release"]
              and source["profile"] == staged["profile"]
              and source["rotation"]["historical_following_growth_bytes"] == 36 << 30
              and not source["admission_granted"], "different qualified following interval")
    fields = ("profile", "expected_producer_unit", "expected_guard_timer", "expected_guard_unit",
              "bootstrap", "first_new_slot", "last", "recording", "run", "log", "guard_receipts",
              "barrier", "namespace", "layout", "fixture", "guard_sha", "guard_seal", "source_preflight",
              "held_gate_before_worker", "native_enrollment_needed")
    return dict(
        {key: staged[key] for key in fields},
        schema="horizon-170-after-ram-writer-interface-v1",
        staged_interface=OLD_INTERFACE, retained_staged_handoff=staged["handoff"],
        preparation=PREPARATION, source_packet=source["source_packet"],
        old_release=source["predecessor_release"], old_actor=source["predecessor_actor"],
        prior_ram_interface=source["predecessor_scope"], first_protected_progress=source["first_protected_progress"],
        handoff=receipt["source"], following_input=source["private_bootstrap"],
        closed_comparison=str(ROOT / "THIRD_CLOSED_COMPARISON.json"),
        predecessor_custody=str(ROOT / "THIRD_TERMINAL_AND_CUSTODY.json"),
        predecessor_drain=str(ROOT / "THIRD_GUARD_DRAIN.json"),
        actor_path=str(ROOT / "SUCCESSOR_ACTOR.json"), release_path=str(ROOT / "SUCCESSOR_RELEASE.json"),
        plan_path=str(ROOT / "ACTUAL_GUARD_PLAN.json"), enrollment_path=str(ROOT / "WRITER_ENROLLMENT.json"),
        additional_input_copy_bytes=0, new_home_growth_bytes=36 << 30,
        admission_or_release=False, publication_authorized=False)


if __name__ == "__main__":
    import json
    print(json.dumps(prep.save(SCOPE_PATH, document())))
