"""Verify the completed 6,602-slot segment before enrollment of its staged successor."""
from pathlib import Path
import stat

from evidence import BASE, bound, checked, need
import fourth170_contract as staged
import ram170_third_contract as previous

ROOT = BASE / "epoch170-from-73766969-gap-20261128-v1"
INTERFACE_DIGEST = None
INTERFACE = dict(path=str(ROOT / "AFTER_RAM_WRITER_INTERFACE.json"), sha256=INTERFACE_DIGEST)
IID = "5f7a0dc3b03346b7b7cfa17a51e150aa"
GUARD_IID = "61ac56a76759428fb6857bf60cae69ac"
PREPARATION = "9bab932302c64c59cd887e4a051855be3af79404579337952669a65bbac2fefe"
RELEASE = "bbbd90b4e78b50abd57e2dac56bf32c9384981a561d85bcf1b3b7b8c46725459"
SLOTS = [73_760_367, 73_766_969]


def interface():
    scope = checked(INTERFACE)
    original = staged.interface()
    preparation = checked(scope["preparation"])
    source = checked(preparation["source"])
    prior = checked(scope["old_release"])
    common = ("profile", "expected_producer_unit", "expected_guard_timer", "expected_guard_unit",
              "bootstrap", "first_new_slot", "last", "recording", "run", "log", "guard_receipts",
              "barrier", "namespace", "layout", "fixture", "guard_sha", "guard_seal", "source_preflight",
              "held_gate_before_worker", "native_enrollment_needed")
    need(scope["schema"] == "horizon-170-after-ram-writer-interface-v1"
         and scope["staged_interface"] == source["registered_interface"] == staged.INTERFACE
         and scope["retained_staged_handoff"] == source["registered_handoff"] == original["handoff"]
         and all(scope[key] == original[key] for key in common)
         and scope["preparation"] == dict(path=str(ROOT / "THIRD_SOURCE_AND_ROTATION.json"), sha256=PREPARATION)
         and scope["handoff"] == preparation["source"] and scope["source_packet"] == source["source_packet"]
         and scope["following_input"] == source["private_bootstrap"]
         and scope["first_protected_progress"] == source["first_protected_progress"]
         and source["predecessor_invocation"] == prior["producer_invocation_id"] == IID
         and scope["old_actor"] == source["predecessor_actor"] == prior["actor"] != original["old_actor"]
         and scope["old_release"] == source["predecessor_release"] and scope["old_release"]["sha256"] == RELEASE
         and scope["prior_ram_interface"] == source["predecessor_scope"] == prior["interface"] == previous.INTERFACE
         and source["profile"] == scope["profile"] and scope["expected_producer_unit"] == staged.UNIT
         and [p["slot"] for p in source["checkpoints"]] == [73_766_969, 73_773_645, 73_780_397, 73_787_145]
         and [scope["bootstrap"], scope["first_new_slot"], scope["last"]] == [73_766_969, 73_766_970, 73_787_145]
         and len(source["inputs_already_resident"]) == 13 and scope["additional_input_copy_bytes"] == 0
         and scope["new_home_growth_bytes"] == source["rotation"]["historical_following_growth_bytes"] == 36 << 30
         and scope["admission_or_release"] is scope["publication_authorized"] is False,
         "changed successor source, staging or RAM predecessor")
    names = {"actor_path":"SUCCESSOR_ACTOR.json", "release_path":"SUCCESSOR_RELEASE.json",
             "plan_path":"ACTUAL_GUARD_PLAN.json", "enrollment_path":"WRITER_ENROLLMENT.json",
             "closed_comparison":"THIRD_CLOSED_COMPARISON.json", "predecessor_custody":"THIRD_TERMINAL_AND_CUSTODY.json",
             "predecessor_drain":"THIRD_GUARD_DRAIN.json"}
    need(all(scope[key] == str(ROOT / name) for key, name in names.items()), "different evidence path")
    return scope


def previous_owner(fleet):
    row = fleet["current_private170_third_ram_gap"]
    scope = interface()
    need(row["interface"] == previous.INTERFACE and row["actor_ref"] == scope["old_actor"]
         and row["release"] == scope["old_release"] and row["actor"]["producer_invocation_id"] == IID
         and row["unit"]["Id"] == previous.UNIT and row["phase"] in ("worker", "bootstrap", "terminal")
         and row["canonical_replay_claimed"] is row["archive_publication_authorized"] is False,
         "different preceding RAM producer")
    if row["phase"] == "terminal":
        event = row["native_terminal"]
        need(event["INVOCATION_ID"] == IID and event["UNIT"] == previous.UNIT and event["_PID"] == "1"
             and event["_UID"] == "0", "different preceding terminal identity")
    return row


def closed_comparison(scope):
    comparison = bound(Path(scope["closed_comparison"]))
    report = checked(comparison)
    custody_ref = bound(Path(scope["predecessor_custody"]))
    custody = checked(custody_ref)
    drain = checked(bound(Path(scope["predecessor_drain"])))
    source = checked(scope["handoff"])
    evidence = report["evidence"]
    archive = custody["archive"]
    native = evidence["pid1_exit"]["native"]
    terminal = report["checkpoints"][-1]
    expected = source["checkpoints"][0]
    need(custody["comparison"] == comparison and custody["actual_terminal"] == terminal
         and custody["staged_following"] == scope["preparation"] and custody["archive_publication_authorized"] is False
         and drain["custody"] == custody_ref and drain["producer_invocation"] == IID
         and drain["timer_invocation"] == GUARD_IID and drain["release"] == scope["old_release"]
         and drain["producer_and_guard_drained"] and drain["scratch_released"] and not drain["resource_credit_bytes"]
         and report["schema"] == "horizon-170-successor-closed-checkpoint-comparison-v1"
         and report["release"] == scope["old_release"] and report["actor"] == scope["old_actor"]
         and report["interface"] == previous.INTERFACE and evidence["comparison"] == "closed"
         and evidence["closed_segment"] == archive and len(archive["sha256"]) == 64
         and native["InvocationID"] == IID and native["Id"] == previous.UNIT
         and (native["Result"], native["ExecMainCode"], native["ExecMainStatus"]) == ("success", "1", "0")
         and [p["slot"] for p in report["checkpoints"]] == SLOTS and all(p["slot_complete"] for p in report["checkpoints"])
         and [checked(v)["slot"] for v in evidence["signed_checkpoints"]] == SLOTS
         and evidence["signed_endpoint"] == evidence["signed_checkpoints"][-1]
         and evidence["signed_endpoint"]["sha256"] == expected["signed_reference"]["sha256"]
         and all(terminal[k] == expected[k] for k in ("slot","accounts_hash","bank_hash","last_blockhash"))
         and report["canonical_publication_authorized"] is False, "missing verified RAM segment or drained guard")
    archive_path = Path(checked(previous.INTERFACE)["run"]) / "ledger/epoch-170.diagnostic.jet"
    manifest_path = archive_path.with_suffix(".jet.segment.json")
    need(archive_path == Path(archive["path"]) and archive_path.resolve(strict=True) == archive_path
         and manifest_path == Path(archive["manifest"]["path"]) and manifest_path.resolve(strict=True) == manifest_path,
         "different RAM segment location")
    file = archive_path.lstat()
    need(stat.S_ISREG(file.st_mode) and file.st_nlink == 1 and file.st_uid == 1001 and file.st_gid == 1003
         and list(archive["identity"][:3]) == [file.st_dev, file.st_ino, file.st_size]
         and file.st_mtime_ns == archive["identity"][3] * 1_000_000_000 + archive["identity"][4]
         and file.st_ctime_ns == archive["identity"][5] * 1_000_000_000 + archive["identity"][6],
         "retained RAM segment changed")
    manifest = checked(archive["manifest"], root=False)
    need(manifest["terminal"] == terminal and manifest["bootstrap"] == report["checkpoints"][0]
         and manifest["archive_sha256"] == archive["sha256"] and manifest["output_slot_start"] == SLOTS[0]+1
         and manifest["output_slot_count"] == SLOTS[-1]-SLOTS[0], "retained RAM manifest differs")
    return comparison
