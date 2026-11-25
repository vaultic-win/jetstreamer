"""Bind the RAM-backed epoch 229 Bank delta diagnostic to the fleet."""
from pathlib import Path
import re

from ordinary249.delivery248 import V, bound, props, ref

UNIT = "horizon-perf-epoch229-bank-delta@v334.service"
PACKAGE = V / "horizon229-bank-delta-v334"
RUN_ROOT = Path("/home/ubuntu/.jetstreamer-private/epoch229-bank-delta-tmpfs-v334/run")
REGISTRATION = PACKAGE / "cadence-registration.json"
FINALIZED_REWARDS = V / "horizon229-finalized-block-rewards-v1/completion.json"
FINALIZED_REWARDS_SHA = "a353fd5134d3947788610f9b057442d64cfd2cda7e9835e267169a1eabf34923"
PREDECESSOR_VOTES = V / "horizon229-predecessor-vote-comparison-v1/completion.json"
PREDECESSOR_VOTES_SHA = "1f19af6492efbbcae54681b027ce6d922fc2956962c5ae6517ac7f882075a8ce"
DEMOTION_EVIDENCE = V / "horizon229-demotion-native-input-v1/completion.json"
DEMOTION_EVIDENCE_SHA = "768a2698fd86336735e85985a20e78733a662869ab01275f25dca6ffd5dde665"
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup"]


def receipt():
    if not REGISTRATION.is_file():
        return None
    binding = ref(REGISTRATION)
    row = bound(binding)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    assert row["epoch"] == 229 and row["unit"] == UNIT and row["entry_replay_requested"]
    assert row["kind"] == "europe-rooted-bank-delta-comparison" and row["launched"]
    assert row["canonical_epoch_publication_authorized"] is False and row["run_root"] == str(RUN_ROOT)
    assert (row["bootstrap_slot"], row["target_slot"], row["terminal_slot"]) == (98927417, 98931634, 98939266)
    assert row["first_divergent_slot"] == 98931633
    assert re.fullmatch("[0-9a-f]{32}", row["invocation_id"]) and row["main_pid"] > 0
    assert bound(row["admission"])["profile"]["sha256"] == '7506d3180e37e565791401a1ed7398d9caf55b5397e70a1ad18081c10108b85c'
    active_guard = bound(row["active_guard"])
    assert active_guard["producer_invocation_id"] == row["invocation_id"] and active_guard["trip_reason"] is None
    assert active_guard["plan_sha256"] == row["guard_plan"]["sha256"] and active_guard["producer"]["pid"] == row["main_pid"]
    return binding, row


DEMOTION_UNIT = "horizon-qualify-229-called-program-demotion-v1.service"
DEMOTION_PACKAGE = V / "horizon229-called-program-demotion-v1"
DEMOTION_ROOT = Path("/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v1/run")
RETRY_UNIT = "horizon-qualify-229-called-program-demotion-v2.service"
RETRY_PACKAGE = V / "horizon229-called-program-demotion-v2"
RETRY_ROOT = Path("/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v2/run")
DEMOTION_RUNS = ((DEMOTION_UNIT, DEMOTION_PACKAGE, DEMOTION_ROOT), (RETRY_UNIT, RETRY_PACKAGE, RETRY_ROOT))
PARENT_SHA = "060d1807204f66d65854438334847c52a5f3b4c3264fc32fb60243bc42128cfa"
WORKER_SHA = "e92a4c508ea5e9155f4294cb0e7e8399f3ff81821a356bb0a958da5fa49f2695"


def demotion_receipt(unit, package, root):
    path = package / "cadence-registration.json"
    if not path.exists():
        return None
    stamp = path.lstat()
    assert path.resolve() == path and stamp.st_uid == 0 and not stamp.st_mode & 0o222
    source = ref(path)
    row = bound(source)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    assert (row["epoch"], row["unit"], row["kind"], row["run_root"]) == (
        229, unit, "epoch229-called-program-demotion", str(root))
    assert (row["bootstrap_slot"], row["first_replay_slot"], row["divergent_bank_slot"],
            row["terminal_slot"]) == (98927417, 98927418, 98931633, 98939266)
    assert row["launched"] and row["entry_replay_requested"] and row["worker_sha256"] == WORKER_SHA
    assert all(row[key] is False for key in ("canonical_epoch_publication_authorized", "remote_mutations", "r2_mutations"))
    admission = bound(row["admission"])
    parent_ref = admission["parent_qualification"]
    assert parent_ref["path"] == str(package / "parent-qualification.json")
    if unit == DEMOTION_UNIT:
        assert parent_ref["sha256"] == PARENT_SHA
    else:
        parent = bound(parent_ref)
        assert parent["capability"]["run_root"] == str(root)
        assert parent["capability"]["worker_sha256"] == WORKER_SHA
        assert row["node_path"] == parent["artifact"]["path"]
        assert bound(admission["predecessor"])["trip_reason"] == "root-physical-budget"
    assert admission["admitted"] and admission["epoch"] == 229
    guard = bound(row["active_guard"])
    assert re.fullmatch("[0-9a-f]{32}", row["invocation_id"]) and row["main_pid"] > 0
    assert guard["producer_invocation_id"] == row["invocation_id"] and guard["trip_reason"] is None
    assert guard["producer"]["pid"] == row["main_pid"] and guard["plan_sha256"] == row["guard_plan"]["sha256"]
    return source, row


def register_demotion(plan):
    image = None
    for unit, package, root in DEMOTION_RUNS:
        selected = register_demotion_run(plan, unit, package, root)
        if selected is not None:
            image = selected
    return image


def register_demotion_run(plan, unit, package, root):
    registration = demotion_receipt(unit, package, root)
    if registration is None:
        return None
    source, row = registration
    if unit not in plan["tracked_units"]:
        plan["tracked_units"].append(unit)
    claim = dict(epoch=229, unit=unit, invocation_id=row["invocation_id"],
                 scratch_path=str(root), launch_receipt=source)
    diagnostics = plan.setdefault("diagnostics", [])
    previous = [item for item in diagnostics if item["unit"] == unit]
    assert not previous or previous == [claim]
    if not previous:
        diagnostics.append(claim)
    gate = plan["gates"]["229"]
    if source not in gate["evidence"]:
        gate["evidence"].append(source)
    gate["next_action"] = "Check the signed Bank hash at 98,931,633, then the terminal accounts root and private archive close at 98,939,266."
    first_checkpoint = package / "signed-transaction-and-bank.json"
    if first_checkpoint.is_file():
        checkpoint_ref = ref(first_checkpoint)
        if unit == DEMOTION_UNIT:
            assert checkpoint_ref["sha256"] == "5e8b05e035fd73c2acfd89103c6070ba4989e5feda9f951318683cbef268442d"
        checkpoint = bound(checkpoint_ref)
        assert checkpoint["registration"] == source and checkpoint["worker_sha256"] == WORKER_SHA
        assert (checkpoint["epoch"], checkpoint["slot"], checkpoint["transaction_index"]) == (229, 98_931_633, 1764)
        assert checkpoint["bank_hash"] == "7eZpcd8gDPTZ7cGasN6K6YpFiQGbGPJvGeovtAbBrorU"
        if checkpoint_ref not in gate["evidence"]:
            gate["evidence"].append(checkpoint_ref)
        gate["next_action"] = "The signed transaction and Bank hash matched at slot 98,931,633. Verify the independent accounts root at 98,939,266 and close the private segment."
    terminal = package / "terminal.json"
    if terminal.is_file():
        terminal_ref = ref(terminal)
        completed = bound(terminal_ref)
        assert completed["registration"] == source and completed["epoch"] == 229
        if terminal_ref not in gate["evidence"]:
            gate["evidence"].append(terminal_ref)
        gate["next_action"] = completed["next_action"]
    fleet = bound(bound(row["admission"])["fleet_tool"])
    assert fleet["schema"] == "foundation-epoch229-called-program-demotion-fleet-tool-v1"
    return fleet["artifact"]


def live_configuration(registration, unit, run_root):
    if registration is None:
        return []
    _, row = registration
    live = props(unit, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["Id"], live["ActiveState"], live["SubState"]) == (unit, "active", "running")
    assert live["InvocationID"] == row["invocation_id"] and int(live["MainPID"]) == row["main_pid"]
    assert live["ControlGroup"] == "/system.slice/" + unit and live["NRestarts"] == "0"
    node = Path("/proc") / live["MainPID"] / "exe"
    assert node.samefile(row["node_path"]) and not node.readlink().is_relative_to(run_root)
    return [dict(range="229-229", controller_unit=unit, expected_controller_invocation_id=row["invocation_id"],
                 producer_unit=unit, expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(run_root), worker_executable_basename="historical-worker")]


def configuration():
    configured = live_configuration(receipt(), UNIT, RUN_ROOT)
    for unit, package, root in DEMOTION_RUNS:
        configured.extend(live_configuration(demotion_receipt(unit, package, root), unit, root))
    return configured


def gate(plan):
    registered = receipt()
    if registered is None:
        return
    source, row = registered
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    diagnostics = plan.setdefault("diagnostics", [])
    owner = dict(epoch=229, unit=UNIT, invocation_id=row["invocation_id"],
                 scratch_path=str(RUN_ROOT), launch_receipt=source)
    previous = [item for item in diagnostics if item["unit"] == UNIT]
    assert not previous or previous == [owner]
    if not previous:
        diagnostics.append(owner)
    gate_row = plan["gates"]["229"]
    if source not in gate_row["evidence"]:
        gate_row["evidence"].append(source)
    gate_row["next_action"] = "Capture native Bank hashes and account hash leaves at 98931631 and 98931633 for comparison with the finalized vote chain."
    terminal = PACKAGE / "terminal.json"
    if terminal.is_file():
        terminal_ref = ref(terminal)
        acceptance = bound(terminal_ref)
        assert acceptance["registration"] == source
        if terminal_ref not in gate_row["evidence"]:
            gate_row["evidence"].append(terminal_ref)
        gate_row["next_action"] = acceptance["next_action"]
        if FINALIZED_REWARDS.is_file():
            rewards_ref = ref(FINALIZED_REWARDS)
            assert rewards_ref["sha256"] == FINALIZED_REWARDS_SHA
            rewards = bound(rewards_ref)
            assert rewards["schema"] == "foundation-epoch229-finalized-block-rewards-comparison-v1"
            assert rewards["epoch"] == 229 and rewards["bank_evidence"] == acceptance["evidence"]
            assert rewards["publication_authorized"] is False and rewards["remote_mutations"] is False
            assert set(rewards["slots"]) == {"98931631", "98931633"}
            for comparison in rewards["slots"].values():
                assert comparison["status"] == 200 and comparison["block_identity_matched"] is True
                assert comparison["comparison"] == "match"
                assert comparison["native_only"] == comparison["finalized_only"] == 0
            if rewards_ref not in gate_row["evidence"]:
                gate_row["evidence"].append(rewards_ref)
            gate_row["next_action"] = (
                "Both block reward lists match finalized RPC. Compare the retained dirty-account hashes "
                "with independently reconstructed account state at slots 98,931,631 and 98,931,633."
            )
        if PREDECESSOR_VOTES.is_file():
            votes_ref = ref(PREDECESSOR_VOTES)
            assert votes_ref["sha256"] == PREDECESSOR_VOTES_SHA
            votes = bound(votes_ref)
            assert votes["schema"] == "foundation-epoch229-finalized-signed-predecessor-votes-v1"
            assert votes["epoch"] == 229 and votes["bank_evidence"] == acceptance["evidence"]
            assert votes["publication_authorized"] is False and votes["remote_mutations"] is False
            assert votes["request"]["params"][0] == 98931633
            assert set(votes["slots"]) == {"98931630", "98931631"}
            for predecessor in votes["slots"].values():
                assert predecessor["comparison"] == "match"
                witness, = predecessor["witnesses"]
                assert witness["all_message_signatures_verified"] is True
                assert predecessor["finalized_vote_counts"] == {predecessor["replayed_hash"]: witness["count"]}
                assert witness["vote_hash"] == predecessor["replayed_hash"] and witness["count"] > 0
            if votes_ref not in gate_row["evidence"]:
                gate_row["evidence"].append(votes_ref)
            gate_row["next_action"] = (
                "Signed votes match the replayed Bank through slot 98,931,631 and diverge at slot 98,931,633. "
                "Compare the finalized transaction outcomes and retained dirty-account writes in block 98,931,633."
            )
        if DEMOTION_EVIDENCE.is_file():
            demotion_ref = ref(DEMOTION_EVIDENCE)
            assert demotion_ref["sha256"] == DEMOTION_EVIDENCE_SHA
            demotion = bound(demotion_ref)
            assert demotion["schema"] == "foundation-epoch229-demotion-native-input-v1"
            assert (demotion["epoch"], demotion["slot"], demotion["transaction_index"]) == (229, 98931633, 1764)
            assert demotion["activation_slot"] == 84240008
            counterfactual = bound(demotion["source_counterfactual"])
            assert counterfactual["epoch"] == 229 and counterfactual["slot"] == 98931633
            program = counterfactual["omit_candidate_leaf"]["account"]
            assert counterfactual["matching_single_leaf_exclusions"] == [program]
            assert counterfactual["omit_candidate_leaf"]["bank_hash"] == counterfactual["finalized_signed_hash"]
            metadata = bound(counterfactual["block_metadata"])
            assert bound(metadata["source"]["predecessor_votes"])["bank_evidence"] == acceptance["evidence"]
            assert demotion["publication_authorized"] is False and counterfactual["replay_repair_verified"] is False
            if demotion_ref not in gate_row["evidence"]:
                gate_row["evidence"].append(demotion_ref)
            gate_row["next_action"] = (
                "Qualify the Token Program write-lock correction against the signed Bank hash at slot 98,931,633 "
                "and the independent accounts root at slot 98,939,266."
            )


def owns(row):
    producer = row.get("producer", {})
    if producer.get("Id") == UNIT:
        _, active = receipt()
        root = RUN_ROOT
    else:
        for unit, package, root in DEMOTION_RUNS:
            if producer.get("Id") == unit:
                _, active = demotion_receipt(unit, package, root)
                break
        else:
            return False
    assert row["epoch"] == 229 and row["phase"] == "diagnostic-qualification"
    assert producer["InvocationID"] == active["invocation_id"]
    assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
    assert row["scratch_path"] == str(root)
    return True
