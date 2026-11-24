"""Prove the frozen epoch 145 verifier stopped during public audit worker turnover."""
import hashlib
import json
from pathlib import Path

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
DISPATCH = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v7"
UNIT = "horizon-holding-export145-20261121-v1.service"
IID = "c01dc3ba08b74e3aa0d4b531601e9fda"
SEAL_SHA = "6f2eef7457f0fcde62b55a0d64b2f15844bc038bdff4f58fd1d8e676c4572fe4"
TERMINAL = RUNTIME / "epoch145-semantic-continuity-20261121-v1/c01dc3ba-stopped-public-audit-turnover-20261124/TERMINAL.json"
TERMINAL_SHA = "abda107d59f55823a92d3609cbc142dec21e7e63337d9b495f6f070dfe04de24"
STATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state" / IID


def historical():
    seal_path = DISPATCH / "deployment-seal-receipt.json"
    seal_bytes = seal_path.read_bytes()
    if hashlib.sha256(seal_bytes).hexdigest() != SEAL_SHA:
        raise ValueError("changed V5p dispatcher seal")
    seal = json.loads(seal_bytes)
    if seal["destination"] != str(DISPATCH):
        raise ValueError("unbound V5p dispatcher")
    member, = (m for m in seal["members"] if m["name"] == "run-recovery" and m["mode"] == "0555")
    program = DISPATCH / member["name"]
    source = program.read_bytes()
    if hashlib.sha256(source).hexdigest() != member["sha256"]:
        raise ValueError("changed V5p dispatcher")
    api = {"__file__": str(program), "__name__": "prior_145_dispatcher"}
    exec(compile(source, str(program), "exec"), api)
    bound, need = api["bound"], api["require"]
    receipt = {"path": str(TERMINAL), "sha256": TERMINAL_SHA}
    terminal = bound(receipt)
    review = bound(terminal["review"])
    intent = bound(terminal["intent"])
    submission = bound(terminal["submission"])
    recovery, failure = terminal["startup"], terminal["failure"]
    begin, end = bound(recovery), bound(failure)
    native = terminal["native_terminal"]
    need(terminal["schema"] == "horizon-epoch145-v5p-stopped-public-audit-turnover-v1"
         and terminal["dispatcher"] == {"path": str(seal_path), "sha256": SEAL_SHA}
         and terminal["invocation_id"] == terminal["old_manager"]["InvocationID"] == IID
         and begin["iid"] == end["iid"] == submission["invocation_id"] == native["INVOCATION_ID"] == IID
         and native["UNIT"] == UNIT and native["EXIT_CODE"] == "exited" and native["EXIT_STATUS"] == "1"
         and intent["review_sha256"] == terminal["review"]["sha256"] and intent["argv"] == submission["argv"]
         and begin["image"] == review["reader"]["sha256"] and begin["r2_mutations"] is False
         and recovery["path"] == str(STATE / "recovery-started.json") and failure["path"] == str(STATE / "failed.json")
         and end["error"].rstrip().endswith("ValueError: public readers or their HOME obligation changed")
         and terminal["candidate"] == review["failed_phase"]["candidate"]
         and terminal["candidate"]["inode"] == 103237059 and terminal["candidate"]["bytes"] == 105610995833
         and terminal["source_checkpoint_exists"] is False and terminal["resource_credit_bytes"] == 0
         and terminal["replay_launch_authorized"] is False and terminal["archive_publication_authorized"] is False,
         "unbound V5p audit turnover stop")
    phase = dict(review["failed_phase"], InvocationID=IID, failure=failure, recovery=recovery,
                 manager_exit={key: value for key, value in native.items() if key != "MESSAGE"},
                 retry_worker=None, source_checkpoint_exists=False, resource_credit_bytes=0,
                 public_audit_terminal=receipt)
    return api, dict(terminal=terminal, failed_phase=phase, predecessor_review=terminal["review"],
                     original_fragment=terminal["original_fragment"], predecessor_dispatch=terminal["dispatcher"],
                     old_manager=terminal["old_manager"], original_pid1_exit=native,
                     receipts=dict(failure=failure, recovery=recovery, public_audit_terminal=receipt))


def stopped_phase(_status, fit):
    api, proof = historical()
    manager = api["inspect_unit"]()
    api["check_empty"](manager)
    need = api["require"]
    need(manager == proof["old_manager"] and not fit.members(UNIT), "different stopped V5p manager or cgroup")
    api["retained"](api["bound"](proof["predecessor_review"]))
    fragment = proof["original_fragment"]
    api["read"](fragment["path"], fragment["sha256"])
    need({p.name for p in STATE.iterdir()} == {"failed.json", "recovery-started.json"}
         and api["inspect_unit"]() == manager and not fit.members(UNIT),
         "V5p checkpoint or manager changed during the retained-input check")
    return proof["failed_phase"]
