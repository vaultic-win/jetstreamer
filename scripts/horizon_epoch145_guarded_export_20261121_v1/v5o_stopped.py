"""Read the exact epoch 145 stop caused by loss of the registered status writer."""
import hashlib
import json
from pathlib import Path

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
DISPATCH = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v6"
UNIT = "horizon-holding-export145-20261121-v1.service"
IID = "f3474dfad55f4a05a64431421881db29"
OWNER = "e83c7741fbb843029b110f1369e973a4"
SEAL_SHA = "dcccc94741aa37256983e2f21765d1bb96234fd655642126fc98b139ba5644dd"
FRAGMENT_SHA = "13f94b4df6b02eb0e5e85d072a97f62d3c1edebb628407a6e2b3811d295c5658"
TERMINAL = RUNTIME / "epoch145-semantic-continuity-20261121-v1/f3474dfa-stopped-status-owner-20261123/TERMINAL.json"
TERMINAL_SHA = "95fc24c89db925ca86fa1f918a6f61e665d3c124a7e4687ecf8ee44816b01f6f"
PRIVATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state" / IID


def historical():
    seal_file = DISPATCH / "deployment-seal-receipt.json"
    raw = seal_file.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SEAL_SHA:
        raise ValueError("changed V5o dispatcher seal")
    seal = json.loads(raw)
    if seal["destination"] != str(DISPATCH):
        raise ValueError("unbound V5o dispatcher")
    member, = [m for m in seal["members"] if m["name"] == "run-recovery" and m["mode"] == "0555"]
    program = DISPATCH / member["name"]
    source = program.read_bytes()
    if hashlib.sha256(source).hexdigest() != member["sha256"]:
        raise ValueError("changed V5o dispatcher")
    api = {"__file__": str(program), "__name__": "prior_145_dispatcher"}
    exec(compile(source, str(program), "exec"), api)
    need = api["require"]
    receipt = dict(path=str(TERMINAL), sha256=TERMINAL_SHA)
    terminal = api["bound"](receipt)
    review = api["bound"](terminal["review"])
    intent = api["bound"](terminal["intent"])
    submission = api["bound"](terminal["submission"])
    recovery, failure = terminal["startup"], terminal["failure"]
    begin, end = api["bound"](recovery), api["bound"](failure)
    native_end = terminal["native_terminal"]
    need(terminal["schema"] == "horizon-epoch145-v5o-stopped-status-owner-v1"
         and terminal["invocation_id"] == terminal["old_manager"]["InvocationID"] == begin["iid"] == end["iid"] == IID
         and submission["invocation_id"] == IID and intent["argv"] == submission["argv"]
         and terminal["dispatcher"] == {"path": str(seal_file), "sha256": SEAL_SHA}
         and intent["review_sha256"] == terminal["review"]["sha256"]
         and begin["image"] == review["reader"]["sha256"] and begin["r2_mutations"] is False
         and recovery["path"] == str(PRIVATE / "recovery-started.json") and failure["path"] == str(PRIVATE / "failed.json")
         and native_end["UNIT"] == UNIT and native_end["INVOCATION_ID"] == IID
         and terminal["original_status_terminal"]["INVOCATION_ID"] == OWNER
         and native_end["EXIT_CODE"] == "exited" and native_end["EXIT_STATUS"] == "1"
         and end["error"].rstrip().endswith("ValueError: different status writer invocation")
         and terminal["archive_publication_authorized"] is False and terminal["replay_launch_authorized"] is False
         and terminal["source_checkpoint_exists"] is False and terminal["resource_credit_bytes"] == 0,
         "unbound V5o status-owner stop")
    candidate = review["failed_phase"]["candidate"]
    frozen = terminal["candidate"]
    need(candidate["inode"] == frozen["inode"] == 103237059
         and candidate["bytes"] == frozen["bytes"] == 105610995833
         and begin["file"] == frozen["path"], "different frozen epoch 145 candidate")
    phase = dict(review["failed_phase"], InvocationID=IID, failure=failure, recovery=recovery,
                 manager_exit={key: value for key, value in native_end.items() if key != "MESSAGE"},
                 retry_worker=None, source_checkpoint_exists=False, resource_credit_bytes=0,
                 status_owner_terminal=receipt)
    return api, dict(terminal=terminal, failed_phase=phase, predecessor_review=terminal["review"],
                     original_fragment=dict(path=terminal["old_manager"]["FragmentPath"], sha256=FRAGMENT_SHA),
                     predecessor_dispatch=terminal["dispatcher"], old_manager=terminal["old_manager"])


def stopped_phase(_s, fit):
    api, proof = historical()
    need = api["require"]
    manager = api["inspect_unit"]()
    api["check_empty"](manager)
    need(manager == proof["old_manager"] and not fit.members(UNIT), "different stopped V5o manager or cgroup")
    api["retained"](api["bound"](proof["predecessor_review"]))
    api["read"](manager["FragmentPath"], FRAGMENT_SHA)
    need({p.name for p in PRIVATE.iterdir()} == {"failed.json", "recovery-started.json"}
         and api["inspect_unit"]() == manager and not fit.members(UNIT),
         "V5o checkpoint or manager changed during the retained-input check")
    return proof["failed_phase"]
