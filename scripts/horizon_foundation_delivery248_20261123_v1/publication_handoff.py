"""Close completed publisher rows in the existing scheduled Foundation controller."""

import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from ordinary249.delivery248 import aws, bound, props, ref

PACKAGE = Path("/var/lib/jetstreamer/foundation-handoff-v232-a1")
STATE = Path("/home/ubuntu/.jetstreamer-private/foundation-publication-handoffs-v232")
STATUS = STATE.parent / "r2-status-receipts"
HELPER = {"path": str(PACKAGE / "publication_handoff"), "sha256": "91d1518189b826c91e57392c0bea62b174174fc7271b046111a17e0a6e8605d0"}
ROSTER = {"path": str(PACKAGE / "roster.json"), "sha256": "6e6bae82404e3d550b880ddd7dcda7fd7a0eefa410d054de27c099a08cc2e1e0"}
R2 = {"path": "/var/lib/jetstreamer/horizon265-delivery-consumers-v215-seven222a3-qualified/jetstreamer-r2", "sha256": "bab685686ff41d9bfc96a245fc292de38fb1dc91ab3a62c4bf4978bb8a2e8a05"}
STARTED = "39f53479d3a045ac8e11786248231fbf"
SUCCEEDED = "7ad2d189f7e94e70a38c781354912448"


def checked_image(binding):
    path = Path(binding["path"])
    assert path.resolve() == path and path.stat().st_uid == 0 and not path.stat().st_mode & 0o222
    with path.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == binding["sha256"]
    return str(path)


def drained(claim):
    unit = claim["unit"]
    fields = ["Id", "InvocationID", "ActiveState", "MainPID", "ControlPID", "NRestarts", "ControlGroup", "Job", "Result", "LoadState"]
    state = props(unit, fields)
    if state["ActiveState"] != "inactive":
        return None
    assert state["Id"] == unit
    if state["LoadState"] == "not-found":
        assert not state["InvocationID"]
    else:
        assert state["LoadState"] == "loaded" and state["InvocationID"] == claim["invocation_id"]
    assert state["MainPID"] == state["ControlPID"] == state["NRestarts"] == "0"
    assert state["Result"] == "success" and not state["Job"] and not state["ControlGroup"]
    assert not (Path("/sys/fs/cgroup/system.slice") / unit).exists()
    return state


def terminal_evidence(claim):
    iid, unit = claim["invocation_id"], claim["unit"]
    raw = subprocess.check_output(["journalctl", "-b", "--no-pager", "-o", "json",
                                   "--output-fields=_PID,_UID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,UNIT_RESULT",
                                   "_PID=1", "_UID=0", "UNIT=" + unit, "INVOCATION_ID=" + iid], timeout=10)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    events = [json.loads(line) for line in raw.splitlines()]
    assert all((e["_BOOT_ID"], e["UNIT"], e["INVOCATION_ID"], e["_PID"], e["_UID"])
               == (boot, unit, iid, "1", "0") for e in events)
    starts = [e for e in events if e.get("MESSAGE_ID") == STARTED]
    stops = [e for e in events if e.get("MESSAGE_ID") == SUCCEEDED]
    assert len(starts) == len(stops) == 1 and all(e.get("UNIT_RESULT", "success") == "success" for e in events)
    assert int(starts[0]["__MONOTONIC_TIMESTAMP"]) < int(stops[0]["__MONOTONIC_TIMESTAMP"])
    return {"started": starts[0], "finished": stops[0]}


def fallback_publication(completion, wd, record):
    """Bind the exact conditional write, prior bytes, and authenticated readback."""
    done = bound(completion)
    intent_ref = done["intent"]
    intent = bound(intent_ref)
    directory = Path(intent_ref["path"]).parent
    old = bound(intent["previous"])
    raw = done["readback"]
    assert old["key"] == done["key"] and done["authenticated_exact_byte_readback"]
    assert ref(directory / "before.json")["sha256"] == old["readback"]["sha256"]
    assert ref(directory / "payload.json")["sha256"] == raw["sha256"]
    payload = bound(raw)
    assert intent["payload"] == payload and done["key"] == f"epoch-{payload['epoch']}.epoch-status.json"
    return record(wd / "fallback-completion.json", {
        "schema": "horizon-status-only-correction-completion-v1", "epoch": payload["epoch"], "key": done["key"],
        "before_etag": old["etag"], "after_etag": done["etag"], "before_sha256": old["readback"]["sha256"],
        "after_sha256": raw["sha256"], "sampled_at_utc": payload["sampled_at_utc"], "phase": payload["phase"],
        "authenticated_exact_byte_readback": True, "conditional_header": "If-Match", "archive_or_sidecar_mutation": False,
    })


def selected_status(current, previous, claim_ref, record):
    """Finish a fallback receipt if its conditional PUT survived the cadence."""
    marker = current / "completion.json"
    if marker.is_file():
        return ref(marker)
    intent_path, blob = current / "intent.json", current / "payload.json"
    if not intent_path.is_file() or not blob.is_file():
        return previous
    intent_ref = ref(intent_path)
    intent, old = bound(intent_ref), bound(previous)
    payload = ref(blob)
    assert intent["previous"] == previous and intent["key"] == old["key"]
    assert intent["payload"] == bound(payload) and intent["owner"]["claim"] == claim_ref
    assert ref(current / "before.json")["sha256"] == old["readback"]["sha256"]
    observed = aws("head-object", "--key", old["key"])
    etag = observed["ETag"]
    if etag == old["etag"]:
        return previous
    with tempfile.TemporaryDirectory(dir=current) as scratch:
        candidate = Path(scratch) / "status.json"
        got = aws("get-object", "--key", old["key"], "--if-match", etag, str(candidate))
        assert got["ETag"] == etag and ref(candidate)["sha256"] == payload["sha256"]
        final = current / "readback.json"
        if not final.exists():
            with candidate.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(candidate, final)
        assert ref(final)["sha256"] == payload["sha256"]
        return record(marker, dict(key=old["key"], etag=etag, intent=intent_ref,
                                   readback=ref(final), authenticated_exact_byte_readback=True))


def status_cleanup(epoch, claim_ref, spec, proof, completion, wd, record):
    done = bound(completion)
    raw = done["readback"]
    payload = bound(raw)
    claim = bound(claim_ref)
    assert done["authenticated_exact_byte_readback"] and done["key"] == f"epoch-{epoch}.epoch-status.json"
    intent = bound(done["intent"])
    assert intent["payload"] == payload and intent["owner"]["claim"] == claim_ref
    assert intent["owner"]["invocation_id"] == claim["invocation_id"]
    stamp = time.strftime("%Y%m%d%H%M%S", time.strptime(payload["sampled_at_utc"], "%Y-%m-%dT%H:%M:%SZ"))
    latest = STATUS / f"epoch-{epoch}.status-{stamp}.json"
    tool = checked_image(R2)
    if latest.is_file():
        native = ref(latest)
        receipt = bound(native)
        assert receipt["status"] == payload and receipt["object_etag"] == done["etag"].strip('"')
        assert receipt["pipeline_binding"]["invocation_id"] == claim["invocation_id"]
        command = [tool, "status-delete", spec["archive_directory"], "--epochs", f"{epoch}-{epoch}", "--receipt-directory", str(STATUS),
                   "--archive-receipt-directory", spec["receipt_directory"], "--status-publication-receipt", native["path"],
                   "--status-publication-sha256", native["sha256"]]
        subprocess.run(command, check=True, capture_output=True, timeout=60)
        deletion = ref(STATUS / f"epoch-{epoch}.status-deletion.json")
        result = bound(deletion)
        assert result["status_publication_receipt_sha256"] == native["sha256"]
        assert result["archive_receipt_sha256"] == proof["archive"]["sha256"]
    else:
        publisher = fallback_publication(completion, wd, record)
        # Keep existing private-state bindings valid across retries. Runtime
        # directories outside private state must use the qualified receipt root.
        evidence = wd if wd.is_relative_to(STATUS.parent) else STATUS
        plan = wd / "fallback-plan.json" if evidence == wd else evidence / f"epoch-{epoch}.fallback-ready-status-plan.json"
        dest = evidence / f"epoch-{epoch}.fallback-ready-status-deletion.json"
        policy = record(plan, {
            "schema": "jetstreamer-r2-fallback-ready-status-plan-v1", "epoch": epoch, "bucket": spec["bucket"],
            "status_delete_authorized": True, "archive_or_sidecar_mutations": False,
            "fallback_completion": publisher, "raw_status": raw, "archive_receipt": proof["archive"],
            "deletion_intent": str(evidence / f"epoch-{epoch}.fallback-ready-status-delete-intent.json"), "deletion_receipt": str(dest),
        })
        command = [tool, "status-delete-fallback-ready", policy["path"], "--plan-sha256", policy["sha256"], "--self-sha256", R2["sha256"]]
        check = json.loads(subprocess.check_output([*command, "--check-only"], timeout=60))
        assert check["authenticated_ready_pair"] and not check["remote_mutations"]
        subprocess.run(command, check=True, capture_output=True, timeout=60)
        deletion = ref(dest)
        result = bound(deletion)
        assert result["binding"]["archive_receipt"] == proof["archive"] and result["binding"]["fallback_completion"] == publisher
    assert result["authenticated_ready_pair_before"] and result["authenticated_ready_pair_after"] and result["authenticated_status_absent_after"]
    return deletion


def collect(all_claims, statuses, out, record):
    """Called while the sole cadence owner holds its cycle lock."""
    definitions = bound(ROSTER)
    assert {int(n): row["claim"] for n, row in definitions.items()} == all_claims
    closed = {}
    for epoch, claim_ref in all_claims.items():
        wd = STATE / str(epoch)
        marker = wd / "completion.json"
        if marker.exists():
            binding = ref(marker)
            old = bound(binding)
            assert old["claim"] == claim_ref and old["spec"] == definitions[str(epoch)]["spec"]
            assert bound(old["deletion"])["authenticated_status_absent_after"]
            closed[epoch] = binding
            continue
        row = definitions[str(epoch)]
        spec = bound(row["spec"])
        archive = Path(spec["receipt_directory"]) / f"epoch-{epoch}.r2.json"
        if not archive.is_file():
            continue
        claim = bound(claim_ref)
        if drained(claim) is None:
            continue
        wd.mkdir(mode=0o700, exist_ok=True)
        # A previously registered pidfd collector may still be reading the ready prefix.
        watch = Path(claim_ref["path"]).parent / "terminal.lock"
        with watch.open("a+b") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            manager = drained(claim)
            assert manager is not None
            terminal = terminal_evidence(claim)
            proof = json.loads(subprocess.check_output([checked_image(HELPER), row["spec"]["path"], row["spec"]["sha256"]], timeout=30))
            assert proof["archive"] == ref(archive) and proof["epoch"] == epoch
            intent_path = wd / "handoff-intent.json"
            if intent_path.exists():
                intent = ref(intent_path)
                old = bound(intent)
                assert old["claim"] == claim_ref and old["proof"] == proof
                status = old["status"]
            else:
                status = selected_status(out / str(epoch), statuses[epoch], claim_ref, record)
                intent = record(intent_path, {"claim": claim_ref, "proof": proof, "spec": row["spec"], "status": status,
                                              "terminal": terminal, "manager": manager})
            deletion = status_cleanup(epoch, claim_ref, spec, proof, status, wd, record)
            assert drained(claim) is not None
            closed[epoch] = record(marker, {"claim": claim_ref, "spec": row["spec"], "epoch": epoch, "intent": intent,
                                            "archive": proof["archive"], "playback": proof["playback"], "deletion": deletion,
                                            "ready": True, "local_retirement_authorized": False, "capacity_released": False})
    return closed
