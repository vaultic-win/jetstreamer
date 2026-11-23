#!/usr/bin/python3 -IB
"""Resolve the original v5j semantic successor and its current ordinary publication inputs.

inspect reports the implementation, source equivalence and actual predecessor state.
capture records only a genuine completed semantic generation. Neither operation
runs a verifier, changes a unit, uploads an archive or creates a checksum.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = R / "epoch145-semantic-continuity-20261121-v1"
POST = R / "epoch145-publication-20261121-v1"
DISPATCH = R / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v1"
PAIR = R / "fast-range-residency-20261121-v1/archive-publication-58709604/ordinary/QUALIFIED.json"
PAIR_SHA = "cd357ec5b130887d41961aa7803acb50e833bdbc2dd1f8ebba23252a87b5d3a4"
DISPATCH_SEAL = "19c0fe27899e6742d095b075377b2adb9aebdb47b2ad2655688b214cd8b632de"
ORIGINAL = "de6780b860b3467bae21fbd19176ca14"
ARCHIVE = Path("/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/epoch-145.jet")
ANCHORS = Path("/usr/local/lib/jetstreamer/horizon-epoch145-independent-boundary-metadata-20261106-v1")
ANCHOR_SHA = {
    "incoming-62639999-source.json": "5fd04d4f501d77f9866b469f33e3ac729d44187979e6937e9856e880de401ede",
    "terminal-63071999-response.json": "0c0adba08c80831f2cfcbf98ba6a0ad5e4d0cc537f7570c2c0414dce755860c7",
}
PARENT_HASH = "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB"
LAST_HASH = "4zqmYpqcustpx2BQ2gB6y7v1HsvZpPGeyaRKFEsbThum"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
ORIGIN = "https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev"
READER = "58709604dfa4c97336c2e1f6fac53b862ed6f17f"
POH_SOURCE = "historical-runtime/v1_0_8/worker/src/poh_backend.rs"


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def load_dispatch():
    expected = (DISPATCH / "deployment-seal-receipt.json").read_bytes()
    need(hashlib.sha256(expected).hexdigest() == DISPATCH_SEAL, "different semantic dispatcher seal")
    row, = [r for r in json.loads(expected)["members"] if r["name"] == "run-recovery"]
    program = DISPATCH / row["name"]
    need(hashlib.sha256(program.read_bytes()).hexdigest() == row["sha256"], "different semantic dispatcher")
    return runpy.run_path(str(program))


def original_pair(d, git):
    raw, pair_ref = d["read"](PAIR, PAIR_SHA)
    pair = json.loads(raw)
    reader = d["bound"](pair["reader"])
    local = d["bound"](pair["local_acceptance"])
    remote = d["bound"](pair["remote_acceptance"])
    transfer = d["bound"](pair["archive_identity"])
    result = local["local_playback"]
    public = remote["remote_playback"]["playback"]
    need(reader["reader_commit"] == remote["reader_commit"] == READER and pair["threads"] == 1
         and reader["full_and_plugin_capabilities_accepted"] and reader["source_artifact_correspondence_accepted"]
         and reader["minimum_thread_stack_bytes"] == 67108864
         and local["full_exit_code"] == result["process_exit_code"] == public["process_exit_code"] == 0
         and result["report"]["full_epoch_verified"] is True and public["report"]["full_epoch_verified"] is True
         and result["report"]["report"] == public["report"]["report"]
         and result["report"]["report"]["slots"] == pair["slot_count"] == 432000
         and result["pipeline"] == public["pipeline"] == reader["pipeline"]
         and local["full_verifier"] == reader["full_verifier"] and transfer["remote_sha256_readback"] is True
         and transfer["current_reader_playback"] == pair["remote_acceptance"]
         and pair["production_r2_mutations"] == 0, "ordinary paired fixture changed")
    neg = d["read"](pair["negative_stderr"]["path"], pair["negative_stderr"]["sha256"])[0]
    need(b"public archive HTTP status or range identity mismatch" in neg and b"no readiness publication permitted" in neg,
         "missing strong ETag negative result")
    for obj in (reader["full_verifier"], reader["pipeline"], pair["uploader"], pair["uploader_seal"]):
        d["read"](obj["path"], obj["sha256"], 256 << 20)
    scopes = remote["compared_reader_paths"]
    need(len(scopes) == 12 and "Cargo.lock" in scopes and "jetstreamer-firehose" in scopes,
         "different ordinary uploader reader scope")
    tip = git("rev-parse", "origin/account-updates").strip()
    need(re.fullmatch("[0-9a-f]{40}", tip), "missing fetched branch")
    git("merge-base", "--is-ancestor", READER, tip)
    need(not git("diff", "--name-only", READER, tip, "--", *scopes, POH_SOURCE), "current reader inputs changed")
    anchors = [d["read"](ANCHORS / name, sha)[1] for name, sha in ANCHOR_SHA.items()]
    return dict(pair=pair_ref, qualification=pair["reader"], full_verifier=reader["full_verifier"],
                pipeline=reader["pipeline"], uploader=pair["uploader"], uploader_seal=pair["uploader_seal"],
                negative=pair["negative_stderr"], ordinary_reader_scopes=scopes,
                additional_compiled_input=POH_SOURCE, reader_commit=READER, fetched_tip=tip, anchors=anchors)


def validate_terminal(iid, intent, result, review, rows, receipts):
    need(re.fullmatch("[0-9a-f]{32}", iid) and iid != review["old_manager"]["InvocationID"]
         and result["invocation_id"] == iid and result["argv"] == intent["argv"], "foreign semantic generation")
    start = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    end = [r for r in rows if r.get("MESSAGE_ID") == SUCCESS]
    need(len(start) == len(end) == 1 and start[0]["__CURSOR"] == result["manager_start_cursor"]
         and int(start[0]["__MONOTONIC_TIMESTAMP"]) < int(end[0]["__MONOTONIC_TIMESTAMP"])
         and all(r.get("INVOCATION_ID") == iid and r.get("UNIT") == review["old_manager"]["Id"]
                 and r.get("_PID") == "1" and r.get("_BOOT_ID") == intent["original"]["_BOOT_ID"] for r in rows)
         and start[0]["MESSAGE"] == "Started " + review["old_manager"]["Id"] + " - "
             + " ".join(result["argv"][result["argv"].index("--") + 1:]) + ".", "missing unique successful PID1 exit")
    (started, sr), (verified, vr), (extracted, er), (done, dr) = receipts
    candidate = review["failed_phase"]["candidate"]
    source, _, leaf = review["retained_inputs"]
    view = Path(leaf["path"]).parent.parent / "epoch145-prefix-extract-materialized-view-20261121-v1/epoch-145.jet"
    need(started["iid"] == verified["iid"] == extracted["actor_iid"] == done["iid"] == iid
         and started["file"] == verified["paid_source"] == leaf["path"]
         and started["image"] == review["reader"]["sha256"]
         and started["fresh_fit"]["phase145"]["invocation_id"] == iid
         and started["fresh_fit"]["phase145"]["stage"] == "controller"
         and started["fresh_fit"]["serial_145_holding_handback"] == intent["preflight"]["serial_handback"]
         and started["fresh_fit"]["phase145"]["window"]["native_parent"]["pid"] == verified["parent"]
         and verified["before"] == candidate and verified["private_projection"] == str(view)
         and extracted["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
         and extracted["recovery_evidence"] == sr and extracted["verified_frozen"] == vr
         and extracted["archive_publication_authorized"] is False and done["receipt"] == er
         and done["recovered_from"] == extracted["original_export"] == verified["original_export"] == ORIGINAL
         and all(x["r2_mutations"] is False for x in (started, verified, extracted, done)),
         "broken semantic completion, source generation or handback chain")
    e = extracted["extraction"]
    need(verified["extraction"] == dict(e, archive=str(view))
         and e["schema"] == "jetstreamer-private-epoch145-canonical-prefix-extraction-v1"
         and e["archive"] == str(ARCHIVE) and e["epoch"] == 145
         and e["archive_bytes"] == candidate["bytes"] == 105610995833
         and e["output_slot_start"] == 62640000 and e["output_slot_count"] == 432000
         and e["source_archive"] == source["path"]
         and e["source_archive_sha256"] == "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353"
         and e["source_manifest_sha256"] == review["retained_manifest"]["sha256"]
         and e["worker_sha256"] == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
         and e["source_canonical_checkpoint_slot"] == 63072070
         and e["source_canonical_accounts_hash"] == "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p"
         and e["retained_verification_tail_slots"] == 71 and e["source_must_be_retained"] is True
         and e["independent_output_reread_passed"] is True
         and all(e[k] is False for k in ("current_plugin_verification_passed", "canonical_sidecar_authorized",
                 "publication_authorized", "retirement_authorized", "r2_mutations"))
         and all(re.fullmatch(r"[a-f0-9]{64}", e[k]) for k in ("archive_sha256", "output_semantic_sha256",
                 "expected_output_provenance_sha256")), "wrong semantic range or promotion")
    return dict(schema="horizon-145-v5j-semantic-completion-v1", invocation_id=iid, start=sr, verified=vr, extraction=er, completion=dr, pid1_success=end[0]["__CURSOR"],
                archive=str(ARCHIVE), archive_bytes=e["archive_bytes"], archive_sha256=e["archive_sha256"],
                provenance_sha256=e["expected_output_provenance_sha256"])


def semantic(d):
    review = json.loads(d["read"](DISPATCH / "admission-review.json", d["REVIEW_SHA"])[0])
    result_path = d["HANDOFF"] / "submission-result.json"
    if not result_path.exists():
        return None
    result = json.loads(d["read"](result_path)[0])
    intent = json.loads(d["read"](d["HANDOFF"] / "submission-intent.json")[0])
    d["Host"](review, None).check_intent(intent)
    iid = result["invocation_id"]
    need(re.fullmatch("[0-9a-f]{32}", iid) and iid != d["OLD"], "foreign dispatch result")
    root = d["STATE"] / iid
    need(not os.path.lexists(root / "failed.json"), "semantic verifier failed")
    if not (root / "complete.json").exists():
        return None
    d["handbacks"](review, intent["preflight"]["serial_handback"])
    names = ("recovery-started.json", "verified-frozen.json", "extraction-complete.json", "complete.json")
    receipts = []
    for name in names:
        data, ref = d["read"](root / name)
        receipts.append((json.loads(data), ref))
    rows = [json.loads(row) for row in d["out"](["/usr/bin/journalctl", "-o", "json", "--no-pager", "_PID=1",
            "UNIT=" + d["UNIT"], "INVOCATION_ID=" + iid, "_BOOT_ID=" + intent["original"]["_BOOT_ID"]]).splitlines()]
    receipt = validate_terminal(iid, intent, result, review, rows, receipts)
    m = ARCHIVE.lstat()
    saved = review["retained_inputs"][-1]
    need(ARCHIVE.resolve(strict=True) == ARCHIVE and (m.st_dev, m.st_ino, m.st_nlink, m.st_uid, m.st_gid,
         m.st_mode, m.st_size, m.st_mtime_ns) == (saved["dev"], saved["ino"], 1, 0, 0, stat.S_IFREG | 0o400,
         saved["size"], saved["mtime_ns"]) and not os.path.lexists(saved["path"]), "promoted candidate inode differs")
    return receipt


def main():
    need(os.geteuid() == 0 and sys.flags.isolated and __debug__ and sys.argv[1:] in (["inspect"], ["capture"]),
         "expected inspect or capture, as root")
    d = load_dispatch()
    git = lambda *args: subprocess.check_output(["runuser", "-u", "sol", "--", "git", "-C",
                              "/home/sol/workspace/jetstreamer", *args], text=True, timeout=30)
    artifacts = original_pair(d, git)
    verified = semantic(d)
    if sys.argv[1] == "capture":
        need(verified is not None, "waiting for the v5j semantic invocation and PID1 success")
        path = d["HANDOFF"] / "semantic-completion.json"
        with (d["HANDOFF"] / "dispatch.lock").open("rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            need(semantic(d) == verified, "semantic completion changed during capture")
            if path.exists():
                need(json.loads(d["read"](path)[0]) == verified, "different semantic completion already captured")
            else:
                d["record"](path, verified)
    print(json.dumps(dict(schema="horizon-145-v5j-publication-inputs-v1", artifacts=artifacts, semantic=verified,
                          semantic_pending=verified is None, public_origin=ORIGIN,
                          local_first_slot=62640000, local_last_slot=63071999, expected_slots=432000,
                          parent_slot=62639999, parent_blockhash=PARENT_HASH, terminal_blockhash=LAST_HASH,
                          publication_authorized=False, epoch_145_publicly_verified=False), sort_keys=True))


if __name__ == "__main__":
    main()
