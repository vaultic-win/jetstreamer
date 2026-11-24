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
import time

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = R / "epoch145-semantic-continuity-20261121-v1"
POST = R / "epoch145-publication-20261121-v1"
AUDIT_POST = (Path(__file__).resolve().parent.name == "tools-v13k" or
              (Path(__file__).name == "post_inputs.py" and sys.argv[1:2] == ["--audit-turnover"]))
PRESSURE_POST = (Path(__file__).resolve().parent.name == "tools-v13j" or
                 (Path(__file__).name == "post_inputs.py" and sys.argv[1:2] == ["--donor-pressure"]))
PINNED_POST = AUDIT_POST or PRESSURE_POST
GUARD_POST = (PINNED_POST or Path(__file__).resolve().parent.name in ("tools-v13h", "tools-v13i") or
              (Path(__file__).name == "post_inputs.py" and sys.argv[1:2] == ["--guard-walk"]))
MISSED_POST = GUARD_POST or (Path(__file__).resolve().parent.name == "tools-v13g" or
               (Path(__file__).name == "post_inputs.py" and sys.argv[1:2] == ["--missed-clock"]))
LEASE_POST = MISSED_POST or (Path(__file__).resolve().parent.name == "tools-v13f" or
              (Path(__file__).name == "post_inputs.py" and sys.argv[1:2] == ["--lease-ready"]))
RETRY = LEASE_POST or (Path(__file__).resolve().parent.name == "tools-v13e" or
         (Path(__file__).name == "post_inputs.py" and sys.argv[1:2] == ["--retry1"]))
DISPATCH = R / "incident-replay-fit-20261121-v1" / ("tools-homefloor-145-handoff-v8" if AUDIT_POST else "tools-homefloor-145-handoff-v6" if PRESSURE_POST else "tools-homefloor-145-handoff-v5" if GUARD_POST else "tools-homefloor-145-handoff-v4" if MISSED_POST else "tools-homefloor-145-handoff-v3" if LEASE_POST else "tools-homefloor-145-handoff-v2" if RETRY else "tools-homefloor-145-handoff-v1")
PAIR = R / "fast-range-residency-20261121-v1/archive-publication-58709604/ordinary/QUALIFIED.json"
PAIR_SHA = "cd357ec5b130887d41961aa7803acb50e833bdbc2dd1f8ebba23252a87b5d3a4"
DISPATCH_SEAL = "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea" if MISSED_POST else "f69f462cecb76fc586799d36f358e61b1880f99d0c024b0c76dd27d3a2f9637e" if LEASE_POST else "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee" if RETRY else "19c0fe27899e6742d095b075377b2adb9aebdb47b2ad2655688b214cd8b632de"
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
V5Q_IID = "cbacb5a17e6347509640846eccb95cb0"
V5Q_BINDING = "a5dc1d9973d950d36f7302b800f0b10421066e135e0912750fd92b98521cadc4"
V5Q_INTENT = "7e5e053d00263b2e89bfcb22664718d2c9157ec67ca360bd7e165bd9573384e6"
V5Q_RESULT = "398f1a2d5d5a50ab4d35c0f27de035d7c07023b6c8d632ef326b9fcd169cb5e9"
V5Q_START = "7659aca1cf87aaeeb42a5c5c65ad186a03d1e55e9ce4dc0779d351b36ba30781"
V5Q_SAMPLE = "5e1df7ed658d5239dd9109bee5651fc9c301a26fff1329ae8cf30e01a2d4f433"
V5Q_PROVIDER = "f553f7a4f7d4b061f637b0a83e936e6dd6a9a33d4dcae56b15e492f74339b679"
V5P_IID = "c01dc3ba08b74e3aa0d4b531601e9fda"
V5P_DISPATCH = "6f2eef7457f0fcde62b55a0d64b2f15844bc038bdff4f58fd1d8e676c4572fe4"
V5P_STOPPED = "b2febb131aa5c7e1ae42644a241311a8c0d30b82b4ecfb5946b884230d1ea888"
V5O_IID = "f3474dfad55f4a05a64431421881db29"
V5O_BINDING = "d571da98684079bc937a2ddeed52dbcd457eb0a74010519171b851e3e5297137"
V5O_INTENT = "96080ed3e71613abd4072b666d1b6503316797dd30be0a788d7a0d4488c3aa63"
V5O_RESULT = "4d80587d22ffa0883696f96c30958b54d30fb5455bde35050e96b50c8ba8c544"
V5O_START = "e4b9e72a6481ea4f38b8fe7b49986463e2f93d37bc1dcb7f2156049930fd744b"
V5N_IID = "f86e7e61f4b34dc7aedc4e08a128e713"
V5N_DISPATCH = "080e95f9c7be162980589d1513c25ff2a4638d9e00d163a60e12c6d2475a5308"
V5N_REVIEW = "73439c7bff8fbd6ab806ab70f7e8953dae890c8e3b783ab7b8d7c3e270de18ff"
V5N_STOPPED = "a43da5f9618b8a5af9750e4201c67447a2fe50aa830d1445e6a896ad37e88dbf"
V5N_STATE = R / "epoch145-guarded-export-20261121-v1/state" / V5N_IID
V5N_FAILURE = {"path": str(V5N_STATE / "failed.json"),
               "sha256": "553c2d9be55bf4688dd1c8b42bc497ba2f6ea985305e42b7fb7db951f400bd36"}
V5N_RECOVERY = {"path": str(V5N_STATE / "recovery-started.json"),
                "sha256": "dad6a11f67b7717668c0189c607142ac89a64fc7fde8971b28b4e3c8622619ed"}


def selected_submission():
    if AUDIT_POST:
        return V5Q_IID, V5Q_INTENT, V5Q_RESULT, V5Q_START
    return V5O_IID, V5O_INTENT, V5O_RESULT, V5O_START


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def validate_pressure_ancestry(binding, proof, review, original_review, failed, started):
    phase = review["failed_phase"]
    terminal = review["original_pid1_exit"]
    receipts = review["predecessor_receipts"]
    need(proof["schema"] == "horizon-epoch145-donor-pressure-recovery-build-v1"
         and proof["predecessor_dispatch"] == binding["prior_dispatch"]
         and proof["donor_pressure_failure"] == receipts["failure"] == phase["failure"] == V5N_FAILURE
         and proof["donor_pressure_recovery"] == receipts["recovery"] == phase["recovery"] == V5N_RECOVERY
         and review["original_review"] == {"path":str(DISPATCH.parent / "tools-homefloor-145-handoff-v5/admission-review.json"),
                                           "sha256":V5N_REVIEW}
         and all(review[name] == original_review[name] for name in ("retained_inputs", "retained_manifest", "holding"))
         and phase["candidate"] == original_review["failed_phase"]["candidate"]
         and failed["iid"] == started["iid"] == phase["InvocationID"] == terminal["INVOCATION_ID"] == V5N_IID
         and phase["manager_exit"] == terminal and terminal["_PID"] == "1" and terminal["COMMAND"] == "ExecStart"
         and terminal["EXIT_CODE"] == "exited" and terminal["EXIT_STATUS"] == "1"
         and failed["error"].rstrip().endswith("ValueError: insufficient HOME or general-slot memory")
         and phase["source_checkpoint_exists"] is False and phase["resource_credit_bytes"] == 0
         and phase["retry_worker"] is None and started["r2_mutations"] is False,
         "V5o does not descend from the original stopped V5n")


def validate_audit_ancestry(api, binding, proof, review, stopped):
    seal = api["bound"](binding["prior_stopped"])
    member, = (m for m in seal["members"] if m["name"] == "v5p_stopped.py" and m["mode"] == "0444")
    adapter = Path(binding["prior_stopped"]["path"]).with_name(member["name"])
    raw, _ = api["read"](adapter, member["sha256"])
    stopped_api = {"__file__":str(adapter), "__name__":"prior_v5p_stop"}
    exec(compile(raw, str(adapter), "exec"), stopped_api)
    _, original = stopped_api["historical"]()
    prior_review = api["bound"](original["predecessor_review"])
    need(seal["destination"] == str(stopped)
         and proof["schema"] == "horizon-epoch145-audit-turnover-recovery-build-v1"
         and proof["predecessor_dispatch"] == binding["prior_dispatch"] == original["predecessor_dispatch"]
         and proof["public_audit_terminal"] == original["receipts"]["public_audit_terminal"]
         and review["predecessor_receipts"] == original["receipts"]
         and review["failed_phase"] == original["failed_phase"]
         and review["old_manager"] == original["old_manager"]
         and review["original_pid1_exit"] == original["original_pid1_exit"]
         and review["original_review"] == original["predecessor_review"]
         and proof["resumed_status"] == review["resumed_status"]
         and all(review[k] == prior_review[k] for k in ("retained_inputs", "retained_manifest", "holding"))
         and proof["donor_pressure_failure"] == V5N_FAILURE and proof["donor_pressure_recovery"] == V5N_RECOVERY,
         "V5q does not descend from the stopped V5p and retained paid inode")
    for key in ("status_owner_failure", "status_owner_recovery", "status_owner_terminal",
                "donor_pressure_failure", "donor_pressure_recovery"):
        api["bound"](proof[key])
    state = V5N_STATE.parent
    for iid in (V5N_IID, V5O_IID, V5P_IID):
        need({p.name for p in (state / iid).iterdir()} == {"failed.json", "recovery-started.json"},
             "a failed predecessor has an unexpected checkpoint: " + iid)


def guard_bindings():
    # The qualified worker installer records the three sealer results in one
    # root-owned, write-once receipt after validating and installing each.
    successor = "v5q" if AUDIT_POST else "v5o" if PRESSURE_POST else "v5n"
    previous = DISPATCH.parent / ("tools-homefloor-145-handoff-v7" if AUDIT_POST else "tools-homefloor-145-handoff-v5" if PRESSURE_POST else "tools-homefloor-145-handoff-v4")
    previous_digest = V5P_DISPATCH if AUDIT_POST else V5N_DISPATCH if PRESSURE_POST else "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea"
    stopped = "v5p" if AUDIT_POST else "v5n" if PRESSURE_POST else "v5m"
    stopped_digest = V5P_STOPPED if AUDIT_POST else V5N_STOPPED if PRESSURE_POST else "b066013b8e25ae95d43b2e0984ad7df55c47e9a68a32c685e54d1f71667151d7"
    oldseal = (previous / "deployment-seal-receipt.json").read_bytes()
    need(hashlib.sha256(oldseal).hexdigest() == previous_digest, "different preceding dispatcher anchor")
    member, = [m for m in json.loads(oldseal)["members"] if m["name"] == "run-recovery" and m["mode"] == "0555"]
    program = previous / "run-recovery"
    raw = program.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == member["sha256"], "different preceding dispatcher reader")
    api = {"__file__":str(program), "__name__":"prior_145_dispatcher"}
    exec(compile(raw, str(program), "exec"),api)
    raw, receipt = api["read"](BASE / f"{successor.upper()}_RUNTIME_BINDINGS.json")
    b = json.loads(raw)
    if PINNED_POST:
        need(receipt["sha256"] == (V5Q_BINDING if AUDIT_POST else V5O_BINDING),
             "different qualified semantic runtime binding")
    need(b["schema"] == f"horizon-145-qualified-{successor}-runtime-v1"
         and b["prior_dispatch"] == {"path":str(previous/"deployment-seal-receipt.json"),"sha256":previous_digest}
         and b["prior_stopped"] == {"path":str(DISPATCH.parent/f"tools-homefloor-145-{stopped}-stopped-v1/deployment-seal-receipt.json"),"sha256":stopped_digest},
         "foreign predecessor or stopped provider")
    runtime = "audit-turnover" if AUDIT_POST else "donor-pressure" if PRESSURE_POST else "guard-walk"
    for key,path in (("worker",BASE/f"tools-{successor}"),("provider",DISPATCH.parent/f"tools-homefloor-145-{runtime}-rejoin-v1"),("dispatcher",DISPATCH)):
        seal = api["bound"](b[key])
        need(b[key]["path"] == str(path/"deployment-seal-receipt.json") and seal["destination"] == str(path)
             and seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
             and seal["remote_mutations"] is False, "wrong recovery installation")
        members={m["name"]:m["sha256"] for m in seal["members"]}
        if key == "worker":
            need(b["reader"] == {"path":str(path/"export145"),"sha256":members["export145"]}
                 and b["build"] == {"path":str(path/"build-proof.json"),"sha256":members["build-proof.json"]}, "foreign recovery image")
            if PINNED_POST:
                api["read"](b["reader"]["path"], b["reader"]["sha256"])
        if key == "dispatcher":
            need(b["review"] == {"path":str(path/"admission-review.json"),"sha256":members["admission-review.json"]}, "foreign recovery review")
    proof,review=api["bound"](b["build"]),api["bound"](b["review"])
    predecessor = V5P_IID if AUDIT_POST else V5N_IID if PRESSURE_POST else "dba04d40f1b046b4875d7e27e0ff224a"
    need(proof["build_iid"] == b["build_iid"] and proof["source_commit"] == b["source_commit"]
         and proof["capacity_provider"] == b["prior_stopped"] and proof["verifier_sha256"] == b["reader"]["sha256"]
         and proof["guard_walk_failure"]["sha256"] == "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"
         and review["old_manager"]["InvocationID"] == predecessor
         and review["reader"] == b["reader"] and review["seal"] == b["worker"] and review["provider"] == b["provider"], "unqualified recovery family")
    if AUDIT_POST:
        need(b["provider"]["sha256"] == V5Q_PROVIDER, "different V5q live capacity provider")
        validate_audit_ancestry(api, b, proof, review, Path(b["prior_stopped"]["path"]).parent)
    elif PRESSURE_POST:
        api["bound"](b["prior_stopped"])
        failed, started = (api["bound"](ref) for ref in (V5N_FAILURE, V5N_RECOVERY))
        validate_pressure_ancestry(b, proof, review, api["bound"](review["original_review"]), failed, started)
    return b,receipt


def load_dispatch():
    expected = (DISPATCH / "deployment-seal-receipt.json").read_bytes()
    binding = guard_bindings()[0] if GUARD_POST else None
    need(hashlib.sha256(expected).hexdigest() == (binding["dispatcher"]["sha256"] if GUARD_POST else DISPATCH_SEAL),
         "different semantic dispatcher seal")
    row, = [r for r in json.loads(expected)["members"] if r["name"] == "run-recovery"]
    program = DISPATCH / row["name"]
    need(hashlib.sha256(program.read_bytes()).hexdigest() == row["sha256"], "different semantic dispatcher")
    dispatcher = runpy.run_path(str(program))
    if PINNED_POST:
        version, predecessor, key = (("v5q", V5P_IID, "AUDIT_TURNOVER_RETRY") if AUDIT_POST
                                     else ("v5o", V5N_IID, "DONOR_PRESSURE_RETRY"))
        need(dispatcher[key] is True and dispatcher["OLD"] == predecessor
             and dispatcher["HANDOFF"] == BASE / f"{version}-name-handoff"
             and str(dispatcher["READER"]) == binding["reader"]["path"]
             and dispatcher["IMAGE_SHA"] == binding["reader"]["sha256"]
             and dispatcher["REVIEW_SHA"] == binding["review"]["sha256"], "different sealed semantic dispatch configuration")
    return dispatcher


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


def validate_missed_start(started, intent):
    native = started["fresh_fit"]
    window = native["phase145"]["window"]
    if GUARD_POST:
        b,_=guard_bindings()
        if PINNED_POST:
            validate_pressure_start(b, started, intent)
            if AUDIT_POST:
                validate_audit_start(b, started)
            return
        need(started["image"] == b["reader"]["sha256"] and intent["review_sha256"] == b["review"]["sha256"]
             and intent["original"]["INVOCATION_ID"] == "dba04d40f1b046b4875d7e27e0ff224a"
             and window["continuity_seal"] == b["worker"]
             and window["guard_walk_failure"]["sha256"] == "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"
             and window["rejected_guard"]["sha256"] == "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"
             and window["registered_guard_clock"]["sha256"] == "119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"
             and native["fits"] and native["fleet"] == intent["fleet"] and native["epoch159_donor_cover"]["fleet"] == intent["fleet"]
             and native["epoch159_donor_cover"]["credited_retirement_bytes"] == 0, "unbound guard walk recovery")
        return
    need(started["image"] == "9068d5ac9ccd4d35481cbf2882faf67a97b0926133663a2e4885917e714bdc21"
         and intent["original"]["INVOCATION_ID"] == "ff597d64ad37400ea5c6836336fb6706"
         and native["fits"] and native["fleet"] == intent["fleet"]
         and window["continuity_seal"]["sha256"] == "db422be5b246aa3aef2457fd9325f6b8cca739e3e4c63d2e4794ae30c527f6c4"
         and window["missed_clock_failure"]["sha256"] == "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"
         and native["epoch159_donor_cover"]["fleet"] == intent["fleet"]
         and native["epoch159_donor_cover"]["credited_retirement_bytes"] == 0,
         "unbound missed-clock worker or donor")


def validate_pressure_start(binding, started, intent):
    native = started["fresh_fit"]
    phase = native["phase145"]
    window = phase["window"]
    donor = native["epoch159_donor_cover"]
    feature = native["corrected_159_donor"]
    predecessor = V5P_IID if AUDIT_POST else V5N_IID
    need(re.fullmatch("[a-f0-9]{32}", started["iid"]) and started["iid"] != predecessor
         and started["image"] == binding["reader"]["sha256"] and started["r2_mutations"] is False
         and intent["original"]["INVOCATION_ID"] == predecessor
         and intent["review_sha256"] == binding["review"]["sha256"]
         and intent["preflight"]["quote_provider"] == binding["dispatcher"]
         and phase["invocation_id"] == started["iid"] and phase["stage"] == "controller"
         and window["continuity_seal"] == binding["worker"] and window["continuity_build"] == binding["build"]
         and window["donor_pressure_failure"] == V5N_FAILURE and window["donor_pressure_recovery"] == V5N_RECOVERY
         and window["missed_clock_failure"]["sha256"] == "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"
         and window["guard_walk_failure"]["sha256"] == "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"
         and window["rejected_guard"]["sha256"] == "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"
         and window["registered_guard_clock"]["sha256"] == "119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"
         and native["fits"] is True and native["fleet"] == donor["fleet"] == intent["fleet"]
         and native["complete_cpu_quota_micros"] == 64_000_000
         and native["complete_memory_plus_reserve_bytes"] == 810_658_050_048
         and native["resource_credit_bytes"] == donor["credited_retirement_bytes"] == 0
         and native["replay_launch_authorized"] is False and donor["replay_launch_authorized"] is False
         and donor["remaining_home_bytes"] >= 0
         and feature["unit"] == "horizon-epoch159-vote-feature-reference-20261123-v1.service"
         and feature["stage"] in ("unclaimed", "drained"), ("unbound V5q" if AUDIT_POST else "unbound V5o") + " startup, retained bytes or donor")


def validate_audit_start(binding, started):
    native = started["fresh_fit"]
    window = native["phase145"]["window"]
    path = Path(binding["build"]["path"])
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == binding["build"]["sha256"], "changed V5q startup build")
    proof = json.loads(raw)
    need(started["iid"] == V5Q_IID and native["provider_seal"] == binding["provider"]
         and native["status_registration"] == proof["resumed_status"]
         and all(window[k] == proof[k] for k in ("status_owner_failure", "status_owner_recovery",
                                                "status_owner_terminal", "public_audit_terminal")),
         "unbound V5q resumed cadence or prior terminal")


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
    if MISSED_POST:
        validate_missed_start(started, intent)
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


def submission(d, review):
    selected, expected_intent, expected_result, _ = selected_submission()
    pinned = AUDIT_POST or PRESSURE_POST
    result = json.loads(d["read"](d["HANDOFF"] / "submission-result.json", expected_result if pinned else None)[0])
    intent = json.loads(d["read"](d["HANDOFF"] / "submission-intent.json", expected_intent if pinned else None)[0])
    d["Host"](review, None).check_intent(intent)
    iid = result["invocation_id"]
    need(re.fullmatch("[0-9a-f]{32}", iid) and iid != d["OLD"], "foreign dispatch result")
    if pinned:
        need(iid == selected and result["argv"] == intent["argv"],
             "different submitted " + ("V5q" if AUDIT_POST else "V5o") + " invocation")
    return intent, result


def pressure_start(d, intent):
    iid, _, _, digest = selected_submission()
    data, receipt = d["read"](d["STATE"] / iid / "recovery-started.json", digest)
    start = json.loads(data)
    validate_missed_start(start, intent)
    return start, receipt


def live_pressure(d):
    binding, _ = guard_bindings()
    review = d["bound"](binding["review"])
    intent, result = submission(d, review)
    start, receipt = pressure_start(d, intent)
    seal = d["bound"](binding["provider"])
    member, = (m for m in seal["members"] if m["name"] == "post-stop-fit" and m["mode"] == "0555")
    path = Path(binding["provider"]["path"]).with_name("post-stop-fit")
    d["read"](path, member["sha256"])
    observe = runpy.run_path(str(path))["phase145"]
    for delay in (1, 2, 3, None):
        try:
            phase = observe(145)
            break
        except ValueError as exc:
            if delay is None or str(exc) != "foreign 145 descendants":
                raise
            time.sleep(delay)
    host = d["Host"](review, None)
    manager, events = host.state()
    window = phase["window"]
    iid, _, _, _ = selected_submission()
    need(phase["stage"] == "leased-worker" and phase["invocation_id"] == iid
         and manager["InvocationID"] == iid and result == host.accepted(manager, events, intent)
         and window["recovery"] == receipt
         and window["native_parent"] == start["fresh_fit"]["phase145"]["window"]["native_parent"]
         and str(window["native_parent"]["pid"]) == manager["MainPID"],
         "different leased child or original semantic controller")
    if AUDIT_POST:
        sample = json.loads(d["read"](BASE / "V5Q_ACTUAL_ADVANCING_WORKER.json", V5Q_SAMPLE)[0])
        validate_audit_sample(sample, binding, receipt, window)
    return phase


def validate_audit_sample(sample, binding, receipt, window):
    before, after = sample["worker"]
    child = window["native_child"]
    need(sample["iid"] == sample["manager"]["InvocationID"] == V5Q_IID
         and sample["startup"] == receipt and sample["reader"] == binding["reader"]
         and sample["submission"] == {"path":str(BASE / "v5q-name-handoff/submission-result.json"), "sha256":V5Q_RESULT}
         and sample["manager"]["MainPID"] == str(window["native_parent"]["pid"])
         and before["pid"] == after["pid"] == child["pid"]
         and before["start_ticks"] == after["start_ticks"] == child["start_ticks"]
         and after["observed_unix_ns"] > before["observed_unix_ns"]
         and after["cpu_ticks"] > before["cpu_ticks"] and after["rchar"] > before["rchar"]
         and sample["resource_credit_bytes"] == 0 and sample["archive_publication_authorized"] is False,
         "V5q leased child does not match its advancing witness")


def semantic(d):
    review = json.loads(d["read"](DISPATCH / "admission-review.json", d["REVIEW_SHA"])[0])
    result_path = d["HANDOFF"] / "submission-result.json"
    pinned = AUDIT_POST or PRESSURE_POST
    if not pinned and not result_path.exists():
        return None
    intent, result = submission(d, review)
    iid = result["invocation_id"]
    root = d["STATE"] / iid
    need(not os.path.lexists(root / "failed.json"), "semantic verifier failed")
    if pinned:
        pressure_start(d, intent)
    if not (root / "complete.json").exists():
        return None
    d["handbacks"](review, intent["preflight"]["serial_handback"])
    names = ("recovery-started.json", "verified-frozen.json", "extraction-complete.json", "complete.json")
    receipts = []
    for name in names:
        data, ref = d["read"](root / name, selected_submission()[3] if pinned and name == names[0] else None)
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


def verify_build_price(d, price):
    review = json.loads(d["read"](DISPATCH / "admission-review.json", d["REVIEW_SHA"])[0])
    host = d["Host"](review, None)
    intent, result = submission(d, review)
    manager, events = host.state()
    iid = result["invocation_id"]
    phase = price["phase145"]
    started = d["bound"](phase["window"]["recovery"])
    if PINNED_POST:
        need(phase["window"]["recovery"]["sha256"] == selected_submission()[3], "different sealed startup receipt")
    if AUDIT_POST:
        native = started["fresh_fit"]
        window = phase["window"]
        # The raw provider quote has no provider_seal field. The priced build
        # binds its executable in build-incident.sh and the startup binds it here.
        need(native["provider_seal"]["sha256"] == V5Q_PROVIDER
             and price["status_registration"] == native["status_registration"]
             and all(window[k] == native["phase145"]["window"][k] for k in
                     ("continuity_seal", "continuity_build", "public_audit_terminal", "status_owner_terminal",
                      "donor_pressure_failure", "donor_pressure_recovery")),
             "different V5q capacity provider, cadence or stopped predecessors")
        sample = json.loads(d["read"](BASE / "V5Q_ACTUAL_ADVANCING_WORKER.json", V5Q_SAMPLE)[0])
        validate_audit_sample(sample, {"reader":review["reader"]}, window["recovery"], window)
    if MISSED_POST:
        validate_missed_start(started, intent)
    need(result == host.accepted(manager, events, intent) and manager["InvocationID"] == iid
         and intent["original"]["INVOCATION_ID"] == d["OLD"]
         and phase["stage"] == "leased-worker" and phase["invocation_id"] == iid
         and phase["window"]["recovery"]["path"] == str(d["STATE"] / iid / "recovery-started.json")
         and started["iid"] == iid and started["image"] == d["IMAGE_SHA"] and started["r2_mutations"] is False
         and started["fresh_fit"]["phase145"]["window"]["native_parent"] == phase["window"]["native_parent"]
         and started["fresh_fit"]["serial_145_holding_handback"] == intent["preflight"]["serial_handback"],
         "build price is outside the running paid verifier generation")
    d["retained"](review)
    d["retry_handback"](review, price)


def main():
    args = sys.argv[2:] if RETRY and sys.argv[1:2] in (["--retry1"], ["--lease-ready"], ["--missed-clock"], ["--guard-walk"], ["--donor-pressure"], ["--audit-turnover"]) else sys.argv[1:]
    if RETRY and len(args) == 2 and args[0] == "verify-build-price":
        need(os.geteuid() == 0 and sys.flags.isolated and __debug__, "root isolated interpreter required")
        d = load_dispatch()
        verify_build_price(d, json.loads(d["read"](Path(args[1]))[0]))
        return
    if PINNED_POST and args in (["inspect-live"], ["inspect-semantic"]):
        need(os.geteuid() == 0 and sys.flags.isolated and __debug__, "root isolated interpreter required")
        inspect = live_pressure if args == ["inspect-live"] else semantic
        print(json.dumps(inspect(load_dispatch()), sort_keys=True))
        return
    need(os.geteuid() == 0 and sys.flags.isolated and __debug__ and args in (["inspect"], ["capture"]),
         "expected inspect or capture, as root")
    d = load_dispatch()
    git = lambda *args: subprocess.check_output(["runuser", "-u", "sol", "--", "git", "-C",
                              "/home/sol/workspace/jetstreamer", *args], text=True, timeout=30)
    artifacts = original_pair(d, git)
    verified = semantic(d)
    if args == ["capture"]:
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
