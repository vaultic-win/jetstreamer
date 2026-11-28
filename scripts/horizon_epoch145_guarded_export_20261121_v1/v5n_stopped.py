"""Validate the stopped V5n verifier for a read-only whole-fleet quote."""
import hashlib
import json
from pathlib import Path
import runpy

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
UNIT = "horizon-holding-export145-20261121-v1.service"
IID = "f86e7e61f4b34dc7aedc4e08a128e713"
PREV = "dba04d40f1b046b4875d7e27e0ff224a"
FIT = R / "incident-replay-fit-20261121-v1"
DISPATCH = FIT / "tools-homefloor-145-handoff-v5"
DSHA = "080e95f9c7be162980589d1513c25ff2a4638d9e00d163a60e12c6d2475a5308"
REVIEW = "73439c7bff8fbd6ab806ab70f7e8953dae890c8e3b783ab7b8d7c3e270de18ff"
STATE = R / "epoch145-guarded-export-20261121-v1/state" / IID
HANDOFF = R / "epoch145-semantic-continuity-20261121-v1/v5n-name-handoff"
SAMPLE = Path("/home/sol/.jetstreamer-private/epoch145-lease-stop-20261123")
PROVIDER = FIT / "tools-homefloor-145-guard-walk-rejoin-v1/post-stop-fit"
ARTIFACTS = {
    "recovery": (STATE / "recovery-started.json", "dad6a11f67b7717668c0189c607142ac89a64fc7fde8971b28b4e3c8622619ed"),
    "failure": (STATE / "failed.json", "553c2d9be55bf4688dd1c8b42bc497ba2f6ea985305e42b7fb7db951f400bd36"),
    "intent": (HANDOFF / "submission-intent.json", "d15dfa6d3212f8a868bd00ac5df3ef26eee42466c0ac7afc7f0e9ab42aa2f23e"),
    "submitted": (HANDOFF / "submission-result.json", "57eb2aadef0bd6e5591800c439fa0f2e6d701c2f4baa3dc45b5074fdddebd02e"),
    "argv": (HANDOFF / "submission-attempt.json", "c8e5d5d8152dcc9ec89f7bf41587e2515d69bab5ae04b6b146e3e9dc3ba1f533"),
    "worker_sample": (SAMPLE / f"v5n-{IID}-advancing.json", "7c9fe570d5317309d2891e559706d913760f145789c752882e19c1bf2f58118f"),
}
BIRTH = "s=7f76387dd96140468b39dcf01e726fea;i=39337ad;b=763ea84ca81f4dddad364b1ea2ba36dd;m=3740d21d064;t=660f3d9f52d9b;x=75b218dcd9f056c1"
EXIT = "s=7f76387dd96140468b39dcf01e726fea;i=3939abf;b=763ea84ca81f4dddad364b1ea2ba36dd;m=3773256be19;t=660f6ff2a1b51;x=2d6d856f9594a198"
FRAGMENT = "fdcd6569454e0bb7b2c454aac90d268eaecf04c187b96b90d321dbebf75a7406"
PARENT = {"pid": 1465473, "start_ticks": 379697130}
CHILD = {"pid": 1465739, "start_ticks": 379699871}
LEASES = {"100214429", "100214450", "103237059"}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def ref(name):
    path, sha = ARTIFACTS[name]
    return {"path": str(path), "sha256": sha}


def validate(prior, values, rows):
    started, failed, sample = (values[k] for k in ("recovery", "failure", "worker_sample"))
    intent, submitted, argv = (values[k] for k in ("intent", "submitted", "argv"))
    birth, = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    exit_row, = [r for r in rows if r.get("MESSAGE_ID") == "98e322203f7a4ed290d09fe03c09fe15"]
    need(all(r["INVOCATION_ID"] == IID and r["UNIT"] == UNIT and r["_PID"] == "1" and
             r["_BOOT_ID"] == prior["original_pid1_exit"]["_BOOT_ID"] for r in rows) and
         birth["__CURSOR"] == sample["manager_start_cursor"] == submitted["manager_start_cursor"] == BIRTH and
         exit_row["__CURSOR"] == EXIT and exit_row["COMMAND"] == "ExecStart" and
         exit_row["EXIT_STATUS"] == "1" and exit_row["EXIT_CODE"] == "exited", "different V5n PID1 closure")
    need(prior["old_manager"]["InvocationID"] == prior["failed_phase"]["InvocationID"] == PREV and
         intent["original"] == prior["original_pid1_exit"] and intent["review_sha256"] == REVIEW and
         intent["preflight"]["quote_provider"]["sha256"] == sample["dispatch_seal_sha256"] == DSHA and
         submitted["invocation_id"] == started["iid"] == failed["iid"] == sample["invocation_id"] == IID and
         sample["submission"] == ref("submitted") and sample["intent"] == ref("intent") and
         submitted["argv"] == intent["argv"] == argv, "different V5n dispatch or generation")

    payload = [prior["reader"]["path"], "recover-full-output", intent["fleet"]["path"],
               intent["fleet"]["sha256"], prior["reader"]["sha256"]]
    native = started["fresh_fit"]["phase145"]
    worker = sample["window"]
    candidate = started["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"]
    need(argv[argv.index("--") + 1:] == payload and birth["MESSAGE"] == f"Started {UNIT} - " + " ".join(payload) + "."
         and started["image"] == sample["image_sha256"] == payload[-1] and started["r2_mutations"] is False
         and started["initial"]["fleet"] == started["fresh_fit"]["fleet"] == intent["fleet"]
         and started["file"] == prior["retained_inputs"][-1]["path"] and candidate == prior["failed_phase"]["candidate"]
         and sample["stage"] == "leased-worker" and sample["rchar"] > 0 and native["invocation_id"] == IID
         and native["stage"] == "controller" and native["window"]["native_parent"] == worker["native_parent"] == PARENT
         and worker["native_child"] == CHILD and set(worker["leases_worker"]) == set(worker["leases_parent"]) == LEASES
         and native["window"]["continuity_seal"] == worker["continuity_seal"] == prior["seal"]
         and native["window"]["guard_walk_failure"] == worker["guard_walk_failure"] == prior["failed_phase"]["failure"]
         and worker["recovery"] == sample["source"] == ref("recovery"), "different V5n retained candidate or leased worker")

    error = failed["error"].rstrip()
    need(error.startswith("complete 145 capacity observation failed exit status: 1: Traceback ") and
         str(PROVIDER) in error and "build_159_price.py" in error and
         error.endswith("ValueError: insufficient HOME or general-slot memory") and
         int(birth["__REALTIME_TIMESTAMP"]) * 1000 < sample["sample_unix_ns"] < failed["at"] * 10**9
         and int(exit_row["__REALTIME_TIMESTAMP"]) // 10**6 == failed["at"], "different V5n terminal cause or order")
    return dict(prior["failed_phase"], InvocationID=IID, failure=ref("failure"), recovery=ref("recovery"),
                manager_exit={k: v for k, v in exit_row.items() if k != "MESSAGE"},
                retry_worker=None, source_checkpoint_exists=False, resource_credit_bytes=0,
                original_leased_sample=ref("worker_sample"))


def check_state():
    need({p.name for p in STATE.iterdir()} == {"failed.json", "recovery-started.json"},
         "unexpected V5n private checkpoint or terminal state")


def historical():
    seal_file = DISPATCH / "deployment-seal-receipt.json"
    raw = seal_file.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == DSHA, "changed V5n handoff seal")
    seal = json.loads(raw)
    need(seal["destination"] == str(DISPATCH), "different V5n handoff destination")
    member, = [m for m in seal["members"] if m["name"] == "run-recovery" and m["mode"] == "0555"]
    dispatcher = DISPATCH / member["name"]
    need(hashlib.sha256(dispatcher.read_bytes()).hexdigest() == member["sha256"], "changed V5n dispatcher")
    api = runpy.run_path(str(dispatcher))
    review = {"path": str(DISPATCH / "admission-review.json"), "sha256": REVIEW}
    prior = api["bound"](review)
    values = {key: api["bound"](ref(key)) for key in ARTIFACTS}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    fields = "_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,COMMAND"
    rows = api["out"](["/usr/bin/journalctl", "--no-pager", "-ojson", "--output-fields=" + fields,
                       "_BOOT_ID=" + boot, "_PID=1", "UNIT=" + UNIT, "INVOCATION_ID=" + IID])
    phase = validate(prior, values, [json.loads(line) for line in rows.splitlines()])
    argv = values["argv"]
    manager = dict(prior["old_manager"], InvocationID=IID, Description=" ".join(argv[argv.index("--") + 1:]))
    check_state()
    return api, dict(predecessor_review=review, predecessor_dispatch={"path": str(seal_file), "sha256": DSHA},
                     failed_phase=phase, old_manager=manager, original_pid1_exit=phase["manager_exit"],
                     original_fragment=dict(prior["original_fragment"], sha256=FRAGMENT),
                     receipts={key: ref(key) for key in ARTIFACTS})


def stopped_phase(_s, fit):
    api, proof = historical()
    manager = api["inspect_unit"]()
    api["check_empty"](manager)
    need(manager == proof["old_manager"] and not fit.members(UNIT), "different stopped V5n manager or cgroup")
    api["retained"](api["bound"](proof["predecessor_review"]))
    api["read"](manager["FragmentPath"], FRAGMENT)
    check_state()
    need(api["inspect_unit"]() == manager and not fit.members(UNIT), "V5n changed during retained-input check")
    return proof["failed_phase"]
