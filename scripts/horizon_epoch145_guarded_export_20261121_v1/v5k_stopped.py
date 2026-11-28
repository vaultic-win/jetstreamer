"""Recognize the drained 145 verifier after the timestamped whole-fleet RSS failure."""
import hashlib
import json
from pathlib import Path
import runpy

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
UNIT = "horizon-holding-export145-20261121-v1.service"
IID = "ff597d64ad37400ea5c6836336fb6706"
PREV = "f2afc696a63a4e6aa6812451cf3559e5"
DISPATCH = R / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v3"
DSHA = "f69f462cecb76fc586799d36f358e61b1880f99d0c024b0c76dd27d3a2f9637e"
STATE = R / "epoch145-guarded-export-20261121-v1/state" / IID
HANDOFF = R / "epoch145-semantic-continuity-20261121-v1/v5k-name-handoff"
REVIEW = "1a7f7bce208d97831963c66c462bbac28b7f9b84e990d09fa5da7e5efa56d150"
CUT = R / "survivor172-cadence-20261122-v1/recover-14d3c8e8336c6a6b9c5f/TERMINAL.json"
SAMPLE = Path("/home/sol/.jetstreamer-private/epoch145-v5j-phase-handoff-20261123") / ("v5k-" + IID + "-cadence124757.json")
ARTIFACTS = {
    "started": (STATE / "recovery-started.json", "706b0986b8a3979caa083d08ac007d93905919819b50126486e738cee6977e48"),
    "failed": (STATE / "failed.json", "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"),
    "intent": (HANDOFF / "submission-intent.json", "1acc976f93de0120fdf67b5563e21c534564a89b2c8d5c724bd8578d16e92143"),
    "submitted": (HANDOFF / "submission-result.json", "a2cfbdd6f29f3ca2d956ba25f60ae7876fe71c575f1e6c4ab3c591670e437831"),
    "argv": (HANDOFF / "submission-attempt.json", "d6787e85e5a116629f42ece935f13667d4732b8d595a5d595d5a2784030db6b7"),
    "cadence": (CUT, "2207cace258fbf1b1fea4525c3766d366456eb9d489528f89ab77d42a1ed51c7"),
    "worker_sample": (SAMPLE, "dc98543ae2639051a346d12c4051df532ea9ce9350b34ab481220b51ad60e752"),
}
BIRTH = "s=7f76387dd96140468b39dcf01e726fea;i=392cf86;b=763ea84ca81f4dddad364b1ea2ba36dd;m=370ee81b204;t=660f0bb550f3c;x=a7a844a5337d79b4"
EXIT = "s=7f76387dd96140468b39dcf01e726fea;i=392dea5;b=763ea84ca81f4dddad364b1ea2ba36dd;m=3715c5ba3c4;t=660f1292f00fc;x=9ce15931ff2f7280"
FRAGMENT = "ded885b2eba32b0a475ad16ee5d019389e7151bb05087c692d833caad6e52981"
LEASES = {"100214429", "100214450", "103237059"}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def evidence(api):
    prior = api["bound"]({"path": str(DISPATCH / "admission-review.json"), "sha256": REVIEW})
    values = {k: api["bound"]({"path": str(p), "sha256": sha}) for k, (p, sha) in ARTIFACTS.items()}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    fields = "_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,COMMAND"
    result = api["out"](["/usr/bin/journalctl", "--no-pager", "-ojson", "--output-fields=" + fields,
                         "_BOOT_ID=" + boot, "_PID=1", "UNIT=" + UNIT, "INVOCATION_ID=" + IID])
    return prior, values, [json.loads(line) for line in result.splitlines()]


def validate(prior, v, rows):
    started, failed, sampled = v["started"], v["failed"], v["worker_sample"]
    submitted, intent, argv = v["submitted"], v["intent"], v["argv"]
    born, = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    exited, = [r for r in rows if r.get("MESSAGE_ID") == "98e322203f7a4ed290d09fe03c09fe15"]
    need(all(r["INVOCATION_ID"] == IID and r["UNIT"] == UNIT and r["_PID"] == "1" and
             r["_BOOT_ID"] == prior["original_pid1_exit"]["_BOOT_ID"] for r in rows) and
         born["__CURSOR"] == submitted["manager_start_cursor"] == sampled["manager_start_cursor"] == BIRTH and
         exited["__CURSOR"] == EXIT and exited["EXIT_STATUS"] == "1" and exited["EXIT_CODE"] == "exited" and
         exited["COMMAND"] == "ExecStart", "wrong PID1 closure")
    need(prior["old_manager"]["InvocationID"] == PREV and
         failed["iid"] == started["iid"] == sampled["invocation_id"] == submitted["invocation_id"] == IID and
         intent["review_sha256"] == REVIEW and intent["original"] == prior["original_pid1_exit"] and
         argv == intent["argv"] == submitted["argv"] and intent["preflight"]["quote_provider"]["sha256"] == DSHA,
         "different paid dispatch")
    payload = [prior["reader"]["path"], "recover-full-output", intent["fleet"]["path"],
               intent["fleet"]["sha256"], prior["reader"]["sha256"]]
    need(argv[argv.index("--") + 1:] == payload and born["MESSAGE"] == f"Started {UNIT} - " + " ".join(payload) + "." and
         started["image"] == sampled["image_sha256"] == prior["reader"]["sha256"] and
         started["file"] == prior["retained_inputs"][-1]["path"] and started["r2_mutations"] is False,
         "different verifier image or retained candidate")
    win = sampled["window"]
    phase = started["fresh_fit"]["phase145"]
    need(phase["invocation_id"] == IID and phase["stage"] == "controller" and
         phase["window"]["native_parent"] == win["native_parent"] == {"pid": 1359289, "start_ticks": 378357260} and
         win["native_child"] == {"pid": 1359692, "start_ticks": 378359980} and sampled["stage"] == "leased-worker" and
         set(win["leases_parent"]) == set(win["leases_worker"]) == LEASES and sampled["rchar"] > 0 and
         win["recovery"] == sampled["source"] == {"path": str(ARTIFACTS["started"][0]), "sha256": ARTIFACTS["started"][1]},
         "different worker or paid inputs")
    need(int(born["__REALTIME_TIMESTAMP"]) * 1000 < sampled["sample_unix_ns"] < failed["at"] * 10**9 and
         int(exited["__REALTIME_TIMESTAMP"]) // 10**6 == failed["at"] and
         v["cadence"]["error"] == "native HOST RSS unavailable" and v["cadence"]["fleet"] == intent["fleet"] and
         failed["error"].startswith("complete 145 capacity observation failed exit status: 1:") and
         'in fleet_head' in failed["error"] and failed["error"].rstrip().endswith("ValueError: stale or incomplete root fleet"),
         "different census failure")
    ref = lambda key: {"path": str(ARTIFACTS[key][0]), "sha256": ARTIFACTS[key][1]}
    return dict(prior["failed_phase"], InvocationID=IID, failure=ref("failed"), recovery=ref("started"),
                manager_exit={k: v for k, v in exited.items() if k != "MESSAGE"}, retry_worker=None,
                source_checkpoint_exists=False, resource_credit_bytes=0, original_leased_sample=ref("worker_sample"),
                rejected_fleet_sample=ref("cadence"))


def historical():
    """Reconstruct the original closure even after its transient unit has been released."""
    raw = (DISPATCH / "deployment-seal-receipt.json").read_bytes()
    need(hashlib.sha256(raw).hexdigest() == DSHA, "wrong dispatcher seal")
    row, = [r for r in json.loads(raw)["members"] if r["name"] == "run-recovery"]
    script = DISPATCH / row["name"]
    need(hashlib.sha256(script.read_bytes()).hexdigest() == row["sha256"], "wrong dispatcher reader")
    api = runpy.run_path(str(script))
    prior, values, rows = evidence(api)
    phase = validate(prior, values, rows)
    argv = values["argv"]
    expected = dict(prior["old_manager"], InvocationID=IID, Description=" ".join(argv[argv.index("--") + 1:]))
    refs = {k: {"path": str(path), "sha256": digest} for k, (path, digest) in ARTIFACTS.items()}
    refs["recovery"] = refs.pop("started")
    refs["failure"] = refs.pop("failed")
    proof = dict(predecessor_review={"path": str(DISPATCH / "admission-review.json"), "sha256": REVIEW},
                 predecessor_dispatch={"path": str(DISPATCH / "deployment-seal-receipt.json"), "sha256": DSHA},
                 failed_phase=phase, old_manager=expected, original_pid1_exit=phase["manager_exit"],
                 original_fragment=dict(prior["original_fragment"], sha256=FRAGMENT), receipts=refs)
    need({p.name for p in STATE.iterdir()} == {"failed.json", "recovery-started.json"},
         "unexpected terminal state in the failed generation")
    return api, proof


def stopped_phase(s, fit):
    api, proof = historical()
    native = api["inspect_unit"]()
    api["check_empty"](native)
    need(native == proof["old_manager"] and not fit.members(UNIT),
         "failed owner no longer exclusively holds the drained unit")
    api["retained"](api["bound"](proof["predecessor_review"]))
    api["read"](native["FragmentPath"], FRAGMENT)
    need({p.name for p in STATE.iterdir()} == {"failed.json", "recovery-started.json"} and
         api["inspect_unit"]() == native and not fit.members(UNIT), "state or owner changed during inspection")
    return proof["failed_phase"]
