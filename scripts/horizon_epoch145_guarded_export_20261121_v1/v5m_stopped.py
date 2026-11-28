"""Price the stopped V5m verifier from its original PID1, leases and registered guard incident."""
import hashlib
import json
from pathlib import Path
import runpy

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
UNIT = "horizon-holding-export145-20261121-v1.service"
IID = "dba04d40f1b046b4875d7e27e0ff224a"
PREV = "ff597d64ad37400ea5c6836336fb6706"
DISPATCH = R / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v4"
DSHA = "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea"
REVIEW = "28540e178ace196165ea892f924001a72b59396708b8269fb3a057a2627b132f"
STATE = R / "epoch145-guarded-export-20261121-v1/state" / IID
HANDOFF = R / "epoch145-semantic-continuity-20261121-v1/v5m-name-handoff"
CUT = R / "survivor172-cadence-20261122-v1/recover-d70fbbee88bf03f6e186"
GUARDS = R / "epoch168-retry4-rebook-20261123-v1/guard-receipts"
OBSERVATIONS = Path("/home/sol/.jetstreamer-private/epoch145-lease-stop-20261123")
GUARD0 = "6b701446a70e4fc4a09f85526ad81888"
GUARD1 = "e3e83f9497324e20b5e07e2db0bc834f"
PRODUCER = "horizon-qualify-168-full-metered-cold-v4-20261123.service"
ARTIFACTS = {
    "recovery": (STATE/"recovery-started.json", "06d2a4fa77bebe110f4d1c218bc91ec3066dc2e86f07575332d8725c1cf4e9b7"),
    "failure": (STATE/"failed.json", "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"),
    "intent": (HANDOFF/"submission-intent.json", "a74f6baa6df7a09a83e4303a9af4fd5bac6bcbc77b13d26f8bca1b2527609a3a"),
    "submitted": (HANDOFF/"submission-result.json", "b86b407f6d971b8d5e5ec2df4dd3b64eff9cd79b7981490f065eeca4458f55f2"),
    "argv": (HANDOFF/"submission-attempt.json", "aa0197bf7d5dd68155091b3fbd2a8bf735b59ae1598781a87a7ebde0525e8420"),
    "worker_sample": (OBSERVATIONS/f"v5m-{IID}-advancing.json", "92f0cc7f87d1e8c20d0b033c5b8357bcacc8659b5ee281ca38196df42036b824"),
    "cadence": (CUT/"TERMINAL.json", "8e26b646a132844f965601cf25ff7d7b931da08d44565631745e6ee2e8283aed"),
    "registered": (CUT/"REGISTERED.json", "119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"),
    "previous_guard": (GUARDS/f"sample-{GUARD0}.json", "5c17c6b126b48f713a33d655088fcc66cdb48131d71100bd07b9642084a167b6"),
    "rejected_guard": (GUARDS/f"sample-{GUARD1}.json", "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"),
}
BIRTH = "s=7f76387dd96140468b39dcf01e726fea;i=3930a1f;b=763ea84ca81f4dddad364b1ea2ba36dd;m=372d5dd7c7f;t=660f2a2b0d9b7;x=454e19dd6aa54fde"
EXIT = "s=7f76387dd96140468b39dcf01e726fea;i=3931f0c;b=763ea84ca81f4dddad364b1ea2ba36dd;m=37361c5fe7e;t=660f32e995bb6;x=f3aa80e136682cd7"
FRAGMENT = "9b9d2197f07a4a741c20264442b803fd5cac2c338b4f414056e6235d90fb8f76"
LEASES = {"100214429", "100214450", "103237059"}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def ref(name):
    path, sha = ARTIFACTS[name]
    return {"path": str(path), "sha256": sha}


def validate(prior, v, rows):
    started, failed, sample = (v[k] for k in ("recovery", "failure", "worker_sample"))
    intent, submitted, argv = (v[k] for k in ("intent", "submitted", "argv"))
    birth, = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    exit_row, = [r for r in rows if r.get("MESSAGE_ID") == "98e322203f7a4ed290d09fe03c09fe15"]
    need(all(r["INVOCATION_ID"] == IID and r["UNIT"] == UNIT and r["_PID"] == "1" and
             r["_BOOT_ID"] == prior["original_pid1_exit"]["_BOOT_ID"] for r in rows) and
         birth["__CURSOR"] == sample["manager_start_cursor"] == submitted["manager_start_cursor"] == BIRTH and
         exit_row["__CURSOR"] == EXIT and exit_row["COMMAND"] == "ExecStart" and
         exit_row["EXIT_STATUS"] == "1" and exit_row["EXIT_CODE"] == "exited", "different manager closure")
    need(prior["old_manager"]["InvocationID"] == PREV and prior["failed_phase"]["InvocationID"] == PREV and
         intent["original"] == prior["original_pid1_exit"] and intent["review_sha256"] == REVIEW and
         intent["preflight"]["quote_provider"]["sha256"] == sample["dispatch_seal_sha256"] == DSHA and
         submitted["invocation_id"] == started["iid"] == failed["iid"] == sample["invocation_id"] == IID and
         sample["submission"] == ref("submitted") and sample["intent"] == ref("intent") and
         submitted["argv"] == intent["argv"] == argv, "different dispatch or generation")
    payload = [prior["reader"]["path"], "recover-full-output", intent["fleet"]["path"],
               intent["fleet"]["sha256"], prior["reader"]["sha256"]]
    win = sample["window"]
    native = started["fresh_fit"]["phase145"]
    need(argv[argv.index("--") + 1:] == payload and birth["MESSAGE"] == f"Started {UNIT} - " + " ".join(payload) + "."
         and started["image"] == sample["image_sha256"] == payload[-1] and started["r2_mutations"] is False and
         started["file"] == prior["retained_inputs"][-1]["path"] and sample["stage"] == "leased-worker" and
         sample["rchar"] > 0 and native["invocation_id"] == IID and native["stage"] == "controller" and
         native["window"]["native_parent"] == win["native_parent"] == {"pid": 1416212, "start_ticks": 379174913}
         and win["native_child"] == {"pid": 1416486, "start_ticks": 379177645} and
         set(win["leases_worker"]) == set(win["leases_parent"]) == LEASES and
         win["recovery"] == sample["source"] == ref("recovery"), "wrong original candidate or leased worker")

    reg, cut, before, after = (v[k] for k in ("registered", "cadence", "previous_guard", "rejected_guard"))
    need(reg["terminal"] == ref("cadence") and cut["error"] == "native HOST RSS unavailable" and
         reg["config"]["sha256"] == "5b1796b7e8cec8e246f032b5200bfbf8f7a5418b592378c5aefc388237da4a39" and
         cut["failed_sample"]["sha256"] == "12c6e0c8aeebf47eec61587448cfc921d149fc4584eee15786a3a2416b38d551" and
         v["last_accepted"]["previous_Root_operational_review"] == intent["fleet"] and
         v["rejected_sample"]["host_resident_memory"]["before"]["status"] == "unavailable" and
         v["rejected_sample"]["host_resident_memory"]["after"]["status"] == "observed",
         "different missed-clock lineage or real RSS result")
    for guard, iid, counts in ((before, GUARD0, [0, 0]), (after, GUARD1, [1, 0])):
        observation = guard["root_physical_observation"]
        need(guard["guard_invocation_id"] == iid and guard["producer_invocation_id"] == "913443d7f9f44d7e9d3e0eec420acfab"
             and guard["producer"]["cgroup"] == "/system.slice/" + PRODUCER and guard["trip_reason"] is None and
             [observation[k]["vanished_entries"] for k in ("first", "second")] == counts,
             "different native guard producer, trip or counts")
    old_guard, new_guard = ref("previous_guard"), ref("rejected_guard")
    error = failed["error"]
    need(error.startswith(f"live guard refused the registered hold: guard {PRODUCER} measured remaining 143612534784 ")
         and all(v in error for row in (old_guard, new_guard) for v in row.values()) and
         error.endswith("has vanished counts 1/0") and
         int(birth["__REALTIME_TIMESTAMP"])*1000 < sample["sample_unix_ns"] < before["recorded_unix_seconds"]*10**9
         and before["recorded_unix_seconds"] < after["recorded_unix_seconds"] <= failed["at"]
         and int(exit_row["__REALTIME_TIMESTAMP"])//10**6 == failed["at"], "wrong terminal cause or order")
    return dict(prior["failed_phase"], InvocationID=IID, failure=ref("failure"), recovery=ref("recovery"),
                manager_exit={k: val for k, val in exit_row.items() if k != "MESSAGE"}, retry_worker=None,
                source_checkpoint_exists=False, resource_credit_bytes=0, original_leased_sample=ref("worker_sample"),
                rejected_fleet_sample=ref("cadence"), registered_missed_clock=ref("registered"),
                previous_guard=old_guard, rejected_guard=new_guard)


def historical():
    seal_file = DISPATCH / "deployment-seal-receipt.json"
    raw = seal_file.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == DSHA, "changed original handoff")
    member, = [m for m in json.loads(raw)["members"] if m["name"] == "run-recovery" and m["mode"] == "0555"]
    dispatcher = DISPATCH/member["name"]
    need(hashlib.sha256(dispatcher.read_bytes()).hexdigest() == member["sha256"], "changed original dispatcher")
    api = runpy.run_path(str(dispatcher))
    review = {"path": str(DISPATCH/"admission-review.json"), "sha256": REVIEW}
    prior = api["bound"](review)
    values = {k: api["bound"](ref(k)) for k in ARTIFACTS}
    values["rejected_sample"] = api["bound"](values["cadence"]["failed_sample"])
    values["last_accepted"] = api["bound"](values["cadence"]["fleet"])
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
                     receipts={k: ref(k) for k in ARTIFACTS})


def check_state():
    need({p.name for p in STATE.iterdir()} == {"failed.json", "recovery-started.json"},
         "unexpected private checkpoint or terminal state")


def stopped_phase(s, fit):
    api, proof = historical()
    manager = api["inspect_unit"]()
    api["check_empty"](manager)
    need(manager == proof["old_manager"] and not fit.members(UNIT), "current stopped owner or cgroup differs")
    api["retained"](api["bound"](proof["predecessor_review"]))
    api["read"](manager["FragmentPath"], FRAGMENT)
    check_state()
    need(api["inspect_unit"]() == manager and not fit.members(UNIT), "owner changed during retained-input check")
    return proof["failed_phase"]
