"""Recognize the paid 145 controller whose first child lease census failed."""
import json
from pathlib import Path
import runpy

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
IID = "f2afc696a63a4e6aa6812451cf3559e5"
PREVIOUS = "48ad7b2234d74e74b0498e7110e0aee3"
UNIT = "horizon-holding-export145-20261121-v1.service"
DISPATCH = ROOT / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v2"
DISPATCH_SHA = "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee"
REVIEW_SHA = "38774819c4dbbe1246851585afb57ba65df4919cbf457fb6a04b75ef2e77fc07"
IMAGE = "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4"
HANDOFF = ROOT / "epoch145-semantic-continuity-20261121-v1/v5j-name-handoff-retry1"
STATE = ROOT / "epoch145-guarded-export-20261121-v1/state" / IID
ARTIFACTS = {
    "recovery": (STATE / "recovery-started.json","adb40073fd977545227b6eaf1cd0999f8769a5a992999561eab7ca382d3c139e"),
    "failure": (STATE / "failed.json","eff2c5c0da6cb103890f6ced5cb11920959f637234567d7fd2382a2fca2fbcc7"),
    "intent": (HANDOFF / "submission-intent.json","920d4e1dd6035243b5b7c6fdcaf90260099794a473e9ea27e1da8a2d01edb8e3"),
    "submission": (HANDOFF / "submission-result.json","e882341c0f8ce3bb35b7e052b170025b91b7d0479a755aae2433719b0a7f8408"),
    "attempt": (HANDOFF / "submission-attempt.json","8b35960257548cbc40cb097c787fc723176427841a101c275e535c8dd2b7566b"),
    "detached": (HANDOFF / "detached-price-1795435623740868913.json","86bcab0ae5cd458e69cd005cef1c1eb8b09f17ad3547518899f3b9ddcdced21a"),
}
BIRTH = "s=7f76387dd96140468b39dcf01e726fea;i=392c4ea;b=763ea84ca81f4dddad364b1ea2ba36dd;m=370a1c02cdb;t=660f06e938a13;x=efa283a6fcab47c2"
EXIT = "s=7f76387dd96140468b39dcf01e726fea;i=392c529;b=763ea84ca81f4dddad364b1ea2ba36dd;m=370a38fe94f;t=660f070634687;x=f511576f0d9aa00e"
FRAGMENT = "3706f62c265af23cd82b1293eefbd4e65c1269637e93f842a2bd365d12a5e95e"


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def journal(command):
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-","")
    fields = "_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,COMMAND"
    return [json.loads(row) for row in command(["/usr/bin/journalctl","--no-pager","-ojson",
            "--output-fields="+fields,"_BOOT_ID="+boot,"_PID=1","UNIT="+UNIT,"INVOCATION_ID="+IID]).splitlines()]


def profile(read, rows, state=STATE):
    prior, review_ref = read(DISPATCH / "admission-review.json", REVIEW_SHA)
    seal, seal_ref = read(DISPATCH / "deployment-seal-receipt.json", DISPATCH_SHA)
    refs, values = {}, {}
    for key, (p, digest) in ARTIFACTS.items():
        values[key], refs[key] = read(p, digest)
    began, = [e for e in rows if e["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"]
    exited, = [e for e in rows if e["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15"]
    need(all(e["UNIT"] == UNIT and e["INVOCATION_ID"] == IID and e["_PID"] == "1" and
             e["_BOOT_ID"] == prior["original_pid1_exit"]["_BOOT_ID"] for e in rows)
         and began["__CURSOR"] == BIRTH and exited["__CURSOR"] == EXIT and exited["COMMAND"] == "ExecStart"
         and exited["EXIT_STATUS"] == "1" and exited["EXIT_CODE"] == "exited"
         and int(began["__MONOTONIC_TIMESTAMP"]) < int(exited["__MONOTONIC_TIMESTAMP"]), "foreign original process exit")
    intent, result, attempt = (values[k] for k in ("intent","submission","attempt"))
    failure, started = values["failure"], values["recovery"]
    need(prior["old_manager"]["InvocationID"] == PREVIOUS and intent["original"] == prior["original_pid1_exit"]
         and intent["review_sha256"] == REVIEW_SHA and seal["destination"] == str(DISPATCH)
         and intent["preflight"]["quote_provider"] == seal_ref and began["__CURSOR"] == result["manager_start_cursor"]
         and failure["iid"] == result["invocation_id"] == started["iid"] == IID and result["argv"] == intent["argv"] == attempt
         and attempt[attempt.index("--")+1:] == [prior["reader"]["path"], "recover-full-output", intent["fleet"]["path"], intent["fleet"]["sha256"], IMAGE]
         and began["MESSAGE"] == "Started " + UNIT + " - " + " ".join(attempt[attempt.index("--")+1:]) + "."
         and int(began["__REALTIME_TIMESTAMP"])//1000000 <= failure["at"] <= int(exited["__REALTIME_TIMESTAMP"])//1000000,
         "different paid submission")
    price, detached = intent["preflight"]["attached_price"], values["detached"]
    fresh = started["fresh_fit"]
    phase = fresh["phase145"]
    need(started["file"] == prior["retained_inputs"][-1]["path"] and started["image"] == prior["reader"]["sha256"] == IMAGE
         and started["r2_mutations"] is False and set(p.name for p in state.iterdir()) == {"failed.json","recovery-started.json"}
         and phase["invocation_id"] == IID and phase["stage"] == "controller" and "native_child" not in phase["window"]
         and phase["window"]["native_parent"] == {"pid":1347507, "start_ticks":378228485}
         and fresh["serial_145_holding_handback"] == intent["preflight"]["serial_handback"]
         and price["phase145"] == prior["failed_phase"] and not detached["phase145"]["InvocationID"]
         and detached["phase145"]["failure"] == prior["failed_phase"]["failure"]
         and all(v["fits"] is True and v["epoch"] == 145 and v["candidate"] is None and v["resource_credit_bytes"] == 0
                 and v["complete_cpu_quota_micros"] == 64000000 and v["complete_memory_plus_reserve_bytes"] == 810658050048
                 and v["fleet"] == intent["fleet"] for v in (price,detached,fresh))
         and started["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"] == prior["failed_phase"]["candidate"],
         "wrong controller phase, attached or detached full price")
    trace = failure["error"]
    need(trace.startswith("complete 145 capacity observation failed exit status: 1:")
         and 'tools-v5j/incident-phase.py", line 178, in inspect' in trace
         and "leases_parent=leased(pid, objects), leases_worker=leased(child, objects))" in trace
         and "^^^^^^^^^^^^^^^^^^^^^^^" in trace
         and 'session-v4-registered136/overlap.py", line 38, in leases' in trace
         and trace.rstrip().endswith("ValueError: original recovery read lease absent"), "different child lease failure")
    end = {k:v for k,v in exited.items() if k!="MESSAGE"}
    failed = dict(prior["failed_phase"], InvocationID=IID, candidate=prior["failed_phase"]["candidate"],
                  failure=refs["failure"], recovery=refs["recovery"], retry_worker=None, manager_exit=end,
                  source_checkpoint_exists=False, resource_credit_bytes=0)
    return dict(schema="horizon-epoch145-paid-child-lease-failure-v1", predecessor_review=review_ref,
                predecessor_dispatch=seal_ref, receipts=refs, failed_phase=failed,
                old_manager=dict(prior["old_manager"], InvocationID=IID), original_pid1_exit=end,
                original_fragment=dict(prior["original_fragment"],sha256=FRAGMENT),
                native_controller=phase["window"]["native_parent"], acquired_child_leases_proved=False,
                private_or_public_acceptance=False)

PROOF_SHA = "fa4634cb28b292062d682a2b07cf8c675bc0ed42bedf9f6866f3025bafbef8c1"


def historical():
    # This is the read-only evidence API of the actual earlier dispatcher.
    # Read the original immutable seal and authenticate its Python before loading it.
    import hashlib
    seal_data = (DISPATCH / "deployment-seal-receipt.json").read_bytes()
    need(hashlib.sha256(seal_data).hexdigest() == DISPATCH_SHA, "different v2 deployment")
    seal = json.loads(seal_data)
    member, = [r for r in seal["members"] if r["name"] == "run-recovery"]
    path = DISPATCH / "run-recovery"
    need(hashlib.sha256(path.read_bytes()).hexdigest() == member["sha256"], "different v2 dispatcher")
    api = runpy.run_path(str(path))
    def evidence(path, digest):
        data, ref = api["read"](path, digest)
        return json.loads(data), ref
    proof = profile(evidence, journal(api["out"]))
    encoded = (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(hashlib.sha256(encoded).hexdigest() == PROOF_SHA, "original failed generation changed")
    return api, proof


def build_phase(s, fit):
    api, proof = historical()
    native = api["inspect_unit"]()
    api["check_empty"](native)
    need(all(native[k] == v for k, v in proof["old_manager"].items()) and not fit.members(UNIT),
         "failed verifier no longer owns the name")
    api["read"](proof["original_fragment"]["path"], proof["original_fragment"]["sha256"])
    prior = api["bound"](proof["predecessor_review"])
    api["retained"](prior)
    need(native == api["inspect_unit"]() and not fit.members(UNIT), "145 generation changed during build price")
    return proof["failed_phase"]
