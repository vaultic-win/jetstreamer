#!/usr/bin/python3 -IB
"""Register the V7b writer against the running V5F dispatcher and V21b provider."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import re
import runpy
import sys

common = SimpleNamespace(**runpy.run_path(str(Path(__file__).with_name("register-ready.py"))))
ROOT = common.RT
DIRECTORY = ROOT / "epoch145-fixture-phase-dispatch-20261122-v1"
WRITER = ROOT / "epoch136-joint-writer-20261122-v7b"
POST = ROOT / "epoch145-semantic-continuity-20261121-v1/tools-v13b"
PROVIDER = ROOT / "incident-replay-fit-20261121-v1/tools-v21b"
DISPATCHER = "horizon-145-fixture-phase-dispatch-20261122-v1.service"
SEMANTIC = "50af3d8ab5da47e8bdc2828feab53908"


def pinned(path, digest):
    ref = common.ref(path)
    common.need(ref["sha256"] == digest, f"changed registration evidence {path}")
    return ref


def handoff_inputs():
    native = pinned(WRITER / "NATIVE_PACKAGES.json",
                    "aa19524b24e32eb6a30e277c8057c1275329b9fa94f0d3bc47f7992989ba09a7")
    proof = pinned(WRITER / "PROSPECTIVE_NATIVE_PLAN.json",
                   "31c6b517efa45925e58fc035b34a79fa4337f329c48dcb6b08928fe2a52d6c01")
    handoff_ref = pinned(WRITER / "PARENT_NATIVE_HANDOFF.json",
                         "0131b8958990a18d86a067da3dc97b932310fdea3819ae759180115e1a111b3c")
    semantic = pinned(POST.parent / "V5F_ACTUAL_ADVANCING_WORKER.json",
                      "a2a888054492a2be68c5e332ae36daa070b9688c143005cbc97e5cace7cfd496")
    seal = pinned(POST / "deployment-seal-receipt.json", "6654198121f2e9e1b63cb9b48f7f73c500d7b465bc34ac205316b84f90d0ec5c")
    return inspect_handoff(WRITER, POST, SEMANTIC, semantic, seal, native, proof, handoff_ref)


def inspect_handoff(writer, post, semantic_iid, semantic, seal, native, proof, handoff_ref):
    handoff = common.read_ref(handoff_ref)
    packages = common.read_ref(native)
    prospect = common.read_ref(proof)
    for name in ("proof", "parent", "controller", "parent_seal", "controller_seal",
                 "launcher", "mirror_price", "mirror_price_seal"):
        bound = packages[name]
        common.need(common.ref(Path(bound["path"])) == bound, f"changed writer {name}")
    plan_ref = prospect["writer_plan"]
    common.need(Path(plan_ref["path"]) == writer / "production-plan.json", "foreign writer plan")
    common.need(handoff["native_packages"] == native and handoff["native_plan"] == proof
                and handoff["prospective_writer_plan"] == plan_ref and handoff["parent_proof"] == packages["proof"]
                and handoff["physical_dispatch"] is False and handoff["ready_registered"] is False
                and all(handoff[k] == packages[k] for k in ("parent", "controller", "parent_seal", "controller_seal",
                                                            "launcher", "mirror_price", "mirror_price_seal")),
                "different qualified parent handoff")
    for name in ("fixed_mirrors", "fixed_quarter", "native_status", "registration_environment"):
        evidence = handoff[name]
        common.need(common.ref(Path(evidence["path"])) == evidence, f"changed handoff {name}")
    plan = common.read_ref(plan_ref)
    completion = dict(seal=seal, build=common.ref(post / "build-proof.json"),
                      adapter=common.ref(post / "incident-post-phase.py"))
    inspection = prospect["inspection"]
    common.need(not any(packages[k] for k in ("registered", "launched"))
                and not any(prospect[k] for k in ("registered", "launched", "donor_fenced"))
                and all(inspection[k] is False for k in common.NO_ACTION)
                and "holding145_prestart_ready" not in plan
                and inspection["writer_plan"] == plan_ref
                and plan["controller_deployment"] == inspection["writer_deployment"] == packages["controller_seal"]
                and plan["holding145_semantic_worker"] == semantic == prospect["semantic_worker"]
                and plan["holding145_completion"] == completion == prospect["completion"]
                and prospect["semantic_iid"] == semantic_iid, "different prospective writer generation")
    return plan, dict(schema="horizon-136-registered-prestart-offer-v1", launcher=packages["launcher"],
                      parent=packages["parent"], mirror_price=packages["mirror_price"], prestart_evidence=handoff_ref)


def observed_ready(dispatch_seal):
    prior = common.read_ref(pinned(DIRECTORY / "PREDECESSOR_DRAINED.json",
                                  "d267b6e774e26fc5c9d5b95f5845b547afbfde74f58e434b835acd63785a7f07"))
    common.need(common.lock_identity(common.LOCK) == prior["controller_lock"]
                and common.lock_identity(common.OP) == prior["operation_lock"], "predecessor lock changed")
    common.drained(common.OLD)
    common.drained(common.DISPATCH, prior["previous"]["InvocationID"])
    identity = common.dispatcher_owner(DIRECTORY / "tools", dispatch_seal, DISPATCHER, "follow-v5f",
                                       [DIRECTORY / "state/controller.lock", common.LOCK])
    seal = pinned(PROVIDER / "deployment-seal-receipt.json",
                  "b4cc3480c03ac70f23ee252032a8f2b23e1adcfdac836ff5319127e6f0ac69c8")
    return ready_for(identity, DISPATCHER, SEMANTIC, PROVIDER, seal)


def ready_for(identity, dispatcher, semantic, provider, seal):
    document = common.read_ref(seal)
    image = common.ref(provider / "post-stop-fit")
    common.need(document["destination"] == str(provider) and document["sealer_sha256"] == common.SEALER
                and document["remote_mutations"] is False
                and [x["sha256"] for x in document["members"] if x["name"] == "post-stop-fit"
                     and x["mode"] == "0555"] == [image["sha256"]], "different registered provider")
    status = runpy.run_path(image["path"])["registered_status"]()
    consumer = pinned(common.CADENCE, "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e")
    common.need(status["consumer_seal"] == consumer, "different status consumer")
    common.same_dispatcher(dispatcher, identity["dispatcher"])
    return dict(schema="horizon-145-136-prestart-selector-ready-v1", **identity,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                original_semantic_invocation=semantic, operation_lock=common.lock_identity(common.OP),
                registered_provider=dict(image=image, seal=seal), status_consumer_seal=consumer)


def main():
    common.need(os.geteuid() == 0 and sys.flags.isolated and __debug__, "isolated root operator required")
    common.need(len(sys.argv) == 2 and re.fullmatch("[a-f0-9]{64}", sys.argv[1]),
                "register-fixture-ready.py DISPATCH_DEPLOYMENT_SEAL_SHA256")

    def free(identity):
        common.need(common.lock_identity(common.OP) == identity and not common.locks(identity),
                    "operation lock occupied before READY")

    result = common.registration(DIRECTORY, WRITER, lambda: observed_ready(sys.argv[1]),
                                 lambda: common.clean_boundary(DIRECTORY / "state", DIRECTORY),
                                 common.operation, free, handoff_inputs, common.inspect_plan)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
