#!/usr/bin/python3 -IB
"""Register the qualified 136 offer against the original V5n successor slot."""
import json
import os
from pathlib import Path
import re
import runpy
import sys

fixture = runpy.run_path(str(Path(__file__).with_name("register-fixture-ready.py")))
common = fixture["common"]
pin = fixture["pinned"]
root = common.RT
directory = root / "epoch145-v5n-136-dispatch-20261123-v1"
package = directory / "tools"
unit = "horizon-145-v5n-136-dispatch-20261123-v1.service"
writer = root / "epoch136-joint-writer-20261123-v8"
provider = root / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1"
old_directory = root / "epoch145-fixture-retry1-dispatch-20261122-v1"
old_plan = root / "epoch136-joint-writer-20261122-v7c/registered-production-plan.json"
post = root / "epoch145-semantic-continuity-20261121-v1/tools-v13h"
semantic = "f86e7e61f4b34dc7aedc4e08a128e713"


def compiled_refs(dispatch_sha):
    seal = common.read_ref(pin(package / "deployment-seal-receipt.json", dispatch_sha))
    row, = [m for m in seal["members"] if m["name"] == "build-proof.json" and m["mode"] == "0444"]
    build = common.read_ref(pin(package / row["name"], row["sha256"]))
    common.need(seal["destination"] == str(package) and seal["sealer_sha256"] == common.SEALER
                and seal["remote_mutations"] is False and build["live_semantic"]["original"] == semantic,
                "different V5n dispatcher build")
    bindings = build["compiled_with"]

    def checked(path):
        binding = bindings[str(path)]
        common.need(binding == pin(path, binding["sha256"]), "different compiler input")
        return binding

    return checked


def inputs(compiled, handoff_sha):
    binding = pin(writer / "PARENT_NATIVE_HANDOFF.json", handoff_sha)
    prospect = common.read_ref(binding)["native_plan"]
    common.need(prospect == pin(writer / "PROSPECTIVE_NATIVE_PLAN.json", prospect["sha256"]), "wrong native prospect")
    worker = compiled(post.parent / "v5n-name-handoff/submission-result.json")
    common.need(worker["sha256"] == "57eb2aadef0bd6e5591800c439fa0f2e6d701c2f4baa3dc45b5074fdddebd02e",
                "different original V5n invocation")
    plan, offer = fixture["inspect_handoff"](writer, post, semantic, worker, compiled(post / "deployment-seal-receipt.json"),
                                       compiled(writer / "NATIVE_PACKAGES.json"), prospect, binding)
    previous = common.read_ref(pin(old_plan, "2cd10cb835081ff4ba9e6b269b2420ef6f6d5a80c57286491aaded6c3167a8f9"))
    replacement = {"controller", "controller_deployment", "controller_source_commit", "holding145_completion",
                   "holding145_prestart_ready", "holding145_semantic_worker", "joint_fit_145"}
    retained = lambda source: {key: value for key, value in source.items() if key not in replacement}
    common.need(retained(plan) == retained(previous), "the original 136 payload or donor contract changed")
    common.need(plan["joint_fit_145"] == dict(image=compiled(provider / "post-stop-fit"),
               seal=compiled(provider / "deployment-seal-receipt.json")), "different successor capacity provider")
    return plan, offer


def observed(dispatch_sha, compiled):
    prior = common.read_ref(compiled(directory / "PREDECESSOR_DRAINED.json"))
    oldready = common.read_ref(pin(old_directory / "READY.json",
                                    "67079b5ab555351a7a5c8daa7961aef048596e788d1770b7ffabfc0b17c5c09a"))
    common.need(prior["retry"]["InvocationID"] == oldready["dispatcher"]["invocation_id"]
                and prior["operation_lock"] == oldready["operation_lock"], "different drained retry dispatcher")
    for name in ("retry", "previous", "earlier", "earliest"):
        old = prior[name]
        common.drained(old["Id"], old["InvocationID"])
    locks = {"controller_lock": common.LOCK,
             "recent_controller_lock": root / "epoch145-fixture-phase-dispatch-20261122-v1/state/controller.lock",
             "retry_controller_lock": old_directory / "state/controller.lock"}
    common.need(all(common.lock_identity(path) == prior[tag] for tag, path in locks.items())
                and common.lock_identity(common.OP) == prior["operation_lock"], "operation or predecessor lock changed")
    owner = common.dispatcher_owner(package, dispatch_sha, unit, "follow-v5n",
                                    [directory / "state/controller.lock", *locks.values()])
    fit_seal = compiled(provider / "deployment-seal-receipt.json")
    deployment = common.read_ref(fit_seal)
    image = compiled(provider / "post-stop-fit")
    common.need(deployment["destination"] == str(provider) and deployment["sealer_sha256"] == common.SEALER
                and deployment["remote_mutations"] is False, "foreign V5n provider package")
    for member in deployment["members"]:
        common.need(Path(member["name"]).name == member["name"], "foreign provider member")
        pin(provider / member["name"], member["sha256"])
    selected = runpy.run_path(image["path"])["registered_status"]()
    consumer = compiled(root / "survivor172-cadence-20261122-v1/tools-cold168-retry4-136-v1/deployment-seal-receipt.json")
    common.need(selected["consumer_seal"] == consumer, "different active 136 cadence consumer")
    common.same_dispatcher(unit, owner["dispatcher"])
    return dict(schema="horizon-145-136-prestart-selector-ready-v1", **owner,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                original_semantic_invocation=semantic, operation_lock=prior["operation_lock"],
                registered_provider=dict(image=image, seal=fit_seal), status_consumer_seal=consumer)


def check_boundary():
    for folder in (directory, old_directory, root / "epoch145-fixture-phase-dispatch-20261122-v1", common.DIR):
        common.clean_boundary(folder / "state", folder)
    publication = root / "epoch145-publication-20261121-v1"
    common.need(not any(re.fullmatch(r"(?:full|network)-[a-f0-9]{32}", p.name) for p in publication.iterdir()),
                "ordinary 145 publication phase already crossed this boundary")


def main():
    common.need(os.geteuid() == 0 and sys.flags.isolated and __debug__ and len(sys.argv) == 3 and
                all(re.fullmatch("[a-f0-9]{64}", value) for value in sys.argv[1:]),
                "register-v5n-ready.py DISPATCH_SEAL_SHA256 PARENT_HANDOFF_SHA256")
    digest, handoff = sys.argv[1:]
    compiled = compiled_refs(digest)

    def free(identity):
        common.need(common.lock_identity(common.OP) == identity and not common.locks(identity), "operation lock occupied")

    result = common.registration(directory, writer, lambda: observed(digest, compiled), check_boundary,
                                 common.operation, free, lambda: inputs(compiled, handoff), common.inspect_plan)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
