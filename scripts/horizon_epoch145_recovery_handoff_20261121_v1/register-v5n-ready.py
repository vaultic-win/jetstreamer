#!/usr/bin/python3 -IB
"""Register the qualified 136 offer against the selected semantic invocation."""
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
v5r = sys.argv[1:2] == ["--v5r"]
v5q = sys.argv[1:2] == ["--v5q"]
v5o = sys.argv[1:2] == ["--v5o"]
generation = "v5r" if v5r else "v5q" if v5q else "v5o" if v5o else "v5n"
date = "20261124" if v5q or v5r else "20261123"
directory = root / f"epoch145-{generation}-136-dispatch-{date}-v1"
package = directory / "tools"
unit = f"horizon-145-{generation}-136-dispatch-{date}-v1.service"
writer = root / ("epoch136-joint-writer-20261124-v11" if v5r else "epoch136-joint-writer-20261124-v10" if v5q else
                 "epoch136-joint-writer-20261123-v9" if v5o else "epoch136-joint-writer-20261123-v8")
provider = root / f"incident-replay-fit-20261121-v1/tools-homefloor-145-post-{generation}-136-v1"
old_directory = root / "epoch145-fixture-retry1-dispatch-20261122-v1"
old_plan = root / "epoch136-joint-writer-20261122-v7c/registered-production-plan.json"
family = root / "epoch145-semantic-continuity-20261121-v1"
post = family / ("tools-v13l" if v5r else "tools-v13k" if v5q else "tools-v13j" if v5o else "tools-v13h")
semantic = ("8f2b9c06b62147babe83c9ade7271cd3" if v5r else
            "cbacb5a17e6347509640846eccb95cb0" if v5q else "f3474dfad55f4a05a64431421881db29" if v5o else
            "f86e7e61f4b34dc7aedc4e08a128e713")
submission = ("8c3e4d05c59f32545dff03258269e339cbde95ae4bcc5cc5a92aa8ae5514f68b" if v5r else
              "398f1a2d5d5a50ab4d35c0f27de035d7c07023b6c8d632ef326b9fcd169cb5e9" if v5q else
              "4d80587d22ffa0883696f96c30958b54d30fb5455bde35050e96b50c8ba8c544" if v5o else
              "57eb2aadef0bd6e5591800c439fa0f2e6d701c2f4baa3dc45b5074fdddebd02e")


def compiled_refs(dispatch_sha):
    seal = common.read_ref(pin(package / "deployment-seal-receipt.json", dispatch_sha))
    row, = [m for m in seal["members"] if m["name"] == "build-proof.json" and m["mode"] == "0444"]
    build = common.read_ref(pin(package / row["name"], row["sha256"]))
    common.need(seal["destination"] == str(package) and seal["sealer_sha256"] == common.SEALER
                and seal["remote_mutations"] is False and build["live_semantic"]["original"] == semantic,
                "different semantic dispatcher build")
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
    worker = compiled(family / f"{generation}-name-handoff/submission-result.json")
    common.need(worker["sha256"] == submission and common.read_ref(worker)["invocation_id"] == semantic,
                "different original semantic invocation")
    post_ref = compiled(post / "deployment-seal-receipt.json")
    if v5o or v5q or v5r:
        key, name, digest = (("encoded_prefix_custody", "v5r-name-handoff/ACTUAL_ADVANCING_AND_136_CUSTODY.json",
                              "1343de96384e52ff061262a2d80c217d187a1fc8b0ce0e07e32940ee88e89b3b") if v5r else
                             ("audit_turnover_binding", "V5Q_RUNTIME_BINDINGS.json",
                              "a5dc1d9973d950d36f7302b800f0b10421066e135e0912750fd92b98521cadc4") if v5q else
                             ("donor_pressure_binding", "V5O_RUNTIME_BINDINGS.json",
                              "d571da98684079bc937a2ddeed52dbcd457eb0a74010519171b851e3e5297137"))
        seal = common.read_ref(post_ref)
        member, = (m for m in seal["members"] if m["name"] == "build-proof.json" and m["mode"] == "0444")
        build = common.read_ref(pin(post / member["name"], member["sha256"]))
        runtime = pin(family / name, digest)
        common.need(seal["destination"] == str(post) and seal["sealer_sha256"] == common.SEALER
                    and seal["remote_mutations"] is False and build["semantic_submission"] == worker
                    and build[key] == runtime, "post build selected a different semantic runtime")
    plan, offer = fixture["inspect_handoff"](writer, post, semantic, worker, post_ref,
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
    owner = common.dispatcher_owner(package, dispatch_sha, unit, f"follow-{generation}",
                                    [directory / "state/controller.lock", *locks.values()])
    fit_seal = compiled(provider / "deployment-seal-receipt.json")
    deployment = common.read_ref(fit_seal)
    image = compiled(provider / "post-stop-fit")
    common.need(deployment["destination"] == str(provider) and deployment["sealer_sha256"] == common.SEALER
                and deployment["remote_mutations"] is False, "foreign successor provider package")
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
    retired_versions = (("v5n", "20261123"),) if v5o or v5q or v5r else ()
    if v5q or v5r:
        retired_versions += (("v5o", "20261123"),)
    if v5r:
        retired_versions += (("v5q", "20261124"),)
    for version, prior_date in retired_versions:
        retired = root / f"epoch145-{version}-136-dispatch-{prior_date}-v1"
        common.drained(f"horizon-145-{version}-136-dispatch-{prior_date}-v1.service")
        common.clean_boundary(retired / "state", retired)
        common.need(not any(os.path.lexists(retired / name) for name in ("READY.json", "OFFER.json")),
                    "retired selector registered custody")
    publication = root / "epoch145-publication-20261121-v1"
    common.need(not any(re.fullmatch(r"(?:full|network)-[a-f0-9]{32}", p.name) for p in publication.iterdir()),
                "ordinary 145 publication phase already crossed this boundary")


def main():
    args = sys.argv[2:] if v5o or v5q or v5r else sys.argv[1:]
    common.need(os.geteuid() == 0 and sys.flags.isolated and __debug__ and len(args) == 2 and
                all(re.fullmatch("[a-f0-9]{64}", value) for value in args),
                "register-v5n-ready.py [--v5o|--v5q|--v5r] DISPATCH_SEAL_SHA256 PARENT_HANDOFF_SHA256")
    digest, handoff = args
    compiled = compiled_refs(digest)

    def free(identity):
        common.need(common.lock_identity(common.OP) == identity and not common.locks(identity), "operation lock occupied")

    result = common.registration(directory, writer, lambda: observed(digest, compiled), check_boundary,
                                 common.operation, free, lambda: inputs(compiled, handoff), common.inspect_plan)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
