#!/usr/bin/python3 -IB
"""Register the V7c parent plan against the exact inputs of the running retry selector."""
import json
import os
from pathlib import Path
import re
import runpy
import sys

fixture = runpy.run_path(str(Path(__file__).with_name("register-fixture-ready.py")))
common = fixture["common"]
root = common.RT
directory = root / "epoch145-fixture-retry1-dispatch-20261122-v1"
package = directory / "tools"
previous = root / "epoch145-fixture-phase-dispatch-20261122-v1"
writer = root / "epoch136-joint-writer-20261122-v7c"
family = root / "epoch145-semantic-continuity-20261121-v1"
post = family / "tools-v13c"
provider = root / "incident-replay-fit-20261121-v1/tools-v23"
unit = "horizon-145-fixture-retry1-dispatch-20261122-v1.service"
iid = "afcf6cdd1ec0400ea2757f81472987b3"
pin = fixture["pinned"]


def compiled_refs(dispatch_seal):
    seal = common.read_ref(pin(package / "deployment-seal-receipt.json", dispatch_seal))
    common.need(seal["destination"] == str(package) and seal["sealer_sha256"] == common.SEALER and
                seal["remote_mutations"] is False, "different selector package")
    rows = [m for m in seal["members"] if m["name"] == "build-proof.json" and m["mode"] == "0444"]
    common.need(len(rows) == 1, "missing selector build proof")
    proof = common.read_ref(pin(package / "build-proof.json", rows[0]["sha256"]))
    common.need(proof["live_semantic"]["original"] == iid, "selector compiled for a different retry")
    compiled = proof["compiled_with"]
    def bound(path):
        row = compiled[str(path)]
        common.need(set(row) == {"path", "sha256"} and row["path"] == str(path), "unexpected compiler input")
        return pin(path, row["sha256"])
    return bound


def inputs(compiled, handoff_sha):
    handoff_ref = pin(writer / "PARENT_NATIVE_HANDOFF.json", handoff_sha)
    prospect = common.read_ref(handoff_ref)["native_plan"]
    common.need(prospect == pin(writer / "PROSPECTIVE_NATIVE_PLAN.json", prospect["sha256"]), "wrong writer prospect")
    worker = compiled(family / "V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json")
    common.need(worker["sha256"] == "1b16ce2d061e2ec97ab8c1ba81cd2dbcff9d0a759f317fbaf53b64e731a19501",
                "different semantic retry")
    return fixture["inspect_handoff"](writer, post, iid, worker, compiled(post / "deployment-seal-receipt.json"),
             compiled(writer / "NATIVE_PACKAGES.json"), prospect, handoff_ref)


def observed(dispatch_seal, compiled):
    prior = common.read_ref(pin(directory / "PREDECESSOR_DRAINED.json",
                "e292ddb3e46ff8e5fb0d0dd39bacc6bb5376ac238c4868b622ccfdb42df47b5a"))
    for name in ("previous", "earlier", "earliest"):
        record = prior[name]
        common.drained(record["Id"], record["InvocationID"])
    recent = previous / "state/controller.lock"
    for tag, path in (("recent_controller_lock", recent), ("controller_lock", common.LOCK), ("operation_lock", common.OP)):
        common.need(common.lock_identity(path) == prior[tag], "original lock changed")
    owner = common.dispatcher_owner(package, dispatch_seal, unit, "follow-v5f",
                                    [directory / "state/controller.lock", common.LOCK, recent])
    return fixture["ready_for"](owner, unit, iid, provider, compiled(provider / "deployment-seal-receipt.json"))


def main():
    common.need(os.geteuid() == 0 and sys.flags.isolated and __debug__ and len(sys.argv) == 3 and
                all(re.fullmatch("[a-f0-9]{64}", value) for value in sys.argv[1:]),
                "register-retry-ready.py DISPATCH_SEAL_SHA256 PARENT_HANDOFF_SHA256")
    digest = sys.argv[1]
    bindings = compiled_refs(digest)
    def check():
        for stage, folder in ((directory/"state", directory), (previous/"state", previous),
                              (common.SHARED, common.DIR)):
            common.clean_boundary(stage, folder)
    def free(identity):
        common.need(common.lock_identity(common.OP) == identity and not common.locks(identity), "operation lock occupied")
    receipt = common.registration(directory, writer, lambda: observed(digest,bindings), check,
                common.operation, free, lambda: inputs(bindings,sys.argv[2]), common.inspect_plan)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
