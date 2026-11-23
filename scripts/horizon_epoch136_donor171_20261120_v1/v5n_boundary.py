"""Bind the original V5n semantic completion to the V13h pre-post window."""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
FAMILY = RUNTIME / "epoch145-semantic-continuity-20261121-v1"
HANDOFF = FAMILY / "v5n-name-handoff"
POST = FAMILY / "tools-v13h"
PROVIDER = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-v1"
IID = "f86e7e61f4b34dc7aedc4e08a128e713"
UNIT = "horizon-holding-export145-20261121-v1.service"
STATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state" / IID
POST_SEAL = "1d14e72cf55b61e852960c72d566b6cfe5ebccad95f65fb15a20b9647468bb0f"
POST_BUILD = "acd58b6927de438b036275c50d2edbc08f2f33626dec64e6a43d2235b80e541c"
POST_INPUTS = "b685b1095488ed5bccbc6c7919d84faf215e1f6699de76ac821ee937402f0b70"
POST_ADAPTER = "eae6a6796091fc5443d831e32698563d2a1f009679b3adf754788d82e9704166"
PROVIDER_SEAL = "0046e7e126719f6c7c6e9526b96995d0feb85fc88164462659e79815b4c3493c"
PROVIDER_IMAGE = "aacfbfdd3f89ae8db0dcbf3d37d539f1db5e6ce5653bd8d881e65e8f29992d2e"
READINESS = "https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev"


def ref(path, sha256):
    return dict(path=str(path), sha256=sha256)


SEMANTIC_INTENT = ref(HANDOFF / "submission-intent.json",
                      "d15dfa6d3212f8a868bd00ac5df3ef26eee42466c0ac7afc7f0e9ab42aa2f23e")
SEMANTIC_RESULT = ref(HANDOFF / "submission-result.json",
                      "57eb2aadef0bd6e5591800c439fa0f2e6d701c2f4baa3dc45b5074fdddebd02e")
COMPLETION_TOOLS = dict(seal=ref(POST / "deployment-seal-receipt.json", POST_SEAL),
                        build=ref(POST / "build-proof.json", POST_BUILD),
                        adapter=ref(POST / "incident-post-phase.py", POST_ADAPTER))
ORDINARY_PROVIDER = dict(image=ref(PROVIDER / "post-stop-fit", PROVIDER_IMAGE),
                         seal=ref(PROVIDER / "deployment-seal-receipt.json", PROVIDER_SEAL))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validated_phase(phase, semantic):
    completion = semantic["completion"]
    require(phase == dict(Id=UNIT, MainPID="0", stage="v5j-semantic-complete", completion=completion),
            "V13h did not confirm the drained original V5n semantic completion")
    return completion


def join(inputs, captured, phase):
    require(inputs["schema"] == "horizon-145-v5j-publication-inputs-v1"
            and inputs["public_origin"] == READINESS and inputs["expected_slots"] == 432000
            and inputs["local_first_slot"] == 62640000 and inputs["local_last_slot"] == 63071999
            and inputs["publication_authorized"] is False and inputs["epoch_145_publicly_verified"] is False,
            "foreign V13h publication inputs")
    semantic = inputs["semantic"]
    if inputs["semantic_pending"] is True:
        require(semantic is None and captured is None and phase is None, "conflicting pending semantic state")
        return None
    require(inputs["semantic_pending"] is False and semantic == captured
            and semantic["schema"] == "horizon-145-v5j-semantic-completion-v1"
            and semantic["invocation_id"] == IID and semantic["archive_bytes"] == 105610995833
            and isinstance(semantic["pid1_success"], str) and semantic["pid1_success"],
            "missing captured successful original V5n semantic generation")
    for field, name in (("start", "recovery-started.json"), ("verified", "verified-frozen.json"),
                        ("extraction", "extraction-complete.json"), ("completion", "complete.json")):
        binding = semantic[field]
        require(set(binding) == {"path", "sha256"} and binding["path"] == str(STATE / name)
                and re.fullmatch("[a-f0-9]{64}", binding["sha256"]), "wrong original semantic " + field)
    return validated_phase(phase, semantic)


def inspect(pin, check_package, read_immutable, read_inputs, read_phase):
    for binding in (SEMANTIC_INTENT, SEMANTIC_RESULT, COMPLETION_TOOLS["build"], COMPLETION_TOOLS["adapter"]):
        pin(Path(binding["path"]), binding["sha256"])
    post = check_package(POST, POST_SEAL)
    require(sum(row["name"] == "post-inputs" and row["mode"] == "0555" and row["sha256"] == POST_INPUTS
                for row in post["members"]) == 1, "unsealed V13h publication inputs checker")
    provider = check_package(PROVIDER, PROVIDER_SEAL)
    require(sum(row["name"] == "post-stop-fit" and row["mode"] == "0555" and row["sha256"] == PROVIDER_IMAGE
                for row in provider["members"]) == 1, "unsealed V13h ordinary provider")
    inputs = read_inputs(POST / "post-inputs")
    selected = HANDOFF / "semantic-completion.json"
    captured = json.loads(read_immutable(selected)) if os.path.lexists(selected) else None
    # V13h requires an unloaded actor, empty cgroup, no pending job and a stable
    # native owner observation. Reuse that check instead of inferring from file presence.
    phase = None if captured is None else read_phase(PROVIDER / "post-stop-fit")
    done = join(inputs, captured, phase)
    return dict(schema="horizon-136-v5n-completion-join-v1", invocation_id=IID,
                semantic_intent=SEMANTIC_INTENT, semantic_result=SEMANTIC_RESULT, completion_tools=COMPLETION_TOOLS,
                ordinary_provider=ORDINARY_PROVIDER, semantic_complete=done, semantic_pending=done is None,
                resource_credit_bytes=0, activation_authorized=False)


def read_inputs(path):
    return json.loads(subprocess.check_output([path, "inspect"], timeout=45))


def read_phase(path):
    return runpy.run_path(str(path))["phase145"](145)


if __name__ == "__main__":
    require(os.geteuid() == 0 and sys.flags.isolated and __debug__ and sys.argv[1:] == ["inspect"],
            "expected inspect as isolated root")
    evidence = runpy.run_path(str(Path(__file__).resolve().with_name("incident_prestart.py")))
    print(json.dumps(inspect(evidence["pin"], evidence["check_package"], evidence["immutable_bytes"],
                             read_inputs, read_phase), sort_keys=True))
