"""Bind the selected epoch 145 semantic completion to the 136 pre-post window."""
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
V5O_IID = "f3474dfad55f4a05a64431421881db29"
V5O_HANDOFF = FAMILY / "v5o-name-handoff"
V5O_POST = FAMILY / "tools-v13j"
V5O_PROVIDER = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5o-136-v1"
V5O_STATE = STATE.parent / V5O_IID
V5Q_IID = "cbacb5a17e6347509640846eccb95cb0"
V5Q_HANDOFF = FAMILY / "v5q-name-handoff"
V5Q_POST = FAMILY / "tools-v13k"
V5Q_PROVIDER = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5q-136-v1"
V5Q_STATE = STATE.parent / V5Q_IID
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

V5O_RESULT = ref(V5O_HANDOFF / "submission-result.json",
                 "4d80587d22ffa0883696f96c30958b54d30fb5455bde35050e96b50c8ba8c544")
V5O_RUNTIME = ref(FAMILY / "V5O_RUNTIME_BINDINGS.json",
                  "d571da98684079bc937a2ddeed52dbcd457eb0a74010519171b851e3e5297137")
V5O_START = ref(V5O_STATE / "recovery-started.json",
                "e4b9e72a6481ea4f38b8fe7b49986463e2f93d37bc1dcb7f2156049930fd744b")

V5Q_RESULT = ref(V5Q_HANDOFF / "submission-result.json",
                 "398f1a2d5d5a50ab4d35c0f27de035d7c07023b6c8d632ef326b9fcd169cb5e9")
V5Q_RUNTIME = ref(FAMILY / "V5Q_RUNTIME_BINDINGS.json",
                  "a5dc1d9973d950d36f7302b800f0b10421066e135e0912750fd92b98521cadc4")
V5Q_START = ref(V5Q_STATE / "recovery-started.json",
                "7659aca1cf87aaeeb42a5c5c65ad186a03d1e55e9ce4dc0779d351b36ba30781")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validated_phase(phase, semantic):
    completion = semantic["completion"]
    require(phase == dict(Id=UNIT, MainPID="0", stage="v5j-semantic-complete", completion=completion),
            "post adapter did not confirm the drained original semantic completion")
    return completion


def join(inputs, captured, phase, *, v5o=False, v5q=False):
    iid, state, start = ((V5Q_IID, V5Q_STATE, V5Q_START) if v5q else
                         (V5O_IID, V5O_STATE, V5O_START) if v5o else (IID, STATE, None))
    require(inputs["schema"] == "horizon-145-v5j-publication-inputs-v1"
            and inputs["public_origin"] == READINESS and inputs["expected_slots"] == 432000
            and inputs["local_first_slot"] == 62640000 and inputs["local_last_slot"] == 63071999
            and inputs["publication_authorized"] is False and inputs["epoch_145_publicly_verified"] is False,
            "foreign epoch 145 publication inputs")
    semantic = inputs["semantic"]
    if inputs["semantic_pending"] is True:
        require(semantic is None and captured is None and phase is None, "conflicting pending semantic state")
        return None
    require(inputs["semantic_pending"] is False and isinstance(semantic, dict) and semantic == captured
            and semantic["schema"] == "horizon-145-v5j-semantic-completion-v1"
            and semantic["invocation_id"] == iid and semantic["archive_bytes"] == 105610995833
            and isinstance(semantic["pid1_success"], str) and semantic["pid1_success"],
            "missing captured successful original semantic generation")
    for field, name in (("start", "recovery-started.json"), ("verified", "verified-frozen.json"),
                        ("extraction", "extraction-complete.json"), ("completion", "complete.json")):
        binding = semantic[field]
        require(set(binding) == {"path", "sha256"} and binding["path"] == str(state / name)
                and re.fullmatch("[a-f0-9]{64}", binding["sha256"]), "wrong original semantic " + field)
    require(start is None or semantic["start"] == start, "different pinned startup receipt")
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


def v5o_completion_tools(plan, profile, *, v5q=False):
    post, submission = (V5Q_POST, V5Q_RESULT) if v5q else (V5O_POST, V5O_RESULT)
    tools = dict(seal=ref(post / "deployment-seal-receipt.json", profile["seal_sha256"]),
                 build=ref(post / "build-proof.json", profile["build_sha256"]),
                 adapter=ref(post / "incident-post-phase.py", profile["adapter_sha256"]))
    require(plan["holding145_semantic_worker"] == submission
            and plan["holding145_completion"] == tools, "different sealed completion lineage")
    return tools


def inspect_v5o(plan, pin, check_package, read_immutable, read_inputs, read_phase, *, v5q=False):
    if v5q:
        iid, handoff, post_root, provider_root, submission, runtime = (
            V5Q_IID, V5Q_HANDOFF, V5Q_POST, V5Q_PROVIDER, V5Q_RESULT, V5Q_RUNTIME)
        version, build_key = "v5q", "audit_turnover_binding"
    else:
        iid, handoff, post_root, provider_root, submission, runtime = (
            V5O_IID, V5O_HANDOFF, V5O_POST, V5O_PROVIDER, V5O_RESULT, V5O_RUNTIME)
        version, build_key = "v5o", "donor_pressure_binding"
    provider = plan["joint_fit_145"]
    image = provider_root / "post-stop-fit"
    require(provider["image"]["path"] == str(image)
            and provider["seal"]["path"] == str(provider_root / "deployment-seal-receipt.json"),
            "foreign semantic price provider")
    package = check_package(provider_root, provider["seal"]["sha256"])
    rows = {member["name"]:member for member in package["members"]}
    require(rows[image.name]["mode"] == "0555" and rows[image.name]["sha256"] == provider["image"]["sha256"],
            "unsealed semantic price reader")
    profile_name = "profile145-v5j-post.json"
    require(rows[profile_name]["mode"] == "0444", "unsealed semantic post profile")
    profile = json.loads(pin(provider_root / profile_name, rows[profile_name]["sha256"]))
    tools = v5o_completion_tools(plan, profile, v5q=v5q)
    post = check_package(post_root, tools["seal"]["sha256"])
    rows = {member["name"]:member for member in post["members"]}
    require(rows["build-proof.json"]["sha256"] == tools["build"]["sha256"]
            and rows["incident-post-phase.py"]["sha256"] == tools["adapter"]["sha256"]
            and rows["post-inputs"]["mode"] == "0555", "unsealed semantic completion tools")
    build = json.loads(pin(Path(tools["build"]["path"]), tools["build"]["sha256"]))
    require(build[build_key] == runtime and build["semantic_submission"] == submission,
            "post build did not select the actual semantic invocation")
    inputs = read_inputs(post_root / "post-inputs")
    capture = handoff / "semantic-completion.json"
    captured = json.loads(read_immutable(capture)) if os.path.lexists(capture) else None
    phase = None if captured is None else read_phase(image)
    done = join(inputs, captured, phase, v5o=not v5q, v5q=v5q)
    return dict(schema=f"horizon-136-{version}-completion-join-v1", invocation_id=iid,
                semantic_result=submission, completion_tools=tools, ordinary_provider=provider,
                semantic_complete=done, semantic_pending=done is None,
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
