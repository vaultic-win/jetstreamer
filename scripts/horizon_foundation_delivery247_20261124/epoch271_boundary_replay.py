"""Prepare and launch the bounded epoch 271 replay with the sealed trace worker."""

import argparse
import ast
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, "/var/lib/jetstreamer/horizon249-delivery-v214-tools")
import diagnostic271_boundary as diagnostic

V = Path("/var/lib/jetstreamer")
CONTROL = V / "horizon-seven-publication-controller-v222"
PREVIOUS = V / "horizon271-europe-bounded-v287"
PACKAGE = diagnostic.PACKAGE
ROOT = diagnostic.RUN_ROOT
UNIT = diagnostic.UNIT
GUARD = "horizon-271-boundary-trace-protective-v297.service"
TOKENS = V / "horizon271-boundary-trace-tokens-v297"
RECEIPTS = V / "horizon271-boundary-trace-guard-receipts-v297"
TRACE = V / "horizon271-boundary-trace-worker-v296-qualified"
WORKER = TRACE / "jetstreamer-historical-worker-v1-8-11"
TRACE_DIRECTORY = None
TRACE_ENVIRONMENT = None
NAMESPACE_UNIT = "foundation-271-boundary-namespace-v297"
PREDECESSOR = "diagnostic271_europe"
PRIOR_TRACE = PREVIOUS / "terminal.json"
REPO = "/home/ubuntu/workspace/jetstreamer"
SCRIPTS = "scripts/horizon_foundation_delivery247_20261124"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mkdir(path, mode, owner=0):
    path.mkdir(mode=mode)
    os.chown(path, owner, owner)
    path.chmod(mode)


def staged_file(path, content, mode=0o400):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def source_pin():
    git = ["sudo", "-n", "-u", "ubuntu", "git", "-C", REPO]
    commit = subprocess.check_output(
        [*git, "rev-parse", "origin/account-updates"], text=True, timeout=10
    ).strip()
    required = ["bc1ec0f6"]
    if TRACE_DIRECTORY is not None:
        build = json.loads((TRACE / "completion.json").read_bytes())
        required.extend((build["worker_source_commit"], build["guard_source_commit"]))
    for ancestor in required:
        subprocess.run(
            [*git, "merge-base", "--is-ancestor", ancestor, commit], check=True, timeout=10
        )
    for member in (Path(__file__), Path(diagnostic.__file__)):
        tracked = subprocess.check_output(
            [*git, "show", f"{commit}:{SCRIPTS}/{member.name}"], timeout=10
        )
        assert tracked == member.read_bytes(), member
    return commit


def sealed_image(ops, executable):
    seal = ops.bound(ops.ref(TRACE / "deployment-seal-receipt.json"))
    assert seal["destination"] == str(TRACE)
    member, = (row for row in seal["members"] if row["name"] == executable.name)
    assert member["mode"] == "0555" and member["bytes"] == executable.stat().st_size
    image = dict(path=str(executable), sha256=member["sha256"])
    assert ops.checked_image(image) == str(executable)
    return image


def select_trace_mode(stake_inputs):
    global diagnostic, PACKAGE, ROOT, UNIT, GUARD, TOKENS, RECEIPTS, TRACE, WORKER
    global TRACE_DIRECTORY, TRACE_ENVIRONMENT, NAMESPACE_UNIT, PRIOR_TRACE, PREDECESSOR
    if stake_inputs:
        import diagnostic271_stake_inputs as diagnostic

        TRACE_DIRECTORY = "stake-inputs"
        TRACE_ENVIRONMENT = "JETSTREAMER_EPOCH271_STAKE_INPUT_DIR"
        NAMESPACE_UNIT = "foundation-271-stake-inputs-namespace-v307"
        PREDECESSOR = "diagnostic271_reward_tuples"
        GUARD = "horizon-271-stake-inputs-protective-v307.service"
        TOKENS = V / "horizon271-stake-inputs-tokens-v307"
        RECEIPTS = V / "horizon271-stake-inputs-guard-receipts-v307"
        TRACE = V / "horizon271-stake-input-worker-v307-qualified"
        PRIOR_TRACE = V / "horizon271-reward-tuple-replay-v299/terminal.json"
    else:
        import diagnostic271_reward_tuples as diagnostic

        TRACE_DIRECTORY = "reward-tuples"
        TRACE_ENVIRONMENT = "JETSTREAMER_EPOCH271_REWARD_DIR"
        NAMESPACE_UNIT = "foundation-271-reward-namespace-v299"
        PREDECESSOR = "diagnostic271_boundary"
        GUARD = "horizon-271-reward-tuples-protective-v299.service"
        TOKENS = V / "horizon271-reward-tuples-tokens-v299"
        RECEIPTS = V / "horizon271-reward-tuples-guard-receipts-v299"
        TRACE = V / "horizon271-reward-tuple-worker-v299-qualified"
        PRIOR_TRACE = V / "horizon271-boundary-replay-v297/terminal.json"
    PACKAGE, ROOT, UNIT = diagnostic.PACKAGE, diagnostic.RUN_ROOT, diagnostic.UNIT
    WORKER = TRACE / WORKER.name


def prepare(legacy, measure):
    ops = legacy.ops
    branch = source_pin()
    previous = ops.bound(ops.ref(PREVIOUS / "profile.json"))
    old_namespace = ops.bound(ops.ref(PREVIOUS / "namespace.json"))
    terminal = ops.bound(ops.ref(PRIOR_TRACE))
    assert ops.props(terminal["producer"]["Id"], list(terminal["producer"])) == terminal["producer"]
    assert terminal["timer_drained"]["ActiveState"] == "inactive"
    assert old_namespace["result"]["namespace_verified"]
    image = sealed_image(ops, WORKER)
    compiled = ops.bound(ops.ref(TRACE / "completion.json"))
    assert compiled["stdout_protocol_equal_to_reference"] and not compiled["replay_started"]
    assert not compiled["publication_authorized"]
    fit = measure.current(previous)
    assert fit["disk_shortfall_bytes"] == fit["memory_shortfall_bytes"] == 0, (
        fit["disk_shortfall_bytes"], fit["memory_shortfall_bytes"]
    )
    for path in (PACKAGE, ROOT, TOKENS, RECEIPTS):
        assert not path.exists() and not path.is_symlink(), path
    mkdir(PACKAGE, 0o700)
    mkdir(RECEIPTS, 0o700)
    mkdir(TOKENS, 0o755)
    mkdir(ROOT, 0o700, 1000)
    for leaf in ("output", "output/compact-indexes", "output/compact-indexes/270",
                 "output/compact-indexes/271", "state", "tmp", "tmp/isolated-empty-gcloud"):
        mkdir(ROOT / leaf, 0o700, 1000)
    if TRACE_DIRECTORY is not None:
        mkdir(ROOT / TRACE_DIRECTORY, 0o700, 1000)
    staged_file(ROOT / "output/genesis.tar.bz2", b"", 0o444)
    gate = V / "horizon271-europe-bounded-tokens-v287/pre-start.sh"
    staged_file(TOKENS / gate.name, gate.read_bytes(), 0o555)
    old = PREVIOUS / "producer.service"
    assert ops.ref(old) == previous["producer"]
    service = old.read_text()
    replacements = {
        previous["run_root"]: str(ROOT),
        str(gate.parent): str(TOKENS),
        previous["worker"]["path"]: str(WORKER),
        str(Path(previous["worker"]["path"]).parent): str(TRACE),
        "epoch-271-europe-qualification.jet": "epoch-271-boundary-trace.jet",
    }
    for original, updated in replacements.items():
        assert original in service, original
        service = service.replace(original, updated)
    if TRACE_DIRECTORY is not None:
        service += f'Environment="{TRACE_ENVIRONMENT}={ROOT / TRACE_DIRECTORY}"\n'
    staged_file(PACKAGE / "producer.service", service.encode())
    mounts = {name.replace(previous["run_root"], str(ROOT)): row
              for name, row in previous["mounts"].items()}
    snapshot = ops.bound(previous["snapshot"])["snapshot"]
    guard = ops.bound(previous["guard"])
    template = ops.bound(guard["plan"])
    if TRACE_DIRECTORY is not None:
        guard["binary"] = sealed_image(ops, TRACE / "guard")
        assert compiled["guard_tests_passed"] > 0
    assert ops.checked_image(guard["binary"]) == guard["binary"]["path"]
    assert template["minimum_free_bytes"] == fit["guard_minimum_free_bytes"]
    assert template["maximum_root_physical_bytes"] == previous["disk_cap_bytes"]
    template.update(unit=UNIT, worker_root=str(ROOT), receipt_directory=str(RECEIPTS))
    check = ops.funds.put(PACKAGE / "static-guard-plan.json", template)
    check_guard = [guard["binary"]["path"], check["path"], "--plan-sha256",
                   check["sha256"], "--self-sha256", guard["binary"]["sha256"], "--validate-plan-only"]
    validation = json.loads(subprocess.check_output(check_guard, timeout=15))
    assert validation["validated"] and validation["unit"] == UNIT
    assert validation["self_sha256"] == guard["binary"]["sha256"]
    ops.funds.put(PACKAGE / "static-guard-validation.json",
                  dict(guard, plan=check, validation=validation))
    props, argv = legacy.startup.start_props(UNIT, PACKAGE / "producer.service")
    proof = dict(snapshot=snapshot, worker=image, mounts=mounts, argv=argv)
    if TRACE_DIRECTORY is not None:
        proof["trace_directory"] = str(ROOT / TRACE_DIRECTORY)
        proof["trace_environment"] = TRACE_ENVIRONMENT
    args = [
        "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={NAMESPACE_UNIT}", *props, "--",
        "/usr/bin/python3", "-I", "-B", "-c", NAMESPACE_CHECK, json.dumps(proof),
    ]
    result = json.loads(subprocess.check_output(args, timeout=45))
    assert result == dict(mounts=len(mounts), worker_readonly=True, snapshot_readonly=True)
    namespace = ops.funds.put(PACKAGE / "namespace.json", dict(proof, result=result))
    profile = dict(
        previous, unit=UNIT, run_root=str(ROOT), worker_root=str(ROOT), worker=image,
        producer=ops.ref(PACKAGE / "producer.service"), guard=guard["binary"],
        prior_trace=ops.ref(PRIOR_TRACE), mounts=mounts, argv=argv,
        worker_build=ops.ref(TRACE / "completion.json"),
        launcher_source=branch, namespace=namespace,
    )
    print(json.dumps(ops.funds.put(PACKAGE / "profile.json", profile)), flush=True)


NAMESPACE_CHECK = """
import hashlib, json, os, sys
from pathlib import Path
args = json.loads(sys.argv[1])
if "trace_directory" in args:
    directory = Path(args["trace_directory"])
    assert os.environ[args["trace_environment"]] == str(directory)
    assert directory.stat().st_uid == os.geteuid() == 1000
    assert not any(directory.iterdir()) and os.access(directory, os.W_OK)
for name, proof in args["mounts"].items():
    target = Path(name)
    stamp = target.stat()
    assert (stamp.st_dev, stamp.st_ino, stamp.st_size) == (proof["device"], proof["inode"], proof["size"])
    assert os.statvfs(target).f_flag & os.ST_RDONLY
worker = Path(args["worker"]["path"])
assert hashlib.sha256(worker.read_bytes()).hexdigest() == args["worker"]["sha256"]
assert os.statvfs(worker).f_flag & os.ST_RDONLY
proof = args["snapshot"]
snapshot = Path(proof["path"])
stamp = snapshot.stat()
assert (stamp.st_dev, stamp.st_ino, stamp.st_size, stamp.st_uid) == (proof["device"], proof["inode"], proof["size"], 0)
assert os.statvfs(snapshot).f_flag & os.ST_RDONLY
with snapshot.open("rb") as stream:
    assert stream.read(4) == bytes.fromhex("28b52ffd")
print(json.dumps(dict(mounts=len(args["mounts"]), worker_readonly=True, snapshot_readonly=True)))
"""


def install_cadence(ops):
    before = {}
    installed = {}
    replacements = {}
    name = diagnostic.__name__
    predecessor = PREDECESSOR
    gate_anchor = (
        "    inactive229.adopt({}, plan['gates']['229']['evidence'])"
        if TRACE_ENVIRONMENT == "JETSTREAMER_EPOCH271_STAKE_INPUT_DIR"
        else f"    {predecessor}.gate(plan)"
    )
    module = CONTROL / f"{name}.py"
    assert Path(diagnostic.__file__) == module
    for filename, edits in {
        "cycle.py": (
            (f"import {predecessor}\n", f"import {predecessor}\nimport {name}\n"),
            (f"cfg['diagnostic_replays'] += {predecessor}.configuration()",
             f"cfg['diagnostic_replays'] += {predecessor}.configuration()\ncfg['diagnostic_replays'] += {name}.configuration()"),
            (gate_anchor, f"{gate_anchor}\n    {name}.gate(plan)"),
            (f"and not {predecessor}.owns(r)", f"and not {predecessor}.owns(r) and not {name}.owns(r)"),
        ),
        "native_binding_replays.py": (
            (f"import {predecessor}\n", f"import {predecessor}\nimport {name}\n"),
            (f", {predecessor}", f", {predecessor}, {name}"),
        ),
    }.items():
        member = CONTROL / filename
        before[filename] = ops.ref(member)
        text = member.read_text()
        staged_file(PACKAGE / (filename + ".previous"), text.encode())
        for original, updated in edits:
            assert text.count(original) == 1, (filename, original)
            text = text.replace(original, updated)
        ast.parse(text)
        with tempfile.NamedTemporaryFile(dir=CONTROL, delete=False, mode="w") as staged:
            os.fchmod(staged.fileno(), member.stat().st_mode & 0o777)
            staged.write(text)
            staged.flush()
            os.fsync(staged.fileno())
        replacements[member] = staged.name
    for member, candidate in replacements.items():
        os.replace(candidate, member)
        installed[member.name] = ops.ref(member)
    directory = os.open(CONTROL, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    ops.funds.put(PACKAGE / "cadence-deployment.json",
                  dict(before=before, installed=installed, adapter=ops.ref(module)))


def launch(legacy, measure):
    ops = legacy.ops
    source_pin()
    profile = ops.bound(ops.ref(PACKAGE / "profile.json"))
    prior = ops.bound(profile["prior_trace"])
    assert ops.props(prior["producer"]["Id"], list(prior["producer"])) == prior["producer"]
    assert profile["worker"] == sealed_image(ops, WORKER)
    assert ops.checked_image(profile["node"]) == profile["node"]["path"]
    ns = ops.bound(profile["namespace"])
    assert ns["result"]["worker_readonly"] and ns["result"]["snapshot_readonly"]
    assert ns["argv"] == profile["argv"]
    props, argv = legacy.startup.start_props(UNIT, PACKAGE / "producer.service")
    assert argv == profile["argv"] and ops.ref(PACKAGE / "producer.service") == profile["producer"]
    for unit in (UNIT, GUARD, GUARD.replace(".service", ".timer")):
        state = ops.props(unit, ["ActiveState", "LoadState", "Job"])
        assert state == dict(ActiveState="inactive", LoadState="not-found", Job=""), state
    assert not any(RECEIPTS.iterdir()) and list(TOKENS.iterdir()) == [TOKENS / "pre-start.sh"]
    assert not diagnostic.configuration()
    pinned = legacy.inventory()
    fit = measure.current(profile)
    assert fit["disk_shortfall_bytes"] == fit["memory_shortfall_bytes"] == 0
    accepted = ops.bound(fit["completion"])
    current = ops.bound(accepted["statuses"]["271"])
    assert current["authenticated_exact_byte_readback"] and ops.bound(current["readback"])["phase"] == "verification"
    install_cadence(ops)
    fit = measure.current(profile)
    legacy.ROOT = PACKAGE
    legacy.PRODUCER, legacy.GUARD = UNIT, GUARD
    legacy.TIMER = GUARD.replace(".service", ".timer")
    legacy.RECEIPTS, legacy.TOKENS = RECEIPTS, TOKENS
    legacy.REGISTRATION = diagnostic.PACKAGE / "cadence-registration.json"
    legacy.start(profile, props, argv, fit, pinned)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "launch"))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--reward-tuples", action="store_true")
    modes.add_argument("--stake-inputs", action="store_true")
    args = parser.parse_args()
    if args.reward_tuples or args.stake_inputs:
        select_trace_mode(args.stake_inputs)
    assert os.geteuid() == 0 and __debug__
    legacy = load("europe_diagnostic_admission", PREVIOUS / "admit.py")
    assert os.environ["CODEX_THREAD_ID"] == legacy.replay.THREAD
    measure = load("boundary_replay_capacity", V / "horizon230-full-v291/measure291.py")
    os.umask(0o077)
    with legacy.partition.take(), (CONTROL / "cycle.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert legacy.partition.locked(legacy.partition.LOCK, os.getpid())
        state = legacy.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"])
        assert state["ActiveState"] in {"inactive", "failed"} and not state["Job"], state
        _, _, fleet = measure.source.latest()
        for row in fleet["active"]:
            if row["epoch"] == 230:
                import diagnostic230_slot_hashes

                if diagnostic230_slot_hashes.owns(row):
                    registration, claim = diagnostic230_slot_hashes.receipt()
                    owner = row["producer"]
                    assert (owner["Id"], owner["InvocationID"]) == (
                        diagnostic230_slot_hashes.UNIT, claim["invocation_id"]
                    ), registration
                    plan = legacy.ops.bound(claim["guard_plan"])
                    assert plan["unit"] == owner["Id"]
                    measure.source.GUARDS[230] = Path(plan["receipt_directory"])
                else:
                    assert row["producer"]["Id"] == "horizon-qualify-230-europe-singleton-v288.service"
                    measure.source.GUARDS[230] = V / "horizon230-full-guard-receipts-v291"
            if row["epoch"] == 275:
                import replay275

                registration, _, _, _ = replay275.evidence()
                owner = row["producer"]
                assert (owner["Id"], owner["InvocationID"]) == (
                    registration["producer"], registration["invocation_id"]
                )
                measure.source.GUARDS[275] = replay275.GUARD_RECEIPTS
        if args.operation == "prepare":
            prepare(legacy, measure)
        else:
            launch(legacy, measure)


if __name__ == "__main__":
    main()
