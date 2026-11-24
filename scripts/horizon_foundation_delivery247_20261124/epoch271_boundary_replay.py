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
    subprocess.run(
        [*git, "merge-base", "--is-ancestor", "bc1ec0f6", commit], check=True, timeout=10
    )
    for member in (Path(__file__), Path(diagnostic.__file__)):
        tracked = subprocess.check_output(
            [*git, "show", f"{commit}:{SCRIPTS}/{member.name}"], timeout=10
        )
        assert tracked == member.read_bytes(), member
    return commit


def worker_image(ops):
    seal = ops.bound(ops.ref(TRACE / "deployment-seal-receipt.json"))
    assert seal["destination"] == str(TRACE)
    member, = (row for row in seal["members"] if row["name"] == WORKER.name)
    assert member["mode"] == "0555" and member["bytes"] == WORKER.stat().st_size
    image = dict(path=str(WORKER), sha256=member["sha256"])
    assert ops.checked_image(image) == str(WORKER)
    return image


def prepare(legacy, measure):
    ops = legacy.ops
    branch = source_pin()
    previous = ops.bound(ops.ref(PREVIOUS / "profile.json"))
    old_namespace = ops.bound(ops.ref(PREVIOUS / "namespace.json"))
    terminal = ops.bound(ops.ref(PREVIOUS / "terminal.json"))
    assert ops.props(terminal["producer"]["Id"], list(terminal["producer"])) == terminal["producer"]
    assert terminal["timer_drained"]["ActiveState"] == "inactive"
    assert old_namespace["result"]["namespace_verified"]
    image = worker_image(ops)
    compiled = ops.bound(ops.ref(TRACE / "completion.json"))
    assert compiled["stdout_protocol_equal_to_reference"] and not compiled["replay_started"]
    assert not compiled["publication_authorized"]
    for path in (PACKAGE, ROOT, TOKENS, RECEIPTS):
        assert not path.exists() and not path.is_symlink(), path
    mkdir(PACKAGE, 0o700)
    mkdir(RECEIPTS, 0o700)
    mkdir(TOKENS, 0o755)
    mkdir(ROOT, 0o700, 1000)
    for leaf in ("output", "output/compact-indexes", "output/compact-indexes/270",
                 "output/compact-indexes/271", "state", "tmp", "tmp/isolated-empty-gcloud"):
        mkdir(ROOT / leaf, 0o700, 1000)
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
    staged_file(PACKAGE / "producer.service", service.encode())
    mounts = {name.replace(previous["run_root"], str(ROOT)): row
              for name, row in previous["mounts"].items()}
    snapshot = ops.bound(previous["snapshot"])["snapshot"]
    fit = measure.current(previous)
    assert fit["disk_shortfall_bytes"] == fit["memory_shortfall_bytes"] == 0
    guard = ops.bound(previous["guard"])
    template = ops.bound(guard["plan"])
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
    args = [
        "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        "--unit=foundation-271-boundary-namespace-v297", *props, "--",
        "/usr/bin/python3", "-I", "-B", "-c", NAMESPACE_CHECK, json.dumps(proof),
    ]
    result = json.loads(subprocess.check_output(args, timeout=45))
    assert result == dict(mounts=len(mounts), worker_readonly=True, snapshot_readonly=True)
    namespace = ops.funds.put(PACKAGE / "namespace.json", dict(proof, result=result))
    profile = dict(
        previous, unit=UNIT, run_root=str(ROOT), worker_root=str(ROOT), worker=image,
        producer=ops.ref(PACKAGE / "producer.service"), guard=guard["binary"],
        prior_trace=ops.ref(PREVIOUS / "terminal.json"), mounts=mounts, argv=argv,
        worker_build=ops.ref(TRACE / "completion.json"),
        launcher_source=branch, namespace=namespace,
    )
    print(json.dumps(ops.funds.put(PACKAGE / "profile.json", profile)), flush=True)


NAMESPACE_CHECK = """
import hashlib, json, os, sys
from pathlib import Path
args = json.loads(sys.argv[1])
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
    module = CONTROL / "diagnostic271_boundary.py"
    assert Path(diagnostic.__file__) == module
    for name, edits in {
        "cycle.py": (
            ("import diagnostic271_europe\n", "import diagnostic271_europe\nimport diagnostic271_boundary\n"),
            ("cfg['diagnostic_replays'] += diagnostic271_europe.configuration()",
             "cfg['diagnostic_replays'] += diagnostic271_europe.configuration()\ncfg['diagnostic_replays'] += diagnostic271_boundary.configuration()"),
            ("    diagnostic271_europe.gate(plan)", "    diagnostic271_europe.gate(plan)\n    diagnostic271_boundary.gate(plan)"),
            ("and not diagnostic271_europe.owns(r)]", "and not diagnostic271_europe.owns(r) and not diagnostic271_boundary.owns(r)]"),
        ),
        "native_binding_replays.py": (
            ("import diagnostic271_europe\n", "import diagnostic271_europe\nimport diagnostic271_boundary\n"),
            ("diagnostic271_trace, diagnostic271_europe)",
             "diagnostic271_trace, diagnostic271_europe, diagnostic271_boundary)"),
        ),
    }.items():
        member = CONTROL / name
        before[name] = ops.ref(member)
        text = member.read_text()
        staged_file(PACKAGE / (name + ".previous"), text.encode())
        for original, updated in edits:
            assert text.count(original) == 1, (name, original)
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
    assert profile["worker"] == worker_image(ops)
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
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    legacy = load("europe_diagnostic_admission", PREVIOUS / "admit.py")
    assert os.environ["CODEX_THREAD_ID"] == legacy.replay.THREAD
    measure = load("boundary_replay_capacity", V / "horizon230-full-v291/measure291.py")
    measure.source.GUARDS[230] = V / "horizon230-full-guard-receipts-v291"
    os.umask(0o077)
    with legacy.partition.take(), (CONTROL / "cycle.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert legacy.partition.locked(legacy.partition.LOCK, os.getpid())
        state = legacy.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"])
        assert state == dict(ActiveState="inactive", Job=""), state
        if args.operation == "prepare":
            prepare(legacy, measure)
        else:
            launch(legacy, measure)


if __name__ == "__main__":
    main()
