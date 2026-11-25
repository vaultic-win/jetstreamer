"""Prepare and start the invocation-bound workerless epoch 226 retry."""

import argparse
import fcntl
import json
import os
import subprocess
import time
from pathlib import Path

from epoch226_layered_capacity import BROKER_MEMORY, PRODUCER_MEMORY, ROOT_CAP, inspect, toolkit

PACKAGE = Path("/var/lib/jetstreamer/horizon226-layered-fleet-v3")
STATE = Path("/var/lib/jetstreamer/horizon226-extract-v3")
PRIVATE = Path("/home/ubuntu/.jetstreamer-private")
RUN = PRIVATE / "checkpoint-continuation-226-extract-v3"
PRIOR = STATE.with_name("horizon226-extract-v2")
SOCKET = Path("/run/jetstreamer-horizon-epoch226-holding-v1/source.sock")
PRODUCER = "horizon-qualify-226-checkpoint-continuation-extract-v3.service"
BROKER = "foundation-226-original225-broker-v3.service"
GUARD = "horizon-guard-226-checkpoint-continuation-extract-v3.service"
TIMER = GUARD.replace(".service", ".timer")
GUARD_IMAGE = Path("/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard")
GUARD_SHA = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d"
BROKER_IMAGE = Path("/run/foundation-original225-rust-broker.mdawjaqq/original225-broker")
BROKER_SHA = "753c9c00c19f2f7040a3c4377d8559f770a8c2f3aa15781c5432215157f03838"
BUDGET = 2_124_880_754_968
MANAGER = ["Id", "LoadState", "ActiveState", "SubState", "MainPID", "ControlPID", "InvocationID", "Result", "Job"]
REPO = "/home/ubuntu/workspace/jetstreamer"
SOURCE = "scripts/horizon_foundation_delivery247_20261124"


def run_systemd(unit, properties, argv, options=()):
    subprocess.run(
        ["/usr/bin/systemd-run", "--quiet", "--expand-environment=no", f"--unit={unit}", *options,
         *(f"--property={item}" for item in properties), *map(str, argv)],
        check=True, timeout=25,
    )


def wait_for(action, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = action()
        if result is not None:
            return result
        time.sleep(0.15)
    raise TimeoutError("no matching manager or guard event")


def write_exact(path, body, ops):
    with path.open("xb") as stream:
        stream.write(body)
        stream.flush()
        os.fchmod(stream.fileno(), 0o444)
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return ops.ref(path)


def write_plan(path, value, ops):
    return write_exact(path, json.dumps(value, indent=2).encode() + b"\n", ops)


def manager_process(ops, unit, sub):
    row = ops.props(unit, MANAGER)
    if row["SubState"] == sub and len(row["InvocationID"]) == 32:
        return row
    if row["ActiveState"] == "failed":
        raise RuntimeError(f"{unit} failed: {row}")
    return None


def guard_sample(ops, invocation, plan):
    for path in (STATE / "guard-receipts").glob("sample-*.json"):
        ref = ops.ref(path)
        sample = ops.bound(ref)
        assert sample["producer_invocation_id"] == invocation and sample["plan_sha256"] == plan["sha256"]
        assert sample["guard_sha256"] == GUARD_SHA and sample["producer_stop_enabled"]
        assert sample["trip_reason"] is None and sample["root_physical_observation_error"] is None
        assert sample["producer"]["sub"] == "start-pre" and sample["producer"]["pid"] == 0
        assert sample["workers"] == []
        state = ops.props(GUARD, MANAGER)
        if state["ActiveState"] == "inactive" and state["Result"] == "success":
            assert state["InvocationID"] == sample["guard_invocation_id"]
            return ref, sample
    return None


def start(cap, kit, fit, release):
    ops = kit.ops
    assert not STATE.exists() and not RUN.exists() and not SOCKET.exists()
    for unit in (PRODUCER, BROKER, GUARD, TIMER):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}
    assert fit["disk_margin_bytes"] >= 0 and fit["memory_margin_bytes"] >= 0
    assert release["schema"] == "foundation-epoch226-extraction-cadence-release-v3"
    assert cap.checked(dict(path=str(GUARD_IMAGE), sha256=GUARD_SHA)) == GUARD_IMAGE
    assert cap.checked(dict(path=str(BROKER_IMAGE), sha256=BROKER_SHA)) == BROKER_IMAGE
    artifact = ops.bound(fit["node"])["node"]
    image = cap.checked(artifact)
    binder = cap.checked(release["binder"])
    inherited = ops.bound(ops.ref(PRIOR / "startup-intent.json"))
    old_guard = ops.bound(ops.ref(PRIOR / "guard-plan.json"))
    old_launch = ops.bound(ops.ref(PRIOR / "fleet-launch.json"))

    STATE.mkdir(mode=0o755)
    STATE.chmod(0o755)
    for name, mode in (("control", 0o700), ("guard-receipts", 0o700), ("tokens", 0o755)):
        path = STATE / name
        path.mkdir(mode=mode)
        path.chmod(mode)
    RUN.mkdir(mode=0o700)
    os.chown(RUN, 1000, 1000)
    memory = ops.funds.put(STATE / "capacity.json", fit)

    broker_props = [
        "Type=exec", "User=root", "Group=ubuntu", "Restart=no", "KillMode=control-group", "Delegate=no",
        f"MemoryMax={BROKER_MEMORY}", "MemorySwapMax=0", "AllowedCPUs=12-13", "CPUQuota=200%",
        "TasksMax=64", "UMask=0077", "ProtectSystem=strict", "ProtectHome=read-only",
        "ProtectControlGroups=yes", "NoNewPrivileges=yes", "PrivateTmp=yes", "PrivateDevices=yes",
        "EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env",
        "RuntimeDirectory=jetstreamer-horizon-epoch226-holding-v1", "RuntimeDirectoryMode=0750",
        f"StandardOutput=append:{STATE / 'control/broker.log'}", "StandardError=inherit",
    ]
    broker_argv = [str(BROKER_IMAGE), PRODUCER, str(BUDGET)]
    broker_intent = ops.funds.put(STATE / "broker-intent.json", dict(
        unit=BROKER, arguments=broker_argv, properties=broker_props, capacity=memory))
    owned = {}
    try:
        run_systemd(BROKER, broker_props, broker_argv)
        peer = wait_for(lambda: manager_process(ops, BROKER, "running"), 10)
        owned[BROKER] = peer["InvocationID"]
        wait_for(lambda: True if SOCKET.is_socket() else None, 15)
        binding = json.loads(subprocess.check_output([binder, "--production"], timeout=15))
        assert binding["broker_unit"] == BROKER and binding["producer_unit"] == PRODUCER
        assert binding["broker_invocation_id"] == peer["InvocationID"] and not binding["fixture"]
        assert not binding["admission_issued"] and not binding["producer_started"]
        assert binding["held_broker"]["path"] == str(STATE / "held-broker.json")
        exact_pin = binding["held_broker"]["exact_text"].encode()
        pin = write_exact(STATE / "held-broker.json", exact_pin, ops)
        assert pin["sha256"] == binding["held_broker"]["sha256"]
        binding_ref = ops.funds.put(STATE / "broker-binding.json", binding)
        stage = json.loads(binding["stage"]["exact_text"])
        assert stage["operation"] == "extract" and stage["held_broker"] == pin
        old_plan = ops.bound(ops.ref(PRIOR / "plan.json"))
        assert {k: v for k, v in stage.items() if k != "held_broker"} == {
            k: v for k, v in old_plan["stage"].items() if k != "held_broker"
        }
        protected = fit["protected_existing_bytes"] + fit["additional_start_reserve_bytes"]
        minimum = protected + ROOT_CAP
        space = os.statvfs(RUN)
        assert space.f_bavail * space.f_frsize >= minimum
        admission = ops.bound(ops.ref(PRIOR / "admission.json"))
        admission.update(broker_binding=binding_ref, capacity=memory,
            protected_existing_floor_bytes=protected, node_sha256=artifact["sha256"],
            recorded_unix_seconds=int(time.time()), stage_sha256=binding["stage"]["sha256"],
            producer_unit=PRODUCER, run_root=str(RUN))
        assert admission["candidate_incremental_peak_bytes"] == ROOT_CAP
        admission_ref = write_plan(STATE / "admission.json", admission, ops)
        plan = dict(old_plan, admission=admission_ref, minimum_free_bytes=minimum, stage=stage,
                    node_sha256=artifact["sha256"], producer_unit=PRODUCER, run_root=str(RUN))
        plan_ref = write_plan(STATE / "plan.json", plan, ops)
        substitutions = (
            (str(PRIOR), str(STATE)), (old_launch["run_root"], str(RUN)),
            (old_launch["broker_unit"], BROKER), (GUARD.replace("-v3.", "-v2."), GUARD),
            (TIMER.replace("-v3.", "-v2."), TIMER),
        )
        properties = []
        for old in inherited["properties"]:
            for a, b in substitutions:
                old = old.replace(a, b)
            properties.append(old)
        argv = [image, "226", RUN / "ledger", "--verify",
                f"--checkpoint-continuation-plan={plan_ref['path']}",
                f"--checkpoint-continuation-plan-sha256={plan_ref['sha256']}"]
        intent = ops.funds.put(STATE / "startup-intent.json", dict(unit=PRODUCER,
            broker=broker_intent, release=fit["node"], admission=admission_ref,
            plan=plan_ref, argv=list(map(str, argv)), properties=properties))
        run_systemd(PRODUCER, properties, argv, options=("--no-block",))
        held = wait_for(lambda: manager_process(ops, PRODUCER, "start-pre"), 10)
        invocation = held["InvocationID"]
        owned[PRODUCER] = invocation
        assert held["MainPID"] == "0" and int(held["ControlPID"]) > 0
        guard_plan = dict(old_guard, unit=PRODUCER, invocation_id=invocation, worker_root=str(RUN),
                         receipt_directory=str(STATE / "guard-receipts"))
        guard_ref = write_plan(STATE / "guard-plan.json", guard_plan, ops)
        run_systemd(GUARD,
            ["Type=oneshot", "User=root", "UMask=0077", "Restart=no", "MemoryMax=1G", "MemorySwapMax=0",
             "CPUQuota=100%", "TasksMax=256", "TimeoutStartSec=40", "ProtectSystem=strict",
             "ProtectHome=read-only", "PrivateNetwork=yes", "NoNewPrivileges=yes",
             "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
             "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
             f"ReadWritePaths={STATE / 'guard-receipts'}", f"StandardOutput=append:{STATE / 'control/guard.log'}",
             "StandardError=inherit"],
            [GUARD_IMAGE, guard_ref["path"], "--plan-sha256", guard_ref["sha256"], "--self-sha256", GUARD_SHA],
            options=("--on-active=1s", "--on-unit-inactive=60s", "--timer-property=AccuracySec=1s",
                     "--timer-property=RandomizedDelaySec=0"))
        clock = ops.props(TIMER, ["InvocationID", "ActiveState", "Unit"])
        assert clock["ActiveState"] == "active" and clock["Unit"] == GUARD and len(clock["InvocationID"]) == 32
        owned[TIMER] = clock["InvocationID"]
        sample_ref, sample = wait_for(lambda: guard_sample(ops, invocation, guard_ref), 40)
        assert sample["available_bytes"] >= minimum
        current = manager_process(ops, PRODUCER, "start-pre")
        assert current is not None and current["InvocationID"] == invocation
        token_dir = STATE / "tokens" / invocation
        token_dir.mkdir(mode=0o755)
        token_dir.chmod(0o755)
        token = write_plan(token_dir / "guard-admission.json",
            dict(unit=PRODUCER, invocation_id=invocation, guard_plan=guard_ref, first_guard=sample_ref,
                 guard_timer_invocation_id=clock["InvocationID"], intent=intent), ops)
        ops.funds.put(STATE / "prestart-completion.json",
            dict(intent=intent, manager=current, guard_plan=guard_ref, sample=sample_ref, token=token, timer=clock))
        live = wait_for(lambda: manager_process(ops, PRODUCER, "running"), 72)
        assert live["InvocationID"] == invocation and int(live["MainPID"]) > 0
        assert (Path("/proc") / live["MainPID"] / "exe").readlink() == image
        assert (Path("/proc") / live["MainPID"] / "cmdline").read_bytes().split(b"\0") == [
            *[os.fsencode(x) for x in argv], b""]
        caps = ops.props(PRODUCER, ["MemoryMax", "MemorySwapMax", "AllowedCPUs"])
        assert (caps["MemoryMax"], caps["MemorySwapMax"], caps["AllowedCPUs"]) == (str(PRODUCER_MEMORY), "0", "8-11")
        resource = ops.funds.put(STATE / "runtime-memory-envelope.json",
            dict(actual=caps, enrolled_combined_limit_bytes=PRODUCER_MEMORY+BROKER_MEMORY, saved_prestart=token))
        launch = dict(old_launch, broker_invocation_id=peer["InvocationID"], broker_pid=int(peer["MainPID"]),
            broker_pin=pin, broker_unit=BROKER, first_guard=sample_ref, guard_first_invocation_id=sample["guard_invocation_id"],
            guard_plan=guard_ref, invocation_id=invocation, node_plan=plan_ref, node_sha256=artifact["sha256"],
            runtime_memory=resource, recorded_unix_seconds=int(time.time()), run_root=str(RUN), unit=PRODUCER)
        return ops.funds.put(STATE / "fleet-launch.json", launch)
    except Exception:
        # Stop only units created by this attempt with their recorded invocation.
        for unit in (PRODUCER, TIMER, BROKER):
            identity = owned.get(unit)
            if identity and ops.props(unit, ["InvocationID"])["InvocationID"] == identity:
                subprocess.run(["/usr/bin/systemctl", "stop", unit], check=False, timeout=75)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply"))
    action = parser.parse_args().action
    assert os.geteuid() == 0 and __debug__
    cap, kit = toolkit()
    if action == "check":
        print(json.dumps(inspect(cap, kit)))
        return
    assert os.environ["CODEX_THREAD_ID"] == kit.replay.THREAD
    assert Path(__file__).resolve().parent == PACKAGE
    ops = kit.ops
    release = ops.bound(ops.ref(PACKAGE / "acceptance.json"))
    remote = subprocess.check_output(
        ["/usr/sbin/runuser", "-u", "ubuntu", "--", "git", "-C", REPO, "rev-parse", "origin/account-updates"],
        timeout=15, text=True).strip()
    for script in (Path(__file__), PACKAGE / "epoch226_layered_capacity.py"):
        contents = subprocess.check_output(
            ["/usr/sbin/runuser", "-u", "ubuntu", "--", "git", "-C", REPO,
             "show", f"{remote}:{SOURCE}/{script.name}"], timeout=15)
        assert script.read_bytes() == contents
    with kit.partition.take(), (cap.CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        fit = inspect(cap, kit)
        print(json.dumps(start(cap, kit, fit, release)))


if __name__ == "__main__":
    main()
