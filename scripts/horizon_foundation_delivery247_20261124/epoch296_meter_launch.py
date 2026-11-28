"""Admit and close the cache-bound private epoch 296 diagnostic."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import epoch288_shrink_debt_comparison as capacity
from epoch230_checkpoint_continuation_launch import activate_guarded, inventory

from diagnostic296_meter import attempt_paths, sealed


CONTROL = capacity.V / "horizon-seven-publication-controller-v222"
UNIT, STATE, ROOT = attempt_paths("v3")
PROFILE = STATE / "generic-unit-profile.json"
REGISTRATION = STATE / "cadence-registration.json"
TERMINAL = STATE / "terminal.json"
REPO = Path("/home/ubuntu/workspace/jetstreamer")
SOURCE = Path("scripts/horizon_foundation_delivery247_20261124")
BOOKING = capacity.V / "horizon257-current-reader-delivery-v1/booking.json"
HOOK = capacity.V / "horizon230-final-tail-tokens-v1/pre-start.sh"
TOKENS = capacity.V / "horizon296-meter-bounded-v3-tokens"
GUARD = "horizon-296-meter-bounded-v3-protective.service"
TIMER = GUARD.removesuffix(".service") + ".timer"
CPUS = "40-47"
CAP = 128_347_983_872
GUARD_RAM = 1 << 30
FIELDS = ["Id", "LoadState", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "Job"]


def live_census():
    output = subprocess.check_output([
        "systemctl", "list-units", "--type=service", "--state=running,activating",
        "--no-pager", "--no-legend", "--plain",
    ], text=True, timeout=10)
    return {line.split()[0] for line in output.splitlines()
            if line.startswith(("horizon-", "foundation-", "archive-", "jetstreamer-"))}


def fit(kit):
    ops = kit.ops
    completion, fleet_ref, fleet = capacity.latest_accepted_fleet(kit)
    assert any(row["epoch"] == 296 and row["state"] == "missing"
               for row in fleet["inventory"]["entries"])
    booking_ref = sealed(BOOKING)
    booking = ops.bound(booking_ref)
    owners = {item["epoch"]: item.get("producer", item.get("unit")) for item in fleet["active"]}
    assert set(owners) == {226, 230, 252, 257, 261, 288}
    allowed = kit.measure.source.helper.cpus
    peers = {row["Id"]: row["InvocationID"] for row in owners.values()}
    for role in ("226-broker", "public-audit"):
        row = booking["live_owners"][role]
        peers[row["Id"]] = row["InvocationID"]
    listed = live_census()
    assert listed == set(peers), sorted(listed ^ set(peers))
    current = {}
    for unit, invocation in peers.items():
        row = ops.props(unit, FIELDS + ["AllowedCPUs", "MemoryCurrent", "MemoryMax"])
        assert (row["ActiveState"], row["SubState"], row["InvocationID"]) == ("active", "running", invocation)
        assert not allowed(CPUS) & allowed(row["AllowedCPUs"])
        current[unit] = row

    floor = booking["filesystem_floor_bytes"]
    previous_growth = booking["guard_growth"]
    dirs = {int(epoch): Path(row["sample"]["path"]).parent for epoch, row in previous_growth.items()}
    dirs[230] = capacity.V / "horizon230-middle-fit-v1/guard-receipts"
    growth = {epoch: kit.measure.source.growth_for(epoch, current[owners[epoch]["Id"]], directory)
              for epoch, directory in dirs.items()}
    assert all(row["floor_bytes"] == floor for row in growth.values())
    other = booking["protected_disk_bytes"] - floor - sum(row["remaining_growth_bytes"] for row in previous_growth.values())
    assert other >= booking["receipt_scratch_maximum_bytes"] > 0
    protected = floor + other + sum(row["remaining_growth_bytes"] for row in growth.values())
    assert ROOT.stat().st_dev == Path("/").stat().st_dev
    disk = os.statvfs(ROOT)
    free = disk.f_bavail * disk.f_frsize
    memory = {key: int(value.split()[0]) * 1024 for key, value in
              (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
              if key in ("MemTotal", "MemAvailable")}
    commitment = sum(max(0, int(row["MemoryMax"]) - int(row["MemoryCurrent"])) for row in current.values())
    room = memory["MemAvailable"] - memory["MemTotal"] // 10 - commitment
    assert live_census() == listed
    assert all(ops.props(unit, ["InvocationID"])["InvocationID"] == invocation for unit, invocation in peers.items())
    return dict(sampled_unix_seconds=time.time(), completion=completion, fleet=fleet_ref,
                owners=current, guard_growth=growth, booking=booking_ref, disk_free_bytes=free,
                existing_disk_protected_bytes=protected, disk_margin_bytes=free-protected-CAP,
                uncommitted_memory_bytes=room, cpus=CPUS, publication_authorized=False)


def launch(kit):
    ops = kit.ops
    assert not REGISTRATION.exists() and not TERMINAL.exists()
    for name in (Path(__file__).name, "diagnostic296_meter.py", "epoch288_shrink_debt_comparison.py",
                 "epoch230_checkpoint_continuation_launch.py"):
        installed = Path(__file__).parent / name
        sealed(installed)
        published = subprocess.check_output(["runuser", "-u", "ubuntu", "--", "git", "-C", str(REPO),
            "show", f"origin/account-updates:{SOURCE / name}"], timeout=15)
        assert installed.read_bytes() == published
    assert (CONTROL / "diagnostic296_meter.py").read_bytes() == (
        Path(__file__).parent / "diagnostic296_meter.py").read_bytes()
    for unit in (UNIT, GUARD, TIMER):
        row = ops.props(unit, ["LoadState", "ActiveState", "Job"])
        assert row == dict(LoadState="not-found", ActiveState="inactive", Job=""), row
    profile_ref = sealed(PROFILE)
    profile = ops.bound(profile_ref)
    assert (profile["epoch"], profile["unit"], profile["guarded_whole_tree_cap_bytes"]) == (296, UNIT, CAP)
    guard = profile["guard"]
    capacity.checked(guard)
    capacity.checked(profile["worker"])
    node = capacity.checked(capacity.fixed(profile["argv"][0],
        "bf90af5f3d6ca5f973fc607bc54c0cb0e1cabdc82e61a19f020cef5187939d08"))
    assert ops.bound(profile["cache_namespace"])["host_guard_sees_empty_placeholders"]
    bootstrap = ops.bound(profile["route"])["bootstrap"]
    observed = Path(bootstrap["path"]).stat()
    assert (observed.st_dev, observed.st_ino, observed.st_size) == (
        bootstrap["device"], bootstrap["inode"], bootstrap["bytes"])
    for row in ops.bound(profile["cache_custody"])["index_rows"]:
        source = Path(row["source"]).stat()
        assert (source.st_dev, source.st_ino, source.st_size, source.st_ctime_ns, source.st_mtime_ns) == tuple(
            row[key] for key in ("device", "inode", "size", "ctime_ns", "mtime_ns"))
    sealed(HOOK)
    remote = inventory(kit, epoch=296, unit="foundation-296-meter-materialization-inventory-v1")
    measured = fit(kit)
    properties = dict(profile["properties_without_cpu"], AllowedCPUs=CPUS)
    memory = int(properties["MemoryMax"])
    measured["memory_margin_bytes"] = measured["uncommitted_memory_bytes"] - memory - GUARD_RAM
    if measured["disk_margin_bytes"] < 0 or measured["memory_margin_bytes"] < 0:
        return ops.funds.put(STATE / f"fit-{time.time_ns()}.json", dict(epoch=296, profile=profile_ref,
            measured=measured, admitted=False, publication_authorized=False))
    permission = ops.funds.put(STATE / "admission.json", dict(schema="foundation-epoch296-meter-admission-v1",
        epoch=296, profile=profile_ref, inventory=remote, measured=measured,
        admitted=True, publication_authorized=False))
    template = ops.bound(profile["guard_plan"])
    assert template["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
    assert template["unit"] == UNIT and template["maximum_root_physical_bytes"] == CAP
    TOKENS.mkdir(mode=0o755)
    TOKENS.chmod(0o755)
    props = [f"--property={key}={value}" for key, value in properties.items()]
    props.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    prestart = f"ExecStartPre=/usr/bin/bash {HOOK} 60 {TOKENS}"
    owner, plan, token, active_guard = activate_guarded(
        kit, 296, STATE, TOKENS, UNIT, GUARD, guard, template, permission, props, prestart, profile["argv"])
    return ops.funds.put(REGISTRATION, dict(schema="jetstreamer-historical-performance-launch-receipt-v1",
        epoch=296, kind="epoch296-private-meter-diagnostic", unit=UNIT, run_root=str(ROOT),
        invocation_id=owner["invocation_id"], main_pid=owner["main_pid"], node_path=str(node),
        worker=profile["worker"], profile=profile_ref, admission=permission, guard_plan=plan,
        launch_token=token, active_guard=active_guard, launched=True, evidence={"units":[owner]},
        canonical_epoch_publication_authorized=False, remote_mutations=False, r2_mutations=False))


def settle(kit):
    ops = kit.ops
    source = sealed(REGISTRATION)
    row = ops.bound(source)
    terminal = ops.props(UNIT, FIELDS + ["ExecMainStatus", "Result"])
    assert terminal["InvocationID"] == row["invocation_id"]
    if terminal["ActiveState"] == "active":
        return dict(running=True, unit=UNIT, invocation_id=row["invocation_id"])
    assert terminal["ActiveState"] in ("failed", "inactive") and terminal["MainPID"] == "0"
    assert not terminal["ControlGroup"] and not terminal["Job"]
    assert not (Path("/sys/fs/cgroup/system.slice") / UNIT).exists()
    clock = ops.props(TIMER, ["ActiveState", "InvocationID"])
    if clock["ActiveState"] != "inactive":
        assert clock["InvocationID"] == ops.bound(row["launch_token"])["guard_timer_invocation"]
        subprocess.run(["systemctl", "stop", TIMER], check=True, timeout=10)
    for unit in (GUARD, TIMER):
        closed = ops.props(unit, ["ActiveState", "Job"])
        assert closed == dict(ActiveState="inactive", Job=""), closed
    lines = subprocess.check_output(["journalctl", f"_SYSTEMD_INVOCATION_ID={row['invocation_id']}",
        "--no-pager", "-o", "cat"], text=True, timeout=10).splitlines()
    prefix = "epoch296 compute meter: slot=127870085 entry=7 local_transaction=0 signature="
    trace = [line for line in lines if line.startswith(prefix)]
    assert len(trace) <= 1
    canonical = capacity.V / "horizon296-guarded-singleton-v1/canonical-first-failure-v1/completion.json"
    canonical_ref = sealed(canonical)
    expected = ops.bound(canonical_ref)
    assert expected["slot"] == 127_870_085 and expected["canonical_error"] == "ComputationalBudgetExceeded"
    matches = False
    if trace:
        assert trace[0].startswith(prefix + "2Frxp8iXa8u3nYTZxZZNNjNp7Py6Yidszb3NUCse3zML3aYcbW2pB1PVSs1H4xJxZRaxsk3enrFcdMPE99ezt68J ")
        matches = ("InstructionError(0, ComputationalBudgetExceeded)" in trace[0]
            and all(log in trace[0] for log in expected["canonical_program_logs"]))
    next_action = "Diagnose the private diagnostic exit before requesting another invocation."
    if trace:
        next_action = ("Qualify the repaired worker on the complete epoch and its canonical checkpoint."
            if matches else "Resolve the remaining difference from canonical execution.")
    return ops.funds.put(TERMINAL, dict(schema="foundation-epoch296-meter-diagnostic-terminal-v1",
        launch=source, guard_drained=True, producer=terminal, target_trace=trace,
        canonical_transaction=canonical_ref, target_matches_canonical=matches,
        journal_tail=lines[-25:], next_action=next_action,
        publication_authorized=False, r2_mutations=False))


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    assert len(sys.argv) == 2 and sys.argv[1] in ("--fit", "--launch", "--settle")
    kit = capacity.load_existing()
    os.umask(0o077)
    with kit.partition.take(), (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = {"--fit": fit, "--launch": launch, "--settle": settle}[sys.argv[1]](kit)
    print(json.dumps(result, indent=2))
