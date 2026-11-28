"""Admit Foundation's corrected epoch 296 singleton using the guarded startup path."""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

from epoch230_checkpoint_continuation_launch import SOURCE, activate_guarded, git, inventory


V = Path("/var/lib/jetstreamer")
CONTROL = V / "horizon-seven-publication-controller-v222"
STATE = V / "horizon296-full-retry-v2"
TOKENS = V / "horizon296-full-retry-tokens-v2"
RECEIPTS = STATE / "guard-receipts"
UNIT = "horizon-qualify-296-full-retry-v2.service"
GUARD = "horizon-296-full-retry-protective-v2.service"
TIMER = GUARD.replace(".service", ".timer")
ROOT = Path("/home/ubuntu/.jetstreamer-private/qualification-296-full-retry-v2")
PROFILE = (V / "horizon296-full-retry-preparation-v2/profile.json",
           "c9287ddad9c6bba36fda7bedb7c76cf42ca57576b76c3b6a648ce1b7f473d0f0")
NAMESPACE = (STATE / "namespace.json", "7f6d0f4bc92b1ed901085e7b16d3c24b5eecd48cd7a34e6aaa17eb423a3f4df7")
EFFECTIVE_NAMESPACE = STATE / "effective-namespace-32-39.json"
PLACEMENT = (V / "horizon296-disjoint-placement-proposal-v376/placement.json",
             "eee23d784cd32f1292c6fc8dd605cd9d2d3d298b6382e52c0c1714a504118014")
CPUS = "32-39"
SELECTED_CPUS = list(range(32, 40))
EXCLUSIVE_CPUS = SELECTED_CPUS + list(range(96, 104))
TEMPLATE = (STATE / "static-guard-plan.json", "cc9d0ab895a73c6ef8b2f6c8e297a1faf3d929f49685da977c24fe88ad12dcf5")
VALIDATION = (STATE / "static-guard-validation.json", "ca3686dc0641ed42852c4caaaf487c15d9be4ce3e833447494d42032aa692870")
CHECKPOINT = (V / "horizon296-feature-account-v4/terminal.json",
              "89fb50edf452aca9205c8022670e8dd6863cc131090c95383c6a3f352e20ea05")
FEATURE_UNIT = "horizon-qualify-296-feature-account-v4.service"
FEATURE_GUARD = "horizon-296-feature-account-protective-v4.service"
PRIOR = (V / "horizon296-full-retry-guard-v1/terminal.json",
         "a719218adcf7b7401dec16096426cc9b4f0e28061f0bcdc6036d12a9d63580a7")
PRIOR_UNIT = "horizon-qualify-296-full-retry-v1.service"
PRIOR_GUARD = "horizon-296-full-retry-protective-v1.service"
ROSTER_SCHEMA = "foundation-epoch296-replay-roster-binding-v1"
HOOK = {"path": str(V / "horizon230-final-tail-tokens-v1/pre-start.sh"),
        "sha256": "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0"}
KIT = (V / "horizon292-full-v322/admit.py",
       "f32b86c421bc987852120912574fe72c0f59cfbf19bfc021a69dbe8ae4a5049f")
FIELDS = ("Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup",
          "AllowedCPUs", "MemoryMax", "MemorySwapMax", "NRestarts", "Job")


def reference(path, digest):
    info = path.lstat()
    assert path.resolve() == path and stat.S_ISREG(info.st_mode)
    assert info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o222
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, path
    return {"path": str(path), "sha256": digest}


def input_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def static_inputs(ops, rehash_payloads):
    profile_ref = reference(*PROFILE)
    profile = ops.bound(profile_ref)
    namespace = ops.bound(reference(*NAMESPACE))
    template = ops.bound(reference(*TEMPLATE))
    validation = ops.bound(reference(*VALIDATION))
    checkpoint_ref = reference(*CHECKPOINT)
    checkpoint = ops.bound(checkpoint_ref)
    prior_ref = reference(*PRIOR)
    prior = ops.bound(prior_ref)

    assert profile["schema"] == "foundation-epoch296-corrected-full-replay-preparation-v2"
    assert (profile["epoch"], profile["unit"], profile["guard_unit"], profile["guard_timer"],
            profile["run_root"]) == (296, UNIT, GUARD, TIMER, str(ROOT))
    assert profile["replay_started"] is profile["publication_authorized"] is False
    assert profile["checkpoint_qualification_path"] == checkpoint_ref["path"]
    assert checkpoint["schema"] == "foundation-epoch296-feature-account-terminal-v1"
    assert checkpoint["state"] == "checkpoint-verified" and checkpoint["guard_drained"]
    assert checkpoint["checkpoint"]["slot"] == 127_961_108
    assert checkpoint["worker"] == profile["worker"]
    assert checkpoint["canonical_epoch_publication_authorized"] is False
    assert prior["schema"] == "foundation-epoch296-full-retry-execution-mismatch-v1"
    assert prior["epoch"] == 296 and prior["guard_drained"] and prior["failure"]["slot"] == 127_955_673
    for evidence, unit in ((prior, PRIOR_UNIT), (checkpoint, FEATURE_UNIT)):
        launch = ops.bound(evidence["launch"])
        assert launch["unit"] == unit and launch["invocation_id"] == evidence["invocation_id"]

    assert namespace["schema"] == "foundation-epoch296-corrected-full-replay-namespace-v2"
    assert namespace["profile"] == profile_ref and namespace["host_placeholders_empty"]
    assert namespace["working_scratch_empty"] and not namespace["replay_launched"]
    assert namespace["proof"] == {"read_only_identities": 5, "writable_work_verified": True,
                                  "root": str(ROOT), "worker_started": False}
    assert validation["validated"] and not validation["producer_signaled"]
    assert validation["unit"] == UNIT and validation["plan_sha256"] == TEMPLATE[1]
    assert validation["self_sha256"] == profile["guard"]["sha256"]
    assert template["worker_root"] == str(ROOT) and template["unit"] == UNIT
    assert template["receipt_directory"] == str(RECEIPTS) and template["invocation_id"] == "0" * 32
    cap = profile["requested_cap"]
    assert template["maximum_root_physical_bytes"] == cap["whole_tree_bytes"]
    assert template["maximum_worker_vmas"] == 3_500_000
    assert profile["receipt_startup_bytes"] == cap["staging_incremental_bytes"]
    assert profile["properties"]["MemoryMax"] == str(cap["producer_memory_bytes"])

    node = ops.checked_image(profile["node"])
    worker = ops.checked_image(profile["worker"])
    ops.checked_image(profile["guard"])
    ops.checked_image(HOOK)
    worker_build = ops.bound(profile["worker_build"])
    assert worker_build["exit_status"] == 0 and worker_build["canonical_feature_accounts_regression_passed"]
    assert worker_build["artifact"]["sha256"] == profile["worker"]["sha256"]
    deployment = ops.bound(profile["worker_deployment"])
    assert deployment["destination"] == str(Path(worker).parent)
    assert any(member["name"] == Path(worker).name and member["sha256"] == profile["worker"]["sha256"]
               and member["mode"] == "0555" for member in deployment["members"])
    manifest = ops.bound(profile["cohort_manifest"])
    cohort, = manifest["manifest"]["verification_cohorts"]
    assert (cohort["first_epoch"], cohort["last_epoch"], cohort["publish_through_epoch"]) == (296, 296, 296)
    assert cohort["bootstrap"] == profile["bootstrap"] and cohort["bootstrap"]["slot"] == 127_870_084
    assert cohort["root_checkpoints"] == [profile["terminal_checkpoint"]]
    assert profile["terminal_checkpoint"]["slot"] == 128_303_325
    override = ops.bound(profile["override_manifest"])
    for item in override["entries"]:
        reference(Path(item["path"]), item["sha256"])
    argv, env = profile["argv"], profile["environment"]
    assert argv[:3] == [node, "296", str(ROOT / "work/output")]
    assert "--verify" in argv and "--root-checkpoint-cohort" in argv
    assert f"--cohort-manifest={profile['cohort_manifest']['path']}" in argv
    assert f"--cohort-manifest-fingerprint={manifest['manifest_fingerprint']}" in argv
    assert env["JETSTREAMER_HISTORICAL_WORKER_V1_8_11"] == worker
    assert env["JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST"] == profile["override_manifest"]["path"]
    assert env["JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256"] == profile["override_manifest"]["sha256"]

    bindings = []
    for item in profile["readonly_bindings"]:
        source, target = (Path(item[key]) for key in ("path", "destination"))
        assert source.resolve() == source and target.resolve() == target and target.is_relative_to(ROOT)
        expected = tuple(item[key] for key in ("device", "inode", "size", "mtime_ns", "ctime_ns", "uid", "gid", "mode"))
        info = source.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and input_identity(info) == expected
        empty = target.lstat()
        assert stat.S_ISREG(empty.st_mode) and empty.st_nlink == 1 and empty.st_uid == 1000
        assert empty.st_size == 0 and stat.S_IMODE(empty.st_mode) == 0o600
        if rehash_payloads:
            with source.open("rb") as stream:
                assert input_identity(os.fstat(stream.fileno())) == expected
                assert hashlib.file_digest(stream, "sha256").hexdigest() == item["sha256"]
                assert input_identity(os.fstat(stream.fileno())) == expected
            assert input_identity(source.lstat()) == expected
        bindings.append(f"{source}:{target}")
    assert len(set(bindings)) == 5
    assert " ".join(bindings) == profile["properties"]["BindReadOnlyPaths"]
    assert f"--snapshot-archive={profile['readonly_bindings'][0]['destination']}" in argv
    return profile_ref, profile, template, checkpoint_ref, prior_ref


def check_predecessors(ops, checkpoint_ref, prior_ref):
    for evidence, producer, guard in ((ops.bound(checkpoint_ref), FEATURE_UNIT, FEATURE_GUARD),
                                      (ops.bound(prior_ref), PRIOR_UNIT, PRIOR_GUARD)):
        fields = ("ActiveState", "InvocationID", "MainPID", "ControlGroup", "Job", "Result")
        row = ops.props(producer, list(fields))
        assert row["ActiveState"] in ("inactive", "failed") and row["MainPID"] == "0"
        assert row["InvocationID"] in ("", evidence["invocation_id"])
        assert row["Result"] == evidence["producer"]["Result"] and not row["Job"] and not row["ControlGroup"]
        drain = ops.props(guard, ["ActiveState", "MainPID", "ControlGroup", "Job"])
        assert drain["ActiveState"] in ("inactive", "failed") and drain["MainPID"] == "0"
        assert not drain["ControlGroup"] and not drain["Job"]
        assert ops.props(guard.replace(".service", ".timer"), ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        for unit in (producer, guard):
            assert not (Path("/sys/fs/cgroup/system.slice") / unit).exists()


def placement_inputs(ops, profile_ref, profile):
    pinned = reference(*PLACEMENT)
    proposal = ops.bound(pinned)
    assert proposal["schema"] == "foundation-epoch296-full-retry-placement-v2"
    assert (proposal["epoch"], proposal["unit"], proposal["original_profile"]) == (296, UNIT, profile_ref)
    assert proposal["previous_allowed_cpus"] == profile["properties"]["AllowedCPUs"] == "56-63"
    assert proposal["allowed_cpus"] == CPUS
    assert proposal["online_cpus_on_same_physical_cores"] == EXCLUSIVE_CPUS
    assert proposal["planned_epoch258_cpuset"] == "48-55"
    for flag in ("namespace_qualified_on_this_cpuset", "fresh_complete_fit_for_this_profile",
                 "capacity_reserved", "replay_launched", "publication_authorized"):
        assert proposal[flag] is False
    return pinned


def effective_namespace(ops, profile_ref, profile, placement):
    qualified = reference(EFFECTIVE_NAMESPACE, ops.ref(EFFECTIVE_NAMESPACE)["sha256"])
    proof = ops.bound(qualified)
    assert proof["schema"] == "foundation-epoch296-full-retry-effective-namespace-v2"
    assert (proof["epoch"], proof["producer_unit"], proof["profile"], proof["placement"]) == (
        296, UNIT, profile_ref, placement)
    assert proof["original_namespace"] == reference(*NAMESPACE)
    assert proof["properties"] == producer_properties(profile)
    assert proof["cpuset_effective"] == proof["process_affinity"] == SELECTED_CPUS
    assert proof["readonly_bindings"] == [
        dict({field: item[field] for field in ("destination", "device", "inode", "size")}, read_only=True)
        for item in profile["readonly_bindings"]
    ]
    assert proof["private_work_writable"] is True and proof["token_mount_read_only"] is True
    assert proof["worker_started"] is proof["replay_launched"] is proof["publication_authorized"] is False
    return qualified


def verify_topology(parse_cpus):
    topology = Path("/sys/devices/system/cpu")
    online = parse_cpus((topology / "online").read_text().replace(",", " "))
    selected = set(SELECTED_CPUS)
    siblings = set()
    for cpu in selected:
        physical = parse_cpus((topology / f"cpu{cpu}/topology/thread_siblings_list").read_text().replace(",", " "))
        assert physical & selected == {cpu}
        siblings.update(physical & online)
    assert selected <= online and siblings == set(EXCLUSIVE_CPUS)


def capacity_contract(roster, profile, template, checkpoint, placement):
    fit, quote = roster["capacity"], roster["replay_296_quote"]
    assert roster["schema"] == ROSTER_SCHEMA and roster["epoch"] == 296
    assert roster["admission_issued"] is roster["candidate_held"] is False
    assert roster["publication_authorized"] is False
    assert quote["checkpoint_qualification"] == checkpoint and quote["repaired_worker"] == profile["worker"]
    assert quote["placement"] == placement
    assert quote["candidate_cpus"] == SELECTED_CPUS and quote["exclusive_online_cpus"] == EXCLUSIVE_CPUS
    assert fit["cpus"].split() == [str(cpu) for cpu in SELECTED_CPUS]
    cap = profile["requested_cap"]
    assert fit["candidate_disk_bytes"] == quote["candidate_disk_bytes"] == cap["whole_tree_bytes"] + profile["receipt_startup_bytes"]
    assert fit["candidate_total_memory_bytes"] == quote["candidate_memory_bytes"] == (
        cap["producer_memory_bytes"] + cap["guard_memory_bytes"] + (256 << 20))
    assert fit["guard_floor_bytes"] >= template["minimum_free_bytes"]
    assert fit["fits"] and fit["disk_shortfall_bytes"] == fit["memory_shortfall_bytes"] == 0
    assert fit["required_disk_bytes"] == fit["protected_existing_disk_bytes"] + fit["candidate_disk_bytes"]
    assert fit["required_disk_bytes"] <= fit["available_disk_bytes"]
    assert fit["required_hard_memory_bytes"] <= fit["host_total_memory_bytes"]
    assert fit["required_remaining_memory_bytes"] <= fit["available_memory_bytes"]
    return fit


def check_fit(kit, roster, profile, template, checkpoint, placement, held=None):
    fit = capacity_contract(roster, profile, template, checkpoint, placement)
    assert 0 <= time.time() - roster["recorded_unix_seconds"] <= 90
    parse_cpus = kit.measure.source.helper.cpus
    verify_topology(parse_cpus)
    exclusive = set(EXCLUSIVE_CPUS)
    listed = subprocess.check_output(
        ["systemctl", "list-units", "--type=service", "--state=running,activating",
         "--plain", "--no-legend", "--no-pager"], text=True, timeout=10)
    active = {line.split()[0] for line in listed.splitlines()
              if line.startswith(("horizon-", "foundation-", "archive-", "jetstreamer-"))}
    guards = {guard["unit"] for guard in roster["periodic_guards"].values()}
    peers = set(roster["owners"])
    if held is not None:
        guards.add(GUARD)
        assert UNIT not in peers
        current = kit.ops.props(UNIT, list(held))
        assert current == held
        peers.add(UNIT)
    assert active - guards == peers
    growth = fit["required_remaining_memory_bytes"]
    for unit, owner in roster["owners"].items():
        actual = kit.ops.props(unit, [*FIELDS, "MemoryCurrent"])
        assert all(actual[field] == owner["systemd"][field] for field in FIELDS)
        assert exclusive.isdisjoint(parse_cpus(actual["AllowedCPUs"].replace(",", " "))), f"epoch 296 physical CPU overlaps {unit}"
        growth += max(0, owner["memory_current_bytes"] - int(actual["MemoryCurrent"]))
    for guard in roster["periodic_guards"].values():
        assert kit.ops.props(guard["timer"], ["ActiveState", "InvocationID", "Unit"]) == {
            "ActiveState": "active", "InvocationID": guard["timer_invocation_id"], "Unit": guard["unit"]}
    storage = os.statvfs(ROOT)
    assert ROOT.stat().st_dev == roster["filesystem_device"]
    free = storage.f_bavail * storage.f_frsize
    available, = (int(line.split()[1]) << 10 for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemAvailable:"))
    assert free >= fit["required_disk_bytes"] and available >= growth
    return {"free_bytes": free, "available_memory_bytes": available,
            "required_remaining_memory_bytes": growth, "at_unix_seconds": int(time.time())}


def namespace_at_prestart(profile, pid):
    process = Path("/proc") / str(pid)
    root = process / "root"
    stat_path = process / "stat"
    start_ticks = int(stat_path.read_text().rpartition(")")[2].split()[19])
    assert start_ticks > 0 and (process / "cgroup").read_text().strip() == f"0::/system.slice/{UNIT}"
    assert (Path("/sys/fs/cgroup/system.slice") / UNIT / "cpuset.cpus.effective").read_text().strip() == CPUS
    assert os.sched_getaffinity(pid) == set(SELECTED_CPUS)
    mounts = {}
    for line in (process / "mountinfo").read_text().splitlines():
        fields = line.split()
        assert len(fields) >= 7
        mounts[fields[4]] = set(fields[5].split(","))
    for item in profile["readonly_bindings"]:
        destination = item["destination"]
        viewed = (root / destination.lstrip("/")).stat()
        assert (viewed.st_dev, viewed.st_ino, viewed.st_size) == tuple(
            item[key] for key in ("device", "inode", "size"))
        assert "ro" in mounts[destination]
    # ProtectSystem can make the token directory read-only through an ancestor mount.
    assert "ro" in effective_mount_options(mounts, TOKENS) and "rw" in mounts[str(ROOT / "work")]
    assert (root / str(TOKENS).lstrip("/")).samefile(TOKENS)
    actual = (process / "cmdline").read_bytes().split(b"\0")
    assert actual == [b"/usr/bin/bash", os.fsencode(HOOK["path"]), b"60", os.fsencode(TOKENS), b""]
    assert int(stat_path.read_text().rpartition(")")[2].split()[19]) == start_ticks
    return start_ticks


def effective_mount_options(mounts, path):
    for candidate in (path, *path.parents):
        if str(candidate) in mounts:
            return mounts[str(candidate)]
    raise AssertionError(f"No mount covers {path}")


def assert_dormant(ops):
    assert not TOKENS.exists() and not any(RECEIPTS.iterdir())
    for name in ("admission.json", "startup-owner.json", "guard-plan.json", "guard-arm.json", "pre-release.json",
                 "handoff.json", "cadence-registration.json", "launch-failure.json", "launch-failure-drain.json"):
        assert not (STATE / name).exists(), name
    for unit in (UNIT, GUARD, TIMER):
        assert ops.props(unit, ["LoadState", "ActiveState", "Job"]) == {
            "LoadState": "not-found", "ActiveState": "inactive", "Job": ""}


def producer_properties(profile):
    assert profile["properties"]["AllowedCPUs"] == "56-63"
    return dict(profile["properties"], AllowedCPUs=CPUS, ReadOnlyPaths=str(TOKENS), Delegate="no",
                ProtectControlGroups="yes",
                UnsetEnvironment=("HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID "
                                  "HORIZON_SECRET_ACCESS_KEY HORIZON_PUBLIC_BASE_URL"))


def prepare_properties(profile):
    properties = producer_properties(profile)
    args = [f"--property={key}={value}" for key, value in properties.items()]
    args.extend(f"--setenv={key}={value}" for key, value in profile["environment"].items())
    return args, f"ExecStartPre=/usr/bin/bash {HOOK['path']} 60 {TOKENS}"


def record_interruption(ops, admission, held, error):
    fields = ["ActiveState", "InvocationID", "MainPID", "ControlPID", "ControlGroup", "Job"]
    current = ops.props(UNIT, fields)
    failure = ops.funds.put(STATE / "launch-failure.json", {
        "epoch": 296, "admission": admission, "held_owner": held, "observed_owner": current,
        "error_type": type(error).__name__, "canonical_publication_authorized": False,
    })
    if held is None or current["InvocationID"] not in ("", held["InvocationID"]):
        return
    if (STATE / "cadence-registration.json").exists():
        return
    # Keep the protection armed until the producer is confirmed drained.
    if current["InvocationID"] == held["InvocationID"] and current["ActiveState"] not in ("inactive", "failed"):
        assert ops.props(UNIT, fields) == current
        subprocess.run(["systemctl", "stop", UNIT], timeout=30, check=True)
    stopped = ops.props(UNIT, fields)
    assert stopped["ActiveState"] in ("inactive", "failed")
    assert stopped["InvocationID"] in ("", held["InvocationID"])
    assert stopped["MainPID"] == stopped["ControlPID"] == "0"
    assert not stopped["ControlGroup"] and not stopped["Job"]
    assert not (Path("/sys/fs/cgroup/system.slice") / UNIT).exists()

    arm_path = STATE / "guard-arm.json"
    arm_ref = None
    timer_fields = ["Id", "ActiveState", "Unit", "InvocationID", "Job"]
    timer_before = ops.props(TIMER, timer_fields)
    timer_disposition = "arm-unrecorded"
    if arm_path.is_file():
        arm_ref = reference(arm_path, ops.ref(arm_path)["sha256"])
        arm = ops.bound(arm_ref)
        assert arm["schema"] == "foundation-epoch296-full-retry-guard-arm-v2"
        assert arm["epoch"] == 296 and arm["admission"] == admission
        assert arm["producer_invocation_id"] == held["InvocationID"] and arm["guard_unit"] == GUARD
        assert arm["guard_plan"]["path"] == str(STATE / "guard-plan.json")
        plan = ops.bound(reference(Path(arm["guard_plan"]["path"]), arm["guard_plan"]["sha256"]))
        assert plan["invocation_id"] == held["InvocationID"] and plan["unit"] == UNIT
        assert arm["timer_unit"] == TIMER and re.fullmatch("[a-f0-9]{32}", arm["timer_invocation_id"])
        assert re.fullmatch("[a-f0-9]{32}", arm["first_guard_invocation_id"])
        expected = arm["timer_invocation_id"]
        same_active_timer = (
            timer_before["Id"] == TIMER and timer_before["Unit"] == GUARD
            and timer_before["ActiveState"] == "active" and timer_before["InvocationID"] == expected
            and not timer_before["Job"]
        )
        if same_active_timer and ops.props(TIMER, timer_fields) == timer_before:
            subprocess.run(["systemctl", "stop", TIMER], timeout=30, check=True)
            after = ops.props(TIMER, timer_fields)
            assert after["ActiveState"] == "inactive" and after["InvocationID"] in ("", expected)
            assert not after["Job"]
            timer_disposition = "stopped-bound-timer"
        elif (timer_before["Id"] == TIMER and timer_before["Unit"] in ("", GUARD)
              and timer_before["ActiveState"] == "inactive"
              and timer_before["InvocationID"] in ("", expected) and not timer_before["Job"]):
            timer_disposition = "already-inactive"
        else:
            timer_disposition = "timer-identity-mismatch"
    ops.funds.put(STATE / "launch-failure-drain.json", {
        "epoch": 296, "failure": failure, "producer_after": stopped, "guard_arm": arm_ref,
        "timer_before": timer_before, "timer_after": ops.props(TIMER, timer_fields),
        "timer_disposition": timer_disposition, "canonical_publication_authorized": False,
    })


def launch(kit, roster_ref, installation):
    ops = kit.ops
    profile_ref, profile, template, checkpoint, prior = static_inputs(ops, rehash_payloads=False)
    placement = placement_inputs(ops, profile_ref, profile)
    namespace = effective_namespace(ops, profile_ref, profile, placement)
    roster = ops.bound(reference(Path(roster_ref["path"]), roster_ref["sha256"]))
    capacity_contract(roster, profile, template, checkpoint, placement)
    assert_dormant(ops)
    check_predecessors(ops, checkpoint, prior)
    remote = inventory(kit, epoch=296, unit="foundation-296-full-retry-v2-inventory")
    capacity = check_fit(kit, roster, profile, template, checkpoint, placement)
    properties, prestart = prepare_properties(profile)
    TOKENS.mkdir(mode=0o755)
    TOKENS.chmod(0o755)
    admission = ops.funds.put(STATE / "admission.json", {
        "schema": "foundation-epoch296-full-replay-admission-v1", "epoch": 296,
        "profile": profile_ref, "roster": roster_ref, "fit": capacity, "inventory": remote,
        "placement": placement, "effective_namespace": namespace,
        "checkpoint_qualification": checkpoint, "prior_terminal": prior, "cadence": installation,
        "guard_minimum_free_bytes": roster["capacity"]["guard_floor_bytes"],
        "publication_authorized": False,
    })
    current_template = dict(template, minimum_free_bytes=roster["capacity"]["guard_floor_bytes"])
    held = None
    start_ticks = None

    def capture(owner):
        nonlocal held, start_ticks
        held = owner
        start_ticks = namespace_at_prestart(profile, int(owner["ControlPID"]))
        ops.funds.put(STATE / "startup-owner.json", {
            "epoch": 296, "owner": owner, "process_start_ticks": start_ticks, "admission": admission,
        })

    def revalidate(owner, plan_ref, sample, clock, deadline):
        assert owner == held and sample["producer_invocation_id"] == owner["InvocationID"]
        assert sample["plan_sha256"] == plan_ref["sha256"] and clock["Unit"] == GUARD
        assert clock["ActiveState"] == "active" and clock["SubState"] == "waiting"
        assert re.fullmatch("[a-f0-9]{32}", clock["InvocationID"])
        assert re.fullmatch("[a-f0-9]{32}", sample["guard_invocation_id"])
        arm_ref = ops.funds.put(STATE / "guard-arm.json", {
            "schema": "foundation-epoch296-full-retry-guard-arm-v2", "epoch": 296,
            "admission": admission, "producer_invocation_id": owner["InvocationID"],
            "guard_plan": plan_ref, "guard_unit": GUARD, "first_guard_invocation_id": sample["guard_invocation_id"],
            "timer_unit": TIMER, "timer_invocation_id": clock["InvocationID"],
        })
        assert sample["available_bytes"] >= roster["capacity"]["required_disk_bytes"]
        assert sample["minimum_free_bytes"] == current_template["minimum_free_bytes"]
        assert sample["maximum_root_physical_bytes"] == current_template["maximum_root_physical_bytes"]
        assert deadline > time.monotonic_ns() // 1000
        assert namespace_at_prestart(profile, int(owner["ControlPID"])) == start_ticks
        proof = check_fit(kit, roster, profile, current_template, checkpoint, placement, held=owner)
        ops.funds.put(STATE / "pre-release.json", {
            "epoch": 296, "capacity": proof, "guard_plan": plan_ref, "guard_arm": arm_ref, "admission": admission,
        })

    try:
        owner, plan, token, active_guard = activate_guarded(
            kit, 296, STATE, TOKENS, UNIT, GUARD, profile["guard"], current_template, admission,
            properties, prestart, profile["argv"], on_held=capture, before_release=revalidate)
        iid = owner["invocation_id"]
        assert held is not None and iid == held["InvocationID"]
        handoff = ops.funds.put(STATE / "handoff.json", {
            "producer": UNIT, "invocation_id": iid, "guard_plan": plan,
            "launch_token": token, "admission": admission, "ready": False,
        })
        return ops.funds.put(STATE / "cadence-registration.json", {
            "schema": "foundation-epoch296-full-retry-cadence-registration-v2", "epoch": 296,
            "unit": UNIT, "invocation_id": iid, "main_pid": owner["main_pid"], "run_root": str(ROOT),
            "profile": profile_ref, "admission": admission, "handoff": handoff,
            "placement": placement, "effective_namespace": namespace,
            "active_guard": active_guard, "node": profile["node"], "worker": profile["worker"],
            "checkpoint_qualification": checkpoint, "prior_terminal": prior,
            "ready": False, "canonical_publication_authorized": False,
        })
    except Exception as error:
        record_interruption(ops, admission, held, error)
        raise


def cadence_installation(ops, branch):
    path = STATE / "cadence-installation.json"
    installed = reference(path, ops.ref(path)["sha256"])
    receipt = ops.bound(installed)
    assert receipt["epoch"] == 296 and receipt["schema"] == "foundation-epoch296-full-retry-cadence-installation-v2"
    adapter = CONTROL / "replay296.py"
    registry = CONTROL / "guarded_replays.py"
    cycle = CONTROL / "cycle.py"
    for name, path in (("adapter", adapter), ("registry", registry), ("cycle", cycle)):
        assert receipt[name] == reference(path, ops.ref(path)["sha256"])
    guard_helper = Path(__file__).resolve().with_name("epoch230_checkpoint_continuation_launch.py")
    for path in (Path(__file__).resolve(), adapter, guard_helper):
        assert path.read_bytes() == git("show", f"{branch}:{SOURCE / path.name}")
    ops.checked_image(receipt["roster"])
    return installed


def main():
    assert __debug__ and os.geteuid() == 0
    os.umask(0o077)
    # Attach the existing vetted controller and its private lock/helpers.
    reference(*KIT)
    spec = importlib.util.spec_from_file_location("foundation_epoch296_admit", KIT[0])
    kit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kit)
    assert os.environ["CODEX_THREAD_ID"] == kit.replay.THREAD
    if sys.argv[1:] == ["--verify-inputs"]:
        profile_ref, profile, _, checkpoint, _ = static_inputs(kit.ops, rehash_payloads=True)
        placement = placement_inputs(kit.ops, profile_ref, profile)
        print(json.dumps({"epoch": 296, "profile": profile_ref, "checkpoint": checkpoint,
                          "placement": placement, "authenticated_aliases": 5, "replay_launched": False}))
        return
    path, digest = sys.argv[1:]
    roster = Path(path)
    assert roster.name == "roster.json" and roster.parent.parent == V
    assert roster.parent.name.startswith("horizon262-foundation-roster-") and re.fullmatch("[a-f0-9]{64}", digest)
    branch = git("rev-parse", "origin/account-updates").decode().strip()
    with kit.partition.take(), (CONTROL / "cycle.lock").open("rb") as lock:
        metadata = os.fstat(lock.fileno())
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.ops.props("foundation-publication-cadence-v222.service", ["ActiveState", "Job"]) == {
            "ActiveState": "inactive", "Job": ""}
        installation = cadence_installation(kit.ops, branch)
        print(json.dumps(launch(kit, {"path": path, "sha256": digest}, installation)))


if __name__ == "__main__":
    main()
