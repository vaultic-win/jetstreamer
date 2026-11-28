"""Observe the guarded epoch 296 singleton during Foundation cadence."""

import hashlib
import os
from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref
from replay252 import sealed


ORIGINAL_UNIT = "horizon-qualify-296-rooted-singleton-v1.service"
ORIGINAL_STATE = V / "horizon296-guarded-singleton-v1"
ORIGINAL_TERMINAL_SHA = "2dd34c57a0faa24b33cd4ac39ae1d0fe3fae69633b3dad0c45ec95e54bc4383c"
RETRY_STATE = V / "horizon296-full-retry-guard-v1"
RETRY_UNIT = "horizon-qualify-296-full-retry-v1.service"
CORRECTED_STATE = V / "horizon296-full-retry-v2"
CORRECTED_UNIT = "horizon-qualify-296-full-retry-v2.service"
CORRECTED_PROFILE = V / "horizon296-full-retry-preparation-v2/profile.json"
CORRECTED_PROFILE_SHA = "c9287ddad9c6bba36fda7bedb7c76cf42ca57576b76c3b6a648ce1b7f473d0f0"
CORRECTED_PLACEMENT = V / "horizon296-disjoint-placement-proposal-v376/placement.json"
CORRECTED_PLACEMENT_SHA = "eee23d784cd32f1292c6fc8dd605cd9d2d3d298b6382e52c0c1714a504118014"
CORRECTED_CPUS = "32-39"
CORRECTED_AFFINITY = list(range(32, 40))
EFFECTIVE_NAMESPACE = CORRECTED_STATE / "effective-namespace-32-39.json"
RETRY_TERMINAL_SHA = "a719218adcf7b7401dec16096426cc9b4f0e28061f0bcdc6036d12a9d63580a7"
CHECKPOINT = V / "horizon296-feature-account-v4/terminal.json"
CHECKPOINT_SHA = "89fb50edf452aca9205c8022670e8dd6863cc131090c95383c6a3f352e20ea05"
FLEET_FIELDS = ["ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "NRestarts"]
if (CORRECTED_STATE / "cadence-registration.json").is_file():
    STATE, UNIT, ROOT_NAME = CORRECTED_STATE, CORRECTED_UNIT, "qualification-296-full-retry-v2"
elif (RETRY_STATE / "cadence-registration.json").is_file():
    STATE, UNIT, ROOT_NAME = RETRY_STATE, RETRY_UNIT, "qualification-296-full-retry-v1"
else:
    STATE, UNIT, ROOT_NAME = ORIGINAL_STATE, ORIGINAL_UNIT, "qualification-296-rooted-singleton-v1"
REGISTRATION = STATE / "cadence-registration.json"
ROOT = Path("/home/ubuntu/.jetstreamer-private") / ROOT_NAME


def drained(unit, terminal):
    assert bound(terminal["launch"])["unit"] == unit and terminal["guard_drained"]
    current = props(unit, ["ActiveState", "InvocationID", "MainPID", "ControlGroup", "Job", "Result"])
    assert current["ActiveState"] in ("inactive", "failed") and current["MainPID"] == "0"
    assert current["InvocationID"] in ("", terminal["invocation_id"])
    assert current["ControlGroup"] == current["Job"] == ""
    assert current["Result"] == terminal["producer"]["Result"]


def corrected(row):
    prior_ref = sealed(RETRY_STATE / "terminal.json", RETRY_TERMINAL_SHA)
    prior = bound(prior_ref)
    assert prior["schema"] == "foundation-epoch296-full-retry-execution-mismatch-v1"
    assert prior["failure"]["slot"] == 127_955_673 and row["prior_terminal"] == prior_ref
    drained(RETRY_UNIT, prior)
    checkpoint_ref = sealed(CHECKPOINT, CHECKPOINT_SHA)
    checkpoint = bound(checkpoint_ref)
    assert checkpoint["schema"] == "foundation-epoch296-feature-account-terminal-v1"
    assert checkpoint["checkpoint"]["slot"] == 127_961_108 and checkpoint["state"] == "checkpoint-verified"
    drained("horizon-qualify-296-feature-account-v4.service", checkpoint)
    profile_ref = sealed(CORRECTED_PROFILE, CORRECTED_PROFILE_SHA)
    profile = bound(profile_ref)
    assert row["schema"] == "foundation-epoch296-full-retry-cadence-registration-v2"
    assert row["profile"] == profile_ref and row["checkpoint_qualification"] == checkpoint_ref
    assert profile["unit"] == UNIT and profile["run_root"] == str(ROOT)
    assert profile["terminal_checkpoint"]["slot"] == 128_303_325
    assert profile["worker"] == row["worker"] == checkpoint["worker"] and row["node"] == profile["node"]
    placement_ref = sealed(CORRECTED_PLACEMENT, CORRECTED_PLACEMENT_SHA)
    placement = bound(placement_ref)
    assert row["placement"] == placement_ref and placement["original_profile"] == profile_ref
    assert placement["allowed_cpus"] == CORRECTED_CPUS and profile["properties"]["AllowedCPUs"] == "56-63"
    namespace_ref = sealed(EFFECTIVE_NAMESPACE, row["effective_namespace"]["sha256"])
    namespace = bound(namespace_ref)
    assert row["effective_namespace"] == namespace_ref
    assert namespace["schema"] == "foundation-epoch296-full-retry-effective-namespace-v2"
    assert (namespace["epoch"], namespace["producer_unit"], namespace["profile"], namespace["placement"]) == (
        296, UNIT, profile_ref, placement_ref)
    assert namespace["properties"]["AllowedCPUs"] == CORRECTED_CPUS
    assert namespace["cpuset_effective"] == namespace["process_affinity"] == CORRECTED_AFFINITY
    assert namespace["worker_started"] is namespace["replay_launched"] is namespace["publication_authorized"] is False
    admission = bound(sealed(row["admission"]["path"], row["admission"]["sha256"]))
    fit = bound(sealed(admission["roster"]["path"], admission["roster"]["sha256"]))
    assert admission["schema"] == "foundation-epoch296-full-replay-admission-v1"
    assert admission["epoch"] == fit["epoch"] == 296 and admission["publication_authorized"] is False
    assert admission["profile"] == profile_ref and admission["checkpoint_qualification"] == checkpoint_ref
    assert admission["placement"] == placement_ref and admission["effective_namespace"] == namespace_ref
    assert fit["schema"] == "foundation-epoch296-replay-roster-binding-v1" and fit["capacity"]["fits"]
    quote = fit["replay_296_quote"]
    assert quote["checkpoint_qualification"] == checkpoint_ref and quote["repaired_worker"] == row["worker"]
    assert quote["placement"] == placement_ref and quote["candidate_cpus"] == CORRECTED_AFFINITY
    assert quote["exclusive_online_cpus"] == placement["online_cpus_on_same_physical_cores"]
    assert fit["capacity"]["cpus"].split() == [str(cpu) for cpu in CORRECTED_AFFINITY]
    handoff = bound(sealed(row["handoff"]["path"], row["handoff"]["sha256"]))
    iid = row["invocation_id"]
    assert handoff["producer"] == UNIT and handoff["invocation_id"] == iid and handoff["ready"] is False
    guard = bound(sealed(row["active_guard"]["path"], row["active_guard"]["sha256"], native_receipt=True))
    plan = bound(sealed(guard["plan"], guard["plan_sha256"]))
    assert guard["producer_invocation_id"] == guard["producer"]["invocation_id"] == plan["invocation_id"] == iid
    assert guard["producer"]["pid"] == row["main_pid"] and guard["producer"]["cgroup"] == f"/system.slice/{UNIT}"
    assert guard["producer"]["restarts"] == 0 and guard["producer_stop_enabled"]
    assert guard["trip_reason"] is None and guard["guard_sha256"] == profile["guard"]["sha256"]
    assert plan["unit"] == UNIT and plan["worker_root"] == str(ROOT)
    assert plan["maximum_root_physical_bytes"] == profile["requested_cap"]["whole_tree_bytes"]
    assert plan["minimum_free_bytes"] == admission["guard_minimum_free_bytes"] == fit["capacity"]["guard_floor_bytes"]


def registered():
    source = sealed(REGISTRATION)
    row = bound(source)
    assert (row["epoch"], row["unit"], row["run_root"]) == (296, UNIT, str(ROOT))
    assert row["canonical_publication_authorized"] is False
    if UNIT == CORRECTED_UNIT:
        corrected(row)
    elif UNIT == RETRY_UNIT:
        terminal_ref = sealed(ORIGINAL_STATE / "terminal.json", ORIGINAL_TERMINAL_SHA)
        terminal = bound(terminal_ref)
        assert row["schema"] == "foundation-epoch296-full-retry-cadence-registration-v1"
        assert row["original_terminal"] == terminal_ref and terminal["guard_drained"]
        old = props(ORIGINAL_UNIT, ["ActiveState", "MainPID", "ControlGroup", "Job"])
        assert old["ActiveState"] in ("inactive", "failed") and old["MainPID"] == "0"
        assert old["ControlGroup"] == old["Job"] == ""
        profile = bound(sealed(row["profile"]["path"], row["profile"]["sha256"]))
        assert row["unit"] == profile["unit"] and row["run_root"] == profile["worker_root"]
        dossier = bound(profile["inputs"])
        assert row["node"] == dossier["node"] and row["worker"] == dossier["worker"]
        admission = bound(sealed(row["admission"]["path"], row["admission"]["sha256"]))
        assert admission["profile_sha256"] == row["profile"]["sha256"]
        assert admission["epoch"] == 296 and admission["publication_authorized"] is False
        guard = bound(sealed(row["active_guard"]["path"], row["active_guard"]["sha256"], native_receipt=True))
        assert guard["producer_invocation_id"] == row["invocation_id"]
        assert guard["producer"]["pid"] == row["main_pid"] and guard["producer_stop_enabled"]
        assert guard["trip_reason"] is None and guard["guard_sha256"] == profile["guard_binary"]["sha256"]
    return source, row


def config():
    if not REGISTRATION.is_file():
        return []
    _, row = registered()
    fields = [*FLEET_FIELDS, "AllowedCPUs"] if UNIT == CORRECTED_UNIT else FLEET_FIELDS
    live = props(UNIT, fields)
    if live["ActiveState"] != "active" or live["SubState"] != "running":
        return []
    assert (live["InvocationID"], int(live["MainPID"])) == (row["invocation_id"], row["main_pid"])
    assert live["ControlGroup"] == "/system.slice/" + UNIT and live["NRestarts"] == "0"
    proc = Path("/proc") / live["MainPID"]
    assert (proc / "exe").samefile(row["node"]["path"])
    if UNIT == CORRECTED_UNIT:
        profile = bound(row["profile"])
        assert (proc / "cmdline").read_bytes() == b"".join(arg.encode() + b"\0" for arg in profile["argv"])
        assert live["AllowedCPUs"] == CORRECTED_CPUS
        assert os.sched_getaffinity(int(live["MainPID"])) == set(CORRECTED_AFFINITY)
    group = Path("/sys/fs/cgroup") / live["ControlGroup"].lstrip("/")
    roots = []
    for pid in (group / "cgroup.procs").read_text().split():
        process = Path("/proc") / pid / "exe"
        try:
            worker = process.readlink()
        except FileNotFoundError:
            continue
        if worker.name != "historical-worker":
            continue
        assert worker.is_relative_to(ROOT) and worker.resolve(strict=True) == worker
        with process.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == row["worker"]["sha256"]
        scratch, = [path for path in worker.parents
                    if path.name == "scratch" and path.parent.parent.name == "root-cohort-296-296"]
        roots.append(scratch)
    if not roots:
        return []
    scratch, = roots
    assert props(UNIT, fields) == live
    return [dict(range="296-296", controller_unit=UNIT, producer_unit=UNIT,
                 expected_controller_invocation_id=row["invocation_id"],
                 expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(scratch), worker_executable_basename="historical-worker")]


def verify_replays(observed, configured):
    assert len(observed) == len(configured)
    if observed:
        seen, = observed
        expected, = configured
        assert seen["range"] == expected["range"] and seen["invocation_binding_stable"]
        assert seen["scratch_path"] == expected["scratch_path"]
        for role in ("controller", "producer"):
            for edge in ("before", "after"):
                identity = seen[f"{role}_{edge}"]
                assert identity["unit"] == UNIT and identity["restarts"] == 0
                assert identity["invocation_id"] == expected[f"expected_{role}_invocation_id"]


def gate(plan, configured):
    if not REGISTRATION.is_file():
        return
    source, row = registered()
    gate = plan["gates"]["296"]
    references = [source, row["admission"], row["active_guard"]]
    if UNIT == CORRECTED_UNIT:
        references.extend((row["profile"], row["checkpoint_qualification"], row["prior_terminal"],
                           row["placement"], row["effective_namespace"]))
    elif UNIT == RETRY_UNIT:
        references.extend((row["profile"], row["original_terminal"]))
    for evidence in references:
        if evidence not in gate["evidence"]:
            gate["evidence"].append(evidence)
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    terminal = STATE / "terminal.json"
    if terminal.is_file():
        result = ref(terminal)
        closed = bound(result)
        assert not configured and closed["launch"] == source and closed["guard_drained"]
        assert closed["invocation_id"] == row["invocation_id"]
        if result not in gate["evidence"]:
            gate["evidence"].append(result)
        if UNIT == CORRECTED_UNIT and closed["state"] == "local-cohort-committed":
            gate["state"] = "post-replay-pipeline"
        else:
            gate["state"] = "failed-needs-repair"
        gate["next_action"] = closed["next_action"]
    elif configured:
        gate["state"] = "staged-admissible"
        gate["next_action"] = "Track the guarded replay and verify the AccountsDb root at slot 128,303,325."
