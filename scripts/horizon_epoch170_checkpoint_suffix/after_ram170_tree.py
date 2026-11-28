"""Price the issued 170 disk interval from its native guard and closed sibling tree."""
import os
from pathlib import Path
import stat
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-gap-20261128-v1")
UNIT = "horizon-qualify-170-from-73766969-20261127-v1.service"
ACTOR = dict(path=str(ROOT / "SUCCESSOR_ACTOR.json"), sha256="44a3ac2f1dcd5b2524d3b77f8c76efaa40f55ede6fc2c125ebd99520e61a734d")
RELEASE = dict(path=str(ROOT / "SUCCESSOR_RELEASE.json"), sha256="22b56761682606b010d816b7226b9c005c4e84802b6e00b43624e521f98fa6c8")
PLAN = dict(path=str(ROOT / "ACTUAL_GUARD_PLAN.json"), sha256="749fab6f2e4eff995f21b3280ba8555ad7db3893041f04bc971a5894ff104085")
SCOPE = dict(path=str(ROOT / "AFTER_RAM_WRITER_INTERFACE.json"), sha256="1f8f41eb9e393c0c6d3238cceae5849caf6b806538a1c1f311b747cf9131749c")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def directory_id(path):
    info = path.lstat()
    need(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode),
         "different 170 accounting directory " + str(path))
    return info.st_dev, info.st_ino


def closed_bytes(cmd, tree, run):
    # GNU du deduplicates hard links and reports allocated blocks. Never enter the
    # active run, including intermediate directories RocksDB unlinks while scanning.
    need(run != tree and run.is_relative_to(tree) and not any(c in str(run) for c in "*?[\\"),
         "170 exclusion must be a literal directory inside the guard root")
    identity = directory_id(tree), directory_id(run)
    need(identity[0][0] == identity[1][0], "170 run is on a different filesystem")
    sizes = []
    for _ in range(2):
        output = cmd("/usr/bin/du", "-sx", "-B1", "--exclude=" + str(run), "--", str(tree))
        count, path = output.removesuffix("\n").split("\t")
        need(path == str(tree) and count.isdecimal() and int(count) > 0, "invalid closed 170 tree accounting")
        sizes.append(int(count))
    need((directory_id(tree), directory_id(run)) == identity, "170 accounting root changed")
    return sizes


def native_scans(sample, plan, now):
    walk = sample["root_physical_observation"]
    scans = [walk[key]["physical_bytes"] for key in ("first", "second")]
    need(sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
         and sample["root_physical_observation_error"] is sample["worker_observation_error"] is None
         and 0 <= now - sample["recorded_unix_seconds"] <= 120
         and all(type(n) is int and n > 0 for n in scans)
         and max(scans) == walk["conservative_physical_bytes"] <= plan["maximum_root_physical_bytes"]
         and walk["maximum_physical_bytes"] == sample["maximum_root_physical_bytes"] == plan["maximum_root_physical_bytes"]
         and walk["exceeds_budget"] is False and sample["available_bytes"] >= sample["minimum_free_bytes"] == plan["minimum_free_bytes"],
         "unusable guarded physical scans for the issued 170 interval")
    return scans


def observe(owner, tree, bound, state, cmd):
    # owner() produced tree_guard only after validating native processes, timer,
    # unit limits, release, stop policy and the sample's worker against the live PID.
    need(owner["unit"] == UNIT and owner["phase"] in ("bootstrap", "worker") and owner["interface"] == SCOPE
         and owner["actor"] == ACTOR and owner["release"] == RELEASE and owner["guard_plan"] == PLAN,
         "different 170 tree owner")
    guard = owner["tree_guard"]
    scope, actor, grant, plan = (bound(ref) for ref in (SCOPE, ACTOR, RELEASE, PLAN))
    run = Path(scope["run"])
    sample = bound(guard["sample"])
    iid = actor["producer_invocation_id"]
    need(actor["unit"] == plan["unit"] == scope["expected_producer_unit"] == UNIT
         and actor["interface"] == grant["interface"] == SCOPE and grant["actor"] == ACTOR
         and owner["invocation"] == grant["producer_invocation_id"] == plan["invocation_id"] == iid
         and grant["guard_plan"] == guard["plan"] == PLAN and grant["guard_timer_invocation_id"] == guard["timer_invocation_id"]
         and plan["worker_root"] == str(tree) and plan["receipt_directory"] == scope["guard_receipts"]
         and sample["producer_invocation_id"] == sample["producer"]["invocation_id"] == iid
         and sample["producer"]["pid"] == actor["producer_pid"] == owner["pid"]
         and sample["plan_sha256"] == PLAN["sha256"] and sample["guard_sha256"] == scope["guard_sha"]
         and Path(guard["sample"]["path"]) == Path(scope["guard_receipts"]) / ("sample-" + sample["guard_invocation_id"] + ".json")
         and not os.path.lexists(Path(scope["guard_receipts"]) / "stop-intent.json"),
         "different 170 release, guard or physical observation")
    mounts = state(UNIT, "Id,ProtectHome,ReadWritePaths")
    need(mounts["ProtectHome"] == "read-only" and mounts["ReadWritePaths"] == str(run),
         "170 producer has different writable HOME paths")
    outside = closed_bytes(cmd, tree, run)
    scans = native_scans(sample, plan, time.time())
    need(min(outside) <= min(scans), "closed 170 occupancy exceeds a complete native observation")
    return dict(actor=ACTOR, release=RELEASE, interface=SCOPE, plan=PLAN, guard=guard,
                tree=str(tree), excluded_writable_run=str(run), closed_du_bytes=outside,
                guarded_physical_bytes=scans, bounds=[min(outside), max(scans)],
                minimum_free_bytes=plan["minimum_free_bytes"], maximum_root_physical_bytes=plan["maximum_root_physical_bytes"],
                active_run_occupancy_credit_bytes=0)


def stopped(owner, bound):
    """Retain the floor-stopped owner, its partial output and the full booked envelope."""
    evidence = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-20261127-v1/guard-receipts")
    intent_ref = dict(path=str(evidence / "stop-intent.json"),
                      sha256="824f766892a01f1754cb139ae342340be704ad9141715cbd6071320ab8976ece")
    completion_ref = dict(path=str(evidence / "stop-completion.json"),
                          sha256="b39a216895e15c4568468646d9054d78c6fbda47d04ac5cc352eeba065faabc6")
    need(owner["phase"] == "terminal" and owner["actor"] == ACTOR and owner["release"] == RELEASE
         and owner["unit"] == UNIT and owner["interface"] == SCOPE and owner["guard_plan"] == PLAN,
         "different closed 170 owner")
    actor, grant, plan, intent, end = (bound(ref) for ref in (ACTOR, RELEASE, PLAN, intent_ref, completion_ref))
    event = owner["native_terminal"]
    sample = intent["sample"]
    iid = actor["producer_invocation_id"]
    need(owner["invocation"] == grant["producer_invocation_id"] == plan["invocation_id"] == iid
         and intent["producer_invocation_id"] == sample["producer"]["invocation_id"] == end["producer_invocation_id"] == iid
         and event["INVOCATION_ID"] == end["terminal"]["invocation_id"] == iid
         and event["_BOOT_ID"] == actor["boot_id"].replace("-", "") and event["UNIT"] == plan["unit"] == UNIT
         and event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
         and grant["actor"] == ACTOR and grant["guard_plan"] == PLAN and grant["interface"] == SCOPE
         and intent["plan_sha256"] == end["plan_sha256"] == sample["plan_sha256"] == PLAN["sha256"]
         and end["intent"] == intent_ref["path"] and end["terminal"]["active"] == "inactive" and end["terminal"]["pid"] == 0
         and sample["producer"]["pid"] == actor["producer_pid"] == owner["pid"]
         and intent["reason"] == sample["trip_reason"] == "filesystem-floor" and sample["producer_stop_enabled"] is True
         and sample["available_bytes"] < sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and sample["root_physical_observation_error"] is None and sample["root_physical_observation"]["exceeds_budget"] is False
         and not end["scratch_deleted"] and not end["r2_mutations"], "different 170 floor-stop evidence")
    return dict(reason=intent["reason"], stop_intent=intent_ref, stop_completion=completion_ref, plan=PLAN,
                available_bytes=sample["available_bytes"], minimum_free_bytes=sample["minimum_free_bytes"],
                checkpoint_interval_completed=False, resource_credit_bytes=0)
