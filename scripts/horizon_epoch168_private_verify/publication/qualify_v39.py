"""Exercise the inherited provider in a private namespace, then issue its tested plan."""

import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import derive_v39 as derivation

f = derivation.f
RT = f.ROOT
PUBLICATION = RT / "epoch168-exact-publication-v1/admission-tools-v3/publication"
DELIVERY = RT / "epoch172-current-delivery-20261121-v1"
FIXTURE = DELIVERY / "ORIGINAL_172_V39_FIXTURE.json"
PLAN = DELIVERY / "SHARED_PRICE_V39_PLAN.json"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")


def verify_source(repo):
    revision = f.git(repo, "rev-parse", "HEAD").decode().strip()
    f.git(repo, "merge-base", "--is-ancestor", revision, "refs/remotes/origin/account-updates")
    for name in ("derive_v39.py", "finalizing172.py", Path(__file__).name):
        source = HERE / name
        f.need(source.read_bytes() == f.git(repo, "show", revision + ":" + str(source.relative_to(repo))),
               "source changed: " + name)
    return revision


def plan_members(stage, revision):
    files = derivation.members(stage / "members", revision)
    rows = [dict(name=n, source=str(path), sha256=f.reference(path)["sha256"], mode=mode)
            for n, (path, mode) in files.items()]
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(derivation.NEW), members=rows)


def seal(plan):
    f.need(f.reference(f.SEALER)["sha256"] == f.SEALER_SHA, "different shared sealer")
    descriptor = f.reference(plan)
    output = subprocess.check_output([str(f.SEALER), str(plan), "--plan-sha256", descriptor["sha256"],
                                      "--self-sha256", f.SEALER_SHA], text=True)
    f.need(json.loads(output)["outcome"] == "created", "shared provider already exists")
    return f.reference(derivation.NEW / "deployment-seal-receipt.json")


def isolate(stage):
    f.need(not os.path.samefile("/proc/self/ns/mnt", "/proc/1/ns/mnt"), "fixture needs private mounts")
    family = derivation.NEW.parent
    lower, upper, work = [stage / name for name in ("lower", "upper", "work")]
    for p in (lower, upper, work):
        p.mkdir()
    subprocess.run(["mount", "--bind", str(family), str(lower)], check=True)
    subprocess.run(["mount", "-t", "overlay", "overlay", "-o",
                    f"lowerdir={lower},upperdir={upper},workdir={work}", str(family)], check=True)
    for original in lower.iterdir():
        target = family / original.name
        subprocess.run(["mount", "--bind", str(original), str(target)], check=True)
        f.need(original.samefile(target), "fixture changed original provider custody")


def refuses(action, label):
    try:
        action()
    except (ValueError, FileNotFoundError, KeyError) as exc:
        return dict(case=label, reason=str(exc))
    raise RuntimeError("fixture accepted " + label)


def exercise(result):
    core = runpy.run_path(str(derivation.NEW / "successor_price.py"))
    adapter = runpy.run_path(str(derivation.NEW / "finalizing172.py"))
    fleet = core["bound"](result["fleet"])
    progress = core["read"](core["RT"] / "epoch167-checkpoint-tail-20261127-v1/FIRST_PROTECTED_PROGRESS.json",
                            core["PROGRESS"])[0]
    release = core["bound"](progress["release"])
    base = core["bound"](release["intent"])["quote"]["exact_native_fit"]
    roster = core["bound"](base["prior_fit"])["native"]["released_167"]["tracked_processes"]
    anchors = base["live_guards"]
    unit = adapter["UNIT"]
    anchor = anchors[unit]
    final, ref, live, plan = adapter["validate_files"](core, fleet, roster[unit], anchor)
    detail = result["original_172_accounting"]
    f.need(detail["finalization"] == ref and detail["first_worker"] == final["first_worker"]
           and detail["retained_home_cap"] == 288 << 30 and detail["producer_ram"] == 68 << 30
           and detail["guard_ram"] == 1 << 30 and detail["producer_quota_micros"] == 500000
           and detail["guard_quota_micros"] == 250000
           and detail["resource_credit_bytes"] == detail["resident_lower_bytes"] == detail["reservation_ending_bytes"] == 0,
           "original capacity disappeared")
    refusals = []
    wrong_roster = copy.deepcopy(roster[unit])
    wrong_roster[0][0] += 1
    refusals.append(refuses(lambda:adapter["validate_files"](core, fleet, wrong_roster, anchor), "foreign native parent"))
    missing = dict(core)
    def read_without_final(path, *args):
        if Path(path).name == "ORIGINAL_ARCHIVE_FINALIZATION.json":
            raise FileNotFoundError(path)
        return core["read"](path, *args)
    missing["read"] = read_without_final
    refusals.append(refuses(lambda:adapter["validate_files"](missing, fleet, roster[unit], anchor), "absent completion"))
    # Model the precise V77 list move against the same observed native authority.
    projected = copy.deepcopy(fleet)
    for group in ("actual_executing_replays", "actual_active_bootstraps", "actual_active_private_diagnostics"):
        projected[group] = [r for r in projected[group] if r["epoch"] != 172]
    projected["current_full172_finalization"] = {"phase":"finalizing", "archive_result":ref}
    adapter["fleet_identity"](projected,ref)
    if detail["phase"] == "finalizing":
        manager = core["state"](unit,core["FIELDS"] + ",SubState,NRestarts")
        original_live = copy.deepcopy(live)
        original_live["native"]["open_work_archive"]["inode"] += 1
        refusals.append(refuses(lambda:adapter["pending"](core, final, original_live, plan, manager, anchor), "foreign archive"))
        guard = core["bound"](detail["guard_sample"])
        foreign = dict(guard, plan_sha256="a"*64)
        refusals.append(refuses(lambda:adapter["check_guard"](foreign, core["bound"](anchor), plan,
                                                              guard["recorded_unix_seconds"]), "foreign active guard"))
        occupied = dict(guard, workers=[[1]])
        refusals.append(refuses(lambda:adapter["check_guard"](occupied, core["bound"](anchor), plan,
                                                              guard["recorded_unix_seconds"]), "unexpected worker"))
        # The terminal parser itself qualified the fixture's published file and
        # receipt under its own native deployment. Test the adapter's consumption
        # and its conservation rules with a separate private fixture inode.
    terminal_fixture = terminal_cases(core, adapter, final, live, plan, ref, refusals)
    return dict(refusals=refusals, terminal_fixture=terminal_fixture, current_phase=detail["phase"])


def terminal_cases(core, adapter, final, live, plan, ref, refusals):
    with tempfile.TemporaryDirectory(dir=Path(ref["path"]).parent) as fixture:
        root = Path(fixture)
        archive = root / "epoch-172.jet"
        with archive.open("xb") as fobj:
            fobj.truncate(final["size"])
        info = archive.stat()
        local = dict(path=str(archive), device=info.st_dev, inode=info.st_ino, size=info.st_size, sha256="a"*64)
        tr = dict(path=str(root / "TERMINAL_SUCCESS.json"), sha256="b"*64)
        dr = dict(path=str(root / "TERMINAL_GUARD_DRAINED.json"), sha256="c"*64)
        verified = dict(terminal=tr, admission=final["admission"], first_worker=final["first_worker"], live=final["live"],
                        producer_invocation_id=adapter["IID"], resource_credit_bytes=0, guard_retirement=dr)
        class Guard:
            completion_path = root / "TERMINAL_GUARD_DRAINED.json"
            def inspect(self):
                return verified
        Guard.completion_path.touch()
        adapted = dict(live, output=dict(path=str(root)))
        closed = dict(ActiveState="inactive",MainPID="0",ControlPID="0",Job="")
        synthetic_core = dict(core, bound=lambda bound_ref:dict(local_archive=local))
        # Isolate the unavailable future PID1/cgroup and native resolver only.
        # Verify the installed closure member digests through the real files.
        original_exists = Path.exists
        def fixture_exists(path):
            if path == Path("/sys/fs/cgroup/system.slice",adapter["UNIT"],"cgroup.procs"):
                return False
            return original_exists(path)
        with patch.object(Path,"exists",fixture_exists), patch.object(runpy,"run_path",return_value={"guard":Guard()}):
            def run(arg=closed):
                return adapter["terminal"](synthetic_core, DELIVERY, final, adapted, dict(plan,worker_root=str(root)),
                                           arg, dict(full172_local_commit=tr,full172_guard_retirement=dr))
            accepted, lower = run()
            f.need(accepted == verified and lower == min(info.st_size,info.st_blocks*512), "foreign terminal extents")
            refusals.append(refuses(lambda:run(dict(closed, MainPID="27")), "terminal before parent drain"))
            local["inode"] += 1
            refusals.append(refuses(run, "terminal with foreign published inode"))
        return dict(clean_terminal=True, actual_terminal_claimed=False, allocated_lower_bytes=lower)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("plan","fixture","issue"))
    parser.add_argument("staging_root",type=Path)
    args = parser.parse_args()
    repo = HERE.parents[2]
    revision = verify_source(repo)
    os.umask(0o077)
    if args.phase == "plan":
        stage = Path(tempfile.mkdtemp(prefix="172-v39-members-",dir=args.staging_root))
        desc = plan_members(stage,revision)
        f.need(not derivation.NEW.exists(), "V39 already issued")
        ref = f.save(PLAN,desc)
        print(json.dumps(dict(plan=ref,revision=revision)))
        return
    f.need(not derivation.NEW.exists(), "V39 already issued")
    plan = f.read(f.reference(PLAN))
    f.need(Path(plan["destination"]) == derivation.NEW, "different V39 plan destination")
    for row in plan["members"]:
        f.need(f.reference(row["source"])["sha256"] == row["sha256"], "changed V39 candidate")
    lineage = next(r for r in plan["members"] if r["name"] == "SOURCE.json")
    source = f.read(dict(path=lineage["source"],sha256=lineage["sha256"]))
    f.need(source["revision"] == revision and source["prior_shared_price"]["sha256"] == derivation.PREDECESSOR,
           "plan was built from a different revision or V38")
    if args.phase == "fixture":
        stage = Path(tempfile.mkdtemp(prefix="172-v39-qualification-",dir=args.staging_root))
        isolate(stage)
    else:
        passed = f.read(f.reference(FIXTURE))
        f.need(passed["plan"] == f.reference(PLAN) and passed["revision"] == revision
               and len(passed["checks"]["refusals"]) >= 4 and passed["checks"]["terminal_fixture"]["clean_terminal"]
               and passed["registration_verified"], "no V39 fixture for this plan")
    with LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        ref = seal(PLAN)
    q = json.loads(subprocess.check_output([str(PUBLICATION),"quote",ref["path"],ref["sha256"]]))
    whole = q["whole_roster"]
    alloc = whole["publication168_allocation"]
    f.need(whole["package"] == ref and not whole["resource_credit_bytes"]
           and alloc["charged"] and alloc["memory_max"] == 8 << 30
           and alloc["cpu_micros_per_second"] == 2000000 and alloc["additional_home"] == 16 << 20
           and "fourth_162_accounting" in whole and "adjacent_169_accounting" in whole
           and whole["next_hourly170_accounting"]["producer_memory"] == 56 << 30, "missing V38 peer registration")
    report = dict(seal=ref, plan=f.reference(PLAN), revision=revision, fleet=whole["fleet"], registration_verified=True,
                  fits=q["fits"], home_margin=q["home_margin"], ram_margin=q["ram_margin"],
                  epoch172=whole["original_172_accounting"], publication168=alloc)
    if args.phase == "fixture":
        report["checks"] = exercise(whole)
        evidence = f.save(FIXTURE,report)
    else:
        evidence = f.save(DELIVERY / "V39_ORIGINAL_172_LIVE_QUOTE.json",q)
    print(json.dumps(dict(**{k:report[k] for k in ("seal","plan","revision","fits","home_margin","ram_margin")},
                          receipt=evidence)))


if __name__ == "__main__":
    main()
