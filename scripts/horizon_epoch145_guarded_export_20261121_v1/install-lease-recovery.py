#!/usr/bin/python3 -IB
"""Install the qualified active-lease verifier, its census and its one-shot dispatcher."""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

FAMILY = Path("scripts/horizon_epoch145_guarded_export_20261121_v1")
PROVIDER = "scripts/horizon_incident_replay_fit_20261121_v1/post-stop-fit"
HOMEFLOOR = str(Path(PROVIDER).with_name("homefloor_fit.py"))
FIT = Path("/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1")
SEM = FIT.parent / "epoch145-semantic-continuity-20261121-v1"
DONOR = FIT / "tools-homefloor-145-rejoin-v4"
RETRY4_STATUS = str(Path(PROVIDER).with_name("retry4_status.py"))
RESUMED_IID = "d6d40746a4974ca186acd7f2d5a5cac4"
RESUMED_PACKAGE = FIT.parent / "survivor172-cadence-20261122-v1/tools-cold168-retry4-resume-v1"
RESUMED_SEAL_SHA = "a608208cd09681d366f0994dfc43406b4f8430330e13919a88b3af031efaf160"


def main(commit, iid, flavor="lease-rejoin"):
    if not (os.geteuid() == 0 and sys.flags.isolated and __debug__ and re.fullmatch("[0-9a-f]{40}", commit)
            and re.fullmatch("[0-9a-f]{32}", iid)):
        raise ValueError("expected exact merged COMMIT and successful BUILD_IID")
    if flavor not in ("lease-rejoin", "missed-rejoin", "guard-walk-rejoin", "donor-pressure-rejoin", "status-owner-rejoin", "audit-turnover-rejoin"):
        raise ValueError("unknown recovery build")
    audit_turnover = flavor == "audit-turnover-rejoin"
    status_owner = audit_turnover or flavor == "status-owner-rejoin"
    donor_pressure = status_owner or flavor == "donor-pressure-rejoin"
    guard_walk = donor_pressure or flavor == "guard-walk-rejoin"
    missed = guard_walk or flavor == "missed-rejoin"
    census = FIT / ("tools-homefloor-145-guard-walk-rejoin-v1" if guard_walk else "tools-homefloor-145-missed-rejoin-v1" if missed else "tools-homefloor-145-lease-rejoin-v1")
    dispatch_dir = FIT / ("tools-homefloor-145-handoff-v5" if guard_walk else "tools-homefloor-145-handoff-v4" if missed else "tools-homefloor-145-handoff-v3")
    worker_dir = SEM / ("tools-v5n" if guard_walk else "tools-v5m" if missed else "tools-v5k")
    build_unit = "horizon-145-" + flavor + "-build-v1.service"
    build_price = FIT / ("tools-homefloor-145-v5m-stopped-v1" if guard_walk else "tools-homefloor-145-v5k-stopped-v1" if missed else "tools-homefloor-145-lease-build-v1")
    price_sha = ("b066013b8e25ae95d43b2e0984ad7df55c47e9a68a32c685e54d1f71667151d7" if guard_walk else "ea8e6bd7138cc8eb241c3b39f12e69fc65844505cb60a0d29be966adf56f05c6" if missed
                 else "ba47dd7987accfbb8471b845425dd56a9b9c2e3e2231601e277889e6444a30b5")
    history_name = "v5m_stopped.py" if guard_walk else "v5k_stopped.py" if missed else "v5j_lease_failure.py"
    if donor_pressure:
        census = FIT / "tools-homefloor-145-donor-pressure-rejoin-v1"
        dispatch_dir = FIT / "tools-homefloor-145-handoff-v6"
        worker_dir = SEM / "tools-v5o"
        build_price = FIT / "tools-homefloor-145-v5n-stopped-v1"
        price_sha = "a43da5f9618b8a5af9750e4201c67447a2fe50aa830d1445e6a896ad37e88dbf"
        history_name = "v5n_stopped.py"
    if status_owner:
        census = FIT / "tools-homefloor-145-status-owner-rejoin-v1"
        dispatch_dir = FIT / "tools-homefloor-145-handoff-v7"
        worker_dir = SEM / "tools-v5p"
        build_price = FIT / "tools-homefloor-145-v5o-stopped-v1"
        price_sha = "48e7fbef4140b01a9ea80d2710b21f488f0ed1e8b0ab4f428a9c47a65581ed34"
        history_name = "v5o_stopped.py"
    if audit_turnover:
        census = FIT / "tools-homefloor-145-audit-turnover-rejoin-v1"
        dispatch_dir = FIT / "tools-homefloor-145-handoff-v8"
        worker_dir = SEM / "tools-v5q"
        build_price = FIT / "tools-homefloor-145-v5p-stopped-v1"
        price_sha = "b2febb131aa5c7e1ae42644a241311a8c0d30b82b4ecfb5946b884230d1ea888"
        history_name = "v5p_stopped.py"
    local = Path(__file__).resolve().parent
    def git(*args):
        return subprocess.check_output(["runuser","-u","sol","--","git","-C","/home/sol/workspace/jetstreamer",*args])
    git("merge-base","--is-ancestor",commit,"origin/account-updates")
    for src in (Path(__file__).name, "install-v5j-post.py", history_name):
        if git("show",commit+":"+str(FAMILY/src)) != (local/src).read_bytes():
            raise ValueError("changed installation source " + src)
    util = runpy.run_path(str(local/"install-v5j-post.py"))
    fail = runpy.run_path(str(local/history_name))
    need, ref, item, install, write, record = (util[k] for k in ("require","ref","item","install","write","record"))
    previous, historical = fail["historical"]()
    if status_owner and not audit_turnover:
        phase = historical["failed_phase"]
        historical = dict(historical, original_pid1_exit=historical["terminal"]["native_terminal"],
                          receipts={key: phase[key] for key in ("failure", "recovery", "status_owner_terminal")})
    prior = previous["bound"](historical["predecessor_review"])
    need(not git("diff","--name-only",commit,"origin/account-updates","--",str(FAMILY),PROVIDER,HOMEFLOOR,
                 "scripts/horizon_epoch145_private_prefix_v8","scripts/horizon_epoch166_delivery_20261121_v1",
                 *([RETRY4_STATUS] if status_owner else [])),
         "superseding build inputs on account-updates")
    q = SEM / ("incident-build-" + iid)
    need(q.resolve(strict=True) == q and q.lstat().st_uid == 0 and q.lstat().st_mode & 0o077 == 0, "untrusted build directory")
    rows = [json.loads(row) for row in previous["out"](["/usr/bin/journalctl","--no-pager","-ojson",
            "_PID=1","UNIT="+build_unit,"INVOCATION_ID="+iid]).splitlines()]
    start, = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    end, = [r for r in rows if r.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448"]
    need(" " + flavor + " " in start["MESSAGE"] and start["MESSAGE"].endswith(" " + build_price.name + ".")
         and int(start["__MONOTONIC_TIMESTAMP"]) < int(end["__MONOTONIC_TIMESTAMP"])
         and all(r.get("_BOOT_ID") == historical["original_pid1_exit"]["_BOOT_ID"] for r in rows)
         and not (Path("/sys/fs/cgroup/horizonaudit.slice")/build_unit).exists(), "build not successfully drained")
    product = q/"products"
    sources = {}
    for line in (q/"sources").read_text().splitlines():
        sha, rel = line.split("  ./",1)
        need(rel not in sources and util["digest"](git("show",commit+":"+rel)) == sha
             == ref(product/"source"/rel)["sha256"], "unmerged or changed build input " + rel)
        sources[rel] = sha
    for name in ("lease_startup.rs","materialized.rs","post.rs","incident-phase.py","build-incident.sh","run-incident.sh"):
        need(str(FAMILY/name) in sources, "missing worker source " + name)
    price = json.loads((q/"before.json").read_bytes())
    need(price["fits"] and price["epoch"] == 145 and price["phase145"] == historical["failed_phase"] and
         price["candidate"] is None and price["resource_credit_bytes"] == 0 and
         price["complete_cpu_quota_micros"] == 64000000 and price["complete_memory_plus_reserve_bytes"] == 810658050048 and
         price["available_HOME_bytes"]-price["complete_required_HOME_bytes"] >= 92274688+16777216 and
         price["available_memory_bytes"]-price["required_available_memory_bytes"] >= 805306368, "foreign or underfunded build")
    need(ref(build_price/"deployment-seal-receipt.json")["sha256"] == price_sha
         and ref(DONOR/"deployment-seal-receipt.json")["sha256"] == util["DONOR_SHA"]
         and ref(util["SEALER"])["sha256"] == util["SEAL_SHA"], "different donor or capacity provider")
    if status_owner:
        resumed = price["status_registration"]
        need(resumed["invocation_id"] == RESUMED_IID and
             resumed["consumer_seal"] == ref(RESUMED_PACKAGE/"deployment-seal-receipt.json") ==
             dict(path=str(RESUMED_PACKAGE/"deployment-seal-receipt.json"), sha256=RESUMED_SEAL_SHA) and
             util["digest"](git("show",commit+":"+RETRY4_STATUS)) ==
             ref(build_price/"retry4_status.py")["sha256"] and
             ref(build_price/history_name)["sha256"] == ref(local/history_name)["sha256"],
             "different recovered status writer, registry or stopped proof source")
    prior_seal = previous["bound"](prior["seal"])
    original_build_sha, = [r["sha256"] for r in prior_seal["members"] if r["name"] == "build-proof.json"]
    original_build = previous["bound"]({"path": str(Path(prior["reader"]["path"]).with_name("build-proof.json")),
                                        "sha256": original_build_sha})
    tests = (q/"build.log").read_text()
    existing = original_build["native_fixture_names"]
    readiness = [line.split(" ... ")[0].removeprefix("test ") for line in tests.splitlines()
                 if "lease_startup::tests::" in line and line.endswith(" ... ok")]
    phase_count = 27 if status_owner else 20 if guard_walk else 17 if missed else 14
    phase_tests = any(int(n) >= phase_count for n in re.findall(r"^Ran (\d+) tests in ", tests, re.M))
    need(len(set(readiness)) >= 2 and "test result: FAILED" not in tests and phase_tests and
         all(name+" ... ok" in tests for name in existing), "missing original or lease-readiness build tests")
    tool = product/"export145"
    image = ref(tool)["sha256"]
    artifacts = {Path(path).name:sha for sha,path in (line.split("  ",1) for line in (q/"artifacts").read_text().splitlines())}
    need(artifacts["export145"] == image != prior["reader"]["sha256"] and str(worker_dir/"export145").encode() in tool.read_bytes()
         and str(census/"post-stop-fit").encode() in tool.read_bytes(), "wrong successor binary")
    source = product/"source"/FAMILY
    proof = dict(schema="horizon-epoch145-child-lease-startup-build-v1", source_commit=commit,source_hashes=sources,
                 build_iid=iid,native_success_cursor=end["__CURSOR"],verifier_sha256=image,
                 startup_failure=historical["receipts"]["failure"], previous_recovery=historical["receipts"]["recovery"],
                 predecessor_dispatch=historical["predecessor_dispatch"], capacity=ref(q/"before.json"),capacity_provider=ref(build_price/"deployment-seal-receipt.json"),
                 native_fixture_names=existing+readiness, child_lease_readiness_protocol="self-stop-after-three-leases",
                 tests=ref(q/"build.log"),compiler_outputs=ref(q/"artifacts"),source_snapshot=ref(q/"sources"),
                 memory_peak=int((q/"memory.peak").read_text()),physical_scratch=int((q/"scratch-bytes").read_text().split()[0]),
                 resource_credit_bytes=0, replay_launch_authorized=False,r2_mutations=False)
    if missed:
        for name in ("missed_clock.rs", "missed_clock.py", "test_missed_clock.py"):
            need(str(FAMILY/name) in sources, "missing missed-census build source " + name)
        proof.update(schema="horizon-epoch145-missed-census-recovery-build-v1",
                     startup_failure=original_build["startup_failure"],
                     missed_clock_failure=original_build["missed_clock_failure"] if donor_pressure else historical["receipts"]["failure"],
                     missed_clock_rejection=original_build["missed_clock_rejection"] if donor_pressure else historical["receipts"]["cadence"],
                     leased_sample=original_build["leased_sample"] if status_owner else historical["receipts"]["worker_sample"])
    if guard_walk:
        need(str(FAMILY/"guard_walk.rs") in sources and "guard_walk::tests::" in tests, "missing registered-hold tests")
        proof.update(schema="horizon-epoch145-registered-guard-walk-build-v1",
                     missed_clock_failure=original_build["missed_clock_failure"],
                     missed_clock_rejection=original_build["missed_clock_rejection"],
                     previous_missed_recovery=original_build["previous_missed_recovery" if donor_pressure else "previous_recovery"],
                     guard_walk_failure=original_build["guard_walk_failure"] if donor_pressure else historical["receipts"]["failure"],
                     rejected_guard=original_build["rejected_guard"] if donor_pressure else historical["receipts"]["rejected_guard"],
                     registered_guard_clock=original_build["registered_guard_clock"] if donor_pressure else historical["receipts"]["registered"])
    if donor_pressure:
        need(all(str(FAMILY / name) in sources for name in ("v5n_stopped.py", "test_v5n_stopped.py"))
             and "capacity_pressure_requires_the_exact_sealed_provider_and_donor_frames ... ok" in tests,
             "missing V5n failure or pressure fixtures")
        proof.update(schema="horizon-epoch145-donor-pressure-recovery-build-v1",
                     previous_recovery=original_build["previous_recovery"],
                     donor_pressure_failure=original_build["donor_pressure_failure"] if status_owner else historical["receipts"]["failure"],
                     donor_pressure_recovery=original_build["donor_pressure_recovery"] if status_owner else historical["receipts"]["recovery"])
    if audit_turnover:
        need(all(str(FAMILY / name) in sources for name in ("v5p_stopped.py", "test_v5p_stopped.py"))
             and "test_stopped_generation_retains_candidate_without_a_checkpoint" in tests,
             "missing V5p stop or pre-worker tests")
        proof.update(schema="horizon-epoch145-audit-turnover-recovery-build-v1",
                     public_audit_terminal=historical["receipts"]["public_audit_terminal"],
                     status_owner_failure=original_build["status_owner_failure"],
                     status_owner_recovery=original_build["status_owner_recovery"],
                     status_owner_terminal=original_build["status_owner_terminal"], resumed_status=resumed)
    elif status_owner:
        need(all(str(FAMILY / name) in sources for name in ("v5o_stopped.py", "test_v5o_stopped.py"))
             and all(any(line.startswith(name + " (") and line.endswith(" ... ok")
                         for line in tests.splitlines()) for name in (
                 "test_original_inode_and_failure", "test_binds_v5o_stop_and_preworker_admission",
                 "test_rejects_preworker_price_from_the_predecessor_status_writer")),
             "missing V5o stop or pre-worker tests")
        proof.update(schema="horizon-epoch145-status-owner-recovery-build-v1",
                     status_owner_failure=historical["receipts"]["failure"],
                     status_owner_recovery=historical["receipts"]["recovery"],
                     status_owner_terminal=historical["receipts"]["status_owner_terminal"],
                     resumed_status=resumed)
    need(proof["memory_peak"] <= 805306368 and proof["physical_scratch"] <= 73400320, "build exceeded its envelope")
    script = (source/"run-incident.sh").read_bytes()
    need(script.count(b"PINNED_INCIDENT_SHA") == 1, "unbound launcher")
    launcher = write(q/"lease-ready-launcher",script.replace(b"PINNED_INCIDENT_SHA",image.encode()))
    worker = install(worker_dir, [item("export145",tool,0o555),item("incident-phase.py",source/"incident-phase.py",0o444),
        item("run-recovery",launcher,0o555),item("build-proof.json",record(q/"lease-build-proof.json",proof),0o444)], q/"lease-semantic-plan.json")
    donor_root = build_price if status_owner else DONOR
    donor = json.loads((donor_root/"deployment-seal-receipt.json").read_bytes())
    members = {}
    for row in donor["members"]:
        name = row["name"]
        need(name == Path(name).name and name not in members, "duplicate or indirect donor")
        members[name] = item(name,donor_root/name,int(row["mode"],8))
        need(members[name]["sha256"] == row["sha256"], "changed donor member " + name)
    provider = write(q/"lease-provider",git("show",commit+":"+PROVIDER))
    members["post-stop-fit"] = item("post-stop-fit",provider,0o555)
    homefloor = write(q/"lease-homefloor.py",git("show",commit+":"+HOMEFLOOR))
    members["homefloor_fit.py"] = item("homefloor_fit.py",homefloor,0o444)
    profile = dict(build_sha256=ref(worker_dir/"build-proof.json")["sha256"],image_sha256=image,
                   adapter_sha256=ref(worker_dir/"incident-phase.py")["sha256"],seal_sha256=worker["sha256"])
    members["profile145-lease-semantic.json"] = item("profile145-lease-semantic.json",record(q/"lease-runtime-profile.json",profile),0o444)
    if missed:
        name = "build_159_price.py"
        path = write(q/name,git("show",commit+":"+str(FAMILY/name)))
        members[name] = item(name,path,0o444)
    if guard_walk:
        name = "v5n_feature_cover.py"
        path = write(q/name,git("show",commit+":"+str(FAMILY/name)))
        members[name] = item(name,path,0o444)
    runtime = install(census,list(members.values()),q/"lease-runtime-plan.json")
    cmd = list(prior["sealed_service_argv"])
    need(cmd[-5] == prior["reader"]["path"] and cmd[-1] == prior["reader"]["sha256"], "original verifier argv changed")
    cmd[-5], cmd[-1] = str(worker_dir/"export145"), image
    schema = "horizon-145-missed-census-dispatch-review-v1" if missed else "horizon-145-lease-startup-dispatch-review-v1"
    review = dict(prior, schema=schema,old_manager=historical["old_manager"],
                  original_pid1_exit=historical["original_pid1_exit"],original_fragment=historical["original_fragment"],
                  failed_phase=historical["failed_phase"],predecessor_receipts=historical["receipts"],original_review=historical["predecessor_review"],
                  reader=ref(worker_dir/"export145"),stock_launcher=ref(worker_dir/"run-recovery"),seal=worker,provider=runtime,sealed_service_argv=cmd)
    if status_owner:
        review["resumed_status"] = resumed
    staged = record(q/"lease-dispatch-review.json",review)
    digest = ref(staged)["sha256"]
    dispatcher = git("show",commit+":"+str(FAMILY/"recovery_dispatch.py"))
    prefix = b"AUDIT_TURNOVER_" if audit_turnover else b"STATUS_OWNER_" if status_owner else b"DONOR_PRESSURE_" if donor_pressure else b"GUARD_WALK_" if guard_walk else b"MISSED_CLOCK_" if missed else b"LEASE_START_"
    for needle,replacement in [(prefix+b"IMAGE_SHA",image),(prefix+b"REVIEW_SHA",digest)]:
        need(dispatcher.count(needle) == 1, "different dispatcher template")
        dispatcher = dispatcher.replace(needle,replacement.encode())
    members["run-recovery"] = item("run-recovery",write(q/"lease-dispatch",dispatcher),0o555)
    members["admission-review.json"] = item("admission-review.json",staged,0o444)
    members[history_name] = item(history_name,write(q/"lease-failure-evidence.py",git("show",commit+":"+str(FAMILY/history_name))),0o444)
    if missed:
        members["missed_clock.py"] = item("missed_clock.py",source/"missed_clock.py",0o444)
    dispatch = install(dispatch_dir,list(members.values()),q/"lease-dispatch-plan.json")
    new = runpy.run_path(str(dispatch_dir/"run-recovery"))
    need(new["PACKAGE"] == dispatch_dir and new["LEASE_RETRY"] and new["MISSED_RETRY"] == missed and new["GUARD_RETRY"] == guard_walk and new["READER"] == worker_dir/"export145"
         and new["AUDIT_TURNOVER_RETRY"] == audit_turnover and new["STATUS_OWNER_RETRY"] == status_owner
         and new["REVIEW_SHA"] == digest and new["IMAGE_SHA"] == image and new["OLD"] == fail["IID"]
         and new["original_command"](review,price["fleet"])[-5:] == [str(worker_dir/"export145"),"recover-full-output",
                  price["fleet"]["path"],price["fleet"]["sha256"],image], "different deployed repair")
    if guard_walk:
        generation = "v5q" if audit_turnover else "v5p" if status_owner else "v5o" if donor_pressure else "v5n"
        record(SEM/f"{generation.upper()}_RUNTIME_BINDINGS.json",dict(schema=f"horizon-145-qualified-{generation}-runtime-v1", source_commit=commit,
                build=ref(worker_dir/"build-proof.json"), build_iid=iid, prior_dispatch=historical["predecessor_dispatch"],
                prior_stopped=ref(build_price/"deployment-seal-receipt.json"), worker=worker, reader=review["reader"],
                provider=runtime, dispatcher=dispatch, review=ref(dispatch_dir/"admission-review.json")))
    print(json.dumps(dict(worker=worker,provider=runtime,dispatcher=dispatch,review_sha256=digest,commit=commit,
                          verified_or_published=False,production_worker_started=False),sort_keys=True))


if __name__ == "__main__":
    main(*sys.argv[1:])
