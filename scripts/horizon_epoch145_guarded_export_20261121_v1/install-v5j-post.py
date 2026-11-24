#!/usr/bin/python3 -IB
"""Seal the successful native post build and its five-lane pricing provider."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import runpy
import sys

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = R / "epoch145-semantic-continuity-20261121-v1"
FIT = R / "incident-replay-fit-20261121-v1"
V5R_136 = sys.argv[1:2] == ["--encoded-prefix-136"]
V5Q_136 = sys.argv[1:2] == ["--audit-turnover-136"]
V5O_136 = sys.argv[1:2] == ["--donor-pressure-136"]
V5N_136 = sys.argv[1:2] == ["--guard-walk-136"]
POST_136 = V5R_136 or V5Q_136 or V5O_136 or V5N_136
GUARD_POST = POST_136 or sys.argv[1:2] == ["--guard-walk"]
MISSED_POST = GUARD_POST or sys.argv[1:2] == ["--missed-clock"]
LEASE_POST = MISSED_POST or sys.argv[1:2] == ["--lease-ready"]
RETRY = LEASE_POST or sys.argv[1:2] == ["--retry1"]
if V5R_136:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5r-136-v1", "tools-v13l", None, None)
elif V5Q_136:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5q-136-v1", "tools-v13k", "tools-homefloor-145-handoff-v8", None)
elif V5O_136:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5o-136-v1", "tools-v13j", "tools-homefloor-145-handoff-v6", None)
elif V5N_136:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5n-136-v1", "tools-v13i", "tools-homefloor-145-handoff-v5", None)
elif GUARD_POST:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5n-v1", "tools-v13h", "tools-homefloor-145-handoff-v5", None)
elif MISSED_POST:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5m-v1", "tools-v13g", "tools-homefloor-145-handoff-v4",
                                               "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea")
elif LEASE_POST:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5k-v1", "tools-v13f", "tools-homefloor-145-handoff-v3",
                                               "f69f462cecb76fc586799d36f358e61b1880f99d0c024b0c76dd27d3a2f9637e")
elif RETRY:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5j-v2", "tools-v13e", "tools-homefloor-145-handoff-v2",
                                               "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee")
else:
    target, package, dispatch, dispatch_sha = ("tools-homefloor-145-post-v5j-v1", "tools-v13d", "tools-homefloor-145-handoff-v1",
                                               "19c0fe27899e6742d095b075377b2adb9aebdb47b2ad2655688b214cd8b632de")
TARGET, POST = FIT / target, BASE / package
ENCODED_STAGE = R / "epoch145-encoded-prefix-stage-20261124-v1"
DISPATCH = ENCODED_STAGE / "semantic-handoff-v1" if V5R_136 else FIT / dispatch
DISPATCH_SHA = dispatch_sha
DONOR = FIT / ("tools-homefloor-145-encoded-prefix-rejoin-v1" if V5R_136 else "tools-homefloor-145-audit-turnover-rejoin-v1" if V5Q_136 else "tools-homefloor-145-donor-pressure-rejoin-v1" if V5O_136 else "tools-homefloor-145-guard-walk-rejoin-v1" if GUARD_POST else "tools-homefloor-145-missed-rejoin-v1" if MISSED_POST else "tools-homefloor-145-rejoin-v4")
FAMILY = Path("scripts/horizon_epoch145_guarded_export_20261121_v1")
SOURCE_PROVIDER = "scripts/horizon_incident_replay_fit_20261121_v1/post-stop-fit"
REPO = Path("/home/sol/workspace/jetstreamer")
SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEAL_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
DONOR_SHA = "b2e28f51da8e428c106a23b3e5d73a6d92b1aca84043e82d1e662387d2c18b96" if MISSED_POST else "ed0e272c1cf6df09bb19ff6049154cad9e55f21e96089f66e6f9e3d0f89da9cb"
UNIT = "horizon-145-v5r-136-post-build-v1.service" if V5R_136 else "horizon-145-v5q-136-post-build-v1.service" if V5Q_136 else "horizon-145-v5o-136-post-build-v1.service" if V5O_136 else "horizon-145-v5n-136-post-build-v1.service" if V5N_136 else "horizon-145-v5n-post-build-v1.service" if GUARD_POST else "horizon-145-v5m-post-build-v1.service" if MISSED_POST else "horizon-145-v5k-post-build-v1.service" if LEASE_POST else "horizon-145-v5j-post-build-v2.service" if RETRY else "horizon-145-v5j-post-build-v1.service"
SEAL = "deployment-seal-receipt.json"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ref(p):
    return {"path": str(p), "sha256": digest(p.read_bytes())}


def git(*args):
    return subprocess.check_output(["runuser", "-u", "sol", "--", "git", "-C", REPO, *args])


def write(path, data):
    if not path.exists():
        tmp = path.with_name("." + path.name + "-" + str(os.getpid()))
        with tmp.open("xb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), 0o400)
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
        finally:
            tmp.unlink()
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    m = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode) and m.st_mode & 0o7777 == 0o400
            and m.st_uid == m.st_gid == 0 and m.st_nlink == 1 and path.read_bytes() == data, f"different staged {path}")
    return path


def record(path, data):
    return write(path, (json.dumps(data, sort_keys=True, indent=2) + "\n").encode())


def item(name, path, mode):
    return dict(name=name, source=str(path), sha256=ref(path)["sha256"], mode=mode)


def install(dest, members, planpath):
    members = sorted(members, key=lambda r: r["name"])
    require(len(members) == len({r["name"] for r in members}), "duplicate deployment member")
    plan = record(planpath, dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(dest), members=members))
    if not dest.exists():
        subprocess.run([SEALER, plan, "--plan-sha256", ref(plan)["sha256"], "--self-sha256", SEAL_SHA], check=True)
    seal = json.loads((dest / SEAL).read_bytes())
    require(seal["destination"] == str(dest) and seal["plan_sha256"] == ref(plan)["sha256"] and
            seal["sealer_sha256"] == SEAL_SHA and seal["remote_mutations"] is False and
            sorted(x["name"] for x in seal["members"]) == [x["name"] for x in members], "different sealed package")
    for m in members:
        p = dest / m["name"]
        meta = p.lstat()
        require(p.resolve(strict=True) == p and stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
                and meta.st_uid == meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == m["mode"]
                and ref(p)["sha256"] == m["sha256"], f"different installed {p}")
    return ref(dest / SEAL)


def encoded_bindings(price):
    handoff = BASE / "v5r-name-handoff"
    custody_path = handoff / "ACTUAL_ADVANCING_AND_136_CUSTODY.json"
    custody_ref = ref(custody_path)
    custody = json.loads(custody_path.read_bytes())
    staged = json.loads((ENCODED_STAGE / "STAGED.json").read_bytes())
    dispatcher = ref(DISPATCH / SEAL)
    provider = ref(DONOR / SEAL)
    reader = ref(BASE / "tools-v5r/export145")
    phase = price["phase145"]
    require(custody_ref["sha256"] == "1343de96384e52ff061262a2d80c217d187a1fc8b0ce0e07e32940ee88e89b3b"
            and dispatcher["sha256"] == "83a715e057cda6e3d1d93b8f4e71d8033f1249efab1f371cd430832cda7a7ec9"
            and provider == staged["provider"] and reader["sha256"] == staged["native_profile"]["image"]
            and custody["submission"] == ref(handoff / "submission-result.json")
            and phase["invocation_id"] == custody["manager"]["InvocationID"]
            and phase["stage"] == "leased-worker" and phase["window"]["recovery"] == custody["verifier_start"]
            and phase["window"]["continuity_seal"] == staged["worker"],
            "unbound encoded-prefix price or worker")
    return dict(reader=reader, dispatcher=dispatcher, provider=provider, submission=custody["submission"]), custody_ref


def main(commit, iid, writer_sha=None):
    require(os.geteuid() == 0 and sys.flags.isolated and __debug__, "root isolated interpreter required")
    require(re.fullmatch("[0-9a-f]{40}", commit) and re.fullmatch("[0-9a-f]{32}", iid), "use exact commit and invocation")
    require((V5R_136 and writer_sha is None)
            or (re.fullmatch("[0-9a-f]{64}", writer_sha or "") is not None) == POST_136,
            "the 136 route requires the exact new writer deployment seal")
    q = BASE / ("incident-build-" + iid)
    require(q.resolve(strict=True) == q and q.stat().st_uid == 0 and q.stat().st_mode & 0o077 == 0,
            "untrusted build root")
    git("merge-base", "--is-ancestor", commit, "origin/account-updates")
    require(git("show", commit + ":" + str(FAMILY / "install-v5j-post.py")) == Path(__file__).read_bytes(),
            "installer source differs")
    required = [str(FAMILY), SOURCE_PROVIDER, "scripts/horizon_epoch145_private_prefix_v8",
                "scripts/horizon_epoch166_delivery_20261121_v1"]
    require(not git("diff", "--name-only", commit, "origin/account-updates", "--", *required), "operator sources changed")
    journal = subprocess.check_output(["journalctl", "--no-pager", "-o", "json", "_PID=1", "UNIT=" + UNIT,
                                       "INVOCATION_ID=" + iid], text=True)
    rows = [json.loads(x) for x in journal.splitlines()]
    success, = [r for r in rows if r.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448"]
    start, = [r for r in rows if r.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    require((" v5r-136-post " if V5R_136 else " v5q-136-post " if V5Q_136 else " v5o-136-post " if V5O_136 else " v5n-136-post " if V5N_136 else " v5n-post " if GUARD_POST else " v5m-post " if MISSED_POST else " v5k-post " if LEASE_POST else " v5j-retry1-post " if RETRY else " v5j-post ") in start["MESSAGE"] and int(start["__MONOTONIC_TIMESTAMP"]) < int(success["__MONOTONIC_TIMESTAMP"])
            and not (Path("/sys/fs/cgroup/horizonaudit.slice") / UNIT).exists(), "build has not completed")
    outputs = q / "products"
    inputs = {}
    for line in (q / "sources").read_text().splitlines():
        expected, rel = line.split("  ./", 1)
        require(rel not in inputs and digest(git("show", commit + ":" + rel)) == ref(outputs/"source"/rel)["sha256"]
                == expected, f"different build source {rel}")
        inputs[rel] = expected
    required_tests = ["freezer_covers_uploader_and_grandchild", "current_full_and_plugin_use_the_same_qualified_plan_as_delivery",
                      "authenticates_the_actual_fleet_and_disallows_missing_members",
                      "complete_and_live_prices_keep_the_bounded_qualification", "complete_plugin_requires_all_slots_bound_source_and_stream_digest"]
    log = (q / "build.log").read_text()
    require(all(n + " ... ok" in log for n in required_tests) and "test result: FAILED" not in log
            and log.count("test result: ok.") == 4 and log.count("\nOK\n") == 2
            and re.search(r"Ran 17 tests in ", log)
            and re.search(r"Ran 3 tests in " if V5R_136 else r"Ran 2 tests in ", log), "native/adapter test incomplete")
    image = outputs / "export145"
    image_sha = ref(image)["sha256"]
    artifacts = dict((Path(path).name, sha) for sha, path in (row.split("  ", 1) for row in (q / "artifacts").read_text().splitlines()))
    require(artifacts["export145"] == image_sha and str(POST / "export145").encode() in image.read_bytes()
            and str(TARGET / "post-stop-fit").encode() in image.read_bytes(), "unregistered native image")
    src = outputs / "source" / FAMILY
    adapter = src / "post_inputs.py"
    adapter_args = ["--encoded-prefix" if V5R_136 else "--audit-turnover" if V5Q_136 else "--donor-pressure" if V5O_136 else "--guard-walk" if GUARD_POST else "--missed-clock" if MISSED_POST else "--lease-ready" if LEASE_POST else "--retry1"] if RETRY else []
    model = json.loads(subprocess.check_output([sys.executable, "-IB", adapter, *adapter_args, "inspect"]))
    need_refs = model["artifacts"]
    price = json.loads((q / "before.json").read_bytes())
    require(price["fits"] and price["resource_credit_bytes"] == 0 and price["candidate"] is None and price["epoch"] == 145
            and price["available_memory_bytes"] - price["required_available_memory_bytes"] >= 805306368
            and price["available_HOME_bytes"] - price["complete_required_HOME_bytes"] >= 92274688 + 16777216
            and (q / "memory.peak").read_text().strip().isdigit(), "unfunded build")
    if V5R_136:
        bindings, binding_ref = encoded_bindings(price)
    elif GUARD_POST:
        installer_args = sys.argv
        try:
            sys.argv = [str(adapter), *adapter_args]
            module = runpy.run_path(str(adapter))
            bindings, binding_ref = module["guard_bindings"]()
        finally:
            sys.argv = installer_args
    require(ref(SEALER)["sha256"] == SEAL_SHA and ref(DONOR / SEAL)["sha256"] == (bindings["provider"]["sha256"] if GUARD_POST else DONOR_SHA)
            and ref(DISPATCH / SEAL)["sha256"] == (bindings["dispatcher"]["sha256"] if GUARD_POST else DISPATCH_SHA),
            "changed donor or sealer")
    proof = dict(schema="horizon-145-v5j-post-build-v1", source_commit=commit, source_hashes=inputs,
                 verifier_sha256=image_sha, semantic_image=ref(BASE / ("tools-v5r/export145" if V5R_136 else "tools-v5q/export145" if V5Q_136 else "tools-v5o/export145" if V5O_136 else "tools-v5n/export145" if GUARD_POST else "tools-v5m/export145" if MISSED_POST else "tools-v5k/export145" if LEASE_POST else "tools-v5j/export145")), artifact_hashes=artifacts,
                 build_iid=iid, native_success_cursor=success["__CURSOR"], tests=ref(q/"build.log"),
                 native_fixture_names=required_tests, memory_peak=int((q/"memory.peak").read_text()),
                 physical_scratch=int((q/"scratch-bytes").read_text().split()[0]), build_fleet=price["fleet"],
                 build_price=ref(q/"before.json"), ordinary_pair=need_refs["pair"], current_reader=need_refs["qualification"],
                 qualified_reader_scopes=need_refs["ordinary_reader_scopes"], reader_commit=need_refs["reader_commit"],
                 semantic_dispatch=ref(DISPATCH/SEAL), donor=ref(DONOR/SEAL), source_snapshot=ref(q/"sources"),
                 compiler_outputs=ref(q/"artifacts"), archive_body_verified_by_this_build=False, resource_credit_bytes=0)
    require(proof["semantic_image"]["sha256"] == (bindings["reader"]["sha256"] if GUARD_POST else "9068d5ac9ccd4d35481cbf2882faf67a97b0926133663a2e4885917e714bdc21" if MISSED_POST else "02c9a1ad332fbea43e4b552561fc01e503f1dedcec6347e541db4cf9de56f571" if LEASE_POST else "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4"),
            "different semantic image")
    if V5R_136:
        proof.update(encoded_prefix_custody=binding_ref, semantic_submission=bindings["submission"])
    elif V5Q_136 or V5O_136:
        runtime = "v5q" if V5Q_136 else "v5o"
        proof["audit_turnover_binding" if V5Q_136 else "donor_pressure_binding"] = binding_ref
        proof["semantic_submission"] = ref(BASE / f"{runtime}-name-handoff/submission-result.json")
        prefix = runtime.upper()
        require(proof["semantic_submission"]["sha256"] == module[prefix + "_RESULT"] and
                price["phase145"]["invocation_id"] == module[prefix + "_IID"] and
                price["phase145"]["stage"] == "leased-worker" and
                price["phase145"]["window"]["recovery"]["sha256"] == module[prefix + "_START"],
                "unbound priced semantic invocation")
        if V5Q_136:
            semantic_build = json.loads(Path(bindings["build"]["path"]).read_bytes())
            require(price["phase145"]["window"]["public_audit_terminal"] == semantic_build["public_audit_terminal"]
                    and price["status_registration"] == semantic_build["resumed_status"],
                    "unbound V5q audit turnover or cadence compiler price")
    elif GUARD_POST:
        proof["guard_walk_binding"] = binding_ref
    if MISSED_POST:
        combined = json.loads((q / "donor-combined-price.json").read_bytes())
        require(combined["fleet"] == price["fleet"] and combined["diagnostic"] == price["epoch159_donor_cover"]["diagnostic"]
                and combined["native_recorded_unix_seconds"] == price["recorded_unix_seconds"]
                and combined["build_HOME_bytes"] == (104 << 20) and combined["build_RAM_bytes"] == (768 << 20)
                and combined["remaining_home_bytes"] >= 0 and combined["credited_retirement_bytes"] == 0,
                "unfunded post build after donor handback")
        proof["build_donor_cover"] = ref(q / "donor-combined-price.json")
    launcher = (src/"run-incident-post.sh").read_bytes()
    require(launcher.count(b"PINNED_POST_SHA") == 1, "malformed launcher")
    launch = write(q/"run-post", launcher.replace(b"PINNED_POST_SHA", image_sha.encode()))
    post = install(POST, [item("build-proof.json", record(q/"post-build-proof.json", proof), 0o444),
                   item("export145", image, 0o555), item("run-post", launch, 0o555),
                   item("incident-post-phase.py", src/"incident-post-phase.py", 0o444),
                   item("post-inputs", src/"post_inputs.py", 0o555)], q/"post-seal-plan.json")
    if V5R_136 and writer_sha is None:
        return dict(post=post, build_proof=ref(POST/"build-proof.json"), provider_pending=True,
                    production_worker_started=False, r2_mutations=False)
    donor = json.loads((DONOR/SEAL).read_bytes())
    members = {}
    for row in donor["members"]:
        name = row["name"]
        require(name == Path(name).name and name not in members, "foreign donor member")
        member = item(name, DONOR / name, int(row["mode"], 8))
        require(member["sha256"] == row["sha256"], "different donor source")
        members[name] = member
    provider = write(q / "post-stop-fit", git("show", commit + ":" + SOURCE_PROVIDER))
    members["post-stop-fit"] = item("post-stop-fit", provider, 0o555)
    profile_name = "profile145-v5j-post.json"
    require(profile_name not in members, "unexpected prior post registration")
    profile = {"image_sha256": image_sha, "build_sha256": ref(POST/"build-proof.json")["sha256"],
               "adapter_sha256": ref(POST/"incident-post-phase.py")["sha256"], "seal_sha256": post["sha256"]}
    members[profile_name] = item(profile_name, record(q/profile_name, profile), 0o444)
    if POST_136:
        writer = R / ("epoch136-joint-writer-20261124-v11/controller" if V5R_136 else "epoch136-joint-writer-20261124-v10/controller" if V5Q_136 else "epoch136-joint-writer-20261123-v9/controller" if V5O_136 else "epoch136-joint-writer-20261123-v8/controller")
        writer_seal = writer / SEAL
        require(ref(writer_seal)["sha256"] == writer_sha, "different registered 136 controller seal")
        deployment = json.loads(writer_seal.read_bytes())
        require(deployment["destination"] == str(writer) and deployment["sealer_sha256"] == SEAL_SHA
                and deployment["remote_mutations"] is False, "foreign 136 deployment")
        member, = [m for m in deployment["members"] if m["name"] == "admit136" and m["mode"] == "0555"]
        require(ref(writer / "admit136")["sha256"] == member["sha256"], "136 controller image changed")
        name = "profile136-fixture-writer.json"
        members[name] = item(name, record(q / name, dict(seal_sha256=writer_sha, image_sha256=member["sha256"])), 0o444)
        provider_sources = {"retry4_status.py": "scripts/horizon_incident_replay_fit_20261121_v1/retry4_status.py",
                            "build_159_price.py": str(FAMILY / "build_159_price.py")}
        for name, source in provider_sources.items():
            staged = write(q / ("provider-" + name), git("show", commit + ":" + source))
            members[name] = item(name, staged, 0o444)
    fit = install(TARGET, list(members.values()), q/"post-provider-plan.json")
    return dict(post=post, provider=fit, compiler_outputs=ref(q/"artifacts"), build_proof=ref(POST/"build-proof.json"),
                current_reader=need_refs["qualification"], original_pair=need_refs["pair"], public_origin=model["public_origin"],
                resource_credit_bytes=0, production_worker_started=False, r2_mutations=False)


if __name__ == "__main__":
    print(json.dumps(main(*(sys.argv[2:] if RETRY else sys.argv[1:])), sort_keys=True))
