#!/usr/bin/python3 -IB
"""Seal the successful native post build and its five-lane pricing provider."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = R / "epoch145-semantic-continuity-20261121-v1"
FIT = R / "incident-replay-fit-20261121-v1"
DONOR = FIT / "tools-homefloor-145-rejoin-v4"
TARGET = FIT / "tools-homefloor-145-post-v5j-v1"
POST = BASE / "tools-v13d"
DISPATCH = FIT / "tools-homefloor-145-handoff-v1"
FAMILY = Path("scripts/horizon_epoch145_guarded_export_20261121_v1")
SOURCE_PROVIDER = "scripts/horizon_incident_replay_fit_20261121_v1/post-stop-fit"
REPO = Path("/home/sol/workspace/jetstreamer")
SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEAL_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
DONOR_SHA = "ed0e272c1cf6df09bb19ff6049154cad9e55f21e96089f66e6f9e3d0f89da9cb"
UNIT = "horizon-145-v5j-post-build-v1.service"
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


def main(commit, iid):
    require(os.geteuid() == 0 and sys.flags.isolated and __debug__, "root isolated interpreter required")
    require(re.fullmatch("[0-9a-f]{40}", commit) and re.fullmatch("[0-9a-f]{32}", iid), "use exact commit and invocation")
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
    require(" v5j-post " in start["MESSAGE"] and int(start["__MONOTONIC_TIMESTAMP"]) < int(success["__MONOTONIC_TIMESTAMP"])
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
            and re.search(r"Ran 6 tests in ", log) and re.search(r"Ran 2 tests in ", log), "native/adapter test incomplete")
    image = outputs / "export145"
    image_sha = ref(image)["sha256"]
    artifacts = dict((Path(path).name, sha) for sha, path in (row.split("  ", 1) for row in (q / "artifacts").read_text().splitlines()))
    require(artifacts["export145"] == image_sha and str(POST / "export145").encode() in image.read_bytes()
            and str(TARGET / "post-stop-fit").encode() in image.read_bytes(), "unregistered native image")
    src = outputs / "source" / FAMILY
    model = json.loads(subprocess.check_output([sys.executable, "-IB", src / "post_inputs.py", "inspect"]))
    need_refs = model["artifacts"]
    price = json.loads((q / "before.json").read_bytes())
    require(price["fits"] and price["resource_credit_bytes"] == 0 and price["candidate"] is None and price["epoch"] == 145
            and price["available_memory_bytes"] - price["required_available_memory_bytes"] >= 805306368
            and price["available_HOME_bytes"] - price["complete_required_HOME_bytes"] >= 92274688 + 16777216
            and (q / "memory.peak").read_text().strip().isdigit(), "unfunded build")
    require(ref(SEALER)["sha256"] == SEAL_SHA and ref(DONOR / SEAL)["sha256"] == DONOR_SHA
            and ref(DISPATCH / SEAL)["sha256"] == "19c0fe27899e6742d095b075377b2adb9aebdb47b2ad2655688b214cd8b632de",
            "changed donor or sealer")
    proof = dict(schema="horizon-145-v5j-post-build-v1", source_commit=commit, source_hashes=inputs,
                 verifier_sha256=image_sha, semantic_image=ref(BASE / "tools-v5j/export145"), artifact_hashes=artifacts,
                 build_iid=iid, native_success_cursor=success["__CURSOR"], tests=ref(q/"build.log"),
                 native_fixture_names=required_tests, memory_peak=int((q/"memory.peak").read_text()),
                 physical_scratch=int((q/"scratch-bytes").read_text().split()[0]), build_fleet=price["fleet"],
                 build_price=ref(q/"before.json"), ordinary_pair=need_refs["pair"], current_reader=need_refs["qualification"],
                 qualified_reader_scopes=need_refs["ordinary_reader_scopes"], reader_commit=need_refs["reader_commit"],
                 semantic_dispatch=ref(DISPATCH/SEAL), donor=ref(DONOR/SEAL), source_snapshot=ref(q/"sources"),
                 compiler_outputs=ref(q/"artifacts"), archive_body_verified_by_this_build=False, resource_credit_bytes=0)
    require(proof["semantic_image"]["sha256"] == "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4",
            "different semantic image")
    launcher = (src/"run-incident-post.sh").read_bytes()
    require(launcher.count(b"PINNED_POST_SHA") == 1, "malformed launcher")
    launch = write(q/"run-post", launcher.replace(b"PINNED_POST_SHA", image_sha.encode()))
    post = install(POST, [item("build-proof.json", record(q/"post-build-proof.json", proof), 0o444),
                   item("export145", image, 0o555), item("run-post", launch, 0o555),
                   item("incident-post-phase.py", src/"incident-post-phase.py", 0o444),
                   item("post-inputs", src/"post_inputs.py", 0o555)], q/"post-seal-plan.json")
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
    fit = install(TARGET, list(members.values()), q/"post-provider-plan.json")
    return dict(post=post, provider=fit, compiler_outputs=ref(q/"artifacts"), build_proof=ref(POST/"build-proof.json"),
                current_reader=need_refs["qualification"], original_pair=need_refs["pair"], public_origin=model["public_origin"],
                resource_credit_bytes=0, production_worker_started=False, r2_mutations=False)


if __name__ == "__main__":
    print(json.dumps(main(*sys.argv[1:]), sort_keys=True))
