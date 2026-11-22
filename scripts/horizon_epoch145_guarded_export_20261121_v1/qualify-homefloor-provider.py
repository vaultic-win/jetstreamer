"""Qualify an identical copy of the sealed retry13 provider in the semantic reader's fixed directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tempfile

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
D = R / "incident-replay-fit-20261121-v1"
DONOR = D / "tools-homefloor-retry13-170-adopted"
DEST = D / "tools-homefloor-145-rejoin-v1"
VERIFIER = R / "epoch145-semantic-continuity-20261121-v1/tools-v5g"
SEAL = "deployment-seal-receipt.json"
PROFILE = "profile145-homefloor-semantic.json"
SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
PROFILE_SHA = "11ca6456fdd9e8ea0abe8a25d42deaec4e536983af14228a21fd57702ecd1d0a"
VERIFIER_SEAL = "34b3b4481942f31b9c2476661b1871f40a8766cac8ea33ddada1942ddab5946f"
ORIGINAL = "afcf6cdd1ec0400ea2757f81472987b3"
FAILURE_SHA = "5e001f59750a67f2cdce6aa43fb11b7d55e648a40d52e3fbee26ed3ead66a366"


def need(valid, message):
    if not valid:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ref(path):
    return dict(path=str(path), sha256=digest(path.read_bytes()))


def write(path, data, mode=0o400):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def record(path, data):
    write(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())
    return ref(path)


def members(path, seal_hash):
    need(path.resolve(strict=True) == path and ref(path / SEAL)["sha256"] == seal_hash,
         "foreign provider seal")
    seal = json.loads((path / SEAL).read_bytes())
    need(seal["destination"] == str(path) and seal["sealer_sha256"] == SEALER_SHA
         and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
         and all(seal[k] is False for k in ("replay_launch_authorized", "remote_mutations", "r2_mutations")),
         "invalid sealed provider")
    result = {}
    for row in seal["members"]:
        name = row["name"]
        need(re.fullmatch(r"[\w.-]+", name) and name not in (".", "..") and name not in result, "invalid member name")
        member = path / name
        md = member.lstat()
        need(stat.S_ISREG(md.st_mode) and md.st_uid == md.st_gid == 0 and md.st_nlink == 1
             and stat.S_IMODE(md.st_mode) == int(row["mode"], 8) in (0o444, 0o555)
             and md.st_size == row["bytes"] and ref(member)["sha256"] == row["sha256"], "changed " + name)
        result[name] = dict(name=name, sha256=row["sha256"], mode=int(row["mode"], 8))
    need(set(p.name for p in path.iterdir()) == set(result) | {SEAL, "SHA256SUMS"},
         "unexpected provider member")
    need(result[PROFILE]["sha256"] == PROFILE_SHA, "unqualified semantic registration")
    return result


def inspect(package, fleet, fleet_sha, output):
    native = runpy.run_path(str(package / "post-stop-fit"))
    need(all(native[k] for k in ("HOMEFLOOR", "RETRY11", "COLD170", "RETRY13_170")),
         "directory selected a different producer family")
    cfg, adapter, refs = native["profile145"](package, focused="homefloor-semantic")
    need(adapter == VERIFIER / "incident-phase.py" and refs["seal"] == ref(VERIFIER / SEAL)
         and cfg["seal_sha256"] == VERIFIER_SEAL, "foreign semantic bundle")
    proc = subprocess.run([package / "post-stop-fit", "145", fleet, fleet_sha], capture_output=True)
    write(output / (package.parent.name + ".stderr"), proc.stderr)
    proc.check_returncode()
    v = json.loads(proc.stdout)
    holding = v["registered_retry11_holding"]
    obligations = v["recovery_obligations"]
    actor170 = v["replacements"]["170"]
    cadence = R / "survivor172-cadence-20261122-v1/COLD170_RETRY13_V2_STATUS_ACTIVE.json"
    need(ref(cadence)["sha256"] == "6b180fd6e5fab24a547e4951b290b50404d8d39fae5e0a9374db0bb27800f486",
         "different retry13 writer activation")
    writer = json.loads(cadence.read_bytes())
    need(actor170["admission"] == writer["admission"]
         and actor170["producer_invocation_id"] == "c44b5215f8d949159e7ce9cf911e9be1"
         and v["status_registration"]["invocation_id"] == writer["new"]["invocation_id"]
         and v["survivors"]["172"]["invocation_id"] == "0e17b745938546608b0bdc52815151d0"
         and v["replacements"]["167"]["producer_invocation_id"] == "6e4b569b61d7420fb30a24a4ad0609dd",
         "different admitted producers or status writer")
    need(v["epoch"] == 145 and v["fleet"] == dict(path=str(fleet), sha256=fleet_sha) and v["fits"]
         and v["candidate"] is None and not v["replay_launch_authorized"] and v["resource_credit_bytes"] == 0
         and v["phase145"]["InvocationID"] == ORIGINAL and v["phase145"]["failure"]["sha256"] == FAILURE_SHA
         and v["phase145"]["candidate"]["inode"] == 103237059 and not v["phase145"]["source_checkpoint_exists"]
         and v["cold170"]["stable_root"]["sha256"] == "654e6612f8ce9ee2f9f5c9f172f79f9ce5da4b0f6f02443c856f3a5228a5ca69"
         and v["bookings"]["170"]["cap_bytes"] == 384 << 30 and v["candidate136"]["cap"] == 72 << 30
         and holding["stage"] in ("copy-only", "completed-copy") and holding["restore_overlap_bytes"] == 64922604512
         and holding["stage_bytes"] == holding["resource_credit_bytes"] == holding["additional_reservation_bytes"] == 0
         and obligations["public_storage"]["remaining_archive_growth_bytes"] == 0
         and obligations["prefix"]["maximum_HOME_allocation_bytes"] == 16 << 20 and obligations["missing_mirror_bytes"] >= 0,
         "incomplete HOME, custody or archive-reader price")
    path = output / (package.parent.name + ".json")
    write(path, proc.stdout)
    return ref(path)


def main(donor_sha, fleet_name, fleet_sha, stage_only=False):
    need(os.geteuid() == 0 and sys.flags.isolated and __debug__, "expected isolated native root qualification")
    fleet = Path(fleet_name)
    need(fleet.parent.parent == R and fleet.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
         and fleet.resolve(strict=True) == fleet and ref(fleet)["sha256"] == fleet_sha, "foreign fleet")
    need(donor_sha == "7bd459de59d3381b45f0c9b22de2f53db8dc5d91e70b2312d3facc95d367ac91",
         "different 170 adopted provider")
    source = members(DONOR, donor_sha)
    need(ref(SEALER)["sha256"] == SEALER_SHA, "foreign sealer")
    qa = Path(tempfile.mkdtemp(prefix="semantic145-", dir=D / "homefloor-qualification"))
    stage = qa / DEST.name
    stage.mkdir(mode=0o700)
    for name, row in source.items():
        write(stage / name, (DONOR / name).read_bytes(), row["mode"])
    staged = inspect(stage, fleet, fleet_sha, qa)
    if stage_only:
        print(json.dumps(record(qa / "SEMANTIC145_PROVIDER_STAGED.json",
                         dict(source_seal=ref(DONOR / SEAL), staged_price=staged, profile=ref(stage / PROFILE),
                              members_validated=len(source), verifier_started=False, deployed=False))))
        return
    plan = dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(DEST),
                members=[dict(row, source=str(DONOR / name)) for name, row in source.items()])
    plan_path = qa / "plan.json"
    plan_ref = record(plan_path, plan)
    if not DEST.exists():
        subprocess.run([SEALER, plan_path, "--plan-sha256", plan_ref["sha256"], "--self-sha256", SEALER_SHA], check=True)
    seal = ref(DEST / SEAL)
    need(members(DEST, seal["sha256"]) == source and json.loads((DEST / SEAL).read_bytes())["plan_sha256"] == plan_ref["sha256"],
         "different deployed provider")
    deployed = inspect(DEST, fleet, fleet_sha, qa)
    evidence = record(qa / "SEMANTIC145_PROVIDER_QUALIFIED.json",
                      dict(source_seal=ref(DONOR / SEAL), seal=seal, profile=ref(DEST / PROFILE), verifier=ref(VERIFIER / SEAL),
                           all_members_identical=len(source), staged_price=staged, deployed_price=deployed,
                           verifier_started=False, replay_launch_authorized=False, resource_credit_bytes=0))
    print(json.dumps(evidence))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("donor_sha")
    parser.add_argument("fleet_name")
    parser.add_argument("fleet_sha")
    parser.add_argument("--stage-only", action="store_true", help="retain qualification evidence without installing the provider")
    main(**vars(parser.parse_args()))
