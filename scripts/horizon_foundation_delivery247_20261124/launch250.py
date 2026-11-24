"""Admit a pinned staged successor through the existing publication controller."""

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

CONTROLLER = Path("/var/lib/jetstreamer/horizon-seven-publication-controller-v222")
sys.path[:0] = [str(CONTROLLER), "/var/lib/jetstreamer/horizon249-delivery-v214-tools"]
from ordinary249 import native_status
from ordinary249.delivery248 import aws, bound, props, ref
import publication_handoff
from seven_status import publisher_fields, verify_publisher
import staged211retry
import staged250
from staged250 import PROFILE
from staged211 import sealed

SCRATCH = 1 << 30
FIELDS = sorted(set(publisher_fields + [
    "LoadState", "ControlPID", "MemoryMax", "MemorySwapMax", "AllowedCPUs",
    "ExecMainStartTimestampMonotonic", "ControlGroup", "SubState",
]))


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return sealed(path)


def cpus(value):
    result = set()
    for span in value.split(","):
        limits = [int(n) for n in span.split("-")]
        result.update(range(limits[0], limits[-1] + 1))
    return result


def sandbox(plan, public_origin, profile=PROFILE):
    ssh = os.environ["SSH_AUTH_SOCK"]
    subprocess.run(["/usr/bin/ssh-add", "-l"], check=True, stdout=subprocess.DEVNULL, timeout=5)
    writable = [profile.state / name for name in ("tmp", "playback", "receipts")]
    writable.append(Path(plan["repository"]) / ".git")
    return [
        "--property=Type=exec", "--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env",
        "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
        "--property=NoNewPrivileges=yes", "--property=UMask=0077", "--property=MemoryMax=10G",
        "--property=MemorySwapMax=0", "--property=TasksMax=512", "--property=Restart=no",
        "--property=AllowedCPUs=" + profile.cpus, "--property=CPUQuota=800%",
        "--property=ReadWritePaths=" + " ".join(map(str, writable)),
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID",
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID",
        "--setenv=SSH_AUTH_SOCK=" + ssh, "--setenv=GIT_TERMINAL_PROMPT=0",
        "--setenv=TMPDIR=" + str(profile.state / "tmp"),
        "--setenv=HORIZON_PUBLIC_BASE_URL=" + public_origin,
    ]


def capacity(price, plan, profile, staged_peer):
    priced = bound(price)
    fleet = bound(priced["fleet"])
    when = datetime.fromisoformat(fleet["sampled_at_utc"]).timestamp()
    assert 0 <= time.time() - when <= 1800 and fleet["memory_target"]["valid"]
    observation = bound(priced["observer"])
    identities = [row.get("unit", row.get("producer")) for row in fleet["active"]]
    for row in fleet["active"]:
        if row["phase"] == "private-held-extraction":
            broker = row["capacity_owners"]["broker"]
            identities.append(dict(Id=broker["unit"], InvocationID=broker["invocation_id"], MainPID=str(broker["pid"])))
    peer_scratch = SCRATCH if staged_peer else 0
    if staged_peer and not any(p["Id"] == staged250.UNIT for p in identities):
        peer_claim = bound(staged_peer["claim"])
        booking, launch = map(bound, peer_claim["evidence"])
        peer = launch["unit"]
        assert peer["Id"] == staged250.UNIT and peer["InvocationID"] == peer_claim["invocation_id"]
        assert when < launch["time"] and booking["scratch_bytes"] == SCRATCH
        identities.append(peer)
    peers = {}
    for owner in identities:
        fields = ["Id", "InvocationID", "MainPID", "ActiveState", "SubState", "NRestarts", "AllowedCPUs", "MemoryMax"]
        unit = props(owner["Id"], fields)
        assert all(unit[key] == owner[key] for key in ("Id", "InvocationID", "MainPID"))
        assert unit["ActiveState"] == "active" and unit["SubState"] == "running" and unit["NRestarts"] == "0"
        assert not cpus(unit["AllowedCPUs"]) & cpus(profile.cpus)
        peers[unit["Id"]] = unit
    assert sum(int(p["MemoryMax"]) for p in peers.values()) + profile.memory_cap < (
        observation["host_memory"]["conservative_available_kib"] * 1024
    )
    fs = os.statvfs(profile.state)
    available = fs.f_frsize * fs.f_bavail
    assert available > max(priced["protected_floor_bytes"], plan["minimum_free_bytes"]) + SCRATCH + peer_scratch
    return peers, available


def preflight(profile):
    definitions, staged_211, _, staged_250 = publication_handoff.select_roster()
    assert not profile.registration.exists()
    if profile.epoch == 211:
        staged211retry.prior_drained(staged_211)
    else:
        assert staged_250 is None
    original = definitions[str(profile.epoch)]
    previous = bound(original["claim"])
    terminal = props(profile.predecessor, FIELDS)
    assert terminal["ActiveState"] == "failed" and terminal["InvocationID"] == previous["invocation_id"]
    assert terminal["ControlPID"] == terminal["MainPID"] == terminal["NRestarts"] == "0"
    assert not terminal["ControlGroup"] and not terminal["Job"]
    successor = props(profile.unit, FIELDS)
    assert successor["LoadState"] == "not-found" and not successor["Job"] and not successor["ControlGroup"]
    assert successor["MainPID"] == "0"

    release = sealed(profile.package / "acceptance.json")
    proof = bound(release)
    if profile.epoch == 211:
        repair = bound(proof["custody_repair"])
        expected = bound(repair["expectation"])["independent_evidence"]
        assert len(expected) == 8
        assert expected == [sealed(Path(row["path"])) for row in expected]
    plan_ref = sealed(profile.plan)
    assert proof["plan"] == plan_ref and plan_ref["sha256"] == profile.plan_sha
    assert sealed(profile.image)["sha256"] == profile.image_sha
    plan = bound(plan_ref)
    git = ["/usr/bin/git", "-c", f"safe.directory={plan['repository']}", "-C", plan["repository"]]
    head = subprocess.check_output([*git, "rev-parse", "origin/account-updates"], text=True).strip()
    subprocess.run([*git, "merge-base", "--is-ancestor", proof["source"], head], check=True)
    subprocess.run([*git, "diff", "--exit-code", plan["reader_commit"], head, "--", *proof["reader_paths"]], check=True)
    original_spec = bound(original["spec"])
    assert original_spec["archive_bytes"] == profile.size
    assert proof["inventory"] == sealed(profile.package / "authenticated-pin.json")
    archive = bound(proof["inventory"])
    assert archive["archive_etag"] == profile.etag and archive["archive_length"] == profile.size
    assert archive["archive_metadata_sha256"] == original_spec["archive_sha256"]

    auth = bound(profile.old_status)
    objects = {v["Key"]: v for v in aws("list-objects-v2", "--prefix", f"epoch-{profile.epoch}.")["Contents"]}
    archive_key = f"epoch-{profile.epoch}.jet"
    assert set(objects) == {archive_key, profile.key}
    remote = objects[archive_key]
    assert remote["ETag"].strip('"') == profile.etag and remote["Size"] == profile.size
    assert objects[profile.key]["ETag"] == auth["etag"]
    price = sealed(Path(os.environ[f"HORIZON_{profile.epoch}_CAPACITY_RECEIPT"]))
    peers, available = capacity(price, plan, profile, staged_250)
    origin = bound(original["handoff"])["producer"]
    start, = [
        int(event["__REALTIME_TIMESTAMP"]) // 1000 for event in origin["events"]
        if event["MESSAGE_ID"] == publication_handoff.STARTED
        and event["INVOCATION_ID"] == origin["unit"]["InvocationID"]
    ]
    options = sandbox(plan, original_spec["public_origin"], profile)
    return original, original_spec, release, plan_ref, auth, price, peers, available, start, options


def launch(profile):
    original, old_spec, release, plan, auth, price, peers, available, start, options = preflight(profile)
    args = staged250.expected_argv(old_spec, profile)
    initial = profile.root / "initial-status"
    profile.root.mkdir(mode=0o700)
    initial.mkdir(mode=0o700)
    before = initial / "before.json"
    prior = aws("get-object", "--key", profile.key, "--if-match", auth["etag"], str(before))
    assert prior["ETag"] == auth["etag"] and ref(before)["sha256"] == auth["readback"]["sha256"]
    os.chmod(before, 0o400)
    booking = write(profile.root / "booking.json", dict(
        handoff=original["handoff"], argv=args, predecessor=original["claim"], release=release,
        capacity=price, peers=peers, free_bytes=available, scratch_bytes=SCRATCH, sandbox=options,
    ))
    subprocess.run([
        "/usr/bin/systemd-run", "--quiet", "--unit=" + profile.unit, "--property=RuntimeMaxSec=345600",
        "--property=StandardOutput=append:" + str(profile.root / "operation.log"),
        "--property=StandardError=inherit", *options, *args,
    ], check=True, timeout=25)
    unit = props(profile.unit, FIELDS)
    pid = int(unit["MainPID"])
    iid = unit["InvocationID"]
    assert unit["SubState"] == "running" and unit["AllowedCPUs"] == profile.cpus and int(unit["MemoryMax"]) == profile.memory_cap
    assert os.path.samefile(f"/proc/{pid}/exe", profile.image)
    assert Path(f"/proc/{pid}/cmdline").read_bytes() == b"\0".join(map(os.fsencode, args)) + b"\0"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    launched = write(profile.root / "launch.json", dict(booking=booking, unit=unit, time=now.timestamp()))
    owner = dict(epoch=profile.epoch, unit=profile.unit, phase="upload-readback", invocation_id=iid,
                 expected_exec_start=unit["ExecStart"], evidence=[booking, launched])
    verify_publisher(owner, props(profile.unit, publisher_fields))
    claim = write(profile.root / "pipeline-claim.json", owner)
    spec = write(profile.root / "publication-spec.json", dict(
        old_spec, uploader_pid=pid, reader_plan=plan, receipt_directory=str(profile.state / "receipts"),
    ))
    baseline = bound(auth["readback"])
    payload = dict(
        baseline, sampled_at_utc=now.strftime("%Y-%m-%dT%H:%M:%SZ"), phase="verification",
        elapsed_execution_millis=int(now.timestamp()) * 1000 - start,
    )
    intent = write(initial / "intent.json", dict(
        key=profile.key, previous=profile.old_status, payload=payload, owner=dict(claim=claim, unit=profile.unit, invocation_id=iid),
        basis="Prior measured retry estimate, pending the first sample for the eight-worker publisher.",
        evidence=[booking, launched, original["handoff"], profile.old_status],
    ))
    blob = initial / "payload.json"
    native_status.payload(blob, payload)
    put = aws("put-object", "--key", profile.key, "--if-match", auth["etag"], "--body", str(blob), "--content-type", "application/json")
    after = initial / "readback.json"
    got = aws("get-object", "--key", profile.key, "--if-match", put["ETag"], str(after))
    assert got["ETag"] == put["ETag"] and ref(after)["sha256"] == ref(blob)["sha256"]
    os.chmod(after, 0o400)
    status = write(initial / "completion.json", dict(
        key=profile.key, etag=got["ETag"], intent=intent, readback=sealed(after), authenticated_exact_byte_readback=True,
    ))
    registration = write(profile.registration, dict(
        schema=f"foundation-staged-{profile.epoch}-cadence-registration-v1", epoch=profile.epoch, predecessor=original["claim"],
        predecessor_status=profile.old_status, claim=claim, spec=spec, initial_status=status,
    ))
    assert staged250.load(original, profile)["registration"] == registration
    print(json.dumps(dict(unit=profile.unit, pid=pid, invocation_id=iid, started_at_utc=payload["sampled_at_utc"], registration=registration)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--epoch", type=int, choices=(211, 250), default=250)
    args = parser.parse_args()
    profile = staged211retry.PROFILE if args.epoch == 211 else PROFILE
    os.umask(0o077)
    with (CONTROLLER / "cycle.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.check_only:
            preflight(profile)
            print('{"preflight": true, "remote_mutations": false, "worker_started": false}')
        else:
            launch(profile)
