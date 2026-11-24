"""Admit the pinned epoch 250 successor through the existing publication controller."""

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
import staged250 as route
from staged211 import sealed

CPU = "48-55"
SCRATCH = 1 << 30
KEY = "epoch-250.epoch-status.json"
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


def sandbox(plan):
    ssh = os.environ["SSH_AUTH_SOCK"]
    subprocess.run(["/usr/bin/ssh-add", "-l"], check=True, stdout=subprocess.DEVNULL, timeout=5)
    writable = [route.STATE / name for name in ("tmp", "playback", "receipts")]
    writable.append(Path(plan["repository"]) / ".git")
    return [
        "--property=Type=exec", "--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env",
        "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
        "--property=NoNewPrivileges=yes", "--property=UMask=0077", "--property=MemoryMax=10G",
        "--property=MemorySwapMax=0", "--property=TasksMax=512", "--property=Restart=no",
        "--property=AllowedCPUs=" + CPU, "--property=CPUQuota=800%",
        "--property=ReadWritePaths=" + " ".join(map(str, writable)),
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID",
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID",
        "--setenv=SSH_AUTH_SOCK=" + ssh, "--setenv=GIT_TERMINAL_PROMPT=0",
        "--setenv=TMPDIR=" + str(route.STATE / "tmp"),
    ]


def capacity(price, plan):
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
    peers = {}
    for owner in identities:
        fields = ["Id", "InvocationID", "MainPID", "ActiveState", "SubState", "NRestarts", "AllowedCPUs", "MemoryMax"]
        unit = props(owner["Id"], fields)
        assert all(unit[key] == owner[key] for key in ("Id", "InvocationID", "MainPID"))
        assert unit["ActiveState"] == "active" and unit["SubState"] == "running" and unit["NRestarts"] == "0"
        assert not cpus(unit["AllowedCPUs"]) & cpus(CPU)
        peers[unit["Id"]] = unit
    assert sum(int(p["MemoryMax"]) for p in peers.values()) + route.MEMORY_CAP < (
        observation["host_memory"]["conservative_available_kib"] * 1024
    )
    fs = os.statvfs(route.STATE)
    available = fs.f_frsize * fs.f_bavail
    assert available > max(priced["protected_floor_bytes"], plan["minimum_free_bytes"]) + SCRATCH
    return peers, available


def preflight():
    definitions, _, _, successor = publication_handoff.select_roster()
    assert successor is None and not route.REGISTRATION.exists()
    original = definitions["250"]
    previous = bound(original["claim"])
    terminal = props(route.PREDECESSOR, FIELDS)
    assert terminal["ActiveState"] == "failed" and terminal["InvocationID"] == previous["invocation_id"]
    assert terminal["ControlPID"] == terminal["MainPID"] == terminal["NRestarts"] == "0"
    assert not terminal["ControlGroup"] and not terminal["Job"]
    successor = props(route.UNIT, FIELDS)
    assert successor["LoadState"] == "not-found" and not successor["Job"] and not successor["ControlGroup"]
    assert successor["MainPID"] == "0"

    release = sealed(route.PACKAGE / "acceptance.json")
    proof = bound(release)
    plan_ref = sealed(route.PLAN)
    assert proof["plan"] == plan_ref and plan_ref["sha256"] == route.PLAN_SHA
    assert sealed(route.IMAGE)["sha256"] == route.IMAGE_SHA
    plan = bound(plan_ref)
    git = ["/usr/bin/git", "-c", f"safe.directory={plan['repository']}", "-C", plan["repository"]]
    head = subprocess.check_output([*git, "rev-parse", "origin/account-updates"], text=True).strip()
    subprocess.run([*git, "merge-base", "--is-ancestor", proof["source"], head], check=True)
    subprocess.run([*git, "diff", "--exit-code", plan["reader_commit"], head, "--", *proof["reader_paths"]], check=True)
    original_spec = bound(original["spec"])
    assert original_spec["archive_bytes"] == route.SIZE
    assert proof["inventory"] == sealed(route.PACKAGE / "authenticated-pin.json")
    archive = bound(proof["inventory"])
    assert archive["archive_etag"] == route.ETAG and archive["archive_length"] == route.SIZE
    assert archive["archive_metadata_sha256"] == original_spec["archive_sha256"]

    auth = bound(route.OLD_STATUS)
    objects = {v["Key"]: v for v in aws("list-objects-v2", "--prefix", "epoch-250.")["Contents"]}
    assert set(objects) == {"epoch-250.jet", KEY}
    remote = objects["epoch-250.jet"]
    assert remote["ETag"].strip('"') == route.ETAG and remote["Size"] == route.SIZE
    assert objects[KEY]["ETag"] == auth["etag"]
    price = sealed(Path(os.environ["HORIZON_250_CAPACITY_RECEIPT"]))
    peers, available = capacity(price, plan)
    origin = bound(original["handoff"])["producer"]
    start, = [
        int(event["__REALTIME_TIMESTAMP"]) // 1000 for event in origin["events"]
        if event["MESSAGE_ID"] == publication_handoff.STARTED
        and event["INVOCATION_ID"] == origin["unit"]["InvocationID"]
    ]
    return original, original_spec, release, plan_ref, auth, price, peers, available, start, sandbox(plan)


def launch():
    original, old_spec, release, plan, auth, price, peers, available, start, options = preflight()
    args = route.expected_argv(old_spec)
    initial = route.ROOT / "initial-status"
    route.ROOT.mkdir(mode=0o700)
    initial.mkdir(mode=0o700)
    before = initial / "before.json"
    prior = aws("get-object", "--key", KEY, "--if-match", auth["etag"], str(before))
    assert prior["ETag"] == auth["etag"] and ref(before)["sha256"] == auth["readback"]["sha256"]
    os.chmod(before, 0o400)
    booking = write(route.ROOT / "booking.json", dict(
        handoff=original["handoff"], argv=args, predecessor=original["claim"], release=release,
        capacity=price, peers=peers, free_bytes=available, scratch_bytes=SCRATCH, sandbox=options,
    ))
    subprocess.run([
        "/usr/bin/systemd-run", "--quiet", "--unit=" + route.UNIT, "--property=RuntimeMaxSec=345600",
        "--property=StandardOutput=append:" + str(route.ROOT / "operation.log"),
        "--property=StandardError=inherit", *options, *args,
    ], check=True, timeout=25)
    unit = props(route.UNIT, FIELDS)
    pid = int(unit["MainPID"])
    iid = unit["InvocationID"]
    assert unit["SubState"] == "running" and unit["AllowedCPUs"] == CPU and int(unit["MemoryMax"]) == route.MEMORY_CAP
    assert os.path.samefile(f"/proc/{pid}/exe", route.IMAGE)
    assert Path(f"/proc/{pid}/cmdline").read_bytes() == b"\0".join(map(os.fsencode, args)) + b"\0"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    launched = write(route.ROOT / "launch.json", dict(booking=booking, unit=unit, time=now.timestamp()))
    owner = dict(epoch=250, unit=route.UNIT, phase="upload-readback", invocation_id=iid,
                 expected_exec_start=unit["ExecStart"], evidence=[booking, launched])
    verify_publisher(owner, props(route.UNIT, publisher_fields))
    claim = write(route.ROOT / "pipeline-claim.json", owner)
    spec = write(route.ROOT / "publication-spec.json", dict(
        old_spec, uploader_pid=pid, reader_plan=plan, receipt_directory=str(route.STATE / "receipts"),
    ))
    baseline = bound(auth["readback"])
    payload = dict(
        baseline, sampled_at_utc=now.strftime("%Y-%m-%dT%H:%M:%SZ"), phase="verification",
        elapsed_execution_millis=int(now.timestamp()) * 1000 - start,
    )
    intent = write(initial / "intent.json", dict(
        key=KEY, previous=route.OLD_STATUS, payload=payload, owner=dict(claim=claim, unit=route.UNIT, invocation_id=iid),
        basis="Prior measured retry estimate, pending the first sample for the eight-worker publisher.",
        evidence=[booking, launched, original["handoff"], route.OLD_STATUS],
    ))
    blob = initial / "payload.json"
    native_status.payload(blob, payload)
    put = aws("put-object", "--key", KEY, "--if-match", auth["etag"], "--body", str(blob), "--content-type", "application/json")
    after = initial / "readback.json"
    got = aws("get-object", "--key", KEY, "--if-match", put["ETag"], str(after))
    assert got["ETag"] == put["ETag"] and ref(after)["sha256"] == ref(blob)["sha256"]
    os.chmod(after, 0o400)
    status = write(initial / "completion.json", dict(
        key=KEY, etag=got["ETag"], intent=intent, readback=sealed(after), authenticated_exact_byte_readback=True,
    ))
    registration = write(route.REGISTRATION, dict(
        schema="foundation-staged-250-cadence-registration-v1", epoch=250, predecessor=original["claim"],
        predecessor_status=route.OLD_STATUS, claim=claim, spec=spec, initial_status=status,
    ))
    assert route.load(original)["registration"] == registration
    print(json.dumps(dict(unit=route.UNIT, pid=pid, invocation_id=iid, started_at_utc=payload["sampled_at_utc"], registration=registration)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-only", action="store_true")
    check = parser.parse_args().check_only
    os.umask(0o077)
    with (CONTROLLER / "cycle.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if check:
            preflight()
            print('{"preflight": true, "remote_mutations": false, "worker_started": false}')
        else:
            launch()
