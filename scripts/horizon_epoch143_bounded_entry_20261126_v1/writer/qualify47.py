"""Check V47 at its canonical paths inside a private mount namespace on Anza."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import derive47

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
WRITER_ROOT = BASE / "survivor172-cadence-20261122-v1"
HOURLY_ROOT = BASE / "epoch143-first-hourly-20261127-v1"
PRIVATE = Path("/home/sol/.jetstreamer-private")


def run(*args, env=None):
    result = subprocess.run(
        list(map(str, args)), capture_output=True, text=True, timeout=90, env=env
    )
    if result.returncode:
        raise RuntimeError(
            f"{args[0]} failed ({result.returncode})\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def record(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fchmod(stream.fileno(), 0o444)
        os.fsync(stream.fileno())
    return digest(path)


def private_view(fixture, original, tag):
    view = fixture / tag
    view.mkdir()
    upper, work, merged = (view / x for x in ("upper", "work", "merged"))
    for directory in (upper, work, merged):
        directory.mkdir()
    run(
        "mount",
        "-t",
        "overlay",
        "overlay",
        "-o",
        f"lowerdir={original},upperdir={upper},workdir={work}",
        merged,
    )
    run("mount", "--bind", merged, original)


def package(fixture, tag, plans, old):
    plan = plans(old, fixture / (tag + "-sources"))
    plan_sha = record(fixture / (tag + "-plan.json"), plan)
    destination = Path(plan["destination"])
    destination.mkdir()
    members = []
    for row in plan["members"]:
        source = Path(row["source"])
        if digest(source) != row["sha256"]:
            raise ValueError("fixture source changed " + str(source))
        target = destination / row["name"]
        target.touch()
        run("mount", "--bind", source, target)
        run("mount", "-o", "remount,bind,ro", target)
        members.append(
            dict(
                name=row["name"],
                source=str(source),
                bytes=source.stat().st_size,
                mode=f"{row['mode']:04o}",
                sha256=row["sha256"],
            )
        )
    sums = destination / "SHA256SUMS"
    sums.write_text("".join(m["sha256"] + "  " + m["name"] + "\n" for m in members))
    sums.chmod(0o444)
    members.append(
        dict(
            name="SHA256SUMS",
            source="fixture",
            bytes=sums.stat().st_size,
            mode="0444",
            sha256=digest(sums),
        )
    )
    fixture_seal = record(
        destination / "deployment-seal-receipt.json",
        dict(
            schema="jetstreamer-sealed-deployment-receipt-v1",
            fixture=True,
            destination=str(destination),
            members=members,
            plan_sha256=plan_sha,
        ),
    )
    destination.chmod(0o555)
    return destination, dict(
        plan_sha256=plan_sha,
        fixture_seal=fixture_seal,
        materialized_member_bytes=sum(m["bytes"] for m in members),
        members={m["name"]: m["sha256"] for m in members},
    )


def qualify(fixture):
    if (
        os.getuid() != 0
        or Path("/proc/self/ns/mnt").readlink() == Path("/proc/1/ns/mnt").readlink()
    ):
        raise ValueError("run under sudo unshare --mount --propagation private")
    if (
        fixture.parent.resolve(strict=True) != fixture.parent
        or not fixture.is_relative_to(PRIVATE)
        or fixture == PRIVATE
        or fixture.parent.stat().st_dev != PRIVATE.stat().st_dev
    ):
        raise ValueError("the fixture needs a new private directory on HOME")
    for path in (WRITER_ROOT, HOURLY_ROOT, fixture.parent):
        if run("findmnt", "-n", "-o", "PROPAGATION", "-T", path).strip() != "private":
            raise ValueError("mount propagation must be private for " + str(path))
    fixture.mkdir(mode=0o700)
    private_view(fixture, WRITER_ROOT, "writer-view")
    private_view(fixture, HOURLY_ROOT, "booker-view")
    writer, package_result = package(
        fixture, "writer", derive47.stage, WRITER_ROOT / derive47.OLD
    )
    _, booker = package(
        fixture, "booker", derive47.booker, HOURLY_ROOT / "booking-price-v4"
    )
    head = max(
        BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
        key=lambda p: p.stat().st_mtime_ns,
    )
    entry = json.loads(
        run("/usr/bin/python3", "-IB", writer / "status_cycle.py", "--check-entry")
    )
    ready = json.loads(
        run(
            "/usr/bin/python3",
            "-IB",
            writer / "status_cycle.py",
            "--check-v47-handoff",
            head,
            digest(head),
        )
    )
    watch = json.loads(
        run("/usr/bin/python3", "-IB", writer / "watch143_versions.py", "--check-entry")
    )
    if (
        ready["fleet"] != dict(path=str(head), sha256=digest(head))
        or ready["package"] != entry
        or watch["version"] != 46
        or watch["writer"] != ready["old_owner"]
    ):
        raise ValueError("different inherited writer, clock or fleet in the fixture")
    record(fixture / "writer-ready.json", ready)
    tests = run(
        "/usr/bin/python3",
        "-IB",
        HERE / "test_fourth170_writer.py",
        writer,
        env={**os.environ, "TMPDIR": str(fixture)},
    )
    names = (
        "book141.py",
        "prepare143.py",
        "watch143_reentry.py",
        "watch143_versions.py",
        "derive47.py",
        "qualify47.py",
        "test_fourth170_writer.py",
        "transition_v47.py",
        "cutover47.py",
        "rolling170_fourth_status.py",
        "fourth170_contract.py",
    )
    proof = fixture / "QUALIFIED.json"
    h = record(
        proof,
        dict(
            source_only=True,
            systemd_mutations=False,
            r2_mutations=False,
            writer=package_result,
            booker=booker,
            fleet=ready["fleet"],
            inherited_timer=ready["timer"],
            listener=watch,
            interface=ready["successor170_interface"],
            source_hashes={n: digest(HERE / n) for n in names},
            tests=tests,
        ),
    )
    print(json.dumps(dict(path=str(proof), sha256=h)))


if __name__ == "__main__":
    qualify(Path(sys.argv[1]))
