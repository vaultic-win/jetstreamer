"""Validate the requested Foundation epoch 141 receiver with local synthetic data."""

import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import time


V = Path("/var/lib/jetstreamer")
PROOF = V / "horizon141-foundation-receiver-fixture-v2"
ROOT = Path("/home/ubuntu/.jetstreamer-private/horizon141-receiver-fixture-v2")
RAM = ROOT / "ram"
GUARD = V / "horizon251-published-guard-20261118-v1/horizon251-standalone-guard"
GUARD_SHA = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d"
LAYOUT_SHA = "6f54e5205f8e8dad19887bb4413c656d2f43926f8fd1dfd10cfc670207ff5a47"
OWNER_FIELDS = (
    "Id", "LoadState", "ActiveState", "SubState", "InvocationID", "MainPID",
    "ControlPID", "ControlGroup", "Job", "Result", "ExecMainStatus", "NRestarts",
    "AllowedCPUs", "MemoryMax", "MemorySwapMax",
)
GIB = 1 << 30
FIXTURE_BYTES = 2 << 20


def run(*argv, timeout=25):
    return subprocess.check_output(argv, timeout=timeout, text=True)


def manager(unit):
    return dict(line.split("=", 1) for line in run(
        "systemctl", "show", "--no-pager", "--property=" + ",".join(OWNER_FIELDS), unit
    ).splitlines())


def ref(path):
    with path.open("rb") as source:
        return {"path": str(path), "sha256": hashlib.file_digest(source, "sha256").hexdigest()}


def seal(path, value):
    with path.open("xb") as target:
        target.write((json.dumps(value, indent=2) + "\n").encode())
        os.fchmod(target.fileno(), 0o400)
        target.flush()
        os.fsync(target.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return ref(path)


def mount_data(path):
    row, = json.loads(run("findmnt", "--json", "--target", path, "--output",
                          "TARGET,FSTYPE,OPTIONS,MAJ:MIN"))["filesystems"]
    return row


def wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.25)
    raise TimeoutError("fixture missed its invocation-bound transition")


def launch(unit, properties, argv, *, wait=False):
    return run("systemd-run", "--quiet",
               *(("--wait", "--pipe") if wait else ("--no-block",)),
               "--unit=" + unit,
               *(f"--property={key}={value}" for key, value in properties.items()),
               "--", *argv, timeout=50 if wait else 20)


def producer(root):
    assert os.getuid() == os.getgid() == 1000
    assert os.sched_getaffinity(0) == {32, 33}
    m = mount_data(RAM)
    assert m["fstype"] == "tmpfs" and m["target"] == str(RAM)
    assert {"noswap", "nodev", "nosuid"} <= set(m["options"].split(","))
    assert "noexec" not in m["options"].split(",")
    volume = os.statvfs(root)
    assert volume.f_blocks * volume.f_frsize == 44 * GIB
    input_path = root / "input/source"
    assert os.statvfs(input_path).f_flag & os.ST_RDONLY
    try:
        fd = os.open(input_path, os.O_WRONLY)
    except OSError as error:
        import errno
        assert error.errno in (errno.EROFS, errno.EACCES)
    else:
        os.close(fd)
        raise RuntimeError("the projected input was writable")
    assert input_path.stat().st_size == FIXTURE_BYTES
    assert (root / "historical-worker").stat().st_uid == 1000
    child = subprocess.Popen(["sleep", "90"], executable=root / "historical-worker")
    try:
        output = root / "segment.jet"
        with input_path.open("rb") as src, output.open("xb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        assert child.poll() is None, "synthetic worker exited before guard sampling"
        segment = seal(root / "segment.jet.segment.json",
                       {"fixture": True, "bytes": FIXTURE_BYTES, "sha256": ref(output)["sha256"]})
        seal(root / "live.json", {"uid": os.getuid(), "gid": os.getgid(), "cpus": [32, 33],
             "iid": os.environ["INVOCATION_ID"], "mount": m, "worker_pid": child.pid,
             "projected_input_read_only": True, "segment": segment})
        wait_for(lambda: (root / "exit").is_file(), 80)
    finally:
        child.terminate()
        child.wait(timeout=5)


def copy_container(work, destination, limit):
    class CappedFile:
        def __init__(self, file):
            self.file = file
            self.length = 0

        def write(self, data):
            if self.length + len(data) > limit:
                raise ValueError("container exceeds the authorized cap")
            written = self.file.write(data)
            assert written == len(data)
            self.length += written
            return written

    members = ("segment.jet", "segment.jet.segment.json")
    expected = {name: ref(work / name)["sha256"] for name in members}
    temporary = destination.with_suffix(".partial")
    assert not destination.exists()
    try:
        with temporary.open("xb") as file:
            with tarfile.open(fileobj=CappedFile(file), mode="w|") as container:
                for name in members:
                    path = work / name
                    assert path.resolve() == path and stat.S_ISREG(path.lstat().st_mode)
                    container.add(path, arcname=name, recursive=False)
                    assert not destination.exists()
            file.flush()
            os.fsync(file.fileno())
        with tarfile.open(temporary, "r:") as container:
            rows = container.getmembers()
            assert tuple(row.name for row in rows) == members and all(row.isfile() for row in rows)
            for row in rows:
                with container.extractfile(row) as member:
                    assert hashlib.file_digest(member, "sha256").hexdigest() == expected[row.name]
        for name in members:
            assert ref(work / name)["sha256"] == expected[name]
        identity = temporary.stat()
        os.chmod(temporary, 0o400)
        os.link(temporary, destination)
        temporary.unlink()
        assert destination.stat().st_ino == identity.st_ino and destination.stat().st_nlink == 1
        assert 0 < destination.stat().st_size <= limit
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"container": ref(destination), "bytes": destination.stat().st_size,
                "member_sha256": expected, "no_clobber": True, "one_home_inode": True,
                "tmpfs_source_preserved_through_readback": True}
    finally:
        temporary.unlink(missing_ok=True)


def fixture(case, layout, source):
    unit = f"horizon-qualify-141-receiver-{case}-fixture-v2.service"
    guard_unit = f"horizon-141-receiver-{case}-fixture-guard-v2.service"
    assert manager(unit)["LoadState"] == manager(guard_unit)["LoadState"] == "not-found"
    root = RAM / case
    root.mkdir(mode=0o700)
    (root / "input").mkdir(mode=0o700)
    (root / "input/source").touch(mode=0o400)
    shutil.copyfile("/usr/bin/sleep", root / "historical-worker")
    (root / "historical-worker").chmod(0o500)
    for path in (root, root / "input", root / "input/source", root / "historical-worker"):
        os.chown(path, 1000, 1000)
    case_dir = PROOF / case
    case_dir.mkdir(mode=0o700)
    samples = case_dir / "samples"
    samples.mkdir(mode=0o700)
    env = ("HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY "
           "AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN")
    properties = {"Type": "exec", "User": "ubuntu", "Group": "ubuntu", "UMask": "0077",
                  "NoNewPrivileges": "yes", "PrivateNetwork": "yes", "ProtectSystem": "strict",
                  "ProtectHome": "read-only", "ReadWritePaths": str(root),
                  "BindReadOnlyPaths": f"{source}:{root / 'input/source'}", "AllowedCPUs": "32-33",
                  "CPUQuota": "200%", "MemoryMax": str(74 * GIB), "MemorySwapMax": "0",
                  "TasksMax": "64", "KillMode": "control-group", "Restart": "no",
                  "RuntimeMaxSec": "100s", "TimeoutStopSec": "5s", "UnsetEnvironment": env}
    launch(unit, properties, ["/usr/bin/python3", "-B", str(Path(__file__)), "producer", str(root)])
    try:
        wait_for(lambda: (root / "live.json").is_file())
        live = json.loads((root / "live.json").read_text())
        owner = manager(unit)
        assert owner["ActiveState"] == "active" and owner["InvocationID"] == live["iid"]
        assert owner["AllowedCPUs"] == "32-33" and int(owner["MemoryMax"]) == 74 * GIB
        assert owner["MemorySwapMax"] == "0" and owner["NRestarts"] == "0"
        cgroup = Path("/sys/fs/cgroup") / owner["ControlGroup"].lstrip("/")
        assert (cgroup / "memory.max").read_text().strip() == str(74 * GIB)
        assert (cgroup / "memory.swap.max").read_text().strip() == "0"
        assert (cgroup / "cpuset.cpus.effective").read_text().strip() == "32-33"
        assert int(live["worker_pid"]) in [int(pid) for pid in (cgroup / "cgroup.procs").read_text().split()]
        stop = case == "stop"
        limit = 1 << 20 if stop else layout["tmpfs"]["bytes"]
        plan = seal(case_dir / "guard-plan.json", {
            "schema": "jetstreamer-horizon-standalone-guard-plan-v1", "unit": unit,
            "invocation_id": owner["InvocationID"], "filesystem": str(RAM), "worker_root": str(root),
            "minimum_free_bytes": 64 << 20, "maximum_root_physical_bytes": limit,
            "maximum_worker_vmas": 10000, "receipt_directory": str(samples)})
        guard_command = [str(GUARD), plan["path"], "--plan-sha256", plan["sha256"],
                         "--self-sha256", GUARD_SHA]
        static = json.loads(run(*guard_command, "--validate-plan-only"))
        assert static["validated"] and not static["producer_signaled"]
        invocation = launch(guard_unit, {
            "Type": "exec", "UMask": "0077", "NoNewPrivileges": "yes", "PrivateNetwork": "yes",
            "ProtectSystem": "strict", "ProtectHome": "read-only", "ReadWritePaths": str(samples),
            "CapabilityBoundingSet": "CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            "AmbientCapabilities": "CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            "AllowedCPUs": "34", "CPUQuota": "100%", "MemoryMax": str(GIB), "MemorySwapMax": "0",
            "RuntimeMaxSec": "25s", "UnsetEnvironment": env,
        }, guard_command, wait=True)
        reading = json.loads(invocation)
        assert reading["producer_stop_enabled"] and reading["producer_invocation_id"] == owner["InvocationID"]
        assert reading["plan_sha256"] == plan["sha256"] and reading["guard_sha256"] == GUARD_SHA
        assert reading["worker_observation_error"] is None and reading["root_physical_observation_error"] is None
        assert len(reading["workers"]) == 1 and reading["root_physical_observation"]["conservative_physical_bytes"] >= FIXTURE_BYTES
        transfer = None
        if stop:
            assert reading["trip_reason"] == "root-physical-budget"
            completion = json.loads((samples / "stop-completion.json").read_text())
            assert completion["producer_invocation_id"] == owner["InvocationID"] and not completion["scratch_deleted"]
        else:
            assert reading["trip_reason"] is None
            (root / "exit").touch(mode=0o400)
        terminal = wait_for(lambda: (row if
            (row := manager(unit))["ActiveState"] in ("inactive", "failed") and row["MainPID"] == "0"
            else None))
        assert terminal["ControlGroup"] == terminal["Job"] == "" and terminal["NRestarts"] == "0"
        assert not cgroup.exists() and terminal["InvocationID"] in ("", owner["InvocationID"])
        assert not stop or terminal["Result"] in ("success", "signal")
        assert stop or (terminal["Result"] == "success" and terminal["ExecMainStatus"] == "0")
        assert (root / "segment.jet").stat().st_dev == RAM.stat().st_dev
        if not stop:
            try:
                copy_container(root, case_dir / "oversize.tar", 1 << 20)
            except ValueError as error:
                assert str(error) == "container exceeds the authorized cap"
            else:
                raise RuntimeError("oversize container was accepted")
            assert not (case_dir / "oversize.tar").exists() and not (case_dir / "oversize.partial").exists()
            transfer = copy_container(root, case_dir / "output.tar",
                                      layout["home"]["post_exit_output_container_cap_bytes"])
        return seal(case_dir / "result.json", {"owner": owner, "mounted_scope": live["mount"],
                    "terminal": terminal, "plan": plan, "native_sample": reading,
                    "oversize_refused": not stop, "post_exit_transfer": transfer, "fixture_only": True})
    finally:
        if manager(unit)["ActiveState"] in ("activating", "active", "deactivating"):
            run("systemctl", "stop", unit)


def main(layout_file):
    assert os.geteuid() == 0 and ref(layout_file)["sha256"] == LAYOUT_SHA
    layout = json.loads(layout_file.read_text())
    assert layout["tmpfs"]["bytes"] == 44 * GIB and layout["tmpfs"]["noswap"]
    assert layout["ram"]["combined_bytes"] == 75 * GIB and layout["cpu"] == {"producer": 2, "guard": 1}
    assert ref(GUARD)["sha256"] == GUARD_SHA and (PROOF / "fixture-input").is_file()
    assert (PROOF / "fixture-input").stat().st_size == FIXTURE_BYTES
    os.umask(0o077)
    with (V / "horizon-seven-publication-controller-v222/cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert manager("foundation-publication-cadence-v222.service")["ActiveState"] == "inactive"
        ROOT.mkdir(mode=0o700)
        os.chown(ROOT, 1000, 1000)
        RAM.mkdir(mode=0o700)
        run("mount", "-t", "tmpfs", "-o",
            "rw,exec,noswap,nosuid,nodev,size=44G,nr_inodes=1048576,uid=1000,gid=1000,mode=0700",
            "tmpfs", RAM)
        try:
            mount = mount_data(RAM)
            assert mount["target"] == str(RAM) and mount["fstype"] == "tmpfs"
            checks = [fixture(case, layout, PROOF / "fixture-input") for case in ("copy", "stop")]
        finally:
            run("umount", RAM)
        completed = seal(PROOF / "completion.json", {
            "schema": "foundation-epoch141-receiver-fixture-v1",
            "timestamp_utc": dt.datetime.now(dt.UTC).isoformat(), "layout": ref(layout_file),
            "mount": mount, "checks": checks, "guard": ref(GUARD),
            "proof_executable": ref(Path(__file__)), "real_inputs_transferred": False,
            "production_admitted": False, "epoch_claimed": False, "r2_mutations": False,
        })
        print(json.dumps(completed))


if __name__ == "__main__":
    assert __debug__
    if sys.argv[1] == "producer":
        producer(Path(sys.argv[2]))
    else:
        main(Path(sys.argv[1]))
