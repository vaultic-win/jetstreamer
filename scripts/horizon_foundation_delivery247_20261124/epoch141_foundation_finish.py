"""Verify and preserve a closed Foundation epoch 141 third through sixth interval."""

from datetime import datetime, timezone
from hashlib import file_digest
from pathlib import Path
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time


BASE = Path("/var/lib/jetstreamer")
PACKAGE = BASE / "horizon141-foundation-interval2-package-v1"
LOCK = BASE / "horizon-seven-publication-controller-v222/cycle.lock"
FIXTURE = BASE / "horizon141-receiver-fixture-tools-v3/epoch141_receiver_fixture.py"
FIXTURE_SHA = "72dbc82532cacf70857e035f564e8cc4f448bbfab3807c8f508b1f7552056f20"
SCOPE_SHA = {
    3: "d0007aef065d1bc9af56f14fc22c63edf1f87cdf9b35f3f9b702b44f969acbfa",
    4: "e418efbb8329dd5e05c08aa9d829d50c719fd4412981a019416301985bbdf3a6",
    5: "9188755bc441de30ed4e7c646c2c80889872b4d0cfb8a8f0c34c67847866337e",
    6: "f201ca9c60be597b88938be7ab92e13fd7413cf380910c5b81c9ceac12365ddd",
}
HOME = 4 << 30


def read(path):
    return json.loads(path.read_bytes())


def reference(path):
    with path.open("rb") as stream:
        out = file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "sha256": out}


def resolve(binding):
    source = Path(binding["path"])
    assert reference(source)["sha256"] == binding["sha256"]
    metadata = source.lstat()
    for key, actual in (("bytes", metadata.st_size), ("inode", metadata.st_ino), ("device", metadata.st_dev)):
        if key in binding:
            assert binding[key] == actual
    return read(source)


def write_once(path, raw):
    pending = path.with_name(f".{path.name}.{os.getpid()}.pending")
    with pending.open("xb") as stream:
        stream.write(raw)
        os.fchmod(stream.fileno(), 0o400)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def manager(actor):
    fields = "Id,ActiveState,InvocationID,MainPID,ControlPID,ControlGroup,Job,Result"
    result = subprocess.check_output(["/usr/bin/systemctl", "show", actor, "-p", fields], text=True)
    state = dict(row.split("=", 1) for row in result.splitlines())
    assert state["Id"] == actor
    return state


def drained(state):
    return (state["ActiveState"] == "inactive" and state.get("MainPID", "0") == "0"
            and state.get("ControlPID", "0") == "0" and not state.get("ControlGroup") and not state["Job"])


def container_custody(path, names, hashes):
    before = path.lstat()
    assert path.resolve() == path
    assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
    assert stat.S_IMODE(before.st_mode) == 0o400 and 0 < before.st_size <= HOME
    with tarfile.open(path, "r:") as archive:
        payloads = archive.getmembers()
        assert tuple(member.name for member in payloads) == names and all(m.isfile() for m in payloads)
        for member in payloads:
            with archive.extractfile(member) as stream:
                assert file_digest(stream, "sha256").hexdigest() == hashes[member.name]
    after = path.lstat()
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    return {"container": reference(path), "bytes": before.st_size, "member_sha256": hashes,
            "no_clobber": True, "one_home_inode": True, "tmpfs_source_preserved_through_readback": True}



def raw_bootstrap(root, scope, launch, statics, manifest, journal):
    intake_ref = statics["bootstrap_intake"]
    intake = resolve(intake_ref)
    assert Path(intake_ref["path"]) == root / "bootstrap-intake.json"
    payload = Path(intake["installed_path"])
    assert payload.resolve() == payload and payload.parent == root / "payloads"
    assert (intake["gcs_generation_checksums_match"] is True
            and intake["pinned_authenticated_get"] is True and intake["single_physical_copy"] is True)
    before = payload.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
    assert stat.S_IMODE(before.st_mode) == 0o444
    assert (before.st_dev, before.st_ino, before.st_size) == (intake["device"], intake["inode"], intake["bytes"])
    expected = f"snapshot-{manifest['bootstrap']['slot']}-{manifest['bootstrap']['accounts_hash']}.tar.zst"
    assert payload.name == expected
    alias = scope["read_only_bindings"][str(payload)]
    assert f"--snapshot-archive={alias}" in scope["argv"]
    assert journal.count(f"Found existing snapshot archive at {alias}; skipping download".encode()) == 1
    namespace = resolve(launch["held_namespace"])
    assert namespace["producer"]["InvocationID"] == launch["invocation_id"]
    assert namespace["runtime_scope"] == reference(root / "runtime-scope.json")
    payload_ref = reference(payload)
    assert payload_ref["sha256"] == intake["sha256"]
    after = payload.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    return {"file": payload_ref, "intake": intake_ref, "held_namespace": launch["held_namespace"],
            "read_only_alias": alias}

def finish(ordinal, quote_path):
    root = BASE / f"horizon141-foundation-interval{ordinal}-runtime-v1"
    scope_path = root / "runtime-scope.json"
    assert reference(scope_path)["sha256"] == SCOPE_SHA[ordinal]
    scope = read(scope_path)
    launch_path = root / "replay-launch.json"
    launch = read(launch_path)
    admission = resolve(launch["admission"])
    native_path = root / "terminal-evidence/native-exit.json"
    native = read(native_path)
    assert native["scope"] == reference(scope_path) and native["launch"] == reference(launch_path)
    iid = launch["invocation_id"]
    unit = scope["unit"]
    assert native["invocation_id"] == native["native_properties"]["InvocationID"] == iid
    assert native["unit"] == native["native_properties"]["Id"] == unit
    assert native["service_result"] == "success" and native["exit_code"] == "exited" and native["exit_status"] == "0"
    assert native["native_properties"]["ExecMainCode"] == "1" and native["native_properties"]["ExecMainStatus"] == "0"
    assert int(native["native_properties"]["ExecMainExitTimestampMonotonic"]) > 0
    state = manager(unit)
    assert drained(state) and state["InvocationID"] in ("", iid)
    assert not (root / "guard-samples/stop-intent.json").exists()
    raw = subprocess.check_output(["/usr/bin/journalctl", f"_SYSTEMD_INVOCATION_ID={iid}", "-o", "cat", "--no-pager"])
    assert f"epoch 141 held invocation {iid} released with guard sample {launch['first_guard']['sha256']}".encode() in raw

    interval = scope["interval"]
    index = PACKAGE / "index.json"
    assert reference(index)["sha256"] == "fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3"
    start, end = interval["bootstrap"] + 1, interval["endpoint"]
    targets = [row["slot"] for row in read(index)["slots"] if start <= row["slot"] <= end]
    covered = [int(slot) for slot in re.findall(rb"qualified original source slot=(\d+) transactions=", raw)]
    assert len(targets) == len(set(targets)) == interval["original_targets"] and sorted(covered) == sorted(targets)
    ram = Path(scope["tmpfs"])
    assert ram.is_mount()
    archive = ram / scope["output_relative"]
    manifest_path = archive.with_name(archive.name + ".segment.json")
    manifest = read(manifest_path)
    assert manifest["schema_version"] == 1 and manifest["epoch"] == 141
    assert manifest["output_slot_start"] == start and manifest["output_slot_count"] == interval["positions"]
    assert manifest["bootstrap"]["slot"] == start - 1 and manifest["terminal"]["slot"] == end
    assert manifest["terminal"]["slot_complete"] and manifest["terminal"]["accounts_hash"] == scope["terminal_account_hash"]
    assert manifest["worker_executable_sha256"] == scope["worker"]["sha256"]
    statics = resolve(admission["static_inputs"])
    # This field identifies a registered replay handoff archive. The hourly
    # route starts from externally verified raw snapshot bytes.
    assert manifest["bootstrap_archive_sha256"] is None
    bootstrap_payload = raw_bootstrap(root, scope, launch, statics, manifest, raw)
    assert reference(archive)["sha256"] == manifest["archive_sha256"]

    quote = read(quote_path)
    assert quote["schema"] == "foundation-epoch226-suffix-roster-binding-v1"
    assert 0 <= time.time() - quote["recorded_unix_seconds"] <= 300
    owner = {
        3: "active_interval_141_launch",
        4: "active_interval_141_fourth_launch",
        5: "active_interval_141_fifth_launch",
        6: "active_interval_141_sixth_launch",
    }[ordinal]
    assert quote[owner] is None and root.stat().st_dev == quote["filesystem_device"]
    free = os.statvfs(root)
    cap = quote["capacity"]
    assert min(free.f_bavail * free.f_frsize, cap["available_disk_bytes"]) >= cap["protected_existing_disk_bytes"] + HOME
    for actor in [scope["guard_timer"], scope["guard_unit"]]:
        if not drained(manager(actor)):
            subprocess.run(["/usr/bin/systemctl", "stop", actor], check=True)
        assert drained(manager(actor))

    output = root / "post-exit-output"
    output.mkdir(mode=0o700, exist_ok=True)
    journal = output / "native-journal.log"
    if not journal.exists():
        write_once(journal, raw)
    else:
        assert journal.read_bytes() == raw
    assert reference(FIXTURE)["sha256"] == FIXTURE_SHA
    source = FIXTURE.read_text()
    names = (archive.name, manifest_path.name)
    fixed_members = 'members = ("segment.jet", "segment.jet.segment.json")'
    assert source.count(fixed_members) == 1
    copy = {"__name__": "foundation141_copy", "__file__": str(FIXTURE)}
    exec(compile(source.replace(fixed_members, f"members = {names!r}"), str(FIXTURE), "exec"), copy)
    tar_path = output / archive.with_suffix(".tar").name
    if not tar_path.exists():
        custody = copy["copy_container"](ram, tar_path, HOME)
    else:
        hashes = {p.name: reference(p)["sha256"] for p in (archive, manifest_path)}
        custody = container_custody(tar_path, names, hashes)
    terminal = {
        "schema": f"foundation-epoch141-interval{ordinal}-terminal-v1",
        "observed_utc": datetime.now(timezone.utc).isoformat(), "invocation_id": iid,
        "launch": reference(launch_path), "native_exit": reference(native_path), "native_terminal": state,
        "native_journal": reference(journal), "original_entry_index": reference(index),
        "original_entry_slots_verified": len(covered), "private_custody": custody,
        "post_exit_fit": reference(quote_path), "bootstrap": manifest["bootstrap"],
        "bootstrap_payload": bootstrap_payload,
        "terminal_checkpoint": manifest["terminal"], "archive_sha256": manifest["archive_sha256"],
        "archive_bytes": archive.stat().st_size, "output_slot_start": start,
        "output_slot_count": interval["positions"], "guard_drained": True,
        "source_tmpfs_preserved": True, "canonical_publication_authorized": False,
    }
    receipt = root / "replay-terminal.json"
    write_once(receipt, (json.dumps(terminal, indent=2) + "\n").encode())
    print(json.dumps(reference(receipt)))


if __name__ == "__main__":
    assert os.geteuid() == 0 and len(sys.argv) == 3
    interval = int(sys.argv[1])
    assert interval in SCOPE_SHA
    os.umask(0o077)
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finish(interval, Path(sys.argv[2]))
