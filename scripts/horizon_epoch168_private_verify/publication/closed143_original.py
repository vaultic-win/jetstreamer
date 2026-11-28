"""Retain the booked second 143 interval after its original successful native exit."""

import hashlib
import json
import stat
from pathlib import Path


def check(core, directory, fleet):
    read, bound, need = core["read"], core["bound"], core["need"]
    iid = "004593b7e31f4568b153befabbd4e0c9"
    terminal, reference = read(directory / ("terminal-" + iid) / "NATIVE_TERMINAL.json",
                               "067d00412a8ab2e8d6e88a5f72e1d7c9ec826e18705f5d3d16581ee6681455e9")
    actor, actor_ref = read(directory / "HELD_OWNER.json")
    registered = fleet["current_private143_second_hourly_ram_retry"]
    first = bound(terminal["first_progress"])
    exit_row = bound(terminal["pid1_exit"])
    native = exit_row["properties"]
    need(terminal["disposition"] == "native-complete-private-interval" and terminal["epoch"] == 143
         and terminal["invocation_id"] == actor["producer_invocation_id"] == first["producer_invocation_id"] == iid
         and terminal["producer"] == first["held_owner"] == registered["held_owner"] == actor_ref
         and registered["phase"] == "terminal" and registered["actor"] == exit_row["actor"] == actor
         and native["Id"] == actor["unit"] == terminal["unit"]
         and registered["native_terminal"]["invocation_id"] == native["InvocationID"] == iid
         and registered["native_terminal"]["cursor"] == terminal["terminal_cursor"]
         and exit_row["bindings"]["actor"] == actor_ref and native["Result"] == "success" and native["ExecMainCode"] == "1"
         and native["ExecMainStatus"] == native["MainPID"] == native["ControlPID"] == "0"
         and native["ExecMainPID"] == str(actor["producer_pid"])
         and terminal["stop_completion"] is terminal["stop_intent"] is None
         and terminal["guard_plan"] == actor["guard_plan"] and not terminal["archive_publication_authorized"]
         and terminal["resource_credit_bytes"] == 0, "different closed original 143")
    for key, saved in terminal["drained"].items():
        observed = core["state"](key, ",".join(saved))
        need(observed == saved and observed["ActiveState"] == "inactive" and not observed["Job"]
             and not Path("/sys/fs/cgroup/system.slice", key, "cgroup.procs").exists(), "143 still draining " + key)
    archive = Path(terminal["archive"]["path"])
    info = archive.lstat()
    manifest = Path(terminal["segment_manifest"]["path"])
    need(archive == Path("/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1/epoch-143-through-61794627.jet")
         and archive.resolve(strict=True) == archive and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and (info.st_dev, info.st_ino, info.st_size) == (64512,119216794,terminal["archive_bytes"])
         and info.st_size == 1759789770 and manifest == Path(str(archive) + ".segment.json")
         and manifest.resolve(strict=True) == manifest and manifest.stat().st_size <= 16384,
         "different retained 143 output")
    body = manifest.read_bytes()
    segment = json.loads(body)
    need(hashlib.sha256(body).hexdigest() == terminal["segment_manifest"]["sha256"]
         and segment["archive_sha256"] == terminal["archive"]["sha256"]
         and segment["terminal"]["slot"] == terminal["terminal_slot"] == 61794627,
         "different 143 terminal manifest")
    return reference
