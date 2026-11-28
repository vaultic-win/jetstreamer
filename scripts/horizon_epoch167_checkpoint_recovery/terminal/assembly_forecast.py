"""Read-only observation and delivery forecast for the booked private epoch 167 assembler."""

import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch167-assembly-20261127-v1")
STATE = RUNTIME / "assembly-turnover-v1"
RECEIPTS = Path("/home/sol/.jetstreamer-private/r2-status-receipts")
OUTPUT = Path("/home/sol/.jetstreamer-private/epoch167-private-assembly-20261127-v1/output")
UNIT = "horizon-167-private-v3-assembly-20261127-v1.service"
INVOCATION = "ef910ddc2a6545bf9691d23389ad0bfa"
BOOT = "763ea84ca81f4dddad364b1ea2ba36dd"
CAP = 128 << 30
SCHEMA = "horizon-167-private-assembly-observation-v1"
UTC = timezone.utc


def ref(path, digest):
    return {"path": str(path), "sha256": digest}


BOOKING = ref(STATE / "BOOKED.json", "76196db58c045a44b3b910823a60ae16db769302c4bff681ccd1598eb3b856e9")
DISPATCH = ref(STATE / "DISPATCH_RESULT.json", "34f8da8e9b786d6374f371252485fd794f4c64bee47d2adcafc554455099053e")
BASELINE = ref(STATE / "FIRST_ASSEMBLY_RUNTIME_ESTIMATE.json", "0ea3a5336e0dfbf67f7e7a9c606bf9adc1fdf72077b438636031e466490f691d")
TAIL = ref(RECEIPTS / "cycle111808-live166167170-19-20261128-v1/epoch-167.receipt.json", "aecc501f0435e6f1757d32718dce6da83f54579c714cdc886c4227c0a2b019b2")
FIRST_OUTPUT = ref(RECEIPTS / "event-167-native-assembly-aecc501f0435e6f1/RECEIPT.json", "1c703022a082d43c57a1df2aa02821ae0ab71c7b802b18e4ccd07145889bc04c")
TERMINAL = STATE / "PRIVATE_TERMINAL.json"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path, expected=None):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, f"indirect evidence {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        s = os.fstat(handle.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_gid == 0
                and s.st_nlink == 1 and not s.st_mode & 0o022 and s.st_size <= 4 << 20,
                f"untrusted evidence {path}")
        data = handle.read(s.st_size + 1)
        require(len(data) == s.st_size and os.fstat(handle.fileno()).st_ctime_ns == s.st_ctime_ns,
                f"changed evidence {path}")
    actual = ref(path, digest(data))
    require(expected is None or actual == expected, f"evidence digest mismatch {path}")
    return json.loads(data), actual


def checked(reference):
    return read_json(reference["path"], reference)[0]


def status_receipt(reference):
    path = Path(reference["path"])
    require(path.is_relative_to(RECEIPTS), "predecessor outside authenticated receipt store")
    data = checked(reference)
    after = data["after_status"]
    wire = (json.dumps(after, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(data["authenticated_readback"] is True and data["key"] == "epoch-167.epoch-status.json"
            and data["epoch"] == after["epoch"] == 167 and digest(wire) == data["after_sha256"],
            "invalid authenticated epoch 167 predecessor")
    return data


def instant(value):
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(date.utcoffset() == timedelta(0), "timestamp must be UTC")
    return date


def millis(delta):
    return delta // timedelta(milliseconds=1)


def wire_time(date):
    return date.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def basis():
    booked, dispatch, model = map(checked, (BOOKING, DISPATCH, BASELINE))
    plan = checked(booked["plan"])
    require(dispatch["booking"] == model["current_booking"] == BOOKING and dispatch["boot"] == BOOT
            and model["current_invocation"] == dispatch["unit"]["InvocationID"] == INVOCATION
            and booked["unit"] == dispatch["unit"]["Id"] == UNIT
            and plan["epoch"] == 167 and plan["output_directory"] == str(OUTPUT)
            and plan["publication_authorized"] is False, "booking, invocation or destination changed")
    comparator = checked(model["comparison_report"])
    require(comparator["epoch"] == 168 and comparator["slots"] == model["comparison_slots"] == 432000
            and comparator["archive_bytes"] == model["comparison_archive_bytes"],
            "comparison archive identity changed")
    source = status_receipt(FIRST_OUTPUT)
    anchor = source["archive_sample"]
    require(source["assembly_invocation_id"] == INVOCATION and source["assembly_unit"]["Id"] == UNIT
            and not anchor["complete"] and Path(anchor["path"]).parent.parent == OUTPUT,
            "first output does not belong to this assembly")
    tail = status_receipt(TAIL)["terminal_delivery_estimate"]["delivery_tail_ms"]
    require(tail == 99_109_684, "delivery estimate binding changed")
    return booked, dispatch, model, anchor, tail


def unit_state(fields):
    cmd = ["/usr/bin/systemctl", "show", UNIT, "--no-pager", "-p", ",".join(fields)]
    raw = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=8).stdout
    return dict(line.split("=", 1) for line in raw.splitlines())


def file_stamp(s):
    return [s.st_dev, s.st_ino, s.st_size, *divmod(s.st_mtime_ns, 10**9),
            *divmod(s.st_ctime_ns, 10**9)]


def sample_archive(path, anchor, complete):
    require(path.resolve(strict=True) == path, f"indirect archive {path}")
    s = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and s.st_nlink == 1
            and (s.st_dev, s.st_ino) == (anchor["device"], anchor["inode"])
            and stat.S_IMODE(s.st_mode) in ((0o400,) if complete else (0o600, 0o400))
            and 0 < s.st_size <= CAP, "output identity, mode or extent changed")
    return {"path": str(path), "device": s.st_dev, "inode": s.st_ino, "size": s.st_size,
            "complete": complete}, s


def live_sample(booked, dispatch, anchor):
    expected = dispatch["unit"]
    before = unit_state(expected)
    require(before == expected, "assembly no longer matches its running dispatch")
    proc = Path("/proc") / before["MainPID"]
    require((proc / "cgroup").read_text().strip() == "0::" + before["ControlGroup"]
            and Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "") == BOOT,
            "assembly cgroup or boot changed")
    argv = booked["argv"][booked["argv"].index("--") + 1:]
    require((proc / "cmdline").read_bytes() == os.fsencode("\0".join(argv) + "\0")
            and os.path.samefile(proc / "exe", argv[0]), "assembly image or invocation arguments changed")
    image = Path(argv[0])
    s = image.stat()
    require(image.resolve(strict=True) == image and s.st_uid == 0 and s.st_gid == 0
            and stat.S_IMODE(s.st_mode) == 0o555 and s.st_nlink == 1
            and digest(image.read_bytes()) == booked["source"]["assembler"]["sha256"],
            "assembly image seal mismatch")
    path = Path(anchor["path"])
    require(path.name == "epoch-167.jet" and re.fullmatch(r"\.pending-167-[A-Za-z0-9]+", path.parent.name)
            and path.parent.parent == OUTPUT and path.parent.stat().st_uid == 0,
            "wrong pending archive path")
    fd = Path(anchor["producer_fd"])
    require(fd.parent == proc / "fd" and fd.name.isdecimal() and fd.readlink() == path,
            "assembler lost its booked output descriptor")
    fdinfo = dict(row.split(":", 1) for row in (proc / "fdinfo" / fd.name).read_text().splitlines())
    require(int(fdinfo["flags"], 8) & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR),
            "assembler output descriptor is read-only")
    archive, s = sample_archive(path, anchor, False)
    require((s.st_dev, s.st_ino) == (fd.stat().st_dev, int(fdinfo["ino"]))
            and fd.stat().st_ino == s.st_ino and before == unit_state(expected),
            "assembler or open output changed while sampled")
    archive["producer_fd"] = str(fd)
    return {"state": "running", "assembly_unit": before, "archive_sample": archive}


def terminal_sample(booked, anchor):
    terminal, terminal_ref = read_json(TERMINAL)
    event = terminal["native_terminal"]
    require(terminal["success"] is True and terminal["booking"] == BOOKING
            and terminal["publication_authorized"] is False and terminal["unit"] == UNIT
            and event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            and event["UNIT"] == UNIT and event["INVOCATION_ID"] == INVOCATION
            and event["_BOOT_ID"] == BOOT and event["_PID"] == "1" and event["_UID"] == "0",
            "wrong native terminal booking or event")
    report_ref = terminal["private_assembly"]
    accepted = OUTPUT / "accepted"
    require(report_ref["path"] == str(accepted / "assembly.json"), "wrong private report path")
    report = checked(report_ref)
    path = accepted / "epoch-167.jet"
    archive, s = sample_archive(path, anchor, True)
    require(report["schema"] == "horizon-167-private-mixed-worker-assembly-v1"
            and report["invocation"] == INVOCATION and report["unit"] == UNIT and report["epoch"] == 167
            and report["plan"] == booked["plan"] and report["publication_authorized"] is False
            and report["slots"] == 432000 and report["first_slot"] == 72144000 and report["last_slot"] == 72575999
            and report["private_archive"] == str(path) and report["archive_bytes"] == s.st_size
            and re.fullmatch("[0-9a-f]{64}", report["archive_sha256"])
            and file_stamp(s) == terminal["archive_identity"], "private terminal result changed")
    end = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(event["__REALTIME_TIMESTAMP"]))
    return {"state": "terminal", "terminal_at_utc": end.isoformat(), "terminal": terminal_ref,
            "private_report": report_ref, "archive_sha256": report["archive_sha256"], "archive_sample": archive}


def native_observation(booked, dispatch, anchor):
    if TERMINAL.exists():
        data = terminal_sample(booked, anchor)
    else:
        try:
            data = live_sample(booked, dispatch, anchor)
        except (OSError, ValueError, subprocess.SubprocessError):
            if not TERMINAL.exists():
                raise
            data = terminal_sample(booked, anchor)
    return dict(data, schema=SCHEMA, booking=BOOKING, dispatch=DISPATCH, invocation=INVOCATION,
                observed_at_utc=datetime.now(UTC).isoformat())


def observe():
    """Return a native observation. Does not create files or contact R2."""
    booked, dispatch, _, anchor, _ = basis()
    return native_observation(booked, dispatch, anchor)


def previous_measurement(previous, first_ref, anchor):
    archive = previous.get("archive_sample") or {}
    observed = previous.get("assembly_observed_at_utc")
    if not observed and first_ref == FIRST_OUTPUT:
        observed = previous["after_status"]["sampled_at_utc"]
    if (not observed or previous.get("assembly_invocation_id") != INVOCATION
            or any(archive.get(k) != anchor[k] for k in ("path", "device", "inode"))
            or archive.get("complete") is not False):
        return None
    return instant(observed), archive["size"]


def assembly_time(sample, previous, model):
    start = instant(model["current_start_utc"])
    now = instant(sample["observed_at_utc"])
    elapsed = millis(now - start)
    size = sample["archive_sample"]["size"]
    expected = model["comparison_archive_bytes"]
    basis_ms = model["comparison_wall_usec"] // 1000
    require(elapsed >= 0 and expected > 0 and basis_ms > 0, "inconsistent assembly timing")
    if sample["state"] == "terminal":
        end = instant(sample["terminal_at_utc"])
        require(start <= end <= now, "terminal outside observed assembly lifetime")
        return end, {"method": "native successful assembly exit", "remaining_at_observation_ms": 0}
    require(sample["state"] == "running", "unrecognized assembly state")
    units_left = max(0, expected - size)
    # The comparator is a different epoch. Keep time for writes beyond its size and final fsync.
    floor_ms = max(1, basis_ms // 20)
    method = "matched whole-epoch assembly duration at startup"
    remaining = max(floor_ms, basis_ms - elapsed)
    details = {}
    if elapsed >= 120_000 and size >= 256 << 20:
        method = "observed bytes since native start"
        remaining = (units_left * elapsed) // size
        if previous is not None:
            duration = millis(now - previous[0])
            growth = size - previous[1]
            require(duration >= 0 and growth >= 0, "bound observation went backwards")
            if duration >= 120_000:
                details.update(interval_ms=duration, interval_growth_bytes=growth)
                if growth:
                    # Mix the interval with the entire invocation to temper short-lived contention.
                    remaining = (remaining + units_left * duration // growth) // 2
                    method = "mean of same-inode interval and invocation-wide time-to-size estimates"
                else:
                    remaining += duration
                    method = "no measured interval growth; cumulative estimate plus observed wait"
    remaining = max(remaining, floor_ms)
    details.update(method=method, remaining_at_observation_ms=remaining, expected_archive_bytes=expected,
                   comparator_wall_ms=basis_ms, completion_allowance_floor_ms=floor_ms)
    return now + timedelta(milliseconds=remaining), details


def forecast(stamp, previous_receipt, sample=None):
    """Return six wire fields and private provenance. An optional sample is a sealed observation ref."""
    timestamp = instant(stamp)
    require(wire_time(timestamp) == stamp, "wire timestamp must use UTC whole seconds")
    booked, dispatch, model, anchor, tail_ms = basis()
    previous = status_receipt(previous_receipt)
    require(instant(previous["after_status"]["sampled_at_utc"]) < timestamp, "predecessor is not earlier")
    require(previous["after_status"]["phase"] in ("verification", "replay"),
            "delivery has another owner")
    if sample is None:
        observation = native_observation(booked, dispatch, anchor)
    else:
        p = Path(sample["path"])
        require(p.parent == STATE and re.fullmatch(r"FORECAST_SAMPLE_[0-9]+\.json", p.name),
                "unrecognized sealed observation location")
        observation = checked(sample)
        require(stat.S_IMODE(p.stat().st_mode) == 0o400, "observation must be sealed read-only")
    require(observation["schema"] == SCHEMA and observation["booking"] == BOOKING
            and observation["dispatch"] == DISPATCH and observation["invocation"] == INVOCATION,
            "observed assembly identity mismatch")
    archive = observation["archive_sample"]
    terminal = observation["state"] == "terminal"
    expected_path = str(OUTPUT / "accepted" / "epoch-167.jet") if terminal else anchor["path"]
    require(archive["path"] == expected_path and archive["complete"] is terminal
            and archive["inode"] == anchor["inode"] and archive["device"] == anchor["device"]
            and type(archive["size"]) is int and 0 < archive["size"] <= CAP,
            "observed output is not the admitted archive")
    observed = instant(observation["observed_at_utc"])
    require(abs((observed - timestamp).total_seconds()) <= 300,
            "observation does not describe this cadence; take a new sample")
    if terminal:
        require(observation["terminal"]["path"] == str(TERMINAL)
                and observation["private_report"]["path"] == str(OUTPUT / "accepted" / "assembly.json"),
                "terminal observation evidence changed")
        require(instant(observation["terminal_at_utc"]) <= timestamp + timedelta(seconds=1),
                "private assembly terminal follows this cutoff")
    else:
        require(observation["assembly_unit"] == dispatch["unit"] and archive["producer_fd"] == anchor["producer_fd"],
                "observation lost its native assembly owner")
    prior = previous_measurement(previous, previous_receipt, anchor)
    end, timing = assembly_time(observation, prior, model)
    eta = end + timedelta(milliseconds=tail_ms)
    remaining = millis(eta - timestamp)
    require(remaining > 0, "delivery estimate elapsed; bind current verification or delivery owner")
    start = instant(model["current_start_utc"])
    elapsed = millis((end if terminal else timestamp) - start)
    require(elapsed >= 0, "cadence precedes booked assembly")
    after = dict(epoch=167, sampled_at_utc=stamp, phase="verification", elapsed_execution_millis=elapsed,
                 jet_size_bytes=archive["size"], estimated_remaining_millis=remaining)
    timing.update(assembly_start=model["current_start_utc"], assembly_end=end.isoformat(),
                  expected_sidecar_utc=eta.isoformat(), assembly_forecast=BASELINE,
                  assembly_remaining_ms=max(0, millis(end - timestamp)), delivery_tail_ms=tail_ms,
                  delivery_tail_source=TAIL, full_replay_ms=0,
                  assumptions="Epoch 168 V4 sizes epoch 167 V3 imperfectly. "
                  "The 5% running floor allows a larger output or final fsync. "
                  "Delivery includes independent verification, upload, readback and public playback.")
    extra = dict(assembly_invocation_id=INVOCATION, assembly_observed_at_utc=observed.isoformat(),
                 assembly_observation=observation, assembly_observation_ref=sample, archive_sample=archive,
                 terminal_delivery_estimate=timing, current_repair_owner=None, producer_invocation_id=None,
                 measured_canonical_progress=False, archive_publication_authorized=False,
                 measured_private_assembly_bytes=archive["size"], replay_launch_authorized=False)
    return after, extra
