"""Rolling wall-clock forecast for the admitted retry8 replay of epoch 167."""
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import stat

from evidence import checked, names, need, utc

EPOCH = 167
PID = 2472615
IID = "93e60160c9164d3781a5b544fc2a48b4"
UNIT = "horizon-qualify-167-replacement-local3retry8-20261110-v1.service"
LOG = Path("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/producer.log")
LOG_INODE = (64512, 107692718)
TERMINAL = 72575999
WINDOWS = 6
CLOCK = re.compile(rb"^\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d{6})\d*Z ")
MARKER = re.compile(rb"jetstreamer_node\] progress slot (\d+)/(\d+) .*? txs=(\d+) accounts=(\d+)")
TRANSPORT = re.compile(rb"jetstreamer::firehose\].*(?:HTTP (?:429|5\d\d)|firehose encountered an error|Error reading until block:|backing off .*before restarting)", re.I)
COUNTERS = ("slot", "transactions", "account_updates")
MODEL = "Six linked half-hour samples of the same replay. Remaining slots use total elapsed wall time, including transport stalls, plus 10 percent and 12 hours."

def epoch_us(stamp):
    return int(utc(stamp).timestamp()) * 1_000_000

def sample_row(ref, sample):
    stamp = sample["recorded_at_utc"]
    need(ref["path"] == str(names(stamp)["sample"]) and sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2", "unexpected sample name or schema")
    need(not any(sample["mutation"].values()), "mutating observer")
    rows = [row for row in sample["replays"] if row["range"] == str(EPOCH)]
    need(len(rows) == 1 and rows[0]["invocation_binding_stable"] is True, "167 sample missing or unstable")
    row = rows[0]
    for key in ("producer_before", "producer_after"):
        owner = row[key]
        need((owner["unit"], owner["invocation_id"], owner["main_pid"], owner["restarts"], owner["active_state"], owner["sub_state"]) ==
             (UNIT, IID, PID, 0, "active", "running"), "167 producer changed")
    work = row["useful_work"]
    log = work["append_log_evidence"]
    need(work["journal_invocation_id"] == IID and work["counter_resets"] == 0 and log["stdout_append_binding_verified"] is True and
         (log["path"], log["device"], log["inode"], log["producer_main_pid"]) == (str(LOG), *LOG_INODE, PID), "167 counter or stdout identity changed")
    need(work["until_unix_seconds"] == epoch_us(stamp) // 1_000_000 and
         0 < work["until_unix_seconds"] - work["since_unix_seconds"] <= 1800, "167 window time mismatch")
    first, last = work["first"], work["last"]
    if first is None or last is None:
        need(first is None and last is None and not work["sufficient_for_rates"] and work["matching_markers"] == 0, "partial 167 marker history")
    else:
        for point in (first, last):
            need(point["terminal_slot"] == TERMINAL and TERMINAL - 431999 <= point["slot"] <= TERMINAL and
                 work["since_unix_seconds"] <= point["realtime_microseconds"] // 1_000_000 <= work["until_unix_seconds"], "167 marker outside window")
        need(first["realtime_microseconds"] <= last["realtime_microseconds"] and
             all(first[k] <= last[k] for k in COUNTERS), "167 markers went backward")
        if work["sufficient_for_rates"]:
            need(all(work[k] == last[c] - first[c] for k, c in zip(("slot_delta","transaction_delta","account_update_delta"),COUNTERS)),
                 "167 counter deltas differ")
    return work, row["scratch_path"]

def chain(ref):
    history = []
    expected_stamp = None
    scratch = None
    for _ in range(WINDOWS):
        sample = checked(ref)
        stamp = sample["recorded_at_utc"]
        need(expected_stamp is None or stamp == expected_stamp, "previous sample timestamp mismatch")
        work, path = sample_row(ref, sample)
        need(scratch is None or scratch == path, "167 scratch changed across samples")
        scratch = path
        history.append((ref, stamp, work))
        cd = sample["cadence"]
        expected_stamp = cd["previous_sample_recorded_at_utc"]
        gap = (utc(stamp) - utc(expected_stamp)).total_seconds()
        need(cd["observation_reason"] == "routine" and cd["routine_minimum_interval_enforced"] is True and
             cd["minimum_interval_seconds"] == 1800 and gap == cd["observed_interval_seconds"] and 1800 <= gap < 2100,
             "167 previous wall-clock interval unqualified")
        ref = {"path": cd["previous_sample"], "sha256": cd["previous_sample_sha256"]}
    history.reverse()
    previous = None
    size = 0
    for _, _, work in history:
        first, last = work["first"], work["last"]
        capture = work["append_log_evidence"]
        need(capture["snapshot_length_bytes"] >= size, "167 stdout shrank between samples")
        size = capture["snapshot_length_bytes"]
        if first:
            need(previous is None or (previous["realtime_microseconds"] < first["realtime_microseconds"] and
                 all(previous[k] <= first[k] for k in COUNTERS)), "167 linked counters regressed")
            previous = last
    return history

def captured_bytes(log):
    start, count, end = (log[k] for k in ("read_offset_bytes","read_bytes","snapshot_length_bytes"))
    need(0 <= start < end and start + count == end and count <= 32 << 20, "invalid captured stdout bounds")
    with os.fdopen(os.open(LOG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        m = os.fstat(handle.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and m.st_uid == 0 and
             (m.st_dev,m.st_ino) == LOG_INODE and m.st_size >= end and LOG.resolve(strict=True) == LOG, "captured stdout identity changed")
        handle.seek(start)
        data = handle.read(count)
        need(len(data) == count and hashlib.sha256(data).hexdigest() == log["read_sha256"], "captured stdout digest differs")
    return data

def recovery(work, data):
    start, end = work["since_unix_seconds"] * 1_000_000, (work["until_unix_seconds"] + 1) * 1_000_000
    work_start_tag = dt.datetime.fromtimestamp(start // 1_000_000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S").encode()
    work_end_tag = dt.datetime.fromtimestamp((end - 1) // 1_000_000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S").encode()
    latest_error = None
    points = []
    first, last = work["first"], work["last"]
    for line in data.splitlines():
        if b"progress slot " not in line and not TRANSPORT.search(line):
            continue
        clock = CLOCK.match(line)
        if not clock:
            continue
        # Compare coarse UTC text first; avoid parsing the entire captured log.
        sec = clock[1]
        if sec < work_start_tag or sec > work_end_tag:
            continue
        time = epoch_us(sec.decode()+"Z") + int(clock[2])
        if not start <= time < end:
            continue
        if TRANSPORT.search(line):
            latest_error = time if latest_error is None else max(time, latest_error)
        match = MARKER.search(line)
        if match and int(match[2]) == TERMINAL:
            points.append((time, int(match[1]), int(match[3]), int(match[4])))
    if first and last:
        for point in (first, last):
            need((point["realtime_microseconds"], *(point[k] for k in COUNTERS)) in points, "167 native log does not contain observer endpoint")
    if not points or last is None:
        return False, latest_error
    cutoff = last["realtime_microseconds"]
    threshold = max(cutoff - 120_000_000, latest_error or 0)
    recent = [p for p in points if threshold < p[0] < cutoff]
    progressing = end - cutoff <= 120_000_000 and any(p[1] < last["slot"] and p[2] < last["transactions"] for p in recent)
    return progressing, latest_error

def forecast(ref, previous_remaining):
    history = chain(ref)
    latest = history[-1][2]
    advancing, error = recovery(latest, captured_bytes(latest["append_log_evidence"]))
    points = [w for _,_,w in history if w["first"] is not None]
    if not points:
        return dict(model=MODEL, state="stalled-or-recovery-unproven", samples=[r for r,_,_ in history],
                    first=None, last=None, wall_microseconds=epoch_us(history[-1][1]) - epoch_us(history[0][1]),
                    slot_delta=0, latest_transport_error_us=error, capture_sha256=latest["append_log_evidence"]["read_sha256"],
                    estimated_remaining_millis=previous_remaining)
    first, last = points[0]["first"], points[-1]["last"]
    elapsed = epoch_us(history[-1][1]) - first["realtime_microseconds"]
    slots = last["slot"] - first["slot"]
    left = TERMINAL - last["slot"]
    need(elapsed > 0 and 0 <= slots and left > 0, "terminal or regressed rolling replay")
    estimate = (round(left * elapsed * 11 / (slots * 10000)) + 43_200_000) if slots else previous_remaining
    if not advancing:
        estimate = max(estimate, previous_remaining)
    return dict(model=MODEL, state="advancing" if advancing else "stalled-or-recovery-unproven", samples=[r for r,_,_ in history],
                first=first,last=last,wall_microseconds=elapsed,slot_delta=slots,latest_transport_error_us=error,
                capture_sha256=latest["append_log_evidence"]["read_sha256"],estimated_remaining_millis=estimate)
