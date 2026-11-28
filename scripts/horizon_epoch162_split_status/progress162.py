"""Recover the issued 162 worker's private journal progress at the coordinated cutoff."""

import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess

from initial162 import checked, need

UNIT = "horizon-qualify-162-first-hourly-completion-20261127-v2.service"
SCRATCH = "/home/sol/.jetstreamer-private/epoch162-first-hourly-completion-20261127-v2/scratch"
MARKER = re.compile(r"\bblock slot (\d+) total_txs=(\d+)\b")


def seconds(stamp):
    return int(dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())


def journal(selectors, since, until):
    # An explicit window and no -n preserve chronological output. journalctl with
    # -n and --grep returns records newest first on this host.
    args = ["/usr/bin/journalctl", "-q", "--no-pager", "-o", "json",
            "--since=@" + str(since), "--until=@" + str(until),
            "--grep=block slot [0-9]+ total_txs=",
            "--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_PID,_BOOT_ID",
            *(k + "=" + v for k, v in selectors.items())]
    result = subprocess.run(args, capture_output=True, timeout=30)
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return []  # journalctl --grep found no matches
    result.check_returncode()
    need(len(result.stdout) <= 8 << 20, "oversize private 162 journal window")
    return [json.loads(line) for line in result.stdout.splitlines()]


def work(records, selectors, since, until, start_us):
    points = []
    for record in records:
        need(all(record.get(k) == v for k, v in selectors.items()), "foreign 162 journal record")
        match = MARKER.search(record["MESSAGE"])
        need(match is not None, "unrecognized 162 block marker")
        slot, transactions = map(int, match.groups())
        real, mono = int(record["__REALTIME_TIMESTAMP"]), int(record["__MONOTONIC_TIMESTAMP"])
        need(since * 1_000_000 <= real <= until * 1_000_000, "162 record outside sample window")
        if mono < start_us:
            continue
        need(69_984_000 <= slot <= 69_991_076, "162 record outside admitted interval")
        points.append(dict(slot=slot, transactions=transactions, monotonic_us=mono,
                           realtime_microseconds=real, cursor=record["__CURSOR"]))
    if len(points) < 2:
        return None
    first, last = points[0], points[-1]
    if (any(a["slot"] > b["slot"] or a["transactions"] > b["transactions"]
            or a["monotonic_us"] >= b["monotonic_us"] or a["realtime_microseconds"] > b["realtime_microseconds"]
            for a, b in zip(points, points[1:])) or first["slot"] == last["slot"]
            or first["transactions"] == last["transactions"] or first["realtime_microseconds"] == last["realtime_microseconds"]):
        return None
    duration = (last["monotonic_us"] - first["monotonic_us"]) / 1_000_000
    return dict(journal_invocation_id=selectors["_SYSTEMD_INVOCATION_ID"], since_unix_seconds=since,
                until_unix_seconds=until, matching_markers=len(points), first=first, last=last,
                elapsed_seconds=duration, slot_delta=last["slot"] - first["slot"],
                transaction_delta=last["transactions"] - first["transactions"], sufficient_for_rates=True)


def reconcile(row, sample, *, read=checked, read_journal=journal):
    """Called on a row returned by the sealed status162.observe(), or its frozen census."""
    if row is None or row["phase"] != "worker" or row["transaction_replay_claimed"]:
        return row
    native = row["native_diagnostic"]
    need(read(row["observer"]) == sample, "different 162 observer receipt")
    matches = [record for record in sample["diagnostic_replays"] if record["range"] == "162"]
    need(matches == ([native] if native else []), "different 162 diagnostic input")
    if native and native.get("error") != f"failed to inspect scratch {SCRATCH}: No such file or directory (os error 2)":
        return row
    actor, worker = row["actor"], row["worker"]
    iid = row["producer_invocation_id"]
    need(row["epoch"] == 162 and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"]
         and actor == read(row["held_owner"]) and actor["producer_unit"] == UNIT
         and row["unit"]["Id"] == UNIT and row["unit"]["ActiveState"] == "active" and row["unit"]["SubState"] == "running"
         and re.fullmatch("[0-9a-f]{32}", iid) and actor["producer_invocation_id"] == row["unit"]["InvocationID"] == iid
         and str(actor["producer_pid"]) == row["unit"]["MainPID"] and actor["mounts"] == row["mounts"]
         and re.fullmatch(r"[0-9a-f]{32}", actor["boot_id"].replace("-", ""))
         and row["mounts"]["scratch_device"] != row["mounts"]["disk_device"]
         and Path(worker["path"]).is_relative_to(SCRATCH) and Path(worker["path"]).name == "historical-worker"
         and 0 < actor["start_ticks"] <= worker["start_ticks"] and worker["pid"] > 1, "unbound 162 worker")
    if native:
        need(native["status"] == "unavailable" and native["observation"] is None
             and native["producer_unit"] == UNIT and native["expected_producer_invocation_id"] == iid
             and native["scratch_path"] == SCRATCH and not any(native[k] for k in
                 ("ordinary_replay_claim","publication_authorized","replay_launch_authorized","r2_mutations")),
             "different unavailable 162 diagnostic")
    cadence = sample["cadence"]
    prev = {"path": cadence["previous_sample"], "sha256": cadence["previous_sample_sha256"]}
    prev_sample = read(prev)
    need(prev_sample["recorded_at_utc"] == cadence["previous_sample_recorded_at_utc"]
         and prev_sample["schema"] == sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
         "different prior 162 cadence window")
    until = seconds(sample["recorded_at_utc"])
    since = max(seconds(prev_sample["completed_at_utc"]), until - 1800)
    need(since < until, "invalid 162 journal observation window")
    guard = read(row["guard"])
    guard_plan = read(actor["guard_plan"])
    producer = guard["producer"]
    need(guard["producer_invocation_id"] == producer["invocation_id"] == guard_plan["invocation_id"] == iid
         and guard["producer_stop_enabled"] and guard["trip_reason"] is None
         and guard["plan_sha256"] == actor["guard_plan"]["sha256"] and guard_plan["unit"] == UNIT
         and guard["guard_sha256"] == "5be30fba437e03fc26f009247714986dfdc6670426650532b5ec166d67fc9183"
         and not guard["worker_observation_error"] and not guard["root_physical_observation_error"]
         and not guard["root_physical_observation"]["exceeds_budget"]
         and guard["available_bytes"] >= guard["minimum_free_bytes"] == guard_plan["minimum_free_bytes"]
         and producer["pid"] == actor["producer_pid"] and producer["restarts"] == 0
         and producer["cgroup"] == "/system.slice/" + UNIT and len(guard["workers"]) == 1
         and guard["workers"][0][0] == worker["pid"]
         and 0 < guard["workers"][0][1] <= guard["maximum_worker_vmas"] == guard_plan["maximum_worker_vmas"]
         and producer["active"] == "active" and producer["sub"] == "running", "unbound 162 worker guard")
    # The cadence writer may collect its guard shortly after the native cutoff.
    # If it recovered much later, that later census cannot establish historical work.
    if not until - 90 <= guard["recorded_unix_seconds"] <= seconds(sample["completed_at_utc"]) + 90:
        return row
    selectors = dict(_SYSTEMD_UNIT=UNIT, _SYSTEMD_INVOCATION_ID=iid, _PID=str(actor["producer_pid"]),
                     _BOOT_ID=actor["boot_id"].replace("-", ""))
    start = worker["start_ticks"] * 1_000_000 // os.sysconf("SC_CLK_TCK")
    progress = work(read_journal(selectors, since, until), selectors, since, until, start)
    if progress is None:
        return row
    proof = dict(source="guarded producer journal", selectors=selectors, worker=worker, guard=row["guard"],
                 observer=row["observer"], previous_observer=prev, held_owner=row["held_owner"],
                 native_outcome=native["status"] if native else "not enrolled in sample", useful_work=progress)
    return dict(row, private162_journal_progress=proof, transaction_replay_claimed=True)


def wire_row(row):
    """Expose supplemental work to the sealed split_wire.forecast without changing the native receipt."""
    proof = row.get("private162_journal_progress")
    if proof is None:
        return row
    need(row["epoch"] == 162 and row["transaction_replay_claimed"] and proof["guard"] == row["guard"]
         and proof["held_owner"] == row["held_owner"] and proof["worker"] == row["worker"]
         and proof["observer"] == row["observer"], "foreign 162 forecast evidence")
    return dict(row, native_diagnostic={"observation": {"useful_work": proof["useful_work"]}})
