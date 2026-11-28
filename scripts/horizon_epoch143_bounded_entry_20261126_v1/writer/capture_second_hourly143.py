"""Bind epoch 143's first replay marker after the restored checkpoint to its guarded worker."""

import datetime as dt
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from launch_second_hourly143 import BASE, GUARD, HELD, RECEIPTS, TREE, UNIT, durable, need, props, read, ref, run


START = 61_787_632
END = 61_794_627
MARKER = re.compile(r"\bprogress slot (\d+)/(\d+).*? txs=(\d+) accounts=(\d+)")
CHECKPOINT = "epoch 143 verified the same worker's full restored checkpoint at slot 61787631 before replay entries"


def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])


def sample(item, actor, worker):
    guard = json.loads(item.read_bytes())
    physical = guard["root_physical_observation"]
    if (guard["producer_invocation_id"] != actor["producer_invocation_id"] or
            not any(pid == worker and 0 < vmas <= 3_500_000 for pid, vmas in guard["workers"])):
        return None
    need(guard["producer"]["pid"] == actor["producer_pid"] and guard["plan_sha256"] == actor["guard_plan"]["sha256"]
         and guard["producer_stop_enabled"] and guard["maximum_root_physical_bytes"] == TREE
         and guard["trip_reason"] is guard["root_physical_observation_error"] is guard["worker_observation_error"] is None
         and physical["exceeds_budget"] is False, "worker lost guard protection")
    return dict(receipt=ref(item), sample_unix_seconds=guard["recorded_unix_seconds"],
                tree_bytes=min(physical[key]["physical_bytes"] for key in ("first", "second")), cap_bytes=TREE)


def capture():
    held = ref(HELD)
    actor = read(held)
    iid, pid = actor["producer_invocation_id"], actor["producer_pid"]
    native = props(UNIT, "InvocationID", "MainPID", "ActiveState", "ControlGroup", "Job")
    timer = props(GUARD + ".timer", "InvocationID", "ActiveState", "BindsTo", "Job")
    need(native == dict(InvocationID=iid, MainPID=str(pid), ActiveState="active",
                        ControlGroup=f"/system.slice/{UNIT}", Job="")
         and timer == dict(InvocationID=actor["guard_timer_invocation_id"], ActiveState="active", BindsTo=UNIT, Job="")
         and ticks(pid) == actor["start_ticks"] and (BASE / "barrier/allow").read_text() == iid,
         "no live released epoch 143 guard")
    cgroup = Path("/sys/fs/cgroup") / native["ControlGroup"].lstrip("/")
    workers = []
    for line in (cgroup / "cgroup.procs").read_text().splitlines():
        current = int(line)
        path = Path(f"/proc/{current}/exe")
        try:
            name = path.readlink()
            if name.name == "historical-worker":
                workers.append((current, name, ref(path)["sha256"], ticks(current)))
        except FileNotFoundError:
            continue
    if not workers:
        return None
    [(worker, path, digest, worker_ticks)] = workers
    contract = read(actor["contract"])
    need(digest == contract["worker"]["sha256"] and path.is_relative_to(contract["private_run"]),
         "restored historical worker differs from contract")
    selectors = dict(_SYSTEMD_UNIT=UNIT, _SYSTEMD_INVOCATION_ID=iid, _PID=str(pid),
                     _BOOT_ID=actor["boot_id"].replace("-", ""))
    records = run("journalctl", "-q", "--no-pager", "-o", "json", "--grep=verified the same worker's full restored checkpoint|progress slot ",
                  *(f"{key}={value}" for key, value in selectors.items()))
    entries = [json.loads(line) for line in records.splitlines()]
    for item in entries:
        need(all(item[key] == value for key, value in selectors.items()), "foreign journal progress")
    checkpoints = [item for item in entries if CHECKPOINT in item["MESSAGE"]]
    if not checkpoints:
        return None
    checkpoint, = checkpoints
    guard_rows = [row for item in RECEIPTS.glob("sample-*.json") if (row := sample(item, actor, worker))]
    guard_rows.sort(key=lambda row: row["sample_unix_seconds"])
    for item in entries:
        match = MARKER.search(item["MESSAGE"])
        if not match:
            continue
        slot, end, transactions, accounts = map(int, match.groups())
        when = int(item["__REALTIME_TIMESTAMP"])
        need(START <= slot <= end == END and when > int(checkpoint["__REALTIME_TIMESTAMP"]),
             "replay marker predates the restored checkpoint or exceeds the private interval")
        if not transactions:
            continue
        before = [row for row in guard_rows if row["sample_unix_seconds"] * 1_000_000 <= when]
        after = [row for row in guard_rows if row["sample_unix_seconds"] * 1_000_000 > when]
        if not before or not after:
            continue
        need(props(UNIT, *native) == native and props(GUARD + ".timer", *timer) == timer
             and ticks(worker) == worker_ticks and not (RECEIPTS / "stop-intent.json").exists(),
             "producer or live guard changed during progress capture")
        return durable(BASE / "FIRST_PROTECTED_PROGRESS.json", dict(
            schema="horizon-epoch143-second-hourly-first-protected-progress-v1", held_owner=held,
            producer_invocation_id=iid, producer_pid=pid, worker_path=str(path), worker_pid=worker,
            worker_sha256=digest, worker_start_ticks=worker_ticks, slot=slot, last_requested_slot=end,
            transactions=transactions, account_updates=accounts, journal_cursor=item["__CURSOR"],
            journal_message=item["MESSAGE"], checkpoint_journal_cursor=checkpoint["__CURSOR"],
            event_at=dt.datetime.fromtimestamp(when / 1_000_000, dt.timezone.utc).isoformat(),
            guard_before=before[-1], guard_after=after[0], archive_publication_authorized=False,
        ))
    return None


if __name__ == "__main__":
    existing = BASE / "FIRST_PROTECTED_PROGRESS.json"
    print(json.dumps(ref(existing) if existing.exists() else capture()))
