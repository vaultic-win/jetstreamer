"""Maintain the landing forecast for the booked epoch 143 first-hourly replay."""
import datetime as dt
import math
from pathlib import Path
import re
import subprocess
import json
from types import SimpleNamespace

import delivery_eta
from evidence import bound, checked, digest, durable, need
from first_hourly143 import EPOCH143 as PROFILE, recheck
import initial162
import split_wire
import status

EPOCH = PROFILE.epoch
KEY = status.key(EPOCH)
SLOTS = 432_000
START = EPOCH * SLOTS
INITIAL = PROFILE.base / "INITIAL_PUBLIC_STATUS.json"
INTENT = PROFILE.base / "INITIAL_PUBLIC_STATUS_INTENT.json"
FIRST = PROFILE.base / "FIRST_PROTECTED_PROGRESS.json"
HELD = dict(path=str(PROFILE.base / "HELD_OWNER.json"),
            sha256="3e86e32a4e29029bd985a003e94a850d014ee9442a40a45009352577bf817bf8")
MARKER = re.compile(r"\bprogress slot (\d+)/(\d+) [^\n]*? txs=(\d+)")
REVIEW_MS = split_wire.REVIEW


def evidence(row):
    actor = checked(HELD)
    need(row["epoch"] == EPOCH and row["held_owner"] == HELD and row["actor"] == actor
         and actor["contract"] == PROFILE.contract and actor["unit"] == PROFILE.unit
         and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"],
         "another epoch 143 assignment owns this status")
    first = checked(bound(FIRST))
    need(first["held_owner"] == HELD and first["producer_invocation_id"] == actor["producer_invocation_id"]
         and first["producer_pid"] == actor["producer_pid"] and first["worker_sha256"] == PROFILE.worker_sha
         and START <= first["slot"] <= first["last_requested_slot"] == PROFILE.terminal,
         "epoch 143 first recorded slot belongs to another worker")
    if row["phase"] == "worker":
        worker = row["worker"]
        need(worker["pid"] == first["worker_pid"] and worker["start_ticks"] == first["worker_start_ticks"],
             "recorded slot predates this epoch 143 worker")
    return first


def recorded_pair(row, first, until, *, profile=PROFILE, first_path=FIRST):
    """Measure the recorded interval from its retained first block to the same node's latest marker."""
    actor = row["actor"]
    selectors = {"_SYSTEMD_UNIT": profile.unit, "_SYSTEMD_INVOCATION_ID": actor["producer_invocation_id"],
                 "_PID": str(actor["producer_pid"]), "_BOOT_ID": actor["boot_id"].replace("-", "")}
    since = dt.datetime.fromisoformat(first["event_at"])
    result = subprocess.check_output(
        ["/usr/bin/journalctl", "--quiet", "--no-pager", "--output=json", "--lines=4",
         "--grep=INFO  jetstreamer_node.* progress slot ", f"--since=@{since.timestamp():.6f}",
         f"--until=@{until.timestamp():.6f}", *(f"{k}={v}" for k,v in selectors.items())], timeout=15)
    for line in reversed(result.splitlines()):
        event = json.loads(line)
        match = MARKER.search(event["MESSAGE"])
        need(all(event[k] == v for k, v in selectors.items()) and match, "unexpected epoch 143 progress record")
        slot, end, tx = map(int, match.groups())
        micros = int(event["__REALTIME_TIMESTAMP"])
        start_us = round(since.timestamp() * 1_000_000)
        need(max(START, profile.bootstrap + 1) <= slot <= end == profile.terminal and micros <= until.timestamp() * 1_000_000,
             "recorded progress outside the accepted interval or clock")
        if slot > first["slot"] and tx > first["transactions"] and micros > start_us:
            return dict(slot=slot, transactions=tx, cursor=event["__CURSOR"], realtime_us=micros,
                        slots_per_second=(slot-first["slot"])*1_000_000/(micros-start_us),
                        first=bound(first_path), selectors=selectors)
    return None


def forecast(c, row, old=None):
    first = evidence(row)
    closed = row["phase"] == "terminal"
    prev = old["after_status"] if old else None
    sample = recorded_pair(row, first, c.now) if not closed else None
    rate_basis = sample or (old or {}).get("recorded_rate")
    if not rate_basis:
        # At first output the same guarded worker has already advanced from the warmup receipt.
        warmref = bound(PROFILE.base / "FIRST_PROTECTED_REPLAY_SLOT.json")
        warm = checked(warmref)
        need(warm["held_owner"] == HELD and warm["worker_pid"] == first["worker_pid"]
             and warm["worker_start_ticks"] == first["worker_start_ticks"]
             and warm["producer_invocation_id"] == first["producer_invocation_id"]
             and warm["slot"] < START and warm["transactions"] < first["transactions"], "different warmup owner")
        seconds = (dt.datetime.fromisoformat(first["event_at"]) - dt.datetime.fromisoformat(warm["event_at"])).total_seconds()
        need(seconds > 0, "invalid epoch 143 startup clock")
        rate_basis = dict(slot=first["slot"], slots_per_second=(first["slot"]-warm["slot"])/seconds,
                          first=bound(FIRST), warmup=warmref)
    rate = rate_basis["slots_per_second"]
    need(math.isfinite(rate) and rate > 0, "invalid epoch 143 replay rate")
    path = Path(checked(PROFILE.contract)["prepared_output_file"])
    part = split_wire.archive(row, path) if row["phase"] == "worker" else None
    size = part["size"] if part else (prev["jet_size_bytes"] if prev else 0)
    delivery = delivery_eta.estimate(c, EPOCH, size)
    iid = row["actor"]["producer_invocation_id"]
    elapsed = split_wire.elapsed(c, dict(row, producer_invocation_id=iid), prev, old, old is not None)
    if closed and old and old.get("producer_invocation_id") is None:
        age = elapsed-prev["elapsed_execution_millis"]
        need(0 <= age < prev["estimated_remaining_millis"], "epoch 143 repair needs a revised delivery plan")
        remaining = prev["estimated_remaining_millis"]-age
        stages = old["planning_milliseconds"]
    else:
        stages = dict(current_interval=0 if closed else math.ceil((PROFILE.terminal-rate_basis["slot"])*1000/rate),
                      route_review_and_qualification=REVIEW_MS, full_epoch_replay=math.ceil(SLOTS*1000/rate),
                      verified_delivery=delivery["total_millis"])
        remaining = sum(stages.values())
    phase = "replay" if row["phase"] == "worker" else "verification"
    report = dict(epoch=EPOCH, phase=phase, jet_size_bytes=size, sampled_at_utc=c.stamp,
                  elapsed_execution_millis=elapsed, estimated_remaining_millis=remaining)
    return report, dict(private143_held=HELD, first_protected_recording=bound(FIRST), recorded_rate=rate_basis,
                        archive_sample=part, producer_invocation_id=None if closed else iid,
                        current_repair_owner="/root", measured_canonical_progress=False,
                        planning_milliseconds=stages, delivery_forecast=delivery,
                        estimate_model="Finish the private interval, allow 12 hours for route qualification, then budget a full canonical replay at the observed rate and delivery through the verified sidecar.")


def initial(c, row, store):
    """Create once under the sole cadence writer. Recover an uncertain PUT from its durable intent."""
    statuses, ready, archives = store.inventory()
    need(EPOCH not in ready and EPOCH not in archives, "epoch 143 already has an archive or readiness marker")
    if not INTENT.exists():
        need(EPOCH not in statuses and not INITIAL.exists(), "unrecognized initial epoch 143 status")
        report, extra = forecast(c, row)
        recheck(row)
        durable(INTENT, dict(schema="horizon-first-hourly143-initial-status-v1", epoch=EPOCH, key=KEY,
                            previous_receipt=None, conditional_header="If-None-Match", conditional_value="*",
                            after_status=report, after_sha256=digest(status.body(report)), fleet_predecessor=c.fleet_ref,
                            observer=c.sample_ref, archive_publication_authorized=False, **extra))
    pending = checked(bound(INTENT))
    raw = status.body(pending["after_status"])
    need(pending["private143_held"] == row["held_owner"] == HELD and pending["first_protected_recording"] == bound(FIRST)
         and pending["key"] == KEY and pending["epoch"] == EPOCH and pending["after_sha256"] == digest(raw)
         and pending["previous_receipt"] is None, "foreign initial epoch 143 intent")
    acknowledged = None
    if EPOCH not in statuses:
        need(not INITIAL.exists(), "acknowledged epoch 143 status disappeared")
        recheck(row)
        try:
            acknowledged = initial162.conditional_create(store, raw, EPOCH)
        except Exception:
            # A lost acknowledgement is recoverable only from these exact persisted bytes.
            remote_etag, remote_body = store.get(EPOCH)
            need(initial162.valid_etag(remote_etag) and remote_body == raw, "uncertain or foreign initial epoch 143 PUT")
            acknowledged = remote_etag
    etag, observed = store.get(EPOCH)
    need(initial162.valid_etag(etag) and observed == raw and (acknowledged is None or acknowledged == etag),
         "conditional epoch 143 creation lost ownership")
    durable(INITIAL, dict(pending, after_etag=etag, authenticated_readback=True))
    return bound(INITIAL)


def start(head, store):
    fleet = checked(head)
    need(fleet["owner"] == "/root" and not any(r["epoch"] == EPOCH and r["state"] != "missing"
         for r in checked(fleet["authenticated_inventory"])["entries"]), "invalid epoch 143 fleet scope")
    existing = checked(fleet["complete_active_status_audit"])["receipts"].get(str(EPOCH))
    if existing:
        return baseline(existing)
    row = fleet[PROFILE.field]
    recheck(row)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    c = SimpleNamespace(now=now, stamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"), fleet_ref=head,
                        sample_ref=fleet["observer"], prior={"inventory": fleet["authenticated_inventory"]})
    return initial(c, row, store)


def baseline(previous):
    origin = bound(INITIAL)
    initial_status = checked(origin)
    need(initial_status["private143_held"] == HELD and initial_status["conditional_header"] == "If-None-Match"
         and initial_status["previous_receipt"] is None and initial_status["authenticated_readback"], "foreign 143 origin")
    if previous and previous != origin:
        latest = checked(previous)
        need(latest["private143_origin"] == origin and latest["private143_held"] == HELD
             and latest["epoch"] == EPOCH and latest["key"] == KEY and latest["authenticated_readback"]
             and latest["conditional_header"] == "If-Match", "another epoch 143 status chain")
    return previous or origin


def install(fleet, row):
    entry, = (entry for entry in fleet["epochs"] if entry["epoch"] == EPOCH)
    active = row["phase"] != "terminal"
    entry.update(state="executing" if row["phase"] == "worker" else "verification", current_repair_owner="/root",
                 no_live_producer_claimed=not active, repair_open=True, current_private_diagnostic=row,
                 current_status_scope="Private first-hourly interval and canonical delivery planning.")
