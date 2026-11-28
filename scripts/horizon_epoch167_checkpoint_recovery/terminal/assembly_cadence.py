"""Freeze one private assembly measurement per accepted observer and retain its public wire lineage."""
import json
import os
import stat
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import assembly_forecast as model
from evidence import bound, checked, durable, need


FIELD = "current_epoch167_private_assembly"
FAILURE_ID = "d9b373ed55a64feb8242e02dbe79a49c"
QUALIFIED = model.ref(model.RUNTIME / "assembly-forecast-evidence-v1/LIVE_QUALIFICATION.json",
                      "269414975610cbf17462b3e2c43e8b1a2aa59f162a0fc0f7a3d1fb0327e81354")
DEPLOYMENT = model.ref(model.RUNTIME / "assembly-forecast-v1/deployment-seal-receipt.json",
                       "7021e267882b06e70fca022c6b1a1a455ae69997b0004a1e278ed7c421b2af9a")


def observation():
    try:
        return model.observe()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Only an exact PID 1 failure can replace a booked live owner with repair planning.
        filters = ["_PID=1", "_UID=0", "UNIT=" + model.UNIT, "_BOOT_ID=" + model.BOOT,
                   "INVOCATION_ID=" + model.INVOCATION, "MESSAGE_ID=" + FAILURE_ID]
        cmd = ["/usr/bin/journalctl", "--quiet", "--no-pager", "-o", "json", *filters]
        rows = [json.loads(line) for line in subprocess.check_output(cmd, timeout=10).splitlines()]
        if not rows:
            raise error
        event, = rows
        need(all(event[key] == val for key, val in (text.split("=", 1) for text in filters)),
             "foreign 167 failure while inspecting assembly")
        unit = model.unit_state(("Id", "ActiveState", "MainPID", "ControlPID", "Job"))
        need(unit["Id"] == model.UNIT and unit["ActiveState"] in ("inactive", "failed")
             and unit["MainPID"] == unit["ControlPID"] == "0" and not unit["Job"],
             "167 has another active assembly owner")
        _, _, _, arc, _ = model.basis()
        path = Path(arc["path"])
        retained = model.sample_archive(path, arc, False)[0] if path.exists() else None
        return dict(schema=model.SCHEMA, state="failed", booking=model.BOOKING, dispatch=model.DISPATCH,
                    invocation=model.INVOCATION, failure=event, archive_sample=retained,
                    observed_at_utc=datetime.now(model.UTC).isoformat())


def owner_binding():
    sample = observation()
    data = dict(booking=model.BOOKING, dispatch=model.DISPATCH, invocation=model.INVOCATION, state=sample["state"])
    if sample["state"] == "running":
        arc = sample["archive_sample"]
        data.update(native_unit=sample["assembly_unit"], output={k:arc[k] for k in ("path","device","inode","producer_fd")})
    elif sample["state"] == "terminal":
        data.update(terminal=sample["terminal"], private_report=sample["private_report"])
    else:
        data["native_failure_cursor"] = sample["failure"]["__CURSOR"]
    return data


def owns(old):
    estimate = old.get("terminal_delivery_estimate") or {}
    return (old["after_status"]["phase"] == "verification"
            and estimate.get("assembly_forecast") == model.BASELINE
            and (old.get("assembly_invocation_id") == model.INVOCATION
                 or estimate.get("assembly_invocation") == model.INVOCATION
                 or old.get("assembly_observation_ref") is not None))


def freeze(c):
    path = model.STATE / f"FORECAST_SAMPLE_{int(c.now.timestamp())}.json"
    if not path.exists():
        data = dict(observation(), observer=c.sample_ref, fleet_predecessor=c.fleet_ref, cadence_stamp=c.stamp)
        need(abs((model.instant(data["observed_at_utc"]) - c.now).total_seconds()) <= 300,
             "167 observation must be frozen with the coordinated fleet")
        durable(path, data)
    binding = bound(path)
    record = checked(binding)
    need(record["observer"] == c.sample_ref and record["fleet_predecessor"] == c.fleet_ref
         and record["cadence_stamp"] == c.stamp and record["booking"] == model.BOOKING
         and record["dispatch"] == model.DISPATCH and record["invocation"] == model.INVOCATION,
         "saved 167 observation belongs to another cycle or owner")
    if stat.S_IMODE(path.stat().st_mode) != 0o400:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            s = os.fstat(fd)
            need(s.st_uid == s.st_gid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600
                 and os.path.samestat(s, path.stat()), "unexpected permissions on the saved 167 observation")
            os.fchmod(fd, 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)
    return binding


def failed(c, snapshot, sample_ref):
    _, _, baseline, _, tail = model.basis()
    repair = model.status_receipt(model.TAIL)["terminal_delivery_estimate"]["repair_and_requalification_ms"]
    event = snapshot["failure"]
    end = datetime(1970, 1, 1, tzinfo=model.UTC) + timedelta(microseconds=int(event["__REALTIME_TIMESTAMP"]))
    restart = baseline["comparison_wall_usec"] // 1000
    eta = end + timedelta(milliseconds=repair + restart + tail)
    remaining = model.millis(eta - c.now)
    need(remaining > 0 and end <= c.now + timedelta(seconds=1),
         "167 repair needs a new delivery owner and revised forecast")
    arc = snapshot["archive_sample"]
    after = dict(epoch=167, phase="verification", sampled_at_utc=c.stamp, jet_size_bytes=arc["size"] if arc else 0,
                 estimated_remaining_millis=remaining, elapsed_execution_millis=model.millis(end - model.instant(baseline["current_start_utc"])))
    timing = dict(assembly_forecast=model.BASELINE, assembly_invocation=model.INVOCATION, failed_at_utc=end.isoformat(),
                  repair_and_requalification_ms=repair, assembly_restart_ms=restart, delivery_tail_ms=tail,
                  delivery_tail_source=model.TAIL, full_replay_ms=0, expected_sidecar_utc=eta.isoformat(),
                  assumptions="Allow the existing repair/requalification budget, one full reassembly of the selected inputs and verified delivery.")
    return after, dict(assembly_observation_ref=sample_ref, assembly_invocation_id=model.INVOCATION,
                       assembly_observed_at_utc=snapshot["observed_at_utc"], terminal_delivery_estimate=timing,
                       archive_sample=arc, producer_invocation_id=None, measured_canonical_progress=False,
                       current_repair_owner="/root", native_assembly_failure=event)


def forecast(c, original, old, terminal_field):
    snap = getattr(c, "assembly167", None) or freeze(c)
    sample = checked(snap)
    if sample["state"] == "failed":
        after, extra = failed(c, sample, snap)
    else:
        after, extra = model.forecast(c.stamp, original, snap)
        # The outer native CAS writes both policy fields itself.
        for key in ("archive_publication_authorized", "replay_launch_authorized"):
            need(extra.pop(key) is False, "unexpected authorization from private assembly")
    need(old.get(terminal_field) == c.failed167, "wrong historical replay predecessor for 167 assembly")
    extra[terminal_field] = c.failed167
    return after, extra


def install(fleet, receipt):
    if not receipt:
        return
    proof = checked(receipt)
    snap = proof.get("assembly_observation_ref")
    if not snap:
        return
    doc = checked(snap)
    need(proof["assembly_invocation_id"] == doc["invocation"] == model.INVOCATION
         and proof["observer"] == doc["observer"] and proof["fleet_predecessor"] == doc["fleet_predecessor"],
         "167 public status and sample have different owners")
    fleet[FIELD] = snap
    row, = (r for r in fleet["epochs"] if r["epoch"] == 167)
    state = doc["state"]
    actions = {"running":"Assemble the selected 167 sources and verify the completed archive.",
               "terminal":"Independently verify the accepted private archive and complete verified delivery.",
               "failed":"Diagnose the native assembly failure and requalify the selected sources."}
    row.update(state="verification", current_status_scope="Private epoch 167 assembly and verified-delivery estimate.",
               next_action=actions[state], no_live_producer_claimed=state != "running",
               current_repair_owner=proof["current_repair_owner"])
