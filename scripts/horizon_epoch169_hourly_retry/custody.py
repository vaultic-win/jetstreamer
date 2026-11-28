"""Bind the interrupted hourly span, its reason for stopping and its retained bytes."""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c


def manager(unit, invocation, boot):
    raw = subprocess.check_output(["/usr/bin/journalctl", "-q", "--no-pager", "-o", "json",
                                   "_UID=0", "_PID=1", "UNIT=" + unit, "_BOOT_ID=" + boot,
                                   "INVOCATION_ID=" + invocation], timeout=30)
    events = [json.loads(line) for line in raw.splitlines()]
    ids = ["de5b426a63be47a7b6ac3eaac82e2f6f", "7ad2d189f7e94e70a38c781354912448",
           "ae8f7b866b0347b9af31fe1c80b127c0"]
    selected = [row for row in events if row.get("MESSAGE_ID") in ids]
    c.need([row["MESSAGE_ID"] for row in selected] == ids and all(
        (row["_PID"], row["UNIT"], row["INVOCATION_ID"], row["_BOOT_ID"]) == ("1", unit, invocation, boot)
        for row in selected), "different manager stop sequence")
    return [{key: row[key] for key in ("_PID", "_BOOT_ID", "UNIT", "INVOCATION_ID", "MESSAGE_ID",
             "__CURSOR", "__REALTIME_TIMESTAMP", "MESSAGE", "MEMORY_PEAK", "MEMORY_SWAP_PEAK", "CPU_USAGE_NSEC")
             if key in row} for row in selected]


def collect():
    previous = c.OLD_CONTROL
    terminal, terminal_ref = c.read(previous / "results/TERMINAL.json",
        "07e7f475687fecb9cb5fbd154951d84443e4a134c8889f0ce1d8857b884aef3e")
    grant, grant_ref = c.read(previous / "GRANT.json", terminal["grant_sha256"])
    guard = c.OLD / "hourly-guard-receipts"
    intent, intent_ref = c.read(guard / "stop-intent.json",
        "29ae39fcab127923b25302b26a4b505f125f1e9b82d9b957d8513564153dc950", sealed=False)
    end, end_ref = c.read(guard / "stop-completion.json",
        "a49cf5140081a8e0c76e4a235e2610014c648a8b18dcc314cd208f126ada1445", sealed=False)
    sample = intent["sample"]
    plan, plan_ref = c.read(previous / "guard-plan/guard-plan.json", grant["guard_plan_sha256"])
    c.need(terminal["unit"] == grant["unit"] == plan["unit"] == c.OLD_UNIT
           and terminal["invocation_id"] == grant["invocation_id"] == plan["invocation_id"] == c.OLD_IID
           and intent["producer_invocation_id"] == end["producer_invocation_id"] == c.OLD_IID
           and intent["plan_sha256"] == end["plan_sha256"] == plan_ref["sha256"]
           and intent["reason"] == sample["trip_reason"] == "filesystem-floor" and sample["producer_stop_enabled"]
           and sample["producer"]["pid"] == grant["pid"] and sample["producer_invocation_id"] == c.OLD_IID
           and end["terminal"]["pid"] == 0 and end["intent"] == intent_ref["path"] and not end["scratch_deleted"]
           and terminal["disposition"] == "interrupted-or-unclassified" and terminal["archive"] is None
           and terminal["private_span"] is terminal["canonical_publication_authorized"] is False,
           "inconsistent hourly stop provenance")
    shortfall = sample["minimum_free_bytes"] - sample["available_bytes"]
    c.need(shortfall == 87_222_138 and sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
           and sample["root_physical_observation"]["conservative_physical_bytes"] < plan["maximum_root_physical_bytes"]
           and max(vmas for _, vmas in sample["workers"]) < plan["maximum_worker_vmas"], "different stop geometry")
    archive = c.OLD / "v158" / c.BASE_NAME
    manifest = archive.with_suffix(".jet.segment.json")
    c.need(not os.path.lexists(manifest), "a segment manifest already exists")
    partial, _ = c.stable(archive)
    log, data = c.stable(c.OLD / "hourly-run/producer.log", keep_bytes=True)
    c.need(all(log[key] == value for key, value in terminal["log"].items())
           and log["inode"] == grant["log_inode"] and log["device"] == grant["log_device"]
           and partial["size"] == 1_304_621_799 and (partial["device"], partial["inode"]) == (64512,107553266),
           "different stopped archive or log")
    lines = data.decode().splitlines()
    feature, = [s for s in lines if "epoch169 diagnostic bank feature at slot 73239086 entry 164:" in s]
    progress = [s for s in lines if "progress slot " in s][-1]
    emitted = [s for s in lines if "horizon progress: emitted_slot=" in s][-1]
    c.need(feature.endswith("per_byte_logging_cost active=true activated_slot=Some(66528004)")
           and "progress slot 73243205/73245218" in progress and "txs=2389508 " in progress
           and "emitted_slot=73243165 " in emitted and not os.path.lexists(manifest),
           "different v1.5.8 progress")
    events = manager(c.OLD_UNIT, c.OLD_IID, terminal["boot_id"])
    memory = int(events[-1]["MEMORY_PEAK"])
    c.need(0 < memory < c.RAM and int(events[-1]["MEMORY_SWAP_PEAK"]) == 0, "changed previous memory evidence")
    return dict(schema="horizon-169-hourly-interrupted-span-custody-v1", producer_unit=c.OLD_UNIT,
                producer_invocation=c.OLD_IID, terminal=terminal_ref, grant=grant_ref, guard_plan=plan_ref,
                stop_intent=intent_ref, stop_completion=end_ref, disposition="guard-stop-filesystem-floor",
                shortfall=shortfall, observed_home_available=sample["available_bytes"],
                required_floor=sample["minimum_free_bytes"], retained_log=log, retained_incomplete_archive=partial,
                manifest_path=str(manifest), manifest_present=False, pid1=events, max_observed_ram=memory,
                feature_evidence=feature, last_node_progress=progress, last_archive_progress=emitted,
                complete_private_span=False, resource_credit_bytes=0, canonical_publication_authorized=False)


if __name__ == "__main__":
    output = c.CONTROL / "PREDECESSOR_CUSTODY.json"
    print(json.dumps(c.recorded(output, collect())))
