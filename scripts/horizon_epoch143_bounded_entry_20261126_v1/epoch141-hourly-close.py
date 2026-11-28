"""Verify and accept the private first hourly segment after the pinned producer exits."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
import time

watch = runpy.run_path(str(Path(__file__).with_name("epoch141-hourly-exit.py")))
helper, root, capture_dir, unit, iid, require = (watch[k] for k in ("suffix", "ROOT", "DEST", "UNIT", "IID", "require"))
ARMED_SHA = "8ad5a7df1b9f45e4dd9f5bde5587c38c24301ee7844583e8929434f540a347b8"
TARGET = re.compile(r"\] qualified original source slot=(\d+) transactions=(\d+) original_entries=(\d+) hidden_boundaries=(\d+) poh_hashes=(\d+)$")
CP = re.compile(r"\] historical checkpoint slot=(\d+) bank_hash=(\w+) accounts_hash=(\w+) last_blockhash=(\w+) "
                r"capitalization=(\d+) transactions=(\d+) tick_height=(\d+) complete=(true|false) writes=(\d+) next_write_version=(\d+)$")


def expected_data():
    actor, refs, _ = watch["frozen"]()
    armed, ar = helper.read(capture_dir/"ARMED.json", 0)
    require(ar["sha256"] == ARMED_SHA and armed["actor"] == actor and armed["bindings"] == refs
            and armed["unit_reference_held"] and armed["pidfd_bound"], "different capture authority")
    expect, er = helper.read(Path(refs["expectations"]["path"]), 0)
    require(er == refs["expectations"] and expect["epoch"] == 141, "different frozen expectations")
    interval = expect["intervals"][0]
    ix = Path(expect["index"]["path"])
    ix_ref, ix_size = helper.file_ref(ix, 0)
    require(ix_ref == expect["index"] and ix_size < 16 << 20, "original index drift")
    raw = ix.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ix_ref["sha256"], "index changed during capture")
    rows = [r for r in json.loads(raw)["slots"] if interval["bootstrap"]["slot"] < r["slot"] <= interval["terminal"]["slot"]]
    slots = [r["slot"] for r in rows]
    digest = hashlib.sha256(b"".join(struct.pack(">Q", v) for v in slots)).hexdigest()
    require(slots == sorted(set(slots)) == interval["original_target_slots"] and len(slots) == interval["original_target_count"]
            and digest == interval["target_slots_sha256_be_u64"] and sum(r["length"] for r in rows) == interval["original_target_bytes"],
            "original target inventory changed")
    parent, pr = helper.read(Path(interval["parent_and_voted_child"]["path"]), 0)
    require(pr == interval["parent_and_voted_child"] and parent["parent_all_manifest_fields_match"]
            and parent["voted_child_bank_and_blockhash_match"], "the preceding voted parent handoff changed")
    return actor, refs, ar, expect, interval


def checkpoints_and_targets(events, actor, interval, manifest_path, verified_text, bounds):
    expected_slots = interval["original_target_slots"]
    targets, checkpoints, finish = {}, {}, []
    for row in events:
        require(row["_SYSTEMD_UNIT"] == unit and row["_SYSTEMD_INVOCATION_ID"] == iid and row["_PID"] == str(actor["producer_pid"])
                and row["_BOOT_ID"] == actor["boot_id"].replace("-", "")
                and bounds[0] <= int(row["__MONOTONIC_TIMESTAMP"]) <= bounds[1], "foreign journal event")
        msg, cursor = row["MESSAGE"], row["__CURSOR"]
        t = TARGET.search(msg)
        if t:
            slot = int(t[1])
            require(slot not in targets and slot in expected_slots, "duplicate or unexpected original target")
            targets[slot] = dict(cursor=cursor, counters=list(map(int, t.groups()[1:])))
            continue
        cp = CP.search(msg)
        if cp:
            slot, bank, accounts, last, capital, txs, tick, complete, writes, version = cp.groups()
            payload = dict(slot=int(slot), bank_hash=bank, accounts_hash=accounts, last_blockhash=last,
                           capitalization=int(capital), transaction_count=int(txs), tick_height=int(tick),
                           slot_complete=complete=="true", write_count=int(writes), next_write_version=int(version))
            require(int(slot) not in checkpoints or checkpoints[int(slot)]["checkpoint"] == payload, "inconsistent checkpoint logs")
            checkpoints[int(slot)] = dict(cursor=cursor,checkpoint=payload)
            continue
        require(msg.endswith("] "+verified_text+" "+str(manifest_path)), "malformed completion event")
        finish.append(cursor)
    require(sorted(targets) == expected_slots and len(finish) == 1, "incomplete original-target or verified-manifest journal")
    require(set(checkpoints) == {interval["bootstrap"]["slot"], interval["terminal"]["slot"]}, "missing endpoint journals")
    return targets, checkpoints, finish[0]


def verify_manifest(manifest, expect, interval, checkpoints):
    require(manifest["epoch"] == 141 and manifest["schema_version"] == 1 and manifest["runtime"] == expect["runtime"]
            and manifest["worker_executable_sha256"] == expect["worker_sha256"]
            and manifest["output_slot_start"] == interval["output_slot_start"] and manifest["output_slot_count"] == interval["output_slot_count"],
            "unexpected runtime or output range")
    for endpoint in ("bootstrap", "terminal"):
        p = interval[endpoint]
        require(manifest[endpoint] == checkpoints[p["slot"]]["checkpoint"] and manifest[endpoint]["slot_complete"]
                and manifest[endpoint]["accounts_hash"] == p["accounts_hash"], "checkpoint differs from native/frozen endpoint")
    versions = manifest["emitted_raw_write_versions"]
    require(manifest["bootstrap"]["next_write_version"] <= versions["start"] < versions["end"] == manifest["terminal"]["next_write_version"],
            "invalid write-version range")


def reader_scope(actor):
    # The sequential reader occupies part of the finished producer's retained reservation.
    current = helper.native_properties(unit, "Id,ActiveState,MainPID,ControlPID,Job")
    require(current["Id"] == unit and current["ActiveState"] == "inactive"
            and current["MainPID"] == current["ControlPID"] == "0" and not current["Job"],
            "first producer slot is still occupied")
    profile, ref = helper.read(Path(actor["contract"]["path"]),0)
    require(ref == actor["contract"] and profile["producer_RAM_bytes"] == 30 << 30
            and profile["producer_CPU_quota_micros"] == 2000000, "retained 141 reservation changed")
    return dict(retained_booking=actor["booking"],producer_terminal=current,reader_max_memory=256 << 20,
                reader_cpu_quota_micros=500000,reader_archive_scratch_bytes=0,
                evidence_HOME_in_existing_allowance=True,external_resource_credit_bytes=0)


def accept():
    actor, refs, arm, expect, interval = expected_data()
    terminal, terminal_ref = helper.read(capture_dir/"PID1_EXIT.json", 0)
    st = terminal["properties"]
    require(terminal["actor"] == actor and terminal["armed"] == arm and terminal["bindings"] == refs and
            st["Id"] == unit and st["InvocationID"] == iid and st["ActiveState"] == "inactive" and
            st["ExecMainPID"] == str(actor["producer_pid"]) and st["Result"] == "success" and
            st["ExecMainCode"] == "1" and st["ExecMainStatus"] == st["MainPID"] == st["ControlPID"] == "0",
            "first interval did not exit cleanly")
    require(not any((root/"guard-receipts"/name).exists() for name in ("stop-intent.json","stop-completion.json")), "guard stopped recorder")
    budget = reader_scope(actor)
    archive = Path(interval["archive_path"]); manifest_path = archive.with_name(archive.name+".segment.json")
    bounds = (int(st["ExecMainStartTimestampMonotonic"]),int(st["ExecMainExitTimestampMonotonic"]))
    message = expect["native_verified_segment_log"]
    pattern = f"qualified original source slot=|historical checkpoint slot=({interval['bootstrap']['slot']}|{interval['terminal']['slot']}) |{message}"
    output = subprocess.check_output(["/usr/bin/journalctl","--quiet","--no-pager","-o","json",
        "--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_PID", "--grep="+pattern,
        "_BOOT_ID="+actor["boot_id"].replace("-",""), "_PID="+str(actor["producer_pid"]), "_SYSTEMD_UNIT="+unit,
        "_SYSTEMD_INVOCATION_ID="+iid], text=True, timeout=120)
    targets, checkpoints, publish_event = checkpoints_and_targets(
        (json.loads(line) for line in output.splitlines()),actor,interval,manifest_path,message,bounds)
    manifest, mr = helper.read(manifest_path, 1001)
    verify_manifest(manifest,expect,interval,checkpoints)
    archive_ref, size = helper.file_ref(archive, 1001)
    require(size > 0 and archive_ref["sha256"] == manifest["archive_sha256"]
            and helper.file_ref(manifest_path,1001)[0] == mr, "archive or manifest changed")
    dest = capture_dir/"PRIVATE_FIRST_HOURLY_ACCEPTANCE.json"
    if dest.exists():
        prior, published = helper.read(dest,0)
        require(prior["native_terminal"] == terminal_ref and prior["archive"] == archive_ref
                and prior["segment_manifest"] == mr and prior["target_journal"] == {str(k):v for k,v in targets.items()},
                "different existing acceptance")
        return published
    receipt = dict(schema="horizon-141-private-first-hourly-acceptance-v1",recorded_unix_seconds=time.time(),
        epoch=141,producer_invocation_id=iid,bindings=refs,armed=arm,native_terminal=terminal_ref,reader_funding=budget,
        archive=archive_ref,archive_bytes=size,segment_manifest=mr,output_slot_start=manifest["output_slot_start"],
        output_slot_count=manifest["output_slot_count"],terminal_slot=manifest["terminal"]["slot"],
        original_target_count=len(targets),original_target_bytes=interval["original_target_bytes"],
        target_slots_sha256_be_u64=interval["target_slots_sha256_be_u64"],target_journal=targets,checkpoints=checkpoints,
        verified_manifest_journal_cursor=publish_event,publication_authorized=False,resource_credit_bytes=0)
    helper.AUTHORITY = capture_dir
    helper.persist(dest,receipt)
    return helper.file_ref(dest,0)[0]


if __name__=="__main__":
    require(sys.argv[1:] in (["check"],["accept"]), "expected check or accept")
    if sys.argv[1]=="check":
        actor, refs, arm, _, interval = expected_data()
        print(json.dumps(dict(actor=actor["producer_invocation_id"],bindings=refs,armed=arm,targets=interval["original_target_count"])))
    else:
        print(json.dumps(accept()),flush=True)
