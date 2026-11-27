"""Publish normal native replay status for Foundation's live 260 and 262 singletons."""

import datetime as dt
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, "/var/lib/jetstreamer/horizon249-delivery-v214-tools")
from ordinary249.delivery248 import D, V, aws, bound, funds, props, ref

import replay260
import replay262


LANES = {260: replay260, 262: replay262}
CONTROL = V / "horizon-seven-publication-controller-v222"
STATUS = Path("/home/ubuntu/.jetstreamer-private/r2-status-receipts")
INITIAL = V / "horizon-native260262-status-activation-v1"
BASELINE = {
    "path": str(V / "horizon252-status-delivery-baseline-v1/timing.json"),
    "sha256": "6d5803578f0863c7fc26d25db06b919a1c0f6889c28cbf7dd7650372dced91cd",
}
FIELDS = ["ActiveState", "SubState", "MainPID", "InvocationID", "NRestarts",
          "ExecMainStartTimestamp", "ControlGroup", "Job"]


def adopt(statuses):
    for epoch in LANES:
        path = INITIAL / str(epoch) / "completion.json"
        if epoch not in statuses and path.is_file():
            start = ref(path)
            completed = bound(start)
            intent = bound(completed["intent"])
            assert completed["authenticated_exact_byte_readback"]
            assert completed["key"] == f"epoch-{epoch}.epoch-status.json" and intent["previous"] is None
            native = bound(completed["native"])
            assert native["epoch"] == epoch and native["producer_invocation_id"] == intent["owner"]["InvocationID"]
            statuses[epoch] = start


def refresh(epoch, previous, observer, observer_ref, wd, image):
    lane = LANES[epoch]
    row, = (item for item in observer["replays"] if item["range"] == f"{epoch}-{epoch}")
    launch, _, _, evidence = lane.evidence()
    launch_ref = evidence[0]
    lane.verify_replays([row], [dict(
        range=f"{epoch}-{epoch}", scratch_path=row["scratch_path"],
        expected_controller_invocation_id=launch["invocation_id"],
        expected_producer_invocation_id=launch["invocation_id"],
    )])
    owner = props(lane.UNIT, FIELDS)
    assert (owner["ActiveState"], owner["SubState"], owner["InvocationID"], owner["NRestarts"],
            owner["Job"], int(owner["MainPID"])) == (
        "active", "running", launch["invocation_id"], "0", "", launch["main_pid"])
    assert owner["ControlGroup"] == "/system.slice/" + lane.UNIT
    sample = observer["recorded_at_utc"]
    now = dt.datetime.fromisoformat(sample).timestamp()
    start = dt.datetime.strptime(owner["ExecMainStartTimestamp"], "%a %Y-%m-%d %H:%M:%S UTC")
    elapsed = round((now - start.replace(tzinfo=dt.timezone.utc).timestamp()) * 1000)
    assert elapsed > 0
    work = row["useful_work"]
    assert work["journal_invocation_id"] == launch["invocation_id"]
    end = (epoch + 1) * 432000 - 1
    if work["last"]:
        assert work["last"]["terminal_slot"] == end
        last = work["last"]["slot"]
    else:
        last = epoch * 432000 - 1
    assert epoch * 432000 - 1 <= last <= end
    rate = work["slots_per_second"] if work["sufficient_for_rates"] else None
    if rate is None or rate <= 0:
        rate = 1.0
        basis = "Planning rate of one slot per second until this invocation supplies a measured rate."
    else:
        assert math.isfinite(rate)
        basis = "Same-invocation slot rate to the canonical epoch end."
    delivery = bound(BASELINE)["delivery_allowance_millis"]
    estimate = math.ceil(1000 * (end - last) / rate) + delivery
    directory = Path(row["scratch_path"]).parent / "archives"
    assert directory.is_relative_to(lane.ROOT) and directory.resolve() == directory and directory.is_dir()
    wd.mkdir(mode=0o700, exist_ok=True)
    result = wd / "completion.json"
    key = f"epoch-{epoch}.epoch-status.json"
    if result.is_file():
        done = bound(ref(result))
        assert (done["key"], bound(done["intent"])["previous"]) == (key, previous)
        assert done["authenticated_exact_byte_readback"]
        return ref(result)
    receipt = STATUS / (f"epoch-{epoch}.status-" + "".join(ch for ch in sample if ch.isdigit()) + ".json")
    if not receipt.exists():
        items = aws("list-objects-v2", "--no-paginate", "--prefix", f"epoch-{epoch}.")
        assert not items["IsTruncated"]
        expected = {key: bound(previous)["etag"]} if previous is not None else {}
        assert {item["Key"]: item["ETag"] for item in items.get("Contents", [])} == expected
        assert props(lane.UNIT, FIELDS) == owner
        subprocess.run([
            image, "status-publish", directory, "--epochs", f"{epoch}-{epoch}",
            "--receipt-directory", STATUS, "--observer-receipt", observer_ref["path"],
            "--observer-sha256", observer_ref["sha256"],
            "--expected-controller-invocation-id", launch["invocation_id"],
            "--expected-producer-invocation-id", launch["invocation_id"],
            "--elapsed-execution-millis", str(elapsed),
            "--estimated-remaining-millis", str(estimate), "--phase", "replay",
        ], check=True, stdout=subprocess.DEVNULL, timeout=70)
    native_ref = ref(receipt)
    native = bound(native_ref)
    body = native["status"]
    assert native["authenticated_readback"] and native["observer_receipt_sha256"] == observer_ref["sha256"]
    assert native["controller_invocation_id"] == native["producer_invocation_id"] == launch["invocation_id"]
    assert (native["key"], body["epoch"], body["sampled_at_utc"], body["phase"],
            body["elapsed_execution_millis"], body["estimated_remaining_millis"]) == (
        key, epoch, sample, "replay", elapsed, estimate)
    readback = wd / "readback.json"
    if not readback.exists():
        remote = aws("get-object", "--key", key, "--if-match", native["object_etag"], str(readback))
        assert remote["ETag"].strip('"') == native["object_etag"].strip('"')
    else:
        remote = aws("head-object", "--key", key, "--if-match", native["object_etag"])
    assert bound(ref(readback)) == body
    with readback.open("rb") as stream:
        os.fsync(stream.fileno())
    assert props(lane.UNIT, FIELDS) == owner
    intent_path = wd / "intent.json"
    intent = dict(previous=previous, evidence=[observer_ref, native_ref, launch_ref, BASELINE],
                  owner=owner, key=key, payload=body, basis=basis,
                  forecast=dict(last_slot=last, rate=rate, delivery_allowance_millis=delivery))
    if not intent_path.exists():
        funds.put(intent_path, intent)
    intent_ref = ref(intent_path)
    assert bound(intent_ref) == intent
    return funds.put(result, dict(authenticated_exact_byte_readback=True, key=key, etag=remote["ETag"],
                                 intent=intent_ref, readback=ref(readback), native=native_ref))


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    os.umask(0o077)
    cycle_dir, image = map(Path, sys.argv[1:])
    assert cycle_dir.parent == D and cycle_dir.name.startswith("horizon-foundation-seven-lane-v")
    assert image == V / "horizon230-hourly-second-fleet-v1/jetstreamer-r2"
    with (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        audit = bound(ref(cycle_dir / "status-audit.json"))
        accepted = bound(audit["fleet"])
        observer_ref = audit["observer"]
        observer = bound(observer_ref)
        assert accepted["observer_sha256"] == observer_ref["sha256"]
        assert accepted["sampled_at_utc"] == observer["recorded_at_utc"]
        INITIAL.mkdir(mode=0o700, exist_ok=True)
        for epoch in LANES:
            row, = (entry for entry in accepted["active"] if entry["epoch"] == epoch)
            assert row["phase"] == "replay" and row["producer"]["Id"] == LANES[epoch].UNIT
            assert str(epoch) not in audit["statuses"]
            print(json.dumps(refresh(epoch, None, observer, observer_ref, INITIAL / str(epoch), image)))
