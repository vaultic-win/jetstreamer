"""Publish dashboard estimates for the held epoch 226 extraction and epoch 230 window."""

import datetime as dt
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, "/var/lib/jetstreamer/horizon249-delivery-v214-tools")
from ordinary249.delivery248 import D, V, aws, bound, funds, props, ref


CONTROL = V / "horizon-seven-publication-controller-v222"
INITIAL = V / "horizon-focused-foundation-status-activation-v1"
REGISTRATIONS = {
    226: V / "horizon226-extract-v3/fleet-launch.json",
    230: V / "horizon230-middle-hourly-second-runtime-v1/cadence-registration.json",
}
CHECKPOINT_STATUS = {
    230: V / "horizon230-middle-hourly-second-runtime-v1/repair-status-after-checkpoint-v1/completion.json",
    266: V / "horizon266-hourly-checkpoint-runtime-v1/repair-status-after-checkpoint-v1/completion.json",
}
FIELDS = ["Id", "InvocationID", "MainPID", "ExecMainStartTimestamp", "ActiveState",
          "SubState", "Job", "NRestarts"]
DELIVERY_SECONDS = 10 * 3600
COPY = re.compile(r"\[([^\]]+) INFO .+private 226 extraction: validating and copying")
READ_RETRY = re.compile(r"\[([^\]]+) WARN .+Original225 range at byte (\d+) interrupted")


FIRST_7871_REGISTRATION = V / "horizon230-first-7871-runtime-v1/cadence-registration.json"
FIRST_7871_UNIT = "horizon-qualify-230-first-7871-v1.service"
V1627_REGISTRATION = V / "horizon230-v1627-replay-runtime-v1/cadence-registration.json"
V1627_UNIT = "horizon-qualify-230-v1627-window-v1.service"
ADJACENT_REGISTRATION = V / "horizon230-adjacent-99445304-runtime-v1/cadence-registration.json"
ADJACENT_UNIT = "horizon-qualify-230-adjacent-99445304-v1.service"

NEXT_V1627_REGISTRATION = V / "horizon230-next-v1627-window-runtime-v1/cadence-registration.json"
NEXT_V1627_UNIT = "horizon-qualify-230-next-v1627-99468089-v1.service"

FIRST_7871_STATUS = FIRST_7871_REGISTRATION.parent / "repair-status-after-checkpoint-v1/completion.json"
if FIRST_7871_STATUS.is_file():
    CHECKPOINT_STATUS[230] = FIRST_7871_STATUS


def registration_for_sample(epoch, sample):
    if epoch != 230:
        return REGISTRATIONS[epoch]
    units = {row["producer_unit"] for row in sample["diagnostic_replays"]}
    if NEXT_V1627_UNIT in units:
        assert NEXT_V1627_REGISTRATION.is_file()
        assert units.isdisjoint((ADJACENT_UNIT, V1627_UNIT, FIRST_7871_UNIT,
                                "horizon-qualify-230-middle-hourly-second-v1.service"))
        return NEXT_V1627_REGISTRATION
    if ADJACENT_UNIT in units:
        assert ADJACENT_REGISTRATION.is_file() and units.isdisjoint((V1627_UNIT, FIRST_7871_UNIT))
        return ADJACENT_REGISTRATION
    if V1627_UNIT in units:
        assert V1627_REGISTRATION.is_file() and FIRST_7871_UNIT not in units
        return V1627_REGISTRATION
    if FIRST_7871_REGISTRATION.is_file():
        if "horizon-qualify-230-middle-hourly-second-v1.service" in units:
            assert FIRST_7871_UNIT not in units
        else:
            return FIRST_7871_REGISTRATION
    return REGISTRATIONS[epoch]


def placement(epoch, sample):
    registration = registration_for_sample(epoch, sample)
    launch_ref = ref(registration)
    launch = bound(launch_ref)
    owner = props(launch["unit"], FIELDS)
    if (owner["ActiveState"], owner["SubState"]) != ("active", "running"):
        return None
    assert launch["epoch"] == epoch and launch["launched"]
    assert owner["Id"] == launch["unit"] and owner["InvocationID"] == launch["invocation_id"]
    assert int(owner["MainPID"]) > 1 and owner["NRestarts"] == "0" and not owner["Job"]
    root = Path(launch["run_root"])
    evidence = [launch_ref]
    ts = dt.datetime.fromisoformat(sample["recorded_at_utc"])
    phase = "verification"
    if epoch == 226:
        broker = props(launch["broker_unit"], FIELDS)
        assert broker["InvocationID"] == launch["broker_invocation_id"]
        assert int(broker["MainPID"]) == launch["broker_pid"] and broker["NRestarts"] == "0"
        assert broker["ActiveState"] == "active" and broker["SubState"] == "running" and not broker["Job"]
        log = REGISTRATIONS[226].parent / "control/producer.log"
        raw = log.read_text()
        copies = [dt.datetime.fromisoformat(value) for value in COPY.findall(raw)]
        assert len(copies) == 1 and copies[0] <= ts
        retries = [(dt.datetime.fromisoformat(stamp), int(offset))
                   for stamp, offset in READ_RETRY.findall(raw)]
        retries = [(stamp, offset) for stamp, offset in retries if copies[0] < stamp <= ts]
        pin = bound(launch["broker_pin"])
        stamp, offset = retries[-1] if retries else (copies[0], 0)
        remaining_copy = max(7200, math.ceil((pin["length"] - offset) / (4 * (1 << 20))
                                             - (ts - stamp).total_seconds()))
        seconds = remaining_copy + 10 * 3600 + DELIVERY_SECONDS
        path = root / "output/epoch-226-prefix.jet"
        model = dict(copy_started=str(copies[0]), prior_source_offset=offset, source_length=pin["length"],
                     copy_rate_bytes_per_sec=4 * (1 << 20), copy_planning_seconds=remaining_copy,
                     suffix_and_assembly_seconds=10 * 3600, delivery_seconds=DELIVERY_SECONDS)
        return owner, broker, phase, path, seconds, [*evidence, launch["broker_pin"]], model
    row, = (row for row in sample["diagnostic_replays"] if row["producer_unit"] == launch["unit"])
    assert row["status"] == "observed" and row["expected_producer_invocation_id"] == launch["invocation_id"]
    observation = row["observation"]
    assert observation["invocation_binding_stable"] and observation["scratch_path"] == str(root)
    work = observation["useful_work"]
    remaining = {"path": str(V / "horizon230-retained-segment-bindings.tkl5l1q7/bindings.json"),
                 "sha256": "52d1e4fb7ab373cebba7994a7a0b4cdb2f0b27570b00a32d081833131bc3d9ff"}
    first, last = bound(remaining)["remaining_replay"]
    profile = bound(launch["profile"])
    window = profile if registration == ADJACENT_REGISTRATION else profile["replay_bounds"]
    window_start, window_end = window["first_slot"], window["last_slot"]
    retained = 0
    if registration == FIRST_7871_REGISTRATION:
        assert launch["unit"] == FIRST_7871_UNIT and (window_start, window_end) == (99437434, 99445304)
        closed_ref = profile["prior_drained_window"]
        assert closed_ref["sha256"] == "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56"
        closed = bound(closed_ref)
        assert closed["state"] == "local-segment-committed" and closed["guard_drained"]
        assert window_end < closed["first_slot"] <= closed["last_slot"] <= last
        retained = closed["last_slot"] - closed["first_slot"] + 1
        assert retained == closed["slot_count"] == 39522
        evidence.append(closed_ref)
    elif registration == NEXT_V1627_REGISTRATION:
        assert launch["unit"] == NEXT_V1627_UNIT and (window_start, window_end) == (99468090, 99476782)
        for registration_path, digest, bounds in (
            (FIRST_7871_REGISTRATION, "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2",
             (99437434, 99445304)),
            (ADJACENT_REGISTRATION, "db282c37da8fe4dae091a3047dc4e7020bdf60e93905bc2bfc738b0dd4dd3ba7",
             (99445305, 99461591)),
            (V1627_REGISTRATION, "db618cf906b39ffe64f80b7a0c90febaa4d54054cac4a74e2fed12cea772846e",
             (99461592, 99468089)),
            (REGISTRATIONS[230], "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56",
             (99476783, 99516304)),
        ):
            closed_ref = ref(registration_path.parent / "terminal.json")
            assert closed_ref["sha256"] == digest
            closed = bound(closed_ref)
            assert closed["state"] == "local-segment-committed" and closed["guard_drained"]
            if registration_path == V1627_REGISTRATION:
                evidence.append(closed["native_terminal"])
                closed = bound(closed["native_terminal"])
            assert (closed["first_slot"], closed["last_slot"]) == bounds
            assert closed["slot_count"] == bounds[1] - bounds[0] + 1
            retained += closed["slot_count"]
            evidence.append(closed_ref)
    elif registration in (V1627_REGISTRATION, ADJACENT_REGISTRATION):
        if registration == ADJACENT_REGISTRATION:
            assert launch["unit"] == ADJACENT_UNIT and (window_start, window_end) == (99445305, 99461591)
            prior_ref = profile["prior_terminal"]
            earlier = bound(profile["prior_profile"])["prior_drained_window"]
        else:
            assert launch["unit"] == V1627_UNIT and (window_start, window_end) == (99461592, 99468089)
            prior_ref = profile["prior_drained_window"]
            earlier = bound(profile["sizing_predecessor"])["prior_drained_window"]
        assert prior_ref["sha256"] == "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2"
        prior = bound(prior_ref)
        assert prior["guard_drained"] and prior["state"] == "local-segment-committed"
        assert earlier["sha256"] == "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56"
        later = bound(earlier)
        assert later["guard_drained"] and later["state"] == "local-segment-committed"
        retained = prior["slot_count"] + later["slot_count"]
        assert retained == 47393
        evidence.extend((prior_ref, earlier))
    else:
        assert (window_start, window_end) == (99476783, 99516304)
    accepted = 0
    if work["last"] is not None:
        slot = work["last"]["slot"]
        assert window_start - 1 <= slot <= window_end
        accepted = slot - (window_start - 1)
        if accepted:
            phase = "replay"
    rate = 1.6
    allowance = 12 * 3600
    canonical_credit = 0 if registration in (V1627_REGISTRATION, ADJACENT_REGISTRATION, NEXT_V1627_REGISTRATION) else accepted
    seconds = math.ceil((last - first + 1 - retained - canonical_credit) / rate) + allowance + DELIVERY_SECONDS
    path = Path(next(arg.split("=", 1)[1] for arg in profile["argv"] if arg.startswith("--horizon-output=")))
    assert path.is_relative_to(root / "work/output")
    model = dict(remaining_slot_range=[first, last], window_slots_executed=accepted,
                 completed_window_positions=retained, window_positions_credited=canonical_credit,
                 replay_slots_per_sec=rate, repair_and_turnover_seconds=allowance,
                 delivery_seconds=DELIVERY_SECONDS)
    return owner, None, phase, path, seconds, [*evidence, remaining], model


def adopt(statuses):
    for epoch in REGISTRATIONS:
        path = INITIAL / str(epoch) / "completion.json"
        if epoch not in statuses and path.is_file():
            completed = bound(ref(path))
            assert completed["authenticated_exact_byte_readback"]
            assert completed["key"] == f"epoch-{epoch}.epoch-status.json"
            statuses[epoch] = ref(path)
    for epoch, path in CHECKPOINT_STATUS.items():
        if epoch not in statuses or not path.is_file():
            continue
        correction = ref(path)
        completed = bound(correction)
        intent = bound(completed["intent"])
        assert completed["authenticated_exact_byte_readback"] and completed["key"] == f"epoch-{epoch}.epoch-status.json"
        assert intent["owner"]["controller"] == os.environ["CODEX_THREAD_ID"]
        assert bound(completed["readback"]) == intent["payload"] and intent["payload"]["phase"] == "verification"
        previous = bound(statuses[epoch])
        if previous == bound(intent["previous"]):
            statuses[epoch] = correction
        else:
            assert previous["key"] == completed["key"]
            assert bound(previous["readback"])["sampled_at_utc"] >= intent["payload"]["sampled_at_utc"]


def refresh(epoch, previous, sample, observer_ref, state):
    work = placement(epoch, sample)
    if work is None:
        return None
    owner, broker, phase, archive, eta, links, model = work
    key = f"epoch-{epoch}.epoch-status.json"
    state.mkdir(mode=0o700, exist_ok=True)
    completed = state / "completion.json"
    if completed.exists():
        done = bound(ref(completed))
        assert done["authenticated_exact_byte_readback"] and bound(done["intent"])["previous"] == previous
        return ref(completed)
    intent = state / "intent.json"
    if not intent.exists():
        sampled = sample["recorded_at_utc"]
        start = dt.datetime.strptime(owner["ExecMainStartTimestamp"], "%a %Y-%m-%d %H:%M:%S UTC")
        elapsed = (dt.datetime.fromisoformat(sampled) - start.replace(tzinfo=dt.timezone.utc)).total_seconds()
        assert elapsed > 0
        size = 0
        if archive.exists():
            info = archive.lstat()
            assert archive.resolve() == archive and stat.S_ISREG(info.st_mode)
            size = info.st_size
        payload = funds.put(state / "payload.json", dict(
            epoch=epoch, jet_size_bytes=size, elapsed_execution_millis=round(elapsed * 1000),
            estimated_remaining_millis=eta * 1000, sampled_at_utc=sampled, phase=phase))
        funds.put(intent, dict(previous=previous, key=key, owner=owner, broker=broker,
                               evidence=[observer_ref, *links], payload=payload,
                               forecast=model, publication_authorized=False))
    plan = bound(ref(intent))
    assert (plan["previous"], plan["key"], plan["owner"], plan["broker"]) == (previous, key, owner, broker)
    assert props(owner["Id"], FIELDS) == owner
    if broker is not None:
        assert props(broker["Id"], FIELDS) == broker
    listing = aws("list-objects-v2", "--no-paginate", "--prefix", f"epoch-{epoch}.")
    assert not listing["IsTruncated"]
    objects = {row["Key"]: row["ETag"] for row in listing.get("Contents", [])}
    assert set(objects) <= {key}
    current = objects.get(key)
    prior = bound(previous)["etag"] if previous is not None else None
    body = Path(plan["payload"]["path"])
    readback = state / "readback.json"
    if current == prior:
        condition = ["--if-match", prior] if prior is not None else ["--if-none-match", "*"]
        if prior is not None:
            before = state / "before.json"
            if not before.exists():
                response = aws("get-object", "--key", key, "--if-match", prior, str(before))
                assert response["ETag"] == prior
            assert ref(before)["sha256"] == bound(previous)["readback"]["sha256"]
        assert props(owner["Id"], FIELDS) == owner
        current = aws("put-object", "--key", key, *condition, "--content-type",
                      "application/json", "--body", str(body))["ETag"]
    assert current is not None
    if not readback.exists():
        response = aws("get-object", "--key", key, "--if-match", current, str(readback))
        assert response["ETag"] == current
    assert ref(readback)["sha256"] == plan["payload"]["sha256"]
    with readback.open("rb") as stream:
        os.fsync(stream.fileno())
    assert props(owner["Id"], FIELDS) == owner
    return funds.put(completed, dict(authenticated_exact_byte_readback=True, key=key, etag=current,
                                    intent=ref(intent), readback=ref(readback)))


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    os.umask(0o077)
    root = Path(sys.argv[1])
    assert root.parent == D and root.name.startswith("horizon-foundation-seven-lane-v")
    with (CONTROL / "cycle.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        audit = bound(ref(root / "status-audit.json"))
        fleet = bound(audit["fleet"])
        observer_ref = audit["observer"]
        sample = bound(observer_ref)
        assert fleet["observer_sha256"] == observer_ref["sha256"]
        assert fleet["sampled_at_utc"] == sample["recorded_at_utc"]
        INITIAL.mkdir(mode=0o700, exist_ok=True)
        for epoch in REGISTRATIONS:
            row, = (row for row in fleet["active"] if row["epoch"] == epoch)
            registration = registration_for_sample(epoch, sample)
            assert row["launch_receipt"] == str(registration)
            assert row["launch_receipt_sha256"] == ref(registration)["sha256"]
            assert str(epoch) not in audit["statuses"]
            print(json.dumps(refresh(epoch, None, sample, observer_ref, INITIAL / str(epoch))))
