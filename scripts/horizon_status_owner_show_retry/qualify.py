"""Exercise the status publisher's read-only owner retry against a captured interval."""
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

package, fleet_path, output_path = map(Path, sys.argv[1:])
sys.path.insert(0, str(package))
import cycle
import full172
import owners
import status
from evidence import EPOCHS, bound, checked, content, durable, utc

fleet = checked(bound(fleet_path))
done = checked(fleet["authenticated_status_audit"])
records = {int(e): checked(ref) for e, ref in done["receipts"].items()}
assert set(records) == set(EPOCHS) and len(records) == 19
previous = checked(done["fleet_predecessor"])
row = next(r for r in previous["actual_executing_replays"] if r["epoch"] == 172)
timer = row["guard_timer"]
admission = row["admission"], checked(row["admission"])
fields = ("Id", "InvocationID", "ActiveState", "Job", "Triggers")
expected_cmd = ["/usr/bin/systemctl", "show", full172.TIMER, "-p" + ",".join(fields)]
stamp = utc(done["sampled_at_utc"])


class Clock(dt.datetime):
    instant = stamp + dt.timedelta(seconds=30)

    @classmethod
    def now(cls, tz=None):
        return cls.instant.astimezone(tz)


class Manager:
    def __init__(self):
        self.events = []
        self.calls = 0

    def show(self, command, *, text, timeout):
        assert command == expected_cmd and text is True and timeout == 15
        self.calls += 1
        event = self.events.pop(0) if self.events else "success"
        if event == "timeout":
            raise subprocess.TimeoutExpired(command, timeout)
        if event == "exit":
            raise subprocess.CalledProcessError(1, command)
        result = dict(timer)
        if event == "changed":
            result["InvocationID"] = "0" * 32
        if event == "stale":
            Clock.instant = stamp + dt.timedelta(minutes=30)
        return "".join(f"{name}={result[name]}\n" for name in fields)


class Store:
    def __init__(self):
        self.objects = {e: (r["before_etag"], status.body(r["before_status"])) for e, r in records.items()}
        self.puts = []
        self.interrupt_put = None

    def get(self, epoch):
        return self.objects[epoch]

    def put(self, epoch, etag, data):
        assert self.get(epoch)[0] == etag and epoch not in self.puts
        assert data == status.body(records[epoch]["after_status"])
        result = records[epoch]["after_etag"]
        self.objects[epoch] = result, data
        self.puts.append(epoch)
        if self.interrupt_put == epoch:
            raise ConnectionError("fixture lost the successful PUT response")
        return result


def expect_failure(action, error, message=None):
    try:
        action()
    except error as exc:
        if message is not None:
            assert message in str(exc), str(exc)
    else:
        raise AssertionError(f"expected {error.__name__}")


def seed(directory):
    directory.mkdir(mode=0o700)
    for key, ref in done["receipts"].items():
        name = f"epoch-{key}.intent.json"
        intent = content(Path(ref["path"]).with_name(name))
        c = records[int(key)]
        assert all(c[k] == v for k, v in intent.items())
        durable(directory / name, intent)


c = cycle.Cycle.__new__(cycle.Cycle)
c.fleet_ref, c.fleet = done["fleet_predecessor"], previous
c.sample_ref, c.now, c.stamp = done["observer"], stamp, done["sampled_at_utc"]
c.owner_fleet = previous
c.native = previous["actual_executing_replays"]
c.private = previous["actual_active_private_diagnostics"]
c.closures = previous["terminal172_closure"]
c.focused = done["coordinated_private_diagnostic_169"]
c.advancing = {r["epoch"]: bool(r["measured_progress"]) for r in c.native}
c.rows = {r["epoch"]: r for r in c.native if r["epoch"] != 172}
c.full172_row, c.private136 = row, None
c.diagnostic, c.diagnostic169 = (done[f"coordinated_private_diagnostic_{e}"] for e in (168, 169))
c.prior = checked(previous["authenticated_status_audit"])
manager = Manager()
output_path.mkdir(mode=0o700)
results = {}

with (
    patch.object(full172, "admitted", return_value=admission),
    patch.object(full172, "actor", return_value=row["unit"]),
    patch.object(cycle, "current_owners", return_value=(c.native, c.private, c.closures, c.focused)),
    patch.object(owners.subprocess, "check_output", side_effect=manager.show),
    patch.object(cycle.dt, "datetime", Clock),
):
    c.full172 = {"identity": full172.identity(previous)}
    for name, events, exception, reason in (
        ("changed_identity", ["timeout", "changed"], ValueError, "172 guard ownership changed"),
        ("persistent_timeout", ["timeout", "timeout"], subprocess.TimeoutExpired, None),
        ("other_systemctl_failure", ["exit"], subprocess.CalledProcessError, None),
        ("expired_after_retry", ["timeout", "stale"], ValueError, "outside its live publication window"),
    ):
        directory = output_path / name
        seed(directory)
        store = Store()
        manager.events = list(events)
        prior_calls = manager.calls
        Clock.instant = stamp + dt.timedelta(seconds=30)
        expect_failure(lambda: status._publish(c, store, directory, done["ready_epochs"]), exception, reason)
        used = manager.calls - prior_calls
        assert used == len(events) and not manager.events and not store.puts
        results[name] = {"manager_calls": used, "conditional_puts": 0}

    # The first three keys have completed receipts. The fourth PUT succeeds remotely
    # but its response is lost. The next process must read that object back.
    directory = output_path / "partial"
    seed(directory)
    Clock.instant = stamp + dt.timedelta(seconds=30)
    store = Store()
    store.interrupt_put = EPOCHS[3]
    manager.events = ["timeout", "success"]
    expect_failure(lambda: status._publish(c, store, directory, done["ready_epochs"]), ConnectionError)
    assert store.puts == list(EPOCHS[:4]) and len(list(directory.glob("*.receipt.json"))) == 3
    manager.events = ["timeout", "timeout"]
    expect_failure(lambda: status._publish(c, store, directory, done["ready_epochs"]), subprocess.TimeoutExpired)
    assert store.puts == list(EPOCHS[:4])
    store.interrupt_put = None
    manager.events = ["timeout", "success"]
    completed = status._publish(c, store, directory, done["ready_epochs"])
    complete = checked(completed)
    assert len(store.puts) == len(set(store.puts)) == complete["authenticated_status_count"] == 19
    assert complete["authenticated_readback"]
    recovered = checked(complete["receipts"][str(EPOCHS[3])])
    assert recovered["already_published_intent_read_back"]
    assert all(store.objects[e] == (r["after_etag"], status.body(r["after_status"])) for e, r in records.items())
    assert status._publish(c, store, directory, done["ready_epochs"]) == completed
    assert len(store.puts) == 19 and not manager.events
    results["timeout_then_success_and_partial_recovery"] = {
        "completed_before_interruption": 3, "successful_put_without_response": EPOCHS[3],
        "unique_conditional_puts": 19, "duplicate_puts": 0, "authenticated_readbacks": 19,
        "completed": completed,
    }

print(json.dumps({"fleet": bound(fleet_path), "observer": done["observer"], "results": results,
                  "production_writes": 0, "live_queries": 0}, sort_keys=True))
