"""Resume the 09:48 partial batch under its original systemd writer and saved observation."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cutover67 as h
import status_cycle as c
import forecast166
import transition_v67 as handoff

HEAD = c.BASE / "root084808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
HEAD_SHA = "48a22bd8e9bf0f829afd04bff791e1ba618408b3536a50eeaa062d0562cf6bce"
ACCEPTED = {136, 137, 140, 141, 143, 146, 159, 161, 162, 163}


def terminal(old):
    st = h.state(h.WRITER, "InvocationID", "ActiveState", "SubState", "Result", "MainPID", "ControlPID", "Job", "ExecMainStatus")
    c.need(st["InvocationID"] == old["invocation_id"] == "b939d66df42f452ba343a7759cfc2084"
           and st["ActiveState"] == st["SubState"] == "failed" and st["Result"] == "exit-code"
           and st["ExecMainStatus"] == "1" and st["MainPID"] == st["ControlPID"] == "0"
           and not st["Job"], "the failed V66 writer changed")
    proc = Path("/proc") / str(old["pid"])
    c.need(not proc.exists() or c.owners.ticks(old["pid"]) != old["start_ticks"], "incumbent writer is alive")
    bindings = [
        ["_PID=1","_UID=0","UNIT="+h.WRITER,"INVOCATION_ID="+st["InvocationID"],
         "MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15","COMMAND=ExecStart","EXIT_CODE=exited","EXIT_STATUS=1"],
        ["_SYSTEMD_UNIT="+h.WRITER,"_SYSTEMD_INVOCATION_ID="+st["InvocationID"],"_PID="+str(old["pid"]),
         "MESSAGE=ValueError: external forecast expired or follows observation"],
    ]
    cursors = []
    for fields in bindings:
        lines = h.command("/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "json", *fields).splitlines()
        c.need(len(lines) == 1, "missing or ambiguous V66 exit or forecast failure")
        cursors.append(json.loads(lines[0])["__CURSOR"])
    return cursors


def snapshot(package_sha):
    c.need(os.geteuid() == 0 and HERE == h.NEW and h.member(HERE, Path(__file__).name)["sha256"] == package_sha,
           "use the registered recovery package")
    package = c.entry()
    c.need(package["sha256"] == package_sha, "inconsistent writer entry")
    head = c.bound(HEAD)
    c.need(head["sha256"] == HEAD_SHA, "unknown incumbent fleet")
    ready = handoff.ready(vars(c), head, package)
    old = c.checked(ready["old_owner"])["new"]
    end = terminal(old)
    fleet = c.checked(head)
    packet = c.checked(ready["recovered_clock"])
    cfg = c.sealed(packet["config"])
    names = c.names(cfg["not_before_utc"])
    c.need(not (names["out"]/"ROOT_COMPLETE_OPERATIONAL_FLEET.json").exists(), "fleet already committed")
    states = names["statuses"]
    baseline = dict(c.checked(fleet["complete_active_status_audit"])["receipts"])
    completed = {int(p.name.split(".")[0].split("-")[1]) for p in states.glob("epoch-*.receipt.json")}
    intents = {int(p.name.split(".")[0].split("-")[1]) for p in states.glob("epoch-*.intent.json")}
    c.need(completed == intents == ACCEPTED, "different partial status batch")
    target = {}
    store = c.status.Storage()
    c.need(set(map(int,baseline)) == store.inventory()[0], "status population changed")
    for key, original in baseline.items():
        epoch = int(key)
        current = original
        if epoch in completed:
            intent = c.read_ref(states/f"epoch-{epoch}.intent.json")
            current = c.bound(states/f"epoch-{epoch}.receipt.json")
            row = c.checked(current)
            c.need(intent["previous_receipt"] == original and intent["conditional_header"] == "If-Match"
                   and intent["observer"] == ready["recovered_sample"] and intent["fleet_predecessor"] == head
                   and all(row[k] == v for k,v in intent.items()), "unrecognized existing status write")
        c.authenticated(store, epoch, current)
        target[key] = current
    context = c.make_context(head, fleet, ready["recovered_sample"], cfg, names["out"])
    seen = c.census(context, c.handoff())
    c.need(seen == c.checked(ready["saved_census"]), "different saved observations")
    prior = c.checked(target["166"])["after_status"]
    predicted, details = forecast166.forecast(context, prior, target["166"], target["162"])
    c.need(predicted["estimated_remaining_millis"] > 0 and not details["measured_canonical_progress"], "wrong recovered forecast")
    endpoints = h.endpoints(fleet)
    return ready, dict(terminal_cursors=end, remote_readbacks=target, preserved_writes=sorted(completed),
                       observer=ready["recovered_sample"], census=ready["saved_census"], endpoints=endpoints,
                       forecast_166=predicted, forecast_evidence=details)


def recover(digest, apply):
    with h.BOOKING_LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if h.ACTIVE.exists():
            active = h.doc(h.ACTIVE)
            h.owner(active["new"], HERE)
            c.need(active["ready"] == h.ref(h.READY), "different V67 owner")
            return h.ref(h.ACTIVE)
        ready, evidence = snapshot(digest)
        if not apply:
            return dict(ready=ready["recovered_sample"], checked=len(evidence["remote_readbacks"]),
                        committed=evidence["preserved_writes"], forecast=evidence["forecast_166"])
        evidence_path = c.ROOT / "V67_094808_FORECAST_RECOVERY.json"
        c.durable(evidence_path,evidence)
        c.durable(h.READY,ready)
        directory = h.SYSTEMD_DIRECTORY / (h.WRITER + ".d")
        previous = max(directory.glob("*-v66-*.conf"),key=lambda p:p.name)
        raw = previous.read_bytes()
        c.need(raw.count(os.fsencode(h.OLD)) == 1, "wrong previous writer command")
        replacement = raw.replace(os.fsencode(h.OLD), os.fsencode(HERE))
        dropin = directory / ("z" + previous.name.replace("-v66-", "-v67-"))
        if dropin.exists():
            c.need(dropin.read_bytes() == replacement, "different release already staged")
        else:
            h.private_write(dropin, replacement, 0o644)
        h.systemctl("daemon-reload")
        c.need(str(HERE/"status_cycle.py") in h.state(h.WRITER, "ExecStart")["ExecStart"]
               and not c.timer_names() and h.endpoints(c.checked(ready["fleet"])) == evidence["endpoints"],
               "writer route, protected owners or clock changed during recovery")
        terminal(c.checked(ready["old_owner"])["new"])
        h.systemctl("start", h.WRITER)
        return dict(started=True, observer=ready["recovered_sample"], evidence=c.bound(evidence_path))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seal")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(recover(args.seal,args.apply),sort_keys=True))
