"""Bind the November 22 HOME-floor stops to their original producers and guards."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
STATE = ROOT / "four-homefloor-20261122-v1"
FLEET = ROOT / "root171010-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
FLEET_SHA = "6eeb24940a8316f95a6921a55d8781f9a1a41067ac766894b127aab61afec639"
EVENT_SHA = "9719cca38d4d9f8fddb65529436c408139d884c1a7838b4ea323e39a8499a214"
EPOCHS = (166, 167, 168, 170)
SHARED = ROOT / "epoch172-current-delivery-20261121-v1/closure-tools/closure.py"
if hashlib.sha256(SHARED.read_bytes()).hexdigest() != "1eda4eb778e73a8ab670df50980cad9208215f8d4854432d94f83f4054e92541":
    raise ValueError("guard closure implementation changed")
shared = runpy.run_path(str(SHARED))
document, need, drained = (shared[name] for name in ("document", "need", "drained"))


def read(ref):
    path = Path(ref["path"])
    mode = stat.S_IMODE(path.lstat().st_mode)
    need(mode in (0o400, 0o444, 0o600), "unexpected receipt mode")
    return document(path, mode, ref["sha256"])[0]


def binding(epoch):
    need(epoch in EPOCHS, "unknown stopped epoch")
    raw, fleet_ref = shared["member"](FLEET, 0o600, FLEET_SHA, 16 << 20)
    fleet = json.loads(raw)
    event, event_ref = document(STATE / "R2_STOP_CORRECTIONS.json", 0o600, EVENT_SHA)
    need(event["fleet"] == fleet_ref and set(event["reports"]) == set(map(str, EPOCHS)),
         "foreign incident")
    row, = (r for r in fleet["actual_executing_replays"] if r["epoch"] == epoch)
    ref = event["reports"][str(epoch)]
    report = read(ref)
    admission = read(row["admission"])
    unit, iid = row["unit"]["Id"], row["unit"]["InvocationID"]
    timer, timer_id = row["guard_timer"]["Id"], row["guard_timer"]["InvocationID"]
    guard = timer.removesuffix(".timer") + ".service"
    first = read(row["first_guard"])
    plan = read(admission["actual_guard_plan"])
    need(admission["producer_unit"] == unit == plan["unit"] and
         admission["producer_invocation_id"] == iid == plan["invocation_id"] and
         admission["timer_unit"] == first["timer"]["Id"] == timer and
         admission["timer_invocation_id"] == first["timer"]["InvocationID"] == timer_id and
         first["timer"]["Triggers"] == guard and admission["first_guard"] == row["first_guard"],
         "admission or guard identity changed")
    need(report["epoch"] == epoch and report["fleet"] == fleet_ref and
         report["terminal_producer_invocation_id"] == iid and report["authenticated_readback"] is True,
         "foreign stopped producer report")
    completion = read(report["guard_stop_completion"])
    intent = read(report["guard_stop_intent"])
    sample = read(report["guard"])
    need(completion["intent"] == report["guard_stop_intent"]["path"] and
         completion["producer_invocation_id"] == intent["producer_invocation_id"] == sample["producer_invocation_id"] == iid and
         completion["plan_sha256"] == intent["plan_sha256"] == sample["plan_sha256"] == admission["actual_guard_plan"]["sha256"] and
         intent["reason"] == sample["trip_reason"] == "filesystem-floor" and
         sample == intent["sample"] and sample["available_bytes"] < sample["minimum_free_bytes"] and
         completion["terminal"]["pid"] == 0 and completion["terminal"]["invocation_id"] == iid and
         all(completion[k] is False for k in ("remote_mutations", "r2_mutations", "scratch_deleted")),
         "incomplete protective stop")
    need(drained(unit)["InvocationID"] in ("", iid), "different generation of stopped producer")
    return dict(epoch=epoch, incident=event_ref, report=ref, admission=row["admission"],
                first_guard=row["first_guard"], plan=admission["actual_guard_plan"],
                producer_unit=unit, producer_invocation_id=iid, timer_unit=timer,
                timer_invocation_id=timer_id, guard_unit=guard, resource_credit_bytes=0)


class StoppedGuard(shared["GuardClosure"]):
    def committed(self):
        return binding(self.epoch)


def verify(epoch, action):
    proof = binding(epoch)
    if epoch == 168:
        # This transient guard and timer already disappeared with their producer.
        for key in ("timer_unit", "guard_unit"):
            need(drained(proof[key])["LoadState"] == "not-found", "168 guard route still loaded")
        return dict(proof, already_unloaded=True)
    out = STATE / ("guard-" + str(epoch))
    if action == "retire":
        out.mkdir(mode=0o700, exist_ok=True)
    guard = StoppedGuard(epoch, out, Path(proof["admission"]["path"]).parent,
                         proof["producer_unit"], proof["producer_invocation_id"],
                         proof["timer_unit"], proof["timer_invocation_id"], "", "", 0, "", "")
    if action == "preflight":
        if guard.intent_path.exists():
            data, _ = document(guard.intent_path, 0o400)
            need(data["binding"] == proof, "foreign intent for old guard")
            guard.expected_timer(data["before"])
        else:
            guard.expected_timer(shared["manager"](guard.guard_timer))
        return proof
    if action == "inspect":
        return guard.inspect()
    need(action == "retire", "unknown guard action")
    return guard.retire()


if __name__ == "__main__":
    need(sys.flags.isolated and __debug__ and os.geteuid() == 0 and len(sys.argv) == 2 and
         sys.argv[1] in ("preflight", "inspect", "retire"), "invalid guard invocation")
    if sys.argv[1] == "retire":
        for epoch in EPOCHS:
            verify(epoch, "preflight")
    print(json.dumps({e: verify(e, sys.argv[1]) for e in EPOCHS}, sort_keys=True))
