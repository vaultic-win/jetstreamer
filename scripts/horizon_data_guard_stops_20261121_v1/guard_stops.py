"""Reconcile the three original disk-guard stops with the existing archive cadence."""
import os
import sys
from pathlib import Path

from evidence import BASE, bound, checked, need, pair, sealed

ROOT = BASE / "epoch168-witness-incident-20261121-v1"
PREVIOUS = pair(BASE / "root104959-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json",
                "696df8323a2db5535f72b661999b1519b4061f3465af70a068d5a71c3a8e8515")
EVENT = pair(ROOT / "R2_STOP_CORRECTIONS.json",
             "3c46ad428045d24fd867ffb28b8e3b41073be255966b60fdf03395344cbf186a")
EPOCHS = {166, 167, 170}
FIELD = "original_data_guard_stops"
FIRST_CONFIG = ROOT / "scheduled/sealed-next/observer.json"


def closed_epochs(fleet):
    if FIELD not in fleet:
        return set()
    need(fleet[FIELD] == EVENT and "terminal166_local_commit" not in fleet,
         "foreign or conflicting original guard closure")
    return EPOCHS


def stops():
    """Check the native stop chain and the R2 repair readback for each departed invocation."""
    from owners import IDS

    event = checked(EVENT)
    need(event["fleet"] == PREVIOUS and not event["archives_or_sidecars_changed"]
         and set(map(int, event["reports"])) == EPOCHS, "incomplete guard stop event")
    for epoch in sorted(EPOCHS):
        receipt = checked(event["reports"][str(epoch)])
        sample = checked(receipt["guard"])
        intent = checked(receipt["guard_stop_intent"])
        completion = checked(receipt["guard_stop_completion"])
        iid = IDS[epoch][0]
        need(receipt["epoch"] == epoch and receipt["authenticated_readback"]
             and receipt["conditional_header"] == "If-Match"
             and receipt["after_status"]["phase"] == "verification"
             and receipt["before_status"]["phase"] == "replay"
             and not receipt["producer_invocation_id"] and receipt["current_repair_owner"] == "/root"
             and iid == receipt["terminal_producer_invocation_id"] == sample["producer_invocation_id"]
             == intent["producer_invocation_id"] == completion["producer_invocation_id"]
             and intent["reason"] == sample["trip_reason"] == "DATA-fulfillment-observation-failed"
             and intent["sample"] == sample and completion["intent"] == receipt["guard_stop_intent"]["path"]
             and completion["terminal"]["invocation_id"] == iid and completion["terminal"]["pid"] == 0
             and not completion["scratch_deleted"] and not completion["r2_mutations"],
             f"invalid native stop or R2 readback for {epoch}")
    return event["reports"]


def assert_drained(refs):
    from owners import show

    for ref in refs.values():
        unit = checked(ref)["terminal_native"]["Id"]
        native = show(unit, ("ActiveState", "MainPID", "ControlPID", "Job"))
        group = Path("/sys/fs/cgroup/system.slice") / unit
        need(native["ActiveState"] in ("inactive", "failed") and native["MainPID"] == native["ControlPID"] == "0"
             and not native["Job"] and (not group.exists() or not (group/"cgroup.procs").read_text().strip()),
             "original producer still owns a process: " + unit)


def project(cfg, fleet_ref, fleet):
    from owners import IDS

    rows = cfg["replays"]
    if fleet_ref == PREVIOUS:
        need(not closed_epochs(fleet) and [r["range"] for r in rows] == ["166", "167", "170", "172"],
             "unexpected incident predecessor configuration")
        registered = {r["epoch"]: r for r in fleet["actual_executing_replays"]}
        for row in rows:
            e = int(row["range"])
            if e in EPOCHS:
                need(row["expected_producer_invocation_id"] == IDS[e][0] == registered[e]["unit"]["InvocationID"]
                     and row["producer_unit"] == registered[e]["unit"]["Id"], "foreign original producer")
        return dict(cfg, replays=[r for r in rows if int(r["range"]) not in EPOCHS])
    need(closed_epochs(fleet) == EPOCHS and not any(int(r["range"]) in EPOCHS for r in rows),
         "unregistered replacement in the observation")
    return cfg


def select(cfg, fleet_ref, fleet):
    effective = project(cfg, fleet_ref, fleet)
    if fleet_ref == PREVIOUS:
        need(sealed(bound(FIRST_CONFIG)) == effective, "sealed first projection differs")
        return effective, FIRST_CONFIG
    return effective, Path(fleet["sole_next_observer"]["path"])


def select_cycle(c):
    c.historical166 = None
    refs = stops()
    assert_drained(refs)
    c.cfg, _ = select(c.cfg, c.fleet_ref, c.fleet)
    need([r["range"] for r in c.sample["replays"]] == [r["range"] for r in c.cfg["replays"]],
         "scheduled native sample disagrees with the exact surviving roster")
    return dict(c.fleet, **{FIELD: EVENT}, actual_executing_replays=[
        row for row in c.fleet["actual_executing_replays"] if row["epoch"] not in EPOCHS])


def initial_readback(epoch, predecessor, tag, raw):
    from evidence import digest
    from status import body

    refs = checked(EVENT)["reports"]
    ref = refs[str(epoch)]
    receipt = checked(ref)
    prior = checked(predecessor)
    need(receipt["previous_receipt"] == predecessor and receipt["before_etag"] == prior["after_etag"]
         and receipt["before_sha256"] == prior["after_sha256"] and receipt["before_status"] == prior["after_status"]
         and receipt["after_etag"] == tag and raw == body(receipt["after_status"])
         and receipt["after_sha256"] == digest(raw), f"unbound first post-stop status for {epoch}")
    return ref, receipt


def install(fleet, c):
    fleet[FIELD] = EVENT
    for row in fleet["epochs"]:
        if row["epoch"] in EPOCHS:
            row.pop("current_replay", None)
            row.update(current_repair_owner="/root", no_live_producer_claimed=True, state="verification",
                       repair_open=True, original_data_guard_stop=checked(EVENT)["reports"][str(row["epoch"])],
                       current_status_scope="Original producer stopped. Recovering from its retained bootstrap.")


def dispatch(path):
    from race166 import NATIVE, NATIVE_SHA, validate_scheduled

    cfg, fleet_ref, _ = validate_scheduled(path)
    _, effective_path = select(cfg, fleet_ref, checked(fleet_ref))
    assert_drained(stops())
    need(bound(NATIVE)["sha256"] == NATIVE_SHA, "original native observer changed")
    os.execv(NATIVE, [NATIVE, effective_path])


if __name__ == "__main__":
    need(os.geteuid() == 0 and __debug__ and len(sys.argv) == 2, "expected a registered scheduled config")
    dispatch(Path(sys.argv[1]))
