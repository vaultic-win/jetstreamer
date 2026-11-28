"""Correct one accepted 162 status using its original cadence window and conditional event chain."""

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

import progress162

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = ROOT / "epoch162-first-hourly-completion-20261127-v2"
V51 = ROOT / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v51-entry146"
V51_SEAL = "778fec83f9fb484c9d4705aa884bdd9bffb32d2a7d7d7e5719eb37b913ebc58c"
WIRE_SHA = "b0351feba8c00944ceb43c52c3f5ef45f7bad422e18c7b9074b4e66bfc98e0d9"


def load():
    initial_path = BASE / "initial-status-tools-v1/initial162.py"
    # Trust paths and their seals before executing the issued reader and wire model.
    from initial162 import file_ref, need
    need(file_ref(initial_path)[0]["sha256"] == "9d288f485ebd128a7f0784a73c4085f14de97b0188ebfd205be2104c6d480411"
         and file_ref(V51/"deployment-seal-receipt.json")[0]["sha256"] == V51_SEAL
         and file_ref(V51/"split_wire.py")[0]["sha256"] == WIRE_SHA, "different issued 162 dependencies")
    initial = SimpleNamespace(**runpy.run_path(str(initial_path)))
    status, delivery, actor = initial.modules()
    wire = SimpleNamespace(**runpy.run_path(str(V51/"split_wire.py")))
    import evidence
    return SimpleNamespace(initial=initial, status=status, delivery=delivery, actor=actor, wire=wire, ev=evidence)


def live(row, m):
    l = m.actor.api()
    actor, worker = row["actor"], row["worker"]
    m.actor.owner(row["profile"], l.manager(l.UNIT), actor, l)
    p = Path("/proc") / str(worker["pid"])
    m.ev.need(l.ticks(worker["pid"]) == worker["start_ticks"] and str((p/"exe").readlink()) == worker["path"]
              and str(worker["pid"]) in (l.CGROUP/"cgroup.procs").read_text().split()
              and l.manager(l.TIMER)["InvocationID"] == actor["guard_timer_invocation_id"]
              and l.manager(l.TIMER)["ActiveState"] == "active" and l.ALLOW.read_bytes() == row["producer_invocation_id"].encode(),
              "162 worker, admission or guard changed since the sample")


def authorize(m, row, ref, old):
    i = m.initial
    grant, enrollment = i.ref(i.DATA/"GRANT.json"), i.ref(i.ENROLL)
    i.adopted(row, ref, i.ref(i.INITIAL), enrollment, grant)
    i.need(old["private162_split_held"] == row["held_owner"] and old["producer_invocation_id"] == row["producer_invocation_id"]
           and old["private162_split_grant"] == grant and old["private162_split_enrollment"] == enrollment
           and old["observer"] == row["observer"] and old["private162_split_guard"] == row["guard"]
           and old["current_repair_owner"] == "/root" and not old["measured_canonical_progress"]
           and not old["archive_publication_authorized"] and not old["replay_launch_authorized"]
           and old["after_status"]["phase"] == "verification" and old["authenticated_readback"]
           and i.valid_etag(old["after_etag"]) and old["after_sha256"] == i.digest(i.body(old["after_status"])),
           "different 162 status owner, phase or authenticated bytes")


def proposal(m, fleet_ref, fleet, ref, old, row):
    i = m.initial
    sample = i.checked(row["observer"])
    updated = progress162.reconcile(row, sample)
    proof = updated.get("private162_journal_progress")
    i.need(proof, "no guarded 162 progress in accepted window")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    context = SimpleNamespace(now=now, stamp=stamp, prior={"inventory":fleet["authenticated_inventory"]})
    # The rate is measured at the coordinated cutoff. Charge the remaining
    # interval from that time, then retain all review, full-epoch and delivery stages.
    after, extra = m.wire.forecast(context, progress162.wire_row(updated), old["after_status"], old, ref, m.delivery.estimate)
    elapsed_since_marker = round((now.timestamp() - proof["useful_work"]["last"]["realtime_microseconds"]/1_000_000) * 1000)
    i.need(elapsed_since_marker >= 0, "162 marker follows correction")
    stages = extra["planning_milliseconds"]
    stages["interval_remaining"] = max(0, stages["interval_remaining"] - elapsed_since_marker)
    after["estimated_remaining_millis"] = sum(stages.values())
    i.validate_wire(after)
    i.need(after["phase"] == "replay" and stages["full_epoch_replay"] > 0 and stages["delivery"] > 0
           and not extra["measured_canonical_progress"], "incorrect 162 correction phase or forecast")
    return dict(schema="horizon-epoch162-split-guarded-progress-correction-v1", epoch=162, key=i.KEY,
                previous_receipt=ref, conditional_header="If-Match", before_etag=old["after_etag"],
                before_sha256=old["after_sha256"], before_status=old["after_status"],
                after_sha256=i.digest(i.body(after)), after_status=after, sampled_at_utc=stamp, observer=row["observer"],
                fleet_predecessor=fleet_ref, private162_journal_progress=proof, native_diagnostic=row["native_diagnostic"],
                private162_split_phase="worker", private162_split_guard=row["guard"], private162_split_terminal=None,
                private162_canonical_progress=False, archive_publication_authorized=False, replay_launch_authorized=False,
                **extra)


def exchange(m, store, p, recheck):
    i = m.initial
    before, after = map(i.body, (p["before_status"], p["after_status"]))
    i.need(p["key"] == i.KEY and p["epoch"] == 162 and p["conditional_header"] == "If-Match"
           and i.digest(before) == p["before_sha256"] and i.digest(after) == p["after_sha256"] and before != after
           and i.valid_etag(p["before_etag"]), "invalid conditional 162 intent")
    etag, raw = store.get(162)
    if raw == before and etag == p["before_etag"]:
        recheck()
        try:
            written = store.put(162, etag, after)
        except Exception:
            # A lost response may have committed. Only the exact new bytes can settle it.
            etag, raw = store.get(162)
            if raw != after:
                raise
        else:
            etag, raw = store.get(162)
            i.need(written == etag, "superseded 162 conditional update")
    i.need(i.valid_etag(etag) and etag != p["before_etag"] and raw == after, "changed 162 status; reconcile the event")
    return dict(p, after_etag=etag, authenticated_readback=True)


def main(args):
    m = load()
    e, i = m.ev, m.initial
    def check_package():
        package = Path(__file__).resolve().parent
        e.need(package == BASE/"journal-progress-v1" and i.ref(package/"deployment-seal-receipt.json")["sha256"] == args.package_sha,
               "different 162 correction deployment")
        seal = i.checked(i.ref(package/"deployment-seal-receipt.json"))
        members = {x["name"]:x["sha256"] for x in seal["members"]}
        e.need(seal["destination"] == str(package) and all(i.ref(package/name)["sha256"] == members[name]
               and not (package/name).stat().st_mode & 0o222 for name in ("initial162.py","progress162.py","correct162.py")),
               "modified 162 correction source")
    if args.mode == "publish":
        check_package()
    with i.LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        def head():
            return max(ROOT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p:p.stat().st_mtime_ns)
        path = head()
        fleet_ref = i.ref(path)
        fleet = i.checked(fleet_ref)
        e.need(fleet_ref["sha256"] == args.fleet_sha and fleet["owner"] == "/root", "latest accepted fleet changed")
        entry, = [r for r in fleet["epochs"] if r["epoch"] == 162]
        ref = entry["current_authenticated_status_receipt"]
        row = fleet[m.actor.FIELD]
        e.need(ref["sha256"] == args.previous_sha and row["phase"] == "worker" and row == entry["current_private_diagnostic"]
               and row["observer"] == fleet["observer"], "different 162 correction predecessor or worker")
        old = i.checked(ref)
        authorize(m, row, ref, old)
        store = m.status.Storage()
        def recheck():
            e.need(head() == path and i.ref(path) == fleet_ref, "fleet changed during 162 correction")
            statuses, ready, archives = store.inventory()
            e.need(162 in statuses and 162 not in ready and 162 not in archives, "162 canonical inventory changed")
            live(row, m)
        recheck()
        out = e.STATUS_ROOT/("event-162-split-progress-" + ref["sha256"][:16])
        intent, dest = out/"INTENT.json", out/"RECEIPT.json"
        if args.mode == "check":
            etag, raw = store.get(162)
            e.need(raw == i.body(old["after_status"]) and etag == old["after_etag"], "signed 162 predecessor changed")
            plan = proposal(m, fleet_ref, fleet, ref, old, row)
            class Simulated:
                value = etag, raw
                def get(self, epoch):
                    e.need(epoch == 162, "wrong simulated key")
                    return self.value
                def put(self, epoch, condition, payload):
                    e.need(epoch == 162 and self.value[0] == condition, "wrong simulated precondition")
                    self.value = '"' + hashlib.md5(payload).hexdigest() + '"', payload
                    return self.value[0]
            result = exchange(m, Simulated(), plan, lambda: None)
            return dict(mode="authenticated GET and simulated conditional PUT", result=result)
        e.ensure_dir(out)
        if not intent.exists():
            e.need(not dest.exists(), "162 receipt without intent")
            etag, raw = store.get(162)
            e.need(etag == old["after_etag"] and raw == i.body(old["after_status"]), "signed 162 predecessor changed")
            e.durable(intent, proposal(m, fleet_ref, fleet, ref, old, row))
        plan = e.checked(e.bound(intent))
        e.need(plan["previous_receipt"] == ref and plan["before_etag"] == old["after_etag"]
               and plan["before_status"] == old["after_status"] and plan["fleet_predecessor"] == fleet_ref
               and plan["observer"] == row["observer"] and plan["private162_split_guard"] == row["guard"],
               "different pending 162 correction")
        if dest.exists():
            existing = e.checked(e.bound(dest))
            etag, raw = store.get(162)
            e.need(existing == dict(plan, after_etag=etag, authenticated_readback=True)
                   and raw == i.body(plan["after_status"]), "completed 162 correction superseded")
        else:
            e.durable(dest, exchange(m, store, plan, recheck))
        return e.bound(dest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check","publish"))
    parser.add_argument("--fleet-sha", required=True)
    parser.add_argument("--previous-sha", required=True)
    parser.add_argument("--package-sha")
    os.umask(0o077)
    print(json.dumps(main(parser.parse_args()), sort_keys=True))
