"""Keep both prior epoch 162 terminals when observing the retry of its second interval."""
from pathlib import Path
from types import SimpleNamespace

from evidence import checked, need
import second162_retry_route as history
import second162_reserved_progress as progress
import second162_reserved_status as second

FIRST = history.FIRST
SECOND = "horizon-qualify-162-second-replay-20261128-v3.service"
PRIOR = "a06cf6aeef704fb7b1cc013130913e1a"
CUSTODY = history.CUSTODY
SCOPE = dict(path=str(second.PKG.parent / "SCOPE.json"), sha256="95f362d418f76ceb40e979e49a2ae4e0bc3dec6eefae5b74ff98f206c877e8f4")
CLOSED = dict(path='/var/lib/jetstreamer/horizon_runtime_data/epoch162-second-replay-20261128-v2/UNRELEASED_POSTGUARD_CLOSURE.json', sha256="c7ed78cec61b97f93b3645c15af4f95c8aaa243812c96b324f55c9a89249ad90")
INTERFACE = dict(path=str(second.PKG.parent / "INTERFACE.json"), sha256="ff09a7c8a45f6135b64bb25ce7fdea65e78ea71331afd29503baf8c3ad393dcb")

def receiver(row):
    if row["unit"]["Id"] != SECOND:
        return history.receiver(row)
    need(row["epoch"] == 162 and row["actor"]["producer_unit"] == SECOND, "foreign 162 retry")
    return second

def earlier_fleet(fleet):
    prior = fleet.get(second.FIELD)
    if prior:
        need(receiver(prior) is second, "foreign recorded second retry")
    recorded = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"]==162]
    need(recorded == ([prior] if second.active(prior) else []), "duplicate second-interval attempt")
    if not recorded:
        return fleet
    return dict(fleet,actual_active_private_diagnostics=[r for r in fleet["actual_active_private_diagnostics"] if r!=prior])

def previous(fleet):
    before = earlier_fleet(fleet)
    native = history.current(before)
    closure = checked(CLOSED)
    need(closure["invocation_id"] == PRIOR and closure["no_worker"] and closure["no_grant"]
         and native["held_owner"] == closure["held"] and native["producer_invocation_id"] == PRIOR
         and native["unit"]["Id"] == history.SECOND and native["phase"] == "terminal"
         and native["terminal"] == closure["native_end"] and all(not checked(ref)["workers"] for ref in closure["samples"]),
         "earlier second interval returned a different terminal")
    saved = before.get(history.second.FIELD)
    if saved:
        need(saved["held_owner"] == native["held_owner"] and saved["terminal"] == native["terminal"],"earlier 162 gate returned")
    return saved or native

def current(fleet):
    old = previous(fleet)
    retry = second.current(fleet)
    return retry or old

def observe(c, callback):
    row = current(c.fleet)
    return (second if receiver(row) is second else history).observe(c,callback)

def recheck(fleet,row):
    now = current(fleet)
    need(receiver(now) is receiver(row), "162 retry crossed cadence")
    (second if receiver(row) is second else history).recheck(fleet,row)

def frozen(capacity):
    row=capacity.get(second.FIELD)
    prior=history.frozen(capacity)
    if row:
        need(receiver(row) is second and prior and prior["producer_invocation_id"]==PRIOR and prior["phase"]=="terminal",
             "different frozen 162 retry history")
    return row or prior

def save(capacity,fleet,row):
    if receiver(row) is second:
        history.save(capacity,earlier_fleet(fleet),previous(fleet))
        capacity[second.FIELD]=row
    else:
        history.save(capacity,fleet,row)

def install(fleet, prior, row):
    if receiver(row) is second:
        history.install(fleet,earlier_fleet(prior),previous(prior))
        second.install(fleet,row)
    else:
        history.install(fleet,prior,row)

def fields(fleet,row):
    if receiver(row) is not second:
        return history.fields(fleet,row)
    extra=history.fields(earlier_fleet(fleet),previous(fleet))
    extra.update({k.replace("private162_split_", "private162_second_reserved_"):v for k,v in second.status_fields(row).items()})
    return extra

def baseline(c,old):
    return history.baseline(SimpleNamespace(fleet=earlier_fleet(c.fleet)),old)

def reconcile(row,sample):
    return (progress if receiver(row) is second else history).reconcile(row,sample)

def changed_turnover(row, old):
    operator = receiver(row)
    if operator is second:
        return old.get("private162_second_reserved_held") != row["held_owner"]
    return history.changed_turnover(row, old)


def forecast(c,row,prev,old,original,delivery):
    if receiver(row) is not second:
        return history.forecast(c,row,prev,old,original,delivery)
    evidence=None
    if old.get("private162_second_reserved_held")==row["held_owner"]:
        need(old.get("producer_invocation_id") in (row["producer_invocation_id"],None),"foreign retry status")
    else:
        before = earlier_fleet(c.fleet)
        first = history.history.first_terminal(before)
        second_gate = history.previous(before)
        prior = previous(c.fleet)
        names = (("private162_split_held", first), ("private162_second_held", second_gate),
                 ("private162_second_retry_held", prior))
        present = [actor for name,actor in names if name in old]
        need("private162_second_reserved_held" not in old and present and first in present
             and all(old[name] == actor["held_owner"] for name,actor in names if name in old)
             and old.get("producer_invocation_id") in (None,present[-1]["producer_invocation_id"])
             and old["authenticated_readback"] and old["after_status"] == prev,
             "foreign 162 predecessor at retry")
        evidence = dict(previous_receipt=original, after_etag=old["after_etag"], first=CUSTODY,
                        unreleased=CLOSED, earlier_unreleased=history.CLOSED)
    wire=history.history.split_wire
    path=Path(progress.SCRATCH).parent/"ledger/epoch-162.diagnostic.jet"
    result,extra=wire.forecast(c,progress.wire_row(row),prev,old,original,delivery,status_key="private162_second_reserved_held",
                              archive_reader=lambda r:wire.archive(r,path),bounds=(69991077,69998119),closed_predecessor=evidence)
    if evidence:
        extra["private162_second_reserved_turnover"]=evidence
    return result,extra
