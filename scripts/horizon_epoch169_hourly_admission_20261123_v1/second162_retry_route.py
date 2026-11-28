"""Keep both prior epoch 162 terminals when observing the retry of its second interval."""
from pathlib import Path
from types import SimpleNamespace

from evidence import checked, need
import second162_route as history
import second162_retry_progress as progress
import second162_retry_status as second

FIRST = history.FIRST
SECOND = "horizon-qualify-162-second-replay-20261128-v2.service"
PRIOR = "0a4f55edf2b14df6a8a99a41d09834fc"
CUSTODY = history.CUSTODY
SCOPE = dict(path=str(second.PKG.parent / "SCOPE-V2.json"), sha256="7fea44b1ed8b1182f81c30c1f8df61061883f4744907b223ca2e237c9b14e35f")
CLOSED = dict(path=str(second.PKG.parent / "UNRELEASED_PREDECESSOR.json"), sha256="7e29859237415f95d8d8d7b070df842900dadc09f4829c4983ac97c02f10d038")
INTERFACE = dict(path=str(second.PKG.parent / "RETRY_INTERFACE.json"), sha256="c010fe101d3edafb732bbf87f7f8de7fd41a11d9b8b967e14ac5a4f372a8e279")

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
         and native["terminal"] == closure["native_end"] == checked(closure["terminal"])["pid1"],
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
    extra.update({k.replace("private162_split_", "private162_second_retry_"):v for k,v in second.status_fields(row).items()})
    return extra

def baseline(c,old):
    return history.baseline(SimpleNamespace(fleet=earlier_fleet(c.fleet)),old)

def reconcile(row,sample):
    return (progress if receiver(row) is second else history).reconcile(row,sample)

def changed_turnover(row, old):
    operator = receiver(row)
    if operator is second:
        return old.get("private162_second_retry_held") != row["held_owner"]
    return operator is history.second and old.get("private162_second_held") != row["held_owner"]


def forecast(c,row,prev,old,original,delivery):
    if receiver(row) is not second:
        return history.forecast(c,row,prev,old,original,delivery)
    evidence=None
    if old.get("private162_second_retry_held")==row["held_owner"]:
        need(old.get("producer_invocation_id") in (row["producer_invocation_id"],None),"foreign retry status")
    else:
        first=history.first_terminal(earlier_fleet(c.fleet))
        prior=previous(c.fleet)
        need("private162_second_retry_held" not in old and old["private162_split_held"]==first["held_owner"]
             and old.get("private162_second_held") in (None,prior["held_owner"])
             and (old.get("producer_invocation_id") is None
                  or old.get("producer_invocation_id") == PRIOR and old.get("private162_second_held") == prior["held_owner"]
                  or old.get("producer_invocation_id") == history.FIRST_INVOCATION and "private162_second_held" not in old)
             and old["authenticated_readback"] and old["after_status"]==prev,
             "foreign 162 predecessor at retry")
        evidence=dict(previous_receipt=original,after_etag=old["after_etag"],first=CUSTODY,unreleased=CLOSED)
    wire=history.split_wire
    path=Path(progress.SCRATCH).parent/"ledger/epoch-162.diagnostic.jet"
    result,extra=wire.forecast(c,progress.wire_row(row),prev,old,original,delivery,status_key="private162_second_retry_held",
                              archive_reader=lambda r:wire.archive(r,path),bounds=(69991077,69998119),closed_predecessor=evidence)
    if evidence:
        extra["private162_second_retry_turnover"]=evidence
    return result,extra
