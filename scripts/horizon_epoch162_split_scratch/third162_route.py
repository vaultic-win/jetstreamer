"""Preserve all accepted epoch 162 segments while the third interval is observed."""
from pathlib import Path
from types import SimpleNamespace

from evidence import bound, checked, need
import second162_reserved_route as prior
import split_wire
import third162_progress as progress
import third162_status as third
from third162_bindings import INTERFACE, OPERATOR, READER, SCOPE

UNIT = "horizon-qualify-162-third-replay-20261128-v1.service"
TERMINAL = dict(path=str(prior.second.PKG.parent/"split-v1/TERMINAL.json"),
                sha256="b43c8d3a1df6a2b3aa11c4d64076b59cbea6fe0cb735ed12159fb24034339577")
IID = "c64af2c83b994e299e375b44dee7ce21"
STATUS_KEY = "private162_third_held"


def receiver(row):
    if row is None or row["unit"]["Id"] != UNIT:
        return prior.receiver(row)
    need(row["epoch"] == 162 and row["actor"]["producer_unit"] == UNIT, "foreign third 162 actor")
    return third


def earlier_fleet(fleet):
    """Keep the old readers' one-owner check without exposing a successor as its predecessor."""
    row = fleet.get(third.FIELD)
    registered = [item for item in fleet["actual_active_private_diagnostics"] if item["epoch"] == 162]
    need(not row or receiver(row) is third, "different third 162 diagnostic")
    if not third.active(row):
        need(not registered, "unexplained active 162 after the second checkpoint")
        return fleet
    need(registered == [row] and checked(row["held_owner"]) == row["actor"]
         and row["actor"]["producer_invocation_id"] == row["unit"]["InvocationID"] == row["producer_invocation_id"],
         "third interval disagrees with the fleet")
    return dict(fleet, actual_active_private_diagnostics=[item for item in fleet["actual_active_private_diagnostics"] if item != row])


def second_terminal(fleet):
    row = prior.current(earlier_fleet(fleet))
    end = checked(TERMINAL)
    recorded = fleet[prior.second.FIELD]
    need(prior.receiver(row) is prior.second and recorded["unit"]["Id"] == row["unit"]["Id"] == prior.SECOND
         and row["phase"] == recorded["phase"] == "terminal"
         and row["producer_invocation_id"] == recorded["producer_invocation_id"] == IID
         and row["held_owner"] == recorded["held_owner"] == end["held"]
         and row["terminal"] == recorded["terminal"] == end["pid1"]
         and end["private_checkpoint_matched"] and not end["canonical_writes"], "second replay custody changed")
    return recorded


def current(fleet):
    before = second_terminal(fleet)
    return third.current(fleet) or before


def observe(c, callback):
    row = current(c.fleet)
    return (third if receiver(row) is third else prior).observe(c, callback)


def recheck(fleet, row):
    need(receiver(current(fleet)) is receiver(row), "162 turnover during cadence")
    (third if receiver(row) is third else prior).recheck(fleet, row)


def frozen(capacity):
    before = prior.frozen(capacity)
    row = capacity.get(third.FIELD)
    if row:
        need(receiver(row) is third and prior.receiver(before) is prior.second and before["phase"] == "terminal"
             and before["producer_invocation_id"] == IID and before["terminal"] == checked(TERMINAL)["pid1"],
             "foreign prior 162 in saved sample")
    return row or before


def save(capacity, fleet, row):
    if receiver(row) is third:
        prior.save(capacity, earlier_fleet(fleet), second_terminal(fleet))
        capacity[third.FIELD] = row
    else:
        prior.save(capacity, fleet, row)


def install(fleet, previous, row):
    if receiver(row) is third:
        prior.install(fleet, earlier_fleet(previous), second_terminal(previous))
        third.install(fleet, row)
    else:
        prior.install(fleet, previous, row)


def fields(fleet, row):
    if receiver(row) is not third:
        return prior.fields(fleet, row)
    result = prior.fields(earlier_fleet(fleet), second_terminal(fleet))
    result.update({key.replace("private162_split_", "private162_third_"): value
                   for key, value in third.status_fields(row).items()})
    return result


def baseline(c, old):
    return prior.baseline(SimpleNamespace(fleet=earlier_fleet(c.fleet)), old)


def reconcile(row, sample):
    return (progress if receiver(row) is third else prior).reconcile(row, sample)


def changed_turnover(row, old):
    if receiver(row) is third:
        return old.get(STATUS_KEY) != row["held_owner"]
    return prior.changed_turnover(row, old)


def forecast(c, row, previous, old, original, delivery):
    if receiver(row) is not third:
        return prior.forecast(c, row, previous, old, original, delivery)
    turnover = None
    if STATUS_KEY in old:
        need(old[STATUS_KEY] == row["held_owner"] and old.get("producer_invocation_id") in (row["producer_invocation_id"], None),
             "third interval status belongs to another invocation")
    else:
        before = second_terminal(c.fleet)
        need(old.get("private162_second_reserved_held") == before["held_owner"] and old["authenticated_readback"]
             and old["after_status"] == previous and old.get("producer_invocation_id") in (IID,None),
             "unrecognized epoch 162 wire predecessor")
        turnover = dict(previous_receipt=original, after_etag=old["after_etag"], second_terminal=TERMINAL)
    path = Path(progress.SCRATCH).parent/"ledger/epoch-162.diagnostic.jet"
    result, extra = split_wire.forecast(c, progress.wire_row(row), previous, old, original, delivery,
                                        status_key=STATUS_KEY, archive_reader=lambda r: split_wire.archive(r,path),
                                        bounds=(69_998_120,70_004_937), closed_predecessor=turnover)
    if turnover:
        extra["private162_third_turnover"] = turnover
    return result, extra


def ready_fields(writer):
    info = checked(INTERFACE)
    model = checked(SCOPE)
    receipt = checked(OPERATOR)
    need(info["scope"] == SCOPE and info["provider"] == OPERATOR and info["reader"] == READER
         and info["unit"] == UNIT and info["field"] == third.FIELD and model["previous"] == info["previous"] == TERMINAL
         and model["first_slot"] == 69_998_120 and model["last_slot"] == 70_004_937 and model["position_count"] == 6818
         and receipt["destination"] == str(third.PKG) and third.api().scope() == model
         and bound(writer/"third162_status.py")["sha256"] == READER["sha256"], "unregistered third 162 operator")
    return dict(third162_interface=INTERFACE, third162_scope=SCOPE, third162_provider=OPERATOR,
                third162_reader=bound(writer/"third162_status.py"), third162_wire=bound(writer/"third162_route.py"),
                third162_progress=bound(writer/"third162_progress.py"), third162_predecessor=TERMINAL)
