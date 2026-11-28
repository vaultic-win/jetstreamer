"""Keep epoch 169's accepted private span while the adjoining split-scratch owner advances."""
from copy import copy
from pathlib import Path
from functools import partial

from evidence import bound, checked, need
import adjacent169_bindings as refs
import adjacent169_progress as progress
import adjacent169_status as live
import fourth169_status as fourth
import split_wire

UNIT = "horizon-qualify-169-from-73245218-20261128-v1.service"
OLD_IID = "89f12725fa804408958878cb5cb8ca55"
FIELD = live.FIELD
KEY = "private169_adjacent_held"


def ours(row):
    return row is not None and row["unit"]["Id"] == UNIT


def previous(fleet):
    row = fleet[fourth.FIELD]
    terminal = checked(refs.PREVIOUS)
    need(row["phase"] == "terminal" and row["unit"]["Id"] == terminal["unit"] == fourth.UNIT
         and row["invocation_id"] == terminal["invocation_id"] == OLD_IID
         and row["terminal"] == refs.PREVIOUS and row["held"] == refs.PREVIOUS_HELD
         and terminal["disposition"] == "completed-private-span" and terminal["archive"]["size"] == 1893471148
         and not row["canonical_replay_claimed"] and not terminal["canonical_publication_authorized"],
         "different preceding 169 interval")
    return row


def legacy_fleet(fleet):
    row = fleet.get(FIELD)
    registered = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] == 169]
    if not live.active(row):
        need(not registered,"unexpected incumbent on 169 compute")
        return fleet
    need(ours(row) and registered == [row] and checked(row["held_owner"]) == row["actor"]
         and row["actor"]["producer_invocation_id"] == row["unit"]["InvocationID"] == row["producer_invocation_id"]
         and row["actor"]["producer_unit"] == UNIT and not row["canonical_replay_claimed"]
         and not row["archive_publication_authorized"],"unregistered adjacent 169 fleet row")
    return dict(fleet,actual_active_private_diagnostics=[r for r in fleet["actual_active_private_diagnostics"] if r != row])


def accept_assignment(req):
    if req["producer_unit"] != UNIT:
        return fourth.accept_assignment(req)
    layout = live.api()
    actor, ref = layout.pinned(layout.DATA/"HELD_OWNER.json")
    grant = layout.pinned(layout.DATA/"GRANT.json")[0]
    iid = actor["producer_invocation_id"]
    need(req == live.assignment(layout,dict(producer_invocation_id=iid)) and grant["held"] == ref
         and grant["iid"] == iid and layout.ALLOW.read_bytes() == iid.encode(),
         "unregistered adjoining 169 cadence assignment")
    return req


def select(c, successor):
    view = copy(c)
    if not successor:
        view.fleet = legacy_fleet(c.fleet)
    def rows(items):
        return [r for r in items if r["range"] != "169" or (r["producer_unit"] == UNIT) == successor]
    view.cfg = dict(c.cfg,diagnostic_replays=rows(c.cfg["diagnostic_replays"]))
    view.sample = dict(c.sample,diagnostic_replays=rows(c.sample["diagnostic_replays"]))
    return view


def observe(c, observed_lane):
    earlier = select(c,False)
    predecessor, original, original_ctx = fourth.observe(earlier,observed_lane)
    saved = previous(c.fleet)
    names = ("phase","invocation_id","held","terminal")
    need(all(predecessor[k] == saved[k] for k in names),"preceding 169 native receipt changed")
    row = live.observe(select(c,True),partial(observed_lane,private_journal=True))
    if row is not None and not any(v["range"] == "169" for v in earlier.cfg["diagnostic_replays"]):
        row = progress.reconcile(row,c.sample)
    return row or predecessor, original, original_ctx


def recheck(c):
    row = c.retry169
    old = previous(c.fleet)
    fresh = fourth.receiver()["observe"].current(legacy_fleet(c.fleet))
    need(all(fresh[k] == old[k] for k in ("phase","invocation_id","held","terminal")), "old 169 changed during census")
    live.recheck(c.fleet,row if ours(row) else None)


def project(c,row):
    return live.project(c,row) if ours(row) else fourth.receiver()["project"](c,row)


def save(capacity,fleet,row):
    capacity[fourth.FIELD] = previous(fleet) if ours(row) else row
    if ours(row):
        capacity[FIELD] = row


def install(fleet, prior, row):
    if not ours(row):
        return fourth.install(fleet,row)
    fourth.install(fleet,previous(prior))
    live.install(fleet,row)
    entry, = [v for v in fleet["epochs"] if v["epoch"] == 169]
    entry.update(state="executing" if row["phase"] == "worker" else "verification",
                 current_repair_owner="/root",no_live_producer_claimed=not live.active(row),repair_open=True)


def fields(fleet,row):
    if not ours(row):
        return fourth.receiver()["status_fields"](row)
    result = fourth.receiver()["status_fields"](previous(fleet))
    result.update({k.replace("private169_split_", "private169_adjacent_"): v for k,v in live.status_fields(row).items()})
    result["private169_adjacent_guard"] = row.get("guard")
    result["private169_adjacent_terminal"] = row["terminal"]
    return result


def needs_forecast(row,old):
    name = "private169_adjacent_terminal" if ours(row) else "private169_retry_terminal"
    return row["phase"] != "terminal" or old.get(name) != row["terminal"]


def forecast(c,row,previous_status,old,original,delivery):
    if not ours(row):
        return fourth.forecast(c,row,previous_status,old,original,delivery)
    turnover = None
    if KEY in old:
        need(old[KEY] == row["held_owner"] and old.get("producer_invocation_id") in (None,row["producer_invocation_id"]),
             "different adjacent 169 wire owner")
    else:
        prior = previous(c.fleet)
        need(old["authenticated_readback"] and old["after_status"] == previous_status
             and old.get("private169_retry_terminal") == prior["terminal"] and old.get("producer_invocation_id") in (None,OLD_IID),
             "different previous 169 status")
        turnover = dict(previous_receipt=original,after_etag=old["after_etag"],previous_terminal=refs.PREVIOUS)
    adapted = dict(progress.wire_row(row),hourly169_start_intent=row["held_owner"],invocation_id=row["producer_invocation_id"])
    path = Path(progress.SCRATCH).parent/"ledger/epoch-169.diagnostic.jet"
    report, extra = split_wire.forecast(c,adapted,previous_status,old,original,delivery,status_key=KEY,
        bounds=(73_245_219,73_252_243),archive_reader=lambda r: split_wire.archive(r,path),closed_predecessor=turnover)
    if turnover:
        extra["private169_adjacent_turnover"] = turnover
    return report,extra


def ready_fields(writer):
    model = checked(refs.SCOPE)
    spec = checked(refs.INTERFACE)
    pkg = checked(refs.OPERATOR)
    need(spec["scope"] == refs.SCOPE and spec["provider"] == refs.OPERATOR and spec["reader"] == refs.READER
         and spec["unit"] == model["unit"] == UNIT and spec["field"] == FIELD
         and spec["previous"] == model["previous"] == refs.PREVIOUS and spec["previous_held"] == refs.PREVIOUS_HELD
         and (model["first_slot"],model["last_slot"],model["position_count"]) == (73_245_219,73_252_243,7025)
         and live.api().scope() == model and pkg["destination"] == str(live.PKG)
         and bound(writer/"adjacent169_status.py")["sha256"] == refs.READER["sha256"],"different adjacent 169 writer interface")
    return dict(adjacent169_interface=refs.INTERFACE,adjacent169_scope=refs.SCOPE,adjacent169_provider=refs.OPERATOR,
                adjacent169_reader=bound(writer/"adjacent169_status.py"),adjacent169_wire=bound(writer/"adjacent169_route.py"),
                adjacent169_progress=bound(writer/"adjacent169_progress.py"),adjacent169_predecessor=refs.PREVIOUS)
