"""Retain the signed 73,252,243 checkpoint while reporting the next private 169 interval."""
from copy import copy
from functools import partial
from pathlib import Path

from evidence import bound, checked, need
import adjacent169_route as prior
import next169_bindings as refs
import next169_progress as progress
import next169_status as live
import split_wire

UNIT = "horizon-qualify-169-from-73252243-20261128-v1.service"
OLD_IID = "2daf0b7662df43f883288b9a8d684c51"
FIELD = live.FIELD
KEY = "private169_from_73252243_held"


def ours(row):
    return bool(row and row["unit"]["Id"] == UNIT)


def previous(fleet):
    row = fleet[prior.FIELD]
    end, held, grant = map(checked,(refs.PREVIOUS,refs.PREVIOUS_HELD,refs.PREVIOUS_GRANT))
    need(row["phase"] == "terminal" and row["unit"]["Id"] == held["producer_unit"] == prior.UNIT
         and row["producer_invocation_id"] == held["producer_invocation_id"] == grant["iid"] == OLD_IID
         and row["held_owner"] == refs.PREVIOUS_HELD == end["held"] == grant["held"]
         and end["grant"] == refs.PREVIOUS_GRANT and row["terminal"] == end["pid1"]
         and end["archive"]["typed_manifest"]["terminal"]["slot"] == 73_252_243
         and end["private_checkpoint_matched"] and not end["resource_credit_bytes"] and not end["canonical_writes"],
         "changed preceding 169 interval")
    return row


def legacy_fleet(fleet):
    row = fleet.get(FIELD)
    registered = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] == 169]
    if not live.active(row):
        need(not registered,"unexpected live 169 on the terminal predecessor")
        return fleet
    need(ours(row) and registered == [row] and checked(row["held_owner"]) == row["actor"]
         and row["actor"]["producer_unit"] == UNIT and row["producer_invocation_id"] ==
             row["actor"]["producer_invocation_id"] == row["unit"]["InvocationID"]
         and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"]
         and not row["resource_credit_bytes"],"unregistered 169 owner")
    return dict(fleet,actual_active_private_diagnostics=[r for r in fleet["actual_active_private_diagnostics"] if r != row])


def select(c, current):
    view = copy(c)
    if not current:
        view.fleet = legacy_fleet(c.fleet)
    def selected(rows):
        return [r for r in rows if r["range"] != "169" or (r["producer_unit"] == UNIT) == current]
    view.cfg = dict(c.cfg,diagnostic_replays=selected(c.cfg["diagnostic_replays"]))
    view.sample = dict(c.sample,diagnostic_replays=selected(c.sample["diagnostic_replays"]))
    return view


def accept_assignment(req):
    if req["producer_unit"] != UNIT:
        return prior.accept_assignment(req)
    layout = live.api()
    actor, ref = layout.pinned(layout.DATA/"HELD_OWNER.json")
    grant = layout.pinned(layout.DATA/"GRANT.json")[0]
    iid = actor["producer_invocation_id"]
    need(req == live.assignment(layout,actor) and grant["held"] == ref and grant["iid"] == iid
         and layout.ALLOW.read_bytes() == iid.encode(),"different next 169 cadence assignment")
    return req


def observe(c, observed_lane):
    earlier = select(c,False)
    saved, original, original_ctx = prior.observe(earlier,observed_lane)
    terminal = previous(c.fleet)
    need(all(saved[k] == terminal[k] for k in ("phase","producer_invocation_id","terminal","held_owner")),
         "previous 169 changed at the cadence cutoff")
    row = live.observe(select(c,True),partial(observed_lane,private_journal=True))
    if row is not None and not any(r["range"] == "169" for r in earlier.cfg["diagnostic_replays"]):
        row = progress.reconcile(row,c.sample)
    return row or saved,original,original_ctx


def recheck(c):
    earlier = select(c,False)
    earlier.retry169 = previous(c.fleet)
    prior.recheck(earlier)
    live.recheck(c.fleet,c.retry169 if ours(c.retry169) else None)


def project(c,row):
    return live.project(c,row) if ours(row) else prior.project(c,row)


def save(capacity,fleet,row):
    prior.save(capacity,legacy_fleet(fleet),previous(fleet) if ours(row) else row)
    if ours(row):
        capacity[FIELD] = row


def install(fleet, old, row):
    prior.install(fleet,legacy_fleet(old),previous(old) if ours(row) else row)
    if ours(row):
        live.install(fleet,row)
        entry, = [r for r in fleet["epochs"] if r["epoch"] == 169]
        entry.update(state="executing" if row["phase"]=="worker" else "verification",
                     current_repair_owner="/root",no_live_producer_claimed=not live.active(row),repair_open=True)


def fields(fleet,row):
    result = prior.fields(legacy_fleet(fleet),previous(fleet) if ours(row) else row)
    if ours(row):
        result.update({k.replace("private169_split_","private169_from_73252243_"):v
                       for k,v in live.status_fields(row).items()})
    return result


def needs_forecast(row, old):
    if ours(row):
        return row["phase"] != "terminal" or old.get("private169_from_73252243_terminal") != row["terminal"]
    return prior.needs_forecast(row,old)


def forecast(c,row,previous_status,old,original,delivery):
    if not ours(row):
        return prior.forecast(c,row,previous_status,old,original,delivery)
    turnover = None
    if KEY in old:
        need(old[KEY] == row["held_owner"] and old.get("producer_invocation_id") in (None,row["producer_invocation_id"]),
             "changed 169 status owner")
    else:
        predecessor = previous(c.fleet)
        need(old["authenticated_readback"] and old["after_status"] == previous_status
             and old.get("private169_adjacent_terminal") == predecessor["terminal"]
             and old.get("private169_adjacent_held") == predecessor["held_owner"]
             and old.get("producer_invocation_id") in (None,OLD_IID), "different previous 169 forecast")
        turnover = dict(previous_receipt=original,after_etag=old["after_etag"],previous_terminal=refs.PREVIOUS)
    adapted = dict(progress.wire_row(row),hourly169_start_intent=row["held_owner"],invocation_id=row["producer_invocation_id"])
    path = Path(progress.SCRATCH).parent/"ledger/epoch-169.diagnostic.jet"
    report, extra = split_wire.forecast(c,adapted,previous_status,old,original,delivery,status_key=KEY,
        bounds=(73_252_244,73_259_077),archive_reader=lambda r: split_wire.archive(r,path),closed_predecessor=turnover)
    if turnover:
        extra["private169_from_73252243_turnover"] = turnover
    return report,extra


def ready_fields(directory):
    spec, model, seal = map(checked,(refs.INTERFACE,refs.SCOPE,refs.OPERATOR))
    reader = bound(directory/"next169_status.py")
    need(spec["scope"] == refs.SCOPE and model == live.api().scope() and spec["field"] == FIELD
         and spec["unit"] == model["unit"] == UNIT and (model["first_slot"],model["last_slot"]) == (73_252_244,73_259_077)
         and spec["provider"] == refs.OPERATOR and seal["destination"] == str(live.PKG)
         and spec["reader"] == refs.READER and reader["sha256"] == refs.READER["sha256"]
         and spec["previous"] == model["previous"] == refs.PREVIOUS and spec["previous_lease"] == refs.DONOR
         and spec["previous_interface"] == prior.refs.INTERFACE and spec["previous_grant"] == refs.PREVIOUS_GRANT
         and spec["previous_held"] == refs.PREVIOUS_HELD,"different next 169 writer interface")
    return dict(next169_interface=refs.INTERFACE,next169_scope=refs.SCOPE,next169_provider=refs.OPERATOR,
                next169_reader=reader,next169_wire=bound(directory/"next169_route.py"),
                next169_progress=bound(directory/"next169_progress.py"),next169_predecessor=refs.PREVIOUS,
                next169_donor=refs.DONOR)
