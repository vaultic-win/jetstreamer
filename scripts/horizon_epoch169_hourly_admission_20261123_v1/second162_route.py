"""Observe consecutive private 162 producers while preserving the original status chain."""
from types import SimpleNamespace
from pathlib import Path

from evidence import bound, checked, need
import initial162
import progress162
import second162_progress
import second162_status as second
import split_wire
import status162 as first

SECOND = "horizon-qualify-162-second-replay-20261128-v1.service"
FIRST = "horizon-qualify-162-first-hourly-completion-20261127-v2.service"
FIRST_INVOCATION = "e08ac6700a714ea0bf2d08a40516fc7e"
FIRST_HELD = "f98a831d6e5d020c298679a58cc8487c57681e0f8c43d7a1791b6ae8a2e2bae6"
CUSTODY = dict(path=str(second.PKG.parent.parent / "epoch162-first-hourly-completion-20261127-v2/SPLIT162_FIRST_DERIVED_SEGMENT_VERIFIED.json"),
               sha256="445b05009592b381506701162673494fe3d6deb3851a33adade0f4e44d6a64ad")
SCOPE = dict(path=str(second.PKG.parent / "SCOPE-V2.json"),
             sha256="220b9159270070057d3b44d5e0fce304606fd44c18b9348bf5e8cc45fcd9a9ea")

def first_terminal(fleet):
    row = fleet[first.FIELD]
    proof = checked(CUSTODY)
    manifest = proof["validated_derived_segment"]
    need(row["unit"]["Id"] == row["actor"]["producer_unit"] == FIRST and row["phase"] == "terminal"
         and row["producer_invocation_id"] == row["actor"]["producer_invocation_id"] == FIRST_INVOCATION
         == manifest["source_capped_archive"]["producer_invocation"]
         and row["held_owner"]["sha256"] == FIRST_HELD
         and row["terminal"]["MESSAGE_ID"] == first.SUCCESS and checked(row["held_owner"]) == row["actor"]
         and proof["source_files_preserved"] and proof["next_bootstrap_identity_continuous"]
         and manifest["derived_manifest"]["terminal"]["slot"] == 69991076, "unbound first 162 terminal")
    return row

def receiver(row):
    unit = row["unit"]["Id"]
    need(unit in (FIRST, SECOND) and row["epoch"] == 162
         and row["actor"]["producer_unit"] == unit, "foreign 162 assignment")
    return second if unit == SECOND else first

def earlier_fleet(fleet):
    """Only hide the second actor from the older reader, which exclusively owns the first."""
    registered = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] == 162]
    saved = fleet.get(second.FIELD)
    if saved:
        need(receiver(saved) is second, "wrong recorded second 162 actor")
    need(registered == ([saved] if second.active(saved) else []), "duplicate or unregistered private 162")
    if not registered:
        return fleet
    return dict(fleet, actual_active_private_diagnostics=[
        r for r in fleet["actual_active_private_diagnostics"] if r != saved])

def current(fleet):
    retained = first_terminal(fleet)
    before = earlier_fleet(fleet)
    first.recheck(before, retained)
    row = second.current(fleet)
    if row:
        need(receiver(row) is second, "unexpected second receiver result")
    return row or retained

def observe(c, callback):
    row = current(c.fleet)
    if receiver(row) is second:
        return second.observe(c, callback)
    return first.observe(c, callback)

def recheck(fleet, row):
    now = current(fleet)
    need(receiver(row) is receiver(now), "162 owner crossed at census")
    receiver(row).recheck(fleet, row)

def frozen(capacity):
    row = capacity.get(second.FIELD)
    prior = capacity.get(first.FIELD)
    if row:
        need(receiver(row) is second and prior and receiver(prior) is first and prior["phase"] == "terminal"
             and prior["producer_invocation_id"] == FIRST_INVOCATION, "unbound saved 162 census")
    elif prior:
        need(receiver(prior) is first, "foreign original 162 census")
    return row or prior

def save(capacity, fleet, row):
    capacity[first.FIELD] = first_terminal(fleet)
    capacity[receiver(row).FIELD] = row

def install(fleet, previous, row):
    fleet[first.FIELD] = first_terminal(previous)
    receiver(row).install(fleet, row)

def baseline(c, previous):
    return initial162.baseline(SimpleNamespace(split162=first_terminal(c.fleet)), previous)

def fields(fleet, row):
    if receiver(row) is first:
        return first.status_fields(row)
    result = first.status_fields(first_terminal(fleet))
    for key, value in second.status_fields(row).items():
        result[key.replace("private162_split_", "private162_second_")] = value
    return result

def reconcile(row, sample):
    progress = second162_progress if receiver(row) is second else progress162
    return progress.reconcile(row, sample)

def forecast(c, row, previous, old, original, delivery):
    if receiver(row) is first:
        return split_wire.forecast(c, progress162.wire_row(row), previous, old, original, delivery)
    evidence = None
    if old.get("private162_second_held") == row["held_owner"]:
        need(old.get("producer_invocation_id") in (row["producer_invocation_id"], None),
             "foreign incumbent second 162 producer")
    else:
        prior = first_terminal(c.fleet)
        need("private162_second_held" not in old and old["private162_split_held"] == prior["held_owner"]
             and (old.get("producer_invocation_id") == FIRST_INVOCATION or
                  old.get("producer_invocation_id") is None and old.get("private162_split_terminal") == prior["terminal"])
             and old["authenticated_readback"] and old["after_status"] == previous, "foreign prior 162 interval")
        evidence = dict(previous_receipt=original, after_etag=old["after_etag"], first_held=prior["held_owner"],
                        terminal=prior["terminal"], verified_custody=CUSTODY)
    path = Path(second162_progress.SCRATCH).parent / "ledger/epoch-162.diagnostic.jet"
    result, extra = split_wire.forecast(c, second162_progress.wire_row(row), previous, old, original, delivery,
        status_key="private162_second_held", archive_reader=lambda r: split_wire.archive(r,path),
        bounds=(69991077,69998119), closed_predecessor=evidence)
    if evidence:
        extra["private162_second_turnover"] = evidence
    return result, extra
