"""Apply the booked first-hourly routes to the incumbent fleet census."""

from evidence import checked, need
from first_hourly143 import EPOCH141, EPOCH143, active, observe, project, recheck

PROFILES = (EPOCH141, EPOCH143)
CAPACITY_FIELD = "private_first_hourly_reservation"


def census(context):
    rows = [(profile, observe(context, profile)) for profile in PROFILES]
    live = [row for profile, row in rows if active(row)]
    need(len(live) <= 1, "141 and 143 share the first-hourly three-core envelope")
    return rows


def project_all(context, rows):
    for profile, row in rows:
        project(context, row, profile)


def recheck_all(rows):
    for profile, row in rows:
        recheck(row, profile)


def capacity(rows):
    candidates = [row for _, row in rows if active(row)]
    if not candidates:
        return None
    row, = candidates
    booking = checked(row["actor"]["booking"])
    return dict(epoch=row["epoch"], unit=row["unit"]["Id"], held_owner=row["held_owner"],
                booking=row["actor"]["booking"], HOME_bytes=booking["HOME_bytes"],
                RAM_bytes=booking["RAM_bytes"], cpu_quota_micros=booking["cpu_quota_micros"],
                resource_credit_bytes=0)


def install(fleet, rows):
    fleet[CAPACITY_FIELD] = capacity(rows)
    for profile, row in rows:
        if not row:
            continue
        fleet[profile.field] = row
        if active(row):
            diagnostics = fleet["actual_active_private_diagnostics"]
            need(not any(item["epoch"] == profile.epoch for item in diagnostics),
                 f"duplicate first-hourly epoch {profile.epoch}")
            diagnostics.append(row)
            fleet["active_private_diagnostic_count"] += 1
            fleet["active_producer_count"] += 1
