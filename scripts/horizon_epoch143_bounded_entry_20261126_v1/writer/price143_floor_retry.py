"""Separate the candidate's paid runway from each incumbent's armed disk floor."""


def protect(core, quote):
    native = quote["base_169"]["native"]
    raw = native["raw"]
    candidate = raw["replacement143"]
    booked = 64 << 30
    remaining = raw["guarded_hourly_remaining"]
    core.need(0 <= remaining <= booked and (candidate or remaining == booked)
              and quote["closed_143"]["retained_home"] == booked + (64 << 20)
              and not quote["resource_credit_bytes"], "missing exact 143 whole-tree runway")
    guards = {unit: core.bound(ref) for unit, ref in raw["joint"]["guard_samples"].items()}
    for key in ("after_ram170", "ram_gap170", "independent_retry169"):
        actor = native.get(key)
        if actor and actor.get("guard_plan"):
            guards[actor["unit"]] = core.bound(actor["guard_plan"])
    other162 = quote.get("second_162_accounting")
    if other162 and other162.get("phase") in ("held", "bootstrap", "worker"):
        owner = other162["owner"]
        guards[owner["unit"]["Id"]] = core.bound(owner["guard_plan"])
    checked = []
    for observed in native["observed_actors"]:
        epoch, unit, invocation = observed["epoch"], observed["unit"], observed["invocation_id"]
        if epoch == 143:
            core.need(candidate and unit == candidate["unit"] and invocation == candidate["iid"],
                      "different priced 143 producer")
            continue
        floor = guards[unit]
        core.need((floor.get("producer_invocation_id") or floor.get("invocation_id")) == invocation
                  and type(floor["minimum_free_bytes"]) is int and floor["minimum_free_bytes"] > 0,
                  "changed protected sibling guard " + unit)
        checked.append(floor["minimum_free_bytes"])
    floor = max(9_470_567_509_909, quote["required_home"] - remaining, *checked)
    # The producer must fit both the true whole-roster commitment and the
    # complete candidate runway above the highest sibling's installed floor.
    required = max(quote["required_home"], floor + remaining)
    available = quote["available_home"]
    quote.update(epoch143_protected_sibling_floor=floor, epoch143_remaining_replay_home=remaining,
                 epoch143_protected_runway_required_home=required,
                 home_margin=min(quote["home_margin"], available - required),
                 fits=quote["fits"] and available > required)
    return quote
