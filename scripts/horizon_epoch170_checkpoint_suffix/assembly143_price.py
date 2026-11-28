"""Price the exact assembly plan together with the first-hourly 143 launch."""

import assembly_reservation as assembly


def apply(quote, reservation, held, peer, candidate_home, candidate_ram, armed_floor=0):
    if reservation["state"] == "queued-or-drained":
        return dict(quote, assembly168=reservation, guard_floor_bytes=quote["retained_required_home_bytes"])
    admission = reservation["replay"]
    assembly.need(not admission["invocation143"] or admission["invocation143"] == held,
                  "168 holds an unreconciled 143 invocation")
    assembly.need(not admission["invocation170"] or peer and admission["invocation170"] == peer["iid"],
                  "168 holds an unreconciled 170 invocation")
    assembly.need(reservation["incremental_cpu_micros"] == 0, "168 lost its reserved selector CPU")
    assembly_home = reservation["incremental_home"]
    future170 = quote["peer_remaining"] + quote["next_170_reserved"]
    # Keep the assembler's absolute floor intact after 170's outstanding writes.
    # The other constraint already includes the 170 growth and existing guards.
    guard_floor = max(quote["retained_required_home_bytes"], reservation["floor"] + future170)
    retained_home = guard_floor + assembly_home
    required = retained_home + candidate_home
    historical = quote["historical_home_margin"] - assembly_home
    live = quote["live_available_home_bytes"] - required
    margin = min(live, historical)
    available_home = required + margin
    retained_ram = quote["retained_required_ram_bytes"] + reservation["incremental_ram"]
    ram_margin = quote["available_ram_bytes"] - retained_ram - candidate_ram
    return dict(quote, assembly168=reservation, guard_floor_bytes=guard_floor, retained_required_home_bytes=retained_home,
                available_home_bytes=available_home, home_margin_bytes=margin,
                live_home_margin=live, historical_home_margin=historical,
                retained_required_ram_bytes=retained_ram, ram_margin_bytes=ram_margin,
                disk_fits=margin >= 0 and quote["peer_tree_cap_fits"] and
                (not armed_floor or armed_floor >= guard_floor and available_home >= armed_floor + assembly_home + candidate_home),
                memory_fits=ram_margin >= 0)


def recheck(quoted):
    fresh = assembly.reservation()
    keys = ("state", "native", "plan", "admission", "fit", "floor", "replay", "incremental_ram",
            "incremental_cpu_micros")
    assembly.need(all(fresh.get(key) == quoted.get(key) for key in keys)
                  and fresh["incremental_home"] <= quoted["incremental_home"],
                  "168 owner or retained capacity changed after pricing")
    return fresh
