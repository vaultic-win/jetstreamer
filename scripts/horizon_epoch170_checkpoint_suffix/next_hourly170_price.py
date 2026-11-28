"""Price a new hourly 170 owner using the drained predecessor's reserved profile."""
from pathlib import Path

from following_prepare import need, read
import next_hourly170 as next170

GIB = 1 << 30
CONTROL = 64 << 20
HOME = 8 * GIB
RAM = 56 * GIB


def inherited(whole, predecessor, staged):
    ready = read(predecessor)
    closure = read(ready["custody"])
    drained = read(ready["drain"])
    row = whole["after_floor170_accounting"]
    owner = row["actor"]
    layout = read(staged)
    need(not whole["preparation_only"] and whole["resource_credit_bytes"] == 0
         and row["scope"] == owner["interface"] == next170.OLD_SCOPE
         and row["replacement_selected"] and not row["prospective"] and row["resident_credit"] == 0
         and owner["phase"] == "terminal" and owner["invocation"] == next170.OLD_IID
         and owner["actor"] == closure["bindings"]["actor"] and owner["release"] == closure["bindings"]["release"]
         and closure["comparison"] == ready["closed_comparison"]
         and closure["native_producer"]["producer"] == owner["native_terminal"]
         and drained["custody"] == ready["custody"] and drained["guard_plan"] == owner["guard_plan"]
         and drained["guard_drained"] and drained["producer_drained"] and drained["scratch_released"]
         and not drained["resource_credit_bytes"] and not closure["archive_publication_authorized"]
         and row["home_growth"] == HOME and row["producer_memory"] == RAM and row["guard_memory"] == GIB,
         "different or undrained 170 booking")
    need(layout["predecessor"] == predecessor and layout["no_replay_started"] and not layout["release_created"]
         and layout["scratch_unmounted_and_empty"] and 0 < layout["allocated"] <= 256 << 10
         and layout["directories"][2]["path"] == next170.source()["run"],
         "unknown next hourly working directory")
    return row, read(owner["guard_plan"]), layout


def geometry(whole, previous_guard, drawdown):
    native = whole["base_169"]["native"]
    raw = native["raw"]
    available = whole["available_home"]
    remaining143 = whole["epoch143_remaining_replay_home"]
    dormant143 = (whole.get("epoch143_dormant_tree") or {}).get("physical_bytes", 0)
    floor143 = whole.get("epoch143_installed_guard_floor") or 0
    peers = whole["observed_sibling_guard_floors"]
    need(whole["available_ram"] - whole["required_ram"] == whole["ram_margin"]
         and 0 <= remaining143 + dormant143 <= 64 * GIB and remaining143 >= 0 and dormant143 >= 0
         and raw["guarded_hourly_remaining"] == remaining143 + dormant143
         and whole["epoch143_protected_runway_required_home"] >=
             whole["epoch143_protected_sibling_floor"] + remaining143,
         "shared RAM or protected 143 geometry changed")
    floor = max(raw["guard_floor"], whole["guard_floor"] - remaining143,
                whole["required_home"] - remaining143 - HOME,
                previous_guard["minimum_free_bytes"], floor143, *peers)
    active = []
    for field, maximum in (("third_162_accounting", 3 * GIB), ("fourth_162_accounting", 3 * GIB),
                           ("adjacent_169_accounting", 4 * GIB)):
        row = whole[field]
        if row["charged"] and row["phase"] != "terminal":
            size = row["remaining_output"]
            need(0 <= size <= maximum, "unknown peer output reservation " + field)
            active.append((field,size))
    combined = floor + remaining143 + HOME + sum(size for _, size in active)
    required = max(whole["required_home"], whole["epoch143_protected_runway_required_home"],
                   combined, floor143 + HOME)
    margin = min(whole["home_margin"], available - required) - drawdown
    return dict(home_margin=margin, ram_margin=whole["ram_margin"], required_home=required,
                required_ram=whole["required_ram"], available_home=available, guard_floor=floor,
                guard_cap=HOME - CONTROL, producer_memory_max=RAM, guard_memory_max=GIB,
                guard_cpu_quota_micros=1_000_000, producer_cpu_quota_micros=6_000_000,
                future_home_existing_booking=HOME, future_control_home=CONTROL,
                protected_143_remaining=remaining143, protected_peer_output=dict(active),
                remaining_old_run_growth=0, drawdown_allowance=drawdown,
                archive_publication_authorized=False, resource_credit_bytes=0,
                fits=whole["fits"] and margin >= 0 and whole["ram_margin"] >= 0)


def candidate(whole, predecessor, staged, scope, drawdown_ref, *, phase="start"):
    _, guard, layout = inherited(whole, predecessor, staged)
    proof = read(scope)
    drawdown = read(drawdown_ref)
    need(proof["predecessor"] == predecessor and proof["staged_layout"] == staged
         and proof["run"] == layout["directories"][2]["path"]
         and proof["expected_producer_unit"] == next170.UNIT
         and proof["profile"]["producer_memory_bytes"] == RAM
         and proof["profile"]["scratch_noswap_tmpfs_bytes"] == 40 * GIB
         and proof["profile"]["new_home_total_bytes"] == HOME
         and proof["profile"]["new_control_bytes"] == CONTROL
         and proof["following_input"]["single_copy"] and proof["no_worker_started"]
         and not Path(proof["release_path"]).exists() and not Path(proof["barrier"]).exists(),
         "different staged 170 source or released replacement")
    actor = None
    current = whole.get("next_hourly170_accounting")
    if phase == "start":
        need(not Path(proof["actor_path"]).exists() and not (current and current["intent"]),
             "next hourly booking already issued")
    elif phase == "held":
        need(current and current["intent"] and current["producer_booking_reused"],
             "next hourly booking is absent")
        owner = current["actor"]
        need(owner and owner["phase"] == "held" and owner["interface"] == scope and not owner["release"]
             and owner["actor"]["path"] == proof["actor_path"], "different unreleased next hourly owner")
        actor = owner["actor"]
    else:
        raise ValueError("invalid next hourly price phase")
    need(drawdown["worst_stop_unix"] >= drawdown["worst_start_unix"]
         and drawdown["worst_observed_90s_free_byte_decrease"] >= 0,
         "invalid shared allocation drawdown receipt")
    amounts = geometry(whole, guard, drawdown["worst_observed_90s_free_byte_decrease"])
    return dict(amounts, schema="horizon-170-next-hourly-price-v1", phase=phase, actor=actor,
                provider=whole["package"], writer=whole["writer"], fleet=whole["fleet"],
                predecessor=predecessor, staged_layout=staged, scope=scope, drawdown_evidence=drawdown_ref,
                shared_price_unchanged=True, additional_input_bytes=0, whole_roster=whole)
