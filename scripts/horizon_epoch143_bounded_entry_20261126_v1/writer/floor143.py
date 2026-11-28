"""Price the 143 guard floor separately from remaining startup growth."""

G = 1 << 30
M = 1 << 20
FLOOR_MIN = 9470567509909
MAX_STARTUP_CUSHION = 8 * G


def quote_guard_floor(raw, joint, peer_floors, home_margin, held):
    peer_floor = max(peer_floors)
    startup_floor = joint["required_home"] - 36 * G - (44 * G + 64 * M)
    provider_floor = max(peer_floor, startup_floor)
    required = max(FLOOR_MIN, provider_floor)
    if held is None:
        # Keep half of verified headroom for other writes during the hold.
        cushion = min(MAX_STARTUP_CUSHION, max(0, (home_margin - (required - provider_floor)) // 2))
        armed = required + cushion
        extra = armed - provider_floor
    else:
        armed = held["floor"]
        cushion = armed - required
        extra = 0
        covered = max(provider_floor, armed) + raw["guarded_hourly_remaining"] + 64 * M
        if raw["guard_floor"] < covered:
            raise ValueError("complete 143 quote lost the armed floor or remaining hourly growth")
    return dict(guard_floor_bytes=armed, required_guard_floor_bytes=required,
                peer_guard_floor_bytes=peer_floor, startup_guard_floor_bytes=startup_floor,
                guard_floor_headroom_bytes=cushion, guard_floor_fits=armed >= required,
                additional_home_charge_bytes=extra)
