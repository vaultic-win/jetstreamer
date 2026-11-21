"""Qualify the incident projection against the actual pre-stop fleet without writing R2."""
from copy import deepcopy
from types import SimpleNamespace

from cycle import load_fleet
from evidence import checked, need
import guard_stops
from owners import verified_owners
from status import body, follow_event
import full172


def reject(function, *args):
    try:
        function(*args)
    except ValueError:
        return
    raise RuntimeError("invalid fixture was accepted")


def qualify():
    ref = guard_stops.PREVIOUS
    fleet, cfg, prior = load_fleet(ref)
    event = guard_stops.stops()
    guard_stops.assert_drained(event)
    projected = guard_stops.project(cfg, ref, fleet)
    need(projected == dict(cfg, replays=[cfg["replays"][-1]])
         and projected["replays"][0]["range"] == "172", "unexpected projection")
    bad = deepcopy(cfg)
    bad["replays"][1]["expected_producer_invocation_id"] = "0" * 32
    reject(guard_stops.project, bad, ref, fleet)
    reject(guard_stops.project, projected, ref, fleet)
    view = dict(fleet, original_data_guard_stops=guard_stops.EVENT,
                actual_executing_replays=[r for r in fleet["actual_executing_replays"]
                                          if r["epoch"] not in guard_stops.EPOCHS])
    actors, _, _, private = verified_owners(view)
    need(not actors and private["epoch"] == 169 and full172.identity(view)["unit"]["Id"] == full172.UNIT,
         "additional or missing surviving worker")
    reject(guard_stops.project, cfg, {"path": "foreign"}, view)
    for epoch, ref in event.items():
        receipt = checked(ref)
        data = body(receipt["after_status"])
        args = (int(epoch), prior["receipts"][epoch])
        need(follow_event(*args, receipt["after_etag"], data) == (ref, receipt), "stop event readback")
        reject(follow_event, *args, '"other-etag"', data)
        reject(follow_event, *args, receipt["after_etag"], data + b" ")
    guard_stops.install(view, SimpleNamespace())
    rows = [r for r in view["epochs"] if r["epoch"] in guard_stops.EPOCHS]
    need(len(rows) == 3 and all(r["no_live_producer_claimed"] and r["repair_open"] and "current_replay" not in r
                               and r["original_data_guard_stop"] == event[str(r["epoch"])] for r in rows),
         "incorrect census after original guard closures")
    return dict(source_fleet=guard_stops.PREVIOUS, stop_event=guard_stops.EVENT,
                surviving_canonical=[172], surviving_private=[169], original_stops=[166, 167, 170],
                authenticated_stop_receipts_checked=3, negative_projections=3, negative_readbacks=6,
                r2_mutations=False)


if __name__ == "__main__":
    import json
    print(json.dumps(qualify(), sort_keys=True))
