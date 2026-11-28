"""Fund the second-interval retry at startup and keep every live peer's armed guard intact."""
import hashlib
from pathlib import Path
import runpy
from types import FunctionType

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch162-second-replay-20261128-v2"
OP = ROOT / "issued-split-v3"
PROVIDER = "051fcc7f5a7ef31a8fa6fb31372d029c83428e5c4eceb1eecc6dd7235fd64393"
SOURCE = RT / "epoch162-second-replay-20261128-v1/second-price-v3/second_price_custody.py"
SOURCE_SHA = "fad7efd010b558b7888d12ec8a511d7b5e3c000437a9067268ba6acc94ae7810"
INTERFACE = dict(path=str(ROOT / "RETRY_INTERFACE_V3.json"), sha256="2192e657ff4cf56a9404dc41cf5d3223cb437afa3eb7225676b4116d95c18712")
PEER_SHA = "24f4676bb7a6ad7a1e198241c912c2ff25b45936483018004c32309c552b7148"
SAMPLES = RT / "epoch143-first-hourly-20261127-v1/guard-receipts"
SHARED_DRAWDOWN = (
    dict(path=str(SAMPLES/"sample-92a0c1dc79f34a6a8c1c7b341d27a627.json"),sha256="6a597ef19c825a31c7ba6e45306ad5236c6d59069a405b726a8e18bb3e8bc460"),
    dict(path=str(SAMPLES/"sample-76d915d88440424292930b1ec0dc1ae6.json"),sha256="6f588be8e1ee2a5d288882d45ade00f162287a16a54cd37df6f5a5736d847899"),
)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def drawdown(bind):
    before, after = map(bind, SHARED_DRAWDOWN)
    amount = before["available_bytes"] - after["available_bytes"]
    need(before["producer_invocation_id"] == after["producer_invocation_id"] == "4514e85834c34152ae0ecfde8a42001d"
         and before["minimum_free_bytes"] == after["minimum_free_bytes"]
         and after["recorded_unix_seconds"] - before["recorded_unix_seconds"] == 83
         and amount == 20_011_974_656, "changed observed shared-filesystem drawdown")
    return amount


def armed_peers(bind, native):
    fleet = bind(native["fleet"])
    raw = native["base_169"]
    peers = raw["native"]
    rows = fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"] + fleet["actual_active_bootstraps"]
    result = {}
    for owner in raw["observed_actors"]:
        epoch, unit, iid = owner["epoch"], owner["unit"], owner["invocation_id"]
        need(epoch not in result, "duplicate live owner for an epoch")
        if epoch == 162:
            current = native["second_162_accounting"]["owner"]
            need(current["unit"]["Id"] == unit and current["invocation_id"] == iid, "different 162 guard")
            ref = current["guard_plan"]
        elif epoch in (169,170):
            # Distinct installations may price the same actor in more than one
            # representation. They must agree on its exact active guard.
            receipts = [item["guard_plan"] for item in peers.values() if isinstance(item,dict)
                        and item.get("unit") == unit and item.get("invocation") == iid and item.get("guard_plan")]
            need(receipts and all(ref == receipts[0] for ref in receipts), "native price lacks the active peer guard " + unit)
            ref = receipts[0]
        else:
            found = [r for r in rows if r["epoch"] == epoch and r["unit"]["Id"] == unit and r["unit"]["InvocationID"] == iid]
            need(len(found) == 1, "no current fleet guard for " + unit)
            ref = found[0].get("guard_protection") or found[0]["guard"]
            ref = ref.get("plan", ref)
        evidence = bind(ref)
        sampled = evidence.get("producer")
        observed_unit = sampled["cgroup"] if sampled else "/system.slice/" + evidence["unit"]
        observed_iid = evidence.get("producer_invocation_id") or evidence.get("invocation_id")
        floor = evidence["minimum_free_bytes"]
        need(observed_iid == iid and observed_unit == "/system.slice/" + unit and type(floor) is int and floor > 0,
             "different live floor or owner " + unit)
        result[epoch] = dict(unit=unit,invocation=iid,guard=ref,floor=floor)
    return result


def funding(native, free, available, held_floor, remaining, owners, startup):
    floor = max([native["guard_floor"], held_floor] + [row["floor"] for row in owners.values()])
    # The common booking already charges outstanding peer output and the
    # candidate's control. It can exceed the constant floor while peer bytes
    # materialize. Startup also covers the observed 83-second drawdown.
    required = max(native["required_home"], floor + remaining + startup)
    home = min(free, native["available_home"]) - required
    ram = min(available, native["available_ram"]) - native["required_ram"]
    return dict(guard_floor=floor,required_home=required,remaining=remaining,home_margin=home,
                required_ram=native["required_ram"],ram_margin=ram,fits=bool(native["fits"] and min(home,ram) >= 0),
                native_required_home=native["required_home"], armed_peer_floors=owners,
                startup_drawdown_bytes=startup, startup_drawdown_receipts=SHARED_DRAWDOWN)


def quote(phase, held_invocation, profile, enrollment):
    need(Path(__file__).resolve().parent == ROOT/"second-price-v3"
         and hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA, "unsealed 162 retry price")
    l = runpy.run_path(str(OP/"layout.py"))
    spec = l["bound"](enrollment)
    pkg = l["bound"](spec["whole_roster"])
    correct = [m for m in pkg["members"] if m["name"] == "second162_peer.py"]
    need(len(correct) == 1 and correct[0]["sha256"] == PEER_SHA, "common provider lacks the corrected 162 guard")
    previous = runpy.run_path(str(SOURCE))
    native_interface = l["bound"](INTERFACE)

    def geometry(native, free, available, held_floor):
        retained = previous["geometry"](native,free,available,held_floor)
        accounting = native["second_162_accounting"]
        need(accounting["interface"] == INTERFACE and accounting["provider"] == native_interface["provider"]
             and accounting["reader"] == native_interface["reader"] and accounting["enrolled"]
             and accounting["unreleased_predecessor"]["closure"] == native_interface["closure"]
             and accounting["phase"] == ("precharged" if phase == "prestart" else "held")
             and (phase != "postguard" or accounting["owner"]["unit"]["Id"] == l["UNIT"]
                  and accounting["owner"]["invocation_id"] == held_invocation),
             "native roster returned another 162 attempt or resource phase")
        owners = armed_peers(l["bound"],native)
        return funding(native,free,available,held_floor,retained["remaining"],owners,drawdown(l["bound"]))

    issuer = FunctionType(previous["quote"].__code__, dict(previous, BASE=ROOT, PKG=OP, OPERATOR=PROVIDER,
                          HERE=Path(__file__).resolve().parent, geometry=geometry))
    return issuer(phase, held_invocation, profile, enrollment)
