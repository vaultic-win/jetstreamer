"""Adapter for the deployment's existing authenticated status operations and cadence reader."""
import json
import hashlib
import re
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

base = Path("/var/lib/jetstreamer/horizon_runtime_data")
packages = [base/"epoch168-terminal-status-20261121-v1/publisher-v1", base/"epoch166-post168-cadence-20261121-v1/publisher-v1",
            base/"prefix140-status-cadence-20261122-v1/cadence-tools"]
package = Path(sys.argv[2]) if len(sys.argv) >= 3 else packages[0]
assert package in packages, "unregistered status deployment"
sys.path.insert(0, str(package))
from evidence import bound, checked, names, raw, sealed, utc
from cycle import load_fleet
from status import Storage, body, follow_event, forecast

action = sys.argv[1]
data = json.load(sys.stdin)


def provider():
    profile = sys.argv[4] if len(sys.argv) == 5 else "v5n"
    assert profile in ("v5n", "v5o", "v5q")
    root = base / "incident-replay-fit-20261121-v1" / f"tools-homefloor-145-post-{profile}-136-v1"
    seal = checked(dict(path=str(root / "deployment-seal-receipt.json"), sha256=sys.argv[3]))
    assert seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1" and seal["destination"] == str(root)
    assert seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
    assert seal["remote_mutations"] is False
    for item in seal["members"]:
        assert Path(item["name"]).name == item["name"]
        assert hashlib.sha256(raw(root / item["name"])).hexdigest() == item["sha256"]
    fit = runpy.run_path(str(root / "post-stop-fit"))
    assert fit[profile.upper() + "_136"]
    return fit


def registered_head(ref):
    fit = provider()
    for _ in range(64):
        fleet = checked(ref)
        timer = fleet["sole_next_timer"]
        assert isinstance(timer, str)
        name = re.fullmatch(r"horizon-observer-(root[0-9]{6}[-a-zA-Z0-9]+)\.timer", timer)
        assert name is not None
        successor = base / name.group(1) / "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
        if not successor.exists():
            accepted, _ = fit["fleet_head"](ref)
            cfg = sealed(accepted["sole_next_observer"])
            paths = names(cfg["not_before_utc"])
            assert paths["timer"] == timer and paths["out"] == successor.parent
            assert cfg["output"] == str(paths["sample"]) and cfg["previous_sample"] == accepted["observer"]["path"]
            return dict(fleet=ref, due=cfg["not_before_utc"], timer=timer, sample=str(paths["sample"]),
                        next_lock=str(paths["statuses"] / "cycle.lock"))
        next_ref = bound(successor)
        new = checked(next_ref)
        assert new["previous_Root_operational_review"] == ref
        assert new["recorded_unix_seconds"] > fleet["recorded_unix_seconds"]
        ref = next_ref
    raise ValueError("too many cadence successors")


if action in ("v5n-owner", "v5o-owner", "v5q-owner"):
    assert sys.argv[4:] == ([] if action == "v5n-owner" else [action[:3]])
    # The live Python owner holds the same kernel lock as earlier Bash owners.
    print(json.dumps(provider()["registered_status"](), sort_keys=True))
elif action == "head" and len(sys.argv) >= 4:
    assert sys.argv[4:] in ([], ["v5o"], ["v5q"])
    print(json.dumps(registered_head(data["fleet"]), sort_keys=True))
elif action == "head":
    ref = data["fleet"]
    for _ in range(64):
        fleet, cfg, _ = load_fleet(ref)
        paths = names(cfg["not_before_utc"])
        successor = paths["out"] / "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
        if not successor.exists():
            print(json.dumps(dict(fleet=ref, due=cfg["not_before_utc"], timer=paths["timer"],
                                  sample=str(paths["sample"]), next_lock=str(paths["statuses"]/"cycle.lock"))))
            break
        next_ref = bound(successor)
        assert checked(next_ref)["previous_Root_operational_review"] == ref
        ref = next_ref
    else:
        raise ValueError("too many cadence successors")
elif action == "client":
    Storage()
    print("true")
elif action == "project":
    stamp = data["stamp"]
    result, archive = forecast(SimpleNamespace(stamp=stamp, now=utc(stamp), lanes={}),136,data["old"])
    assert archive is None
    print(json.dumps(dict(status=result, body=body(result).decode())))
elif action == "get":
    tag,raw = Storage().get(136)
    print(json.dumps(dict(etag=tag, body=raw.decode())))
elif action == "put":
    value = data["body"].encode()
    assert 0 < len(value) <= 65536 and body(json.loads(value)) == value
    print(json.dumps(Storage().put(136, data["etag"], value)))
elif action == "follow":
    ref, _ = follow_event(136, data["previous"], data["etag"], data["body"].encode())
    print(json.dumps(ref))
else:
    raise ValueError("unsupported status operation")
