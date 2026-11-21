"""Adapter for the deployment's existing authenticated status operations and cadence reader."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

base = Path("/var/lib/jetstreamer/horizon_runtime_data")
packages = [base/"epoch168-terminal-status-20261121-v1/publisher-v1", base/"epoch166-post168-cadence-20261121-v1/publisher-v1"]
package = Path(sys.argv[2]) if len(sys.argv) == 3 else packages[0]
assert package in packages, "unregistered status deployment"
sys.path.insert(0, str(package))
from evidence import bound, checked, names, utc
from cycle import load_fleet
from status import Storage, body, follow_event, forecast

action = sys.argv[1]
data = json.load(sys.stdin)
if action == "head":
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
