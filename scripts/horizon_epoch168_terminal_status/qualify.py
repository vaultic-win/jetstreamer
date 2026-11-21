"""Run the actual pre-close sample through the successor package with an isolated status store."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

pkg, work = map(Path, sys.argv[1:])
sys.path.insert(0, str(pkg))
import closed168
import cycle
import reconcile
import status
from evidence import EPOCHS, bound, checked, durable

work.mkdir(mode=0o700)
real_names = cycle.names

def private_names(when):
    names = real_names(when)
    return dict(names, out=work/("output-"+when.replace(":", "")))

with patch.object(cycle, "names", private_names):
    c = cycle.Cycle(closed168.PREVIOUS["path"], closed168.PREVIOUS["sha256"], closed168.SAMPLE["sha256"])

assert c.retired168 and c.diagnostic["observer_diagnostic_result"]["status"] == "unavailable"
assert [r for r in c.next_cfg["diagnostic_replays"] if r["range"] == "168"] == []
expected_cfg = [c.focused["observer_config"] if r["range"] == "169" else r
                for r in c.cfg["diagnostic_replays"] if r["range"] not in ("168", "172")]
assert c.next_cfg["diagnostic_replays"] == expected_cfg
c.unchanged()
class Store:
    def __init__(self):
        self.objects = {}
        self.puts = []
        for e in EPOCHS:
            rec = checked(c.prior["receipts"][str(e)])
            self.objects[e] = (rec["after_etag"], status.body(rec["after_status"]))
    def get(self,e):
        return self.objects[e]
    def put(self,e,tag,data):
        assert e not in self.puts and self.get(e)[0] == tag
        self.puts.append(e)
        tag='"fixture-'+status.digest(data)+'"'
        self.objects[e]=(tag,data)
        return tag

out=work/"status"
out.mkdir(mode=0o700)
store=Store()
ready=c.prior["ready_epochs"]
complete=status._publish(c,store,out,ready)
assert store.puts==list(EPOCHS) and status._publish(c,store,out,ready)==complete and len(store.puts)==19
done=checked(complete)
reconcile.validate_status(c, done)
assert done["active_producer_count"]==5 and done["active_private_diagnostic_count"]==1 and done["canonical_producer_count"]==4
assert done["replay_lanes"] == sum(c.advancing.values()) and done["receipts"].keys()==c.prior["receipts"].keys()
for key, ref in done["receipts"].items():
    r=checked(ref)
    assert r["previous_receipt"] == c.prior["receipts"][key] and r["authenticated_readback"] and r["sampled_at_utc"]==c.stamp
    assert store.get(int(key))==(r["after_etag"], status.body(r["after_status"]))
cap=dict(checked(c.fleet["current_home_cycle_capacity"]),retained_private_diagnostic_168=c.diagnostic,retained_private_diagnostic_169=c.diagnostic169)
durable(work/"capacity.json",cap);durable(work/"next.json",c.next_cfg)
projected=reconcile.assemble(c,complete,c.fleet["continuing_audit_obligation"]["current_observation"],bound(work/"capacity.json"),bound(work/"next.json"))
assert projected[closed168.FIELD]==closed168.TERMINAL
assert {r["epoch"] for r in projected["actual_executing_replays"]}=={166,167,170,172}
assert [r["epoch"] for r in projected["actual_active_private_diagnostics"]]==[169]
assert projected["active_producer_count"]==5 and projected["canonical_producer_count"]==4
assert [r for r in projected["epochs"] if r["epoch"]==168][0]["no_live_producer_claimed"]
assert all(projected[k]==c.fleet[k] for k in ("complete_projected_memory_bytes","complete_DATA_bytes","all_reservation_ending_bytes"))
assert projected["sole_next_timer"]==c.next["timer"] and closed168.prior(projected)
from types import SimpleNamespace
later=SimpleNamespace(fleet=projected,cfg=c.next_cfg,sample={"diagnostic_replays":c.next_cfg["diagnostic_replays"]},
                      sample_ref={"path":"following","sha256":"f"*64},private=c.private)
assert closed168.observation(later)["observer_diagnostic_result"] is None
def reject(action):
    try:action()
    except ValueError:pass
    else:raise AssertionError("invalid 168 transition accepted")
reject(lambda:closed168.prior(dict(projected, actual_active_private_diagnostics=c.fleet["actual_active_private_diagnostics"])))
reject(lambda:closed168.prior(dict(projected, **{closed168.FIELD:c.fleet_ref})))
later.sample["diagnostic_replays"]=c.cfg["diagnostic_replays"];reject(lambda:closed168.observation(later))
with patch("owners.show",return_value={"ActiveState":"active"}):reject(closed168.native)
c.unchanged()
print(json.dumps(dict(complete=complete,source=c.fleet_ref,sample=c.sample_ref,next=c.due,terminal=closed168.TERMINAL,
                      total=19,retry_puts=0,active=5,replay=4,private=1,resource_credit_bytes=0,
                      negative_cases=4,production_writes=0,projected_timer=projected["sole_next_timer"])))
