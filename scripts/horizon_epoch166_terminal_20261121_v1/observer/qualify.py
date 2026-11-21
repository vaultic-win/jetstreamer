"""Reconcile a real completed interval and isolate a hypothetical subsequent 166 exit."""
from contextlib import contextmanager
import copy
import json
import sys
from pathlib import Path
from unittest.mock import patch

package, predecessor, complete, scratch = map(Path, sys.argv[1:])
sys.path.insert(0,str(package))
import closed166
import owners
import reconcile
import status
from cycle import Cycle
from evidence import bound, checked, content, durable

previous=bound(predecessor)
accepted=content(complete)
c=Cycle(previous['path'],previous['sha256'],accepted['observer']['sha256'])
assert c.terminal166 is None and c.owner_fleet is c.fleet and c.next_cfg==checked(accepted['sole_next_observer'])
audit=accepted['continuing_audit_obligation']['current_observation']
capacity=accepted['current_home_cycle_capacity']
status_ref=accepted['authenticated_status_audit']
same=reconcile.assemble(c,status_ref,audit,capacity,accepted['sole_next_observer'])
assert same==accepted, sorted(k for k in same.keys()|accepted.keys() if same.get(k)!=accepted.get(k))

# The actual six/single-owner-cap receipt stays on its real inode. Only the
# fixture output/status/closure are written under the private scratch argument.
seen=checked(status_ref)
old166=next(r for r in c.fleet['actual_executing_replays'] if r['epoch']==166)
owner_inst=old166['unit']['InvocationID']
archive={'path':'/fixture/epoch-166.jet','size':100_000_000_000,'sha256':'ab'*32,'device':1,'inode':2}
terminal=scratch/'terminal.json'
stamp=int(c.now.timestamp())
durable(terminal,{'epoch':166,'producer_invocation_id':owner_inst,'canonical_r2_verified':False,
                  'resource_credit_bytes':0,'local_archive':archive,
                  'manager_terminal':{'__REALTIME_TIMESTAMP':str((stamp-60)*1000000)}})
ref=bound(terminal)
# Exercise the actual consumer selection, including a receipt from another sample.
sample=dict(c.sample,replays=[r for r in c.sample['replays'] if r['range']!='166'])
cfg=dict(c.cfg,replays=[r for r in c.cfg['replays'] if r['range']!='166'])
choice={'original':c.fleet['sole_next_observer'],'predecessor_fleet':c.fleet_ref,
        'previous_sample':c.fleet['observer'],'output':c.sample_ref['path'],'terminal':ref}
@contextmanager
def selection():
    real_bound=closed166.bound
    def fixture_bound(path):
        if path.name=='selection.json':
            return bound(scratch/'selection.json')
        if path.name=='observer.json' and path.parent.parent.name=='after-166':
            return bound(scratch/'config.json')
        return real_bound(path)
    result=json.dumps({'mode':'closed','selection':choice,'projected_config':cfg}).encode()
    with (patch.object(closed166,'TERMINAL',terminal),
          patch.object(closed166.subprocess,'check_output',return_value=result),
          patch.object(closed166,'bound',side_effect=fixture_bound),
          patch.object(closed166,'sealed',side_effect=checked)):
        yield
durable(scratch/'config.json',cfg);durable(scratch/'selection.json',choice)
c.sample=sample
with selection():assert closed166.native_config(c)==ref
assert c.cfg==cfg
foreign=copy.deepcopy(choice);foreign['previous_sample']['sha256']='00'*32
with patch.dict(choice,{'previous_sample':foreign['previous_sample']}):
    with selection():
        try:closed166.native_config(c)
        except ValueError:pass
        else:raise AssertionError('foreign selection accepted')
c.terminal166=ref;c.owner_fleet=closed166.owner_view(c.fleet,ref)
c.rows={e:r for e,r in c.rows.items() if e!=166};original_exists=Path.exists
selected=c.paths['out']/'observer.json'
with patch.object(Path,'exists',lambda path:False if path==selected else original_exists(path)):
    c.interpret()
expected_next=checked(accepted['sole_next_observer'])
expected_next['replays']=[r for r in expected_next['replays'] if r['range']!='166']
assert c.next_cfg==expected_next
output=scratch/'next-config.json';durable(output,c.next_cfg)
assert {r['epoch'] for r in c.owner_fleet['actual_executing_replays']}=={167,170,172}
assert c.owner_fleet['additional_independent166_DATA_cap_bytes']==309237645312
assert c.owner_fleet['complete_DATA_bytes']==6794761027378 and c.owner_fleet['complete_projected_memory_bytes']==761131708416
# Exercise the actual writer and its immediate readback in a private local store.
# The transport, elapsed wall clock and the synthetic worker disposition are the
# only substitutes. Every original status body and ETag comes from the genuine
# receipts; no fixture can write to the service or the remote bucket.
class FixtureStore:
    def __init__(self, originals):
        self.objects = {
            epoch: (record["before_etag"], status.body(record["before_status"]))
            for epoch, record in originals.items()
        }
        self.written = set()

    def get(self, epoch):
        return self.objects[epoch]

    def put(self, epoch, etag, payload):
        assert self.get(epoch)[0] == etag and epoch not in self.written
        self.written.add(epoch)
        new_etag = '"fixture-' + status.digest(payload) + '"'
        self.objects[epoch] = new_etag, payload
        return new_etag

originals = {int(k): checked(v) for k, v in seen["receipts"].items()}
storage = FixtureStore(originals)
outputs = scratch / "status-readback-fixture"
outputs.mkdir(mode=0o700)
with (patch.object(c, "unchanged"), patch.object(c, "public_fresh"),
      patch.object(status, "observed_archive",
                   side_effect=lambda cycle, e: originals[e].get("archive_sample"))):
    result = status._publish(c, storage, outputs, seen["ready_epochs"])
assert storage.written == set(originals)
for key, fixture in checked(result)["receipts"].items():
    epoch = int(key)
    entry = checked(fixture)
    assert entry["authenticated_readback"] and entry["canonical_producer_count"] == 3
    assert entry["current_replay_lanes"] == sum(c.advancing.values())
    assert entry["observer"] == c.sample_ref and entry["conditional_header"] == "If-Match"
    assert storage.get(epoch) == (entry["after_etag"], status.body(entry["after_status"]))
    if epoch == 166:
        assert entry["terminal166_local_commit"] == ref and entry["producer_invocation_id"] is None
        assert entry["current_repair_owner"] == "/root" and entry["after_status"]["phase"] == "verification"
        assert entry["after_status"]["jet_size_bytes"] == archive["size"] and entry["archive_sample"] == archive
        assert entry["after_status"]["estimated_remaining_millis"] > 0
        assert not entry["archive_publication_authorized"] and not entry["replay_launch_authorized"]
    else:
        assert entry["after_status"] == originals[epoch]["after_status"], key
projected = reconcile.assemble(c, result, audit, capacity, bound(output))
assert projected['terminal166_local_commit']==ref and projected['historical166_before_local_commit']==old166
assert projected['live_replay_count']==projected['canonical_producer_count']==3 and projected['active_producer_count']==5
assert projected['active_private_diagnostic_count']==2 and len(projected['effective_status_receipts'])==19
row=next(r for r in projected['epochs'] if r['epoch']==166)
assert row['state']=='verification' and row['no_live_producer_claimed'] and row['current_repair_owner']=='/root' and 'current_replay' not in row
for key in ('complete_DATA_bytes','complete_projected_memory_bytes','all_reservation_ending_bytes','additional_independent166_DATA_cap_bytes','independent166_post_guard_capacity'):
    assert projected[key]==accepted[key], key
print(json.dumps(dict(real_fleet_fields=len(accepted),real_statuses=len(seen['receipts']),surviving_production=[167,170,172],
    surviving_diagnostics=[168,169],all_original_reservations_preserved=True,simulated_terminal_only=True)))
