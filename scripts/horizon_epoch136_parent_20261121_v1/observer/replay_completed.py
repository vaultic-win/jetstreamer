"""Recompute a completed genuine cadence with the candidate and compare its durable outputs."""
import json
import sys
from unittest.mock import patch
from pathlib import Path

package, previous, accepted = map(Path, sys.argv[1:])
sys.path.insert(0,str(package))
from cycle import Cycle
from evidence import bound, checked, content
from reconcile import assemble
import status

p=bound(previous); after=content(accepted)
assert after["previous_Root_operational_review"]==p
# Run in a read-only systemd sandbox, using the immutable results already in this cycle.
c=Cycle(p["path"],p["sha256"],after["observer"]["sha256"])
assert c.private136 is None and c.paths["out"]==accepted.parent
assert c.next_cfg==checked(after["sole_next_observer"])
assembled=assemble(c,after["authenticated_status_audit"],after["continuing_audit_obligation"]["current_observation"],
                   after["current_home_cycle_capacity"],after["sole_next_observer"])
mismatch={k for k in assembled.keys()|after.keys() if assembled.get(k)!=after.get(k)}
assert not mismatch,sorted(mismatch)
# Run the real status formatter twice against the same authenticated input. Its
# six public fields and their digest also have to match the genuine receipt.
status_ref=after["effective_status_receipts"]["136"]
published=checked(status_ref)
prior_ref=published["previous_receipt"]
prior=checked(prior_ref)
payload=status.body(prior["after_status"])
assert published["before_sha256"]==prior["after_sha256"]==status.digest(payload)
def status_proof():
    return status.proof(c,136,prior_ref,prior,prior["after_etag"],payload)

absent=status_proof()
worker_iid="1"*32
fixture=dict(phase="private-worker-authorized",positive_worker=True,transaction_replay_claimed=True,
             receipt={"path":"/synthetic/capture","sha256":"a"*64},unit={"InvocationID":worker_iid},
             observed_progress={"slot_delta":5,"transaction_delta":13})
with patch.object(c,"private136",fixture):
    positive=status_proof()
assert absent["after_status"]==positive["after_status"]==published["after_status"]
assert absent["after_sha256"]==positive["after_sha256"]==published["after_sha256"]
assert positive["producer_invocation_id"]==worker_iid and positive["private_transaction_progress"] is True
assert positive["measured_canonical_progress"] is False and positive["archive_sample"] is None
for key in ("current_replay_lanes","canonical_producer_count","active_bootstraps","fleet_predecessor",
            "before_etag","conditional_header","archive_publication_authorized","replay_launch_authorized"):
    assert positive[key]==absent[key]==published[key],key
print(json.dumps(dict(prior=p,actual_fleet=bound(accepted),identical_fields=len(assembled),
      owners=assembled["active_producer_count"],checked_statuses=len(assembled["effective_status_receipts"]),
      sole_timer=assembled["sole_next_timer"],audit=assembled["continuing_audit_obligation"]["current_observation"],
      public_136_fields=len(positive["after_status"]),public_136_status_unchanged=True,regenerated_status_writes=0,new_timer=False)))
