"""Current role selection over already-validated complete historical authority."""
from pathlib import Path
import json
from qualified_bindings import metadata_bound,_raw
BINDING={'path': '/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0500-20261109-v1/ROOT_CURRENT0500_COMPLETE_QUALIFIED_SUCCESSOR_AUTHORITY.json', 'sha256': '8e650a13633b2d4df49828db8a0d216c4aa57ac36f9ab43a9cada80a02b88b0b'}
def document(b):
 assert metadata_bound(b['path'],immutable=False)==b
 return json.loads(_raw(b['path'],immutable=False))
def next_operation_bindings():
 a=document(BINDING)
 assert a['schema']=='horizon-current0500-next-qualified-bindings-v1'and a['current_complete_DATA_lower_bound_bytes']==5177463485076
 old=document(a['strict_historical_authority_execution']);assert old['code']==0 and json.loads(old['stdout'])==document(a['predecessor_authority'])
 expected={'driver12':a['accepted_actor_driver'],'helper35':a['postreader30'],'final6':a['final_executor'],'planner6':a['planner'],'operation38':a['operation']}
 for name,b in a['current_qualified_artifact_bindings'].items():
  r=document(b);q=document(r['qualification']);seal=document(r['normal_seal'])
  assert q['all_required_tests_passed']and q['prod_clippy_passed']and q['test_clippy_passed']
  if name in expected:assert r['program']==expected[name]
  assert seal['destination']==str(Path(r['program']['path']).parent)and not seal['replay_launch_authorized']and not seal['publication_authorized']and not seal['r2_mutations']
  assert len([row for row in seal['members']if row['name']==Path(r['program']['path']).name and row['sha256']==r['program']['sha256']and row['mode']=='0555'])==1
  assert len([row for row in seal['members']if row['name']=='artifact-proof.json'and row['sha256']==r['qualification']['sha256']and row['mode']=='0444'])==1
 additions=a['successor_additive_DATA_bookings'];assert len({x['path']for x in additions})==len(additions)
 amount=lambda d:d.get('new_additive_retained_DATA_bytes',d.get('additional_retained_DATA_bytes',d.get('new_retained_DATA_bytes',0)))
 assert 5133440070292+sum(amount(document(x))for x in additions)==a['current_complete_DATA_lower_bound_bytes']
 assert not a['replay_launch_authorized']and a['new_memory_or_DATA_credit_bytes']==0 and not a['full_boundary_route_qualified']
 return a
