from pathlib import Path
import os,json,hashlib,ast
base=Path('/home/sol/.jetstreamer-private');Q=base/'first-lane-full-reader-witness-qualification-20261107-v1';p=Q/'current0430-20261109-v1';C=Q/'combined-runtime';packet=Path('/tmp/continuations0430-driver12-helper35-final6-source-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(root,name,v):
 fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(root,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
authorityfile=p/'ROOT_CURRENT0430_COMPLETE_QUALIFIED_SUCCESSOR_AUTHORITY.json';a=json.loads(authorityfile.read_text());old=C/'ROOT_HELPER27_CURRENT0430_NORMAL_POOL_REVALIDATED_CLOSURE.json';v=json.loads(old.read_text());g=C/'current0430-window-20261109-v1/ROOT_ACTUAL_QUALIFIED_GUARD0430_BINDINGS.json';guard=json.loads(g.read_text())
v.update(supersedes_prior_current_closure=b(old),actual_next_operation_qualification=a['qualification'],actual_final2_qualification=a['final_executor_qualification'],actual_postreader30_qualification=a['postreader30_qualification'])
if guard['actual_QA_proof']not in v['required_final_qualifications']:v['required_final_qualifications'].append(guard['actual_QA_proof'])
closurefile=C/'ROOT_HELPER27_CURRENT0430_NORMAL_POOL_REVALIDATED_CLOSURE_R2.json';save(C,closurefile.name,v)
h=json.loads(Path('/tmp/continuations0230-qualified-phase-required-source-20261109-v1/ROOT_ACTUAL_QUALIFIED_HELPER27_BINDINGS.json').read_text());h.update(schema='horizon-current0430-actual-helper27-bindings-v1',normal_pool_closure=b(closurefile),genuine_current_Frame=json.loads((p/'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json').read_text())['frame'],current_complete_outer=b(C/'REGRESSION_CURRENT0430_R2_genuine-current-outer_ORIGINAL_EXECUTION_V27.json'),historical_helper_image_qualification_unchanged=True,actual_current_successor_authority=b(authorityfile));save(packet,'ROOT_ACTUAL_QUALIFIED_HELPER27_BINDINGS.json',h);save(packet,'ROOT_ACTUAL_QUALIFIED_GUARD0430_BINDINGS.json',guard)
qsource='''"""Metadata getters for genuine0430 qualifications; no body, native, admission or clock action."""
from pathlib import Path
import importlib.util,json,hashlib
OLD=Path('/tmp/continuations0230-qualified-phase-required-source-20261109-v1/qualified_bindings.py')
assert hashlib.sha256(OLD.read_bytes()).hexdigest()==__OLD_SHA__
spec=importlib.util.spec_from_file_location('horizon_historical0230_metadata_getters',OLD)
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
_raw=old._raw;metadata_bound=old.metadata_bound;_sealed=old._sealed
PACKET=Path(__file__).resolve().parent
HELPER_BINDING_SHA=__HELPER_SHA__
GUARD_BINDING_SHA=__GUARD_SHA__
def _document(binding):
 assert metadata_bound(binding['path'],immutable=False)==binding
 return json.loads(_raw(binding['path'],immutable=False))
def _helper_binding():
 f=PACKET/'ROOT_ACTUAL_QUALIFIED_HELPER27_BINDINGS.json';assert metadata_bound(f,immutable=False)['sha256']==HELPER_BINDING_SHA
 v=json.loads(_raw(f,immutable=False));assert v['schema']=='horizon-current0430-actual-helper27-bindings-v1'
 assert not v['replay_launch_authorized'] and v['new_memory_or_DATA_credit_bytes']==0
 for k in ['qualification','exact_source_and_compiler_graph','normal_pool_closure','current_complete_outer','actual_current_successor_authority']:_document(v[k])
 result=_document(v['current_complete_outer']);assert result['code']==0 and '1 passed; 0 failed;'in result['stdout']
 return v
def helper27():
 v=_helper_binding();program,q,proof=_sealed(Path(v['program_directory']),'jetstreamer-r2',Path(v['qualification']['path']))
 assert q['production_artifact']['sha256']==program['sha256'] and q['all_required_tests_passed'] and q['genuine_current_complete_outer_adapter_passed']
 assert q['memory_credit_bytes']==q['DATA_credit_bytes']==0 and not q['replay_launch_authorized'] and not q['publication_authorized']
 return program,proof
def current_guard():
 f=PACKET/'ROOT_ACTUAL_QUALIFIED_GUARD0430_BINDINGS.json';assert metadata_bound(f,immutable=False)['sha256']==GUARD_BINDING_SHA
 v=json.loads(_raw(f,immutable=False));program,q,proof=_sealed(Path(v['program']['path']).parent,'horizon-current0430-guard-window',Path(v['actual_QA_proof']['path']))
 assert program==v['program'] and proof==v['actual_QA_proof']
 assert metadata_bound(v['normal_seal']['path'])==v['normal_seal']
 assert q['sample_utc']=='2026-11-09T04:30:22Z'and q['sample_unix']==1794198622 and q['ordinary_tests_passed']==65
 assert q['all_original_actors_drained']and q['all_required_tests_passed']and q['all_original_61_names_preserved']
 assert not q['replay_launch_authorized']and q['memory_credit_bytes']==q['DATA_credit_bytes']==0
 return program,proof
def closure27():
 v=_helper_binding();binding=v['normal_pool_closure'];c=_document(binding)
 assert c['schema']=='native163-full-reader-extra-QA6-closure-v1'and c['normal_pool_bytes']==6<<30
 assert c['complete_DATA_bytes']==5176926614164 and c['new_QA_memory_released_bytes']==0
 assert c['all_original_QA_actors_terminal_and_drained']and c['all_required_qualification_actors_terminal_successful_and_drained']and c['source_and_DATA_promises_retained']
 assert len(c['actual_terminal_unit_census'])==1539 and len(c['actual_current_additional_terminal_unit_census'])==87
 assert helper27()[1]in c['required_final_qualifications']and current_guard()[1]in c['required_final_qualifications']
 from next_operation_bindings import next_operation_bindings
 a=next_operation_bindings();assert c['actual_current_successor_authority']==v['actual_current_successor_authority']
 assert c['actual_next_operation_qualification']==a['qualification']and c['actual_final2_qualification']==a['final_executor_qualification']and c['actual_postreader30_qualification']==a['postreader30_qualification']
 assert _document(c['actual_helper35_QA5_closure'])['fresh_extra_QA5_bytes_after']==0
 return binding
'''
qsource=qsource.replace('__OLD_SHA__',repr(sha(Path('/tmp/continuations0230-qualified-phase-required-source-20261109-v1/qualified_bindings.py')))).replace('__HELPER_SHA__',repr(sha(packet/'ROOT_ACTUAL_QUALIFIED_HELPER27_BINDINGS.json'))).replace('__GUARD_SHA__',repr(sha(packet/'ROOT_ACTUAL_QUALIFIED_GUARD0430_BINDINGS.json')));ast.parse(qsource);(packet/'qualified_bindings.py').write_text(qsource)
ns='''"""Current role selection over already-validated complete historical authority."""
from pathlib import Path
import json
from qualified_bindings import metadata_bound,_raw
BINDING=__AUTHORITY__
def document(b):
 assert metadata_bound(b['path'],immutable=False)==b
 return json.loads(_raw(b['path'],immutable=False))
def next_operation_bindings():
 a=document(BINDING)
 assert a['schema']=='horizon-current0430-next-qualified-bindings-v1'and a['current_complete_DATA_lower_bound_bytes']==5176926614164
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
'''.replace('__AUTHORITY__',repr(b(authorityfile)));ast.parse(ns);(packet/'next_operation_bindings.py').write_text(ns)
print('Bound genuine0430 metadata getters and complete historical+current closure; no native reader clock started')
