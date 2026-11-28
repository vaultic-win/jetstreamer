"""Metadata getters for genuine0430 qualifications; no body, native, admission or clock action."""
from pathlib import Path
import importlib.util,json,hashlib
OLD=Path('/tmp/continuations0230-qualified-phase-required-source-20261109-v1/qualified_bindings.py')
assert hashlib.sha256(OLD.read_bytes()).hexdigest()=='b215298cc367bfd250f54ebd1072dae6ca89de1e838e973433c352526bfd81f3'
spec=importlib.util.spec_from_file_location('horizon_historical0230_metadata_getters',OLD)
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
_raw=old._raw;metadata_bound=old.metadata_bound;_sealed=old._sealed
PACKET=Path(__file__).resolve().parent
HELPER_BINDING_SHA='83f975b03865e8807b3fa21ba7ef3665ef2ed25ecc9dc0117751c5878e8b7a59'
GUARD_BINDING_SHA='a226175b38de3702073e99ce64064598fdfcb9c604e91f10dab603a276240da2'
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
