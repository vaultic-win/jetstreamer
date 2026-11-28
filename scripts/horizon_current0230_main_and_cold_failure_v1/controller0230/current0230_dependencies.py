"""Actual qualified0230 phase/guard, bridge finalizations and additive DATA."""
from pathlib import Path
import hashlib,json
from qualified_bindings import _raw,_sealed,metadata_bound
from current0200_successor import document,native_success,graph
PIN='367e6847f8c20f3c02c6f81ed5b74a6e5f07b42f6b530cc9d00baec233e0fa3d'
def components():
 raw=_raw(Path(__file__).resolve().parent/'ACTUAL0230_COMPONENT_BINDINGS.json',immutable=False)
 assert hashlib.sha256(raw).hexdigest()==PIN
 return json.loads(raw)
def qualified_metadata_phase():
 c=components();phase=document(c['phase_v3'])
 assert phase['program']['sha256']=='267231b1daf19b5c8b958dc718357552c619147b4ace56c8eb781360c700f237'
 q=document(phase['qualification']);seal=document(phase['normal_seal'])
 assert q['schema']=='horizon-readonly-advisory-phase199-static-qualified-v1'
 assert q['production_artifact']['sha256']==phase['program']['sha256']
 assert metadata_bound(Path(phase['program']['path']).with_name('artifact-proof.json'))==phase['qualification']
 assert q['ordinary_tests_passed']==68 and q['ignored_tests']==3 and q['native_phase_pending'] is False
 assert all(q[k] is True for k in ['prod_clippy_passed','test_clippy_passed','all_required_tests_passed','primary_pending_job_is_wait_only','all_original_clocks_unchanged','no_snapshot_equality_relaxed','no_guard_or_timer_mutation'])
 assert seal['schema']=='jetstreamer-sealed-deployment-receipt-v1' and seal['destination']==str(Path(phase['program']['path']).parent)
 assert all(seal[k] is False for k in ['replay_launch_authorized','publication_authorized','r2_mutations'])
 assert len([r for r in seal['members'] if r['name']=='operation' and r['sha256']==phase['program']['sha256'] and r['mode']=='0555'])==1
 assert len([r for r in seal['members'] if r['name']=='artifact-proof.json' and r['sha256']==phase['qualification']['sha256'] and r['mode']=='0444'])==1
 g=graph(q)
 assert g['booking']==phase['booking']==c['phase_v3_booking']
 assert g['primary_busy_wait_only'] and g['no_final_snapshot_or_original_clock_relaxation']
 supplement=document(c['phase_six_original_native_success_and_drain'])
 assert supplement['schema']=='horizon-readonly-phase145-busy-six-original-success-and-drain-v1'
 assert supplement['program']==phase['program'] and supplement['qualification']==phase['qualification']
 assert supplement['all_six_originals_success_terminal_and_drained'] and supplement['no_reset_signal_or_resource_credit']
 assert len(supplement['originals'])==6
 for row in supplement['originals']:
  native_success(row);document(row['argv'])
 assert document(q['actual_native_phase_execution'])['code']==0
 assert document(q['actual_pending_job_sample'])
 native=q['genuine_native_advisory_phase'];assert native['reader_launched'] is False and native['replay_launch_authorized'] is False and native['resource_samples']==0
 document(native['actual_native_phase'])
 timing=native['actual_timing'];at=timing['actual_monotonic_usec']
 assert timing['no_guard_or_timer_mutation'] and timing['failed_guard_is_not_safety_coverage']
 assert 2000000 <= at-timing['guard_exit_monotonic_usec'] <= 4000000
 assert timing['next_guard_deadline_monotonic_usec']-at >= 25000000
 retained=timing['retained199_advisory_phase']
 assert retained['exact_native_pair_preserved'] and retained['no_guard_or_timer_mutation']
 assert 2000000 <= at-int(retained['guard']['ExecMainExitTimestampMonotonic']) <= 4000000
 cross=document(c['phase_v3_crossfire_execution']);assert cross['code']==0
 cross_result=json.loads(cross['stdout'])
 assert cross_result['reader_launched'] is False and cross_result['replay_launch_authorized'] is False and cross_result['resource_samples']==0
 assert len(cross_result['actual_timing']['earlier_metadata_wait_samples'])==28
 document(cross_result['actual_native_phase'])
 # Real cross-fire wait28 samples; no new native queued-Job capture is inferred.
 assert phase['scope']==q['scope']=='Only qualifier/read-original timing route; admission/assembly/replay commands refused'
 return phase
def qualified_guard():
 c=components()
 directory=Path('/usr/local/lib/jetstreamer/horizon-current0230-bound-guard-window-tools-20261109-v1')
 proof=Path(c['guard0230_accepted_QA']['path'])
 program,q,binding=_sealed(directory,'horizon-current0230-guard-window',proof)
 assert binding==c['guard0230_accepted_QA']
 assert metadata_bound(directory/'deployment-seal-receipt.json')==c['guard0230_normal_seal']
 assert q['schema']=='horizon-current0230-qualified-guard-v1'
 assert program['sha256']==q['production']['sha256']=='134d5aadd216a41f2702a68c7850572c61e659b3504f2220ef590f13c27f6ec3'
 assert q['sample_utc']=='2026-11-09T02:30:22Z' and q['sample_unix']==1794191422
 assert q['ordinary_tests_passed']==65 and q['all_original_61_names_preserved']
 assert all(q[k] is True for k in ['all_original_actors_drained','prod_clippy_passed','test_clippy_passed','all_required_tests_passed'])
 assert q['replay_launch_authorized'] is False and q['memory_credit_bytes']==q['DATA_credit_bytes']==0
 for row in q['originals']:
  assert document(row['execution'])['code']==0
  n=row['original_native'];assert n['Result']=='success' and n['MainPID']==n['ControlPID']==n['NRestarts']==n['ExecMainStatus']=='0' and n['ControlGroup']==''
  assert row['original_outer_reaped'] and row['original_cgroup_empty']
  e=row['original_PID1_success']
  argv_path=Path(row['execution']['path'].replace('-ORIGINAL-EXECUTION.json','-ORIGINAL-ARGV.json'))
  argv=json.loads(_raw(argv_path,immutable=False));unit=next(x.split('=',1)[1] for x in argv if x.startswith('--unit='))+'.service'
  assert e['_PID']=='1' and e['_UID']=='0' and e['UNIT']==unit and e['MESSAGE_ID']=='7ad2d189f7e94e70a38c781354912448'
  assert 'Id' not in n or n['Id']==unit
 return program,binding
def actual_bridges():
 c=components();chain=[]
 for key in ['bridge0130_readonly_finalization','bridge0200_readonly_finalization']:
  value=document(c[key]);assert value['no_Frame_or_reader_or_resource_selection_claim']
  document(value['observer']);r=document(value['metadata_finalization'])
  assert r['schema']=='horizon-exact-closed-generated-metadata-readonly-finalization-v1'
  assert r['all_scoped_files_readonly'] and r['actual_closed_file_count']==1 and r['no_original_payload_path_inode_or_history_change']
  assert r['memory_credit_bytes']==r['DATA_credit_bytes']==0 and len(r['files'])==1
  row=r['files'][0];assert row['binding']==value['observer'] and row['same_path_inode_bytes_digest_and_mtime']
  assert row['after']['mode'] & 0o222 == 0
  for field in ['dev','ino','uid','gid','nlink','size','mtime_ns']:assert row['before'][field]==row['after'][field]
  for writer in value['original_writers_and_cgroups']:
   n=writer['native'];assert n['MainPID']==n['ControlPID']==n['NRestarts']==n['ExecMainStatus']=='0' and n['Result']=='success' and n['ControlGroup']==''
   assert any(e.get('_PID')=='1' and e.get('_UID')=='0' and e.get('INVOCATION_ID')==n['InvocationID'] and e.get('JOB_RESULT')=='done' for e in writer['original_PID1_completion'])
  chain.append(dict(observer=value['observer']))
 return chain
def with_current0230_actual_additions(prior):
 assert prior['current_complete_DATA_lower_bound_bytes']==5164578583188
 c=components();phase=qualified_metadata_phase();qualified_guard();actual_bridges()
 additions=list(prior['successor_additive_DATA_bookings']);total=prior['current_complete_DATA_lower_bound_bytes'];previous=prior['actual_guard0200_booking']
 for key in ['phase_v3_booking','guard0230_booking']:
  binding=c[key];book=document(binding)
  assert book['previous']==previous and book['previous_retained_DATA_lower_bound_bytes']==total
  assert book['new_retained_DATA_bytes']==536870912 and book['normal_pool_bytes']==6<<30 and book['extra_QA_bytes']==0
  assert binding['path'] not in {b['path']for b in additions}
  total+=536870912;assert book['complete_DATA_bytes']==total
  additions.append(binding);previous=binding
 assert total==5165652325012 and len({b['path']for b in additions})==len(additions)
 amount=lambda d:d.get('new_additive_retained_DATA_bytes',d.get('additional_retained_DATA_bytes',d.get('new_retained_DATA_bytes',0)))
 assert 5133440070292+sum(amount(document(b))for b in additions)==total
 result=dict(prior)
 result.update(successor_additive_DATA_bookings=additions,current_complete_DATA_lower_bound_bytes=total,actual_guard0230_booking=c['guard0230_booking'],actual_phase145_v3_booking=c['phase_v3_booking'],actual_qualified_metadata_phase=c['phase_v3'],actual_metadata_phase_six_native_success_and_drain=c['phase_six_original_native_success_and_drain'])
 return result
