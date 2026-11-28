"""Append qualified37/Final4 and actual DATA to the complete strict0100 authority."""
from pathlib import Path
import json,hashlib,os,stat
from qualified_bindings import _raw,metadata_bound
PIN = '1e0cf321f83c2baa6721a5376922c1d3effa8ef35bf4b810736b058be36db325'
def components():
 raw=_raw(Path(__file__).resolve().parent/'ACTUAL0200_SUCCESSOR_COMPONENT_BINDINGS.json',immutable=False)
 assert hashlib.sha256(raw).hexdigest()==PIN
 return json.loads(raw)
def document(binding):
 assert set(binding)=={'path','sha256'}
 raw=_raw(binding['path'],immutable=False)
 assert hashlib.sha256(raw).hexdigest()==binding['sha256']
 return json.loads(raw)
def native_success(row):
 assert document(row['execution'])['code']==0
 n=row['original_native']
 assert all(n[k]=='0' for k in ['MainPID','ControlPID','NRestarts','ExecMainStatus'])
 assert n['Result']=='success' and n['Job']==n['ControlGroup']==''
 e=row['original_PID1_success']
 assert e['_PID']=='1' and e['_UID']=='0' and e['UNIT']==n['Id']
 assert e['MESSAGE_ID']=='7ad2d189f7e94e70a38c781354912448'
 assert row['original_outer_reaped'] and row['original_cgroup_empty'] and row['original_descriptors_drained']
def normal(program,qualification,seal):
 q=document(qualification);s=document(seal)
 assert q['production_artifact']['sha256']==program['sha256']
 assert all(q[k] is True for k in ['prod_clippy_passed','test_clippy_passed','all_required_tests_passed'])
 assert q['replay_launch_authorized'] is False and q['publication_authorized'] is False
 assert q['memory_credit_bytes']==q['DATA_credit_bytes']==0
 assert s['schema']=='jetstreamer-sealed-deployment-receipt-v1' and s['destination']==str(Path(program['path']).parent)
 assert s['replay_launch_authorized'] is False and s['publication_authorized'] is False and s['r2_mutations'] is False
 assert len([r for r in s['members'] if r['name']==Path(program['path']).name and r['sha256']==program['sha256'] and r['mode']=='0555'])==1
 assert len([r for r in s['members'] if r['name']=='artifact-proof.json' and r['sha256']==qualification['sha256'] and r['mode']=='0444'])==1
 assert metadata_bound(Path(program['path']).with_name('artifact-proof.json'))==qualification
 return q
def graph(q):
 g=document(q['exact_source_and_compiler_graph'])
 assert set(g['recipes'])=={'clippy-production','clippy-tests','test-build','release'}
 for row in g['source']:_source_graph_member_bytes(row)
 if 'extern_bindings' in g:
  for argv in g['recipes'].values():
   actual=[argv[i+1] for i,v in enumerate(argv) if v=='--extern']
   assert len(actual)==len(g['extern_bindings']) and set(actual)==set(g['extern_bindings'])
 return g
def actual0100_retirement():
 c=components();r=document(c['successful0100_retirement'])
 assert r['schema']=='horizon-positive185-successful-reader-manager-retirement-v1'
 assert all(r[k] is True for k in ['actual_same_shared_retirement_primitive_exercised','actual_two_owned_manager_aliases_removed','only_successfully_completed_reader_retired','only_zero_process_keeper_stopped','sealed_packages_and_successful_namespaces_preserved'])
 assert r['reset_failed_called'] is False and r['resource_credit_bytes']==r['input_body_reads']==0
 assert r['replay_launch_authorized'] is False and r['publication_authorized'] is False
 i=document(r['intent']);n=i['original_successful_native']
 assert n['InvocationID']=='d7392886345a460996fa632037bb5a2c' and n['ExecMainPID']=='3825939'
 assert n['Result']=='success' and n['ExecMainStatus']==n['MainPID']==n['ControlPID']=='0'
 assert i['original_PID_absent'] and i['original_cgroup_empty'] and i['all_original_payloads_and_successful_output_preserved']
 for k in ['final_reader_native','final_keeper_native']:
  assert r[k]['LoadState']=='not-found' and r[k]['Job']==''
 document(r['timer_audit']);document(r['original_PID1_journal'])
 original=document(c['successful0100_retirement_original_execution']);assert original['code']==0
 output=json.loads(original['stdout'])
 assert output['actual_successful_reader_retirement']==c['successful0100_retirement']
 assert output['context']==c['successful0100_retirement_context'] and output['exact0100_original'] and output['no_replay_or_archive_authority']
 context=document(c['successful0100_retirement_context']);actor=context['actor_terminal_noMain']
 assert actor['InvocationID']=='9568cb52af154f7d8fbd48e7571770fa'
 assert actor['MainPID']==actor['ControlPID']==actor['ExecMainPID']=='0' and actor['ControlGroup']==''
 assert context['resource_credit_bytes']==0 and context['all_raw_promises_preserved']
 document(context['owned_timer_stop']);document(context['first_guard_failure']);document(context['completion']);document(context['record'])
 op=document(c['operation37']);assert r['program']==op['program']
 return c['successful0100_retirement']
def extend0200(prior):
 # Caller has run the entire Root0030/O36 prefix and both actual0100 DATA additions.
 assert prior['current_complete_DATA_lower_bound_bytes']==5162967970452
 c=components();op=document(c['operation37']);f=document(c['Final4'])
 assert op['schema']=='horizon-actual-qualified-operation37-final4-layout-bindings-v1'
 q=normal(op['program'],op['qualification'],op['normal_seal'])
 fq=normal(f['program'],f['qualification'],f['normal_seal'])
 assert q['schema']=='horizon-positive185-upstream-original-qualification-v1'
 assert q['ordinary_count']==66 and q['ignored_native_count']==3 and len(q['originals'])==16
 for row in q['originals']:native_success(row)
 og=graph(q);fg=graph(fq)
 assert og['actual_Helper34']==prior['helper34_binding'] and og['actual_Planner5']==prior['planner5_binding']
 assert q['actual_Planner5_program']==prior['planner'] and q['actual_Planner5_qualification']==prior['planner_qualification']
 assert q['actual_Helper34_program']==prior['postreader30'] and q['actual_Helper34_QA_closure']==prior['helper34_QA_closure']
 assert q['actual_Helper34_current2300_composition_controls']==prior['helper34_2300_composition_controls']
 assert fq['schema']=='horizon-positive185-final4-closed-write-qualified-v1' and fq['ordinary_tests_passed']==28 and fq['ignored_tests']==4
 assert all(fq[k] is True for k in ['all_four_ignored_native_publication_controls_passed','all_original_actors_terminal_and_drained','Driver11_and_qualified_helper_policy_unchanged','original_setup_final_token_clocks_unchanged','failed_guard_still_rejected'])
 for execution in fq['ordinary_and_native_originals']:assert document(execution)['code']==0
 assert q['final_executor']==f['program'] and q['final_executor_qualification']==f['qualification']
 assert q['actual_final4_profile_and_eight_file_read_passed'] and q['exact_successful0100_reader_retirement_qualified']
 assert q['original_caps_and_clocks_unchanged'] and q['authoritative_native_timer_clocks_passed']
 assert q['bounded_probe_only'] and q['full_boundary_route_qualified'] is False
 assert q['fresh_native_first_guard_required'] and q['actual_driver11_native_first_guard_accepted'] is False
 assert q['qualified_route']==op['qualified_route']
 route=document(op['qualified_route']);cap=document(op['capability']);life=document(op['reader_lifecycle_control'])
 assert route['schema']=='horizon-positive185-final-qualified-route-v1' and route['purpose']=='bounded_prefix_probe'
 assert route['capability_acceptance']==op['capability']
 assert route['helper']['image']==cap['helper']==prior['postreader30']
 assert route['helper']['artifact']==prior['postreader30_qualification'] and route['helper']['normal_seal']==prior['postreader30_normal_seal']
 assert cap['executor']==f['program'] and cap['driver']==route['driver']==prior['accepted_actor_driver']
 assert cap['original_setup_seconds']==600 and cap['fresh_native_first_guard_required'] and cap['full_boundary_route_qualified'] is False
 assert cap['actual_c71_sol_eight_file_read']['all_eight_exact_bound_files_read']
 assert cap['actual_persistent_reader_lifecycle_control']==q['actual_reader_lifecycle_control']==op['reader_lifecycle_control']
 assert life['program']['sha256']==op['program']['sha256'] and life['actual_postreader_role']==route['helper']
 assert life['prelaunch_reader_image']==cap['prelaunch_reader_image'] and cap['split_prelaunch_postreader_roles']
 success=document(op['successful_reader_retirement_control'])
 assert success['schema']=='horizon-positive185-successful-reader-retirement-native-control-v1'
 assert success['program']['sha256']==op['program']['sha256'] and success['reset_failed_called'] is False and success['resource_credit_bytes']==0
 layout=op['actual_run_layout_control'];assert layout==q['actual_run_layout_control']
 assert layout['schema']=='horizon-positive185-run-layout-qualified-control-v1'
 assert all(layout[k] is True for k in ['actual_Sol_scan_passed','preexisting_nonempty_symlink_foreign_rejected','no_input_or_replay','no_resource_credit'])
 assert layout['program']['sha256']==op['program']['sha256'];document(layout['positive'])
 for key in ['actual_native_reader_start_phase','actual_timer_unset_to_finite_control','actual_completed_writer_native_control','actual_failed_reader_retirement_control','actual_start_request_common_control','actual_held_start_job_reload_control','actual_held_control_pre_task_reload_timer_audit','actual_run_layout_control_execution','actual_final4_profile_execution']:
  document(q[key])
 retirement=actual0100_retirement()
 additions=list(prior['successor_additive_DATA_bookings']);total=prior['current_complete_DATA_lower_bound_bytes']
 last=None
 for key in ['Final4_booking','Operation37_booking','guard0200_booking']:
  booking=document(c[key]);assert booking['previous_retained_DATA_lower_bound_bytes']==total
  assert booking['new_retained_DATA_bytes']==536870912 and booking['normal_pool_bytes']==6<<30
  assert booking['complete_DATA_bytes']==total+536870912
  assert c[key]['path'] not in {x['path']for x in additions}
  if last is not None:assert booking['previous']==last
  last=c[key];total=booking['complete_DATA_bytes'];additions.append(c[key])
 assert total==5164578583188
 amount=lambda x:x.get('new_additive_retained_DATA_bytes',x.get('additional_retained_DATA_bytes',x.get('new_retained_DATA_bytes',0)))
 assert 5133440070292+sum(amount(document(x))for x in additions)==total
 assert not any('current0130' in x['path'] for x in additions)
 assert document(c['guard0200_booking'])['guard0130_was_not_booked_or_built']
 result=dict(prior)
 result.update(operation=op['program'],qualification=op['qualification'],normal_seal=op['normal_seal'],qualified_route=op['qualified_route'],reader_lifecycle_control=op['reader_lifecycle_control'],successful_reader_retirement_control=op['successful_reader_retirement_control'],final_executor=f['program'],final_executor_qualification=f['qualification'],final_executor_normal_seal=f['normal_seal'],actual_successful0100_reader_retirement=retirement,actual_guard0200_booking=c['guard0200_booking'],actual_Final4_booking=c['Final4_booking'],actual_Operation37_booking=c['Operation37_booking'],successor_additive_DATA_bookings=additions,current_complete_DATA_lower_bound_bytes=total,actual_operation37_binding=c['operation37'],actual_final4_binding=c['Final4'])
 return result

def _source_graph_member_bytes(binding):
    import os, stat, hashlib
    p = Path(binding['path'])
    assert p.is_absolute() and p.resolve(strict=True) == p and (p.suffix in {'.rs', '.json', '.service', '.timer'})
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and (before.st_nlink == 1) and (before.st_size < 4 << 20)
        assert before.st_mode & 18 == 0
        raw = bytearray()
        while len(raw) <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_nlink, x.st_uid, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        assert identity(before) == identity(os.fstat(fd)) == identity(os.lstat(p)) and len(raw) == before.st_size
        assert hashlib.sha256(raw).hexdigest() == binding['sha256']
        return bytes(raw)
    finally:
        os.close(fd)
