ROOT_SUCCESSOR_ARTIFACT_VALIDATOR_INTEGRATED = True
'Reviewed metadata loader only: actual C2/final2 authority remains Root-owned.'
from pathlib import Path
import json, re
from qualified_bindings import _raw, metadata_bound
FUTURE_NEXT_OPERATION_BINDINGS_SHA256 = '805b3c51512bd3c7fe63c85a98b97db0cac4d661b1acc08cda7306335c652e89'
MANIFEST = Path(__file__).resolve().parent / 'ROOT_ACTUAL_QUALIFIED_NEXT_OPERATION_BINDINGS.json'
ORIGINAL_ROOT = Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual1030-original-r3-20261108-v21-c2')
ORIGINAL_IID = '431ff97cd75845a2be8bc86a655c5fee'
ORIGINAL_DEADLINE = 1794135129
RETAINED_DATA_LOWER_BOUND = 5123776393876

def _document(binding):
    assert isinstance(binding, dict) and set(binding) == {'path', 'sha256'}
    assert isinstance(binding['path'], str) and re.fullmatch('[a-f0-9]{64}', binding['sha256'])
    assert metadata_bound(binding['path'], immutable=False) == binding
    return json.loads(_raw(binding['path'], immutable=False))

def _contains(value, binding):
    if value == binding:
        return True
    if isinstance(value, dict):
        return any((_contains(x, binding) for x in value.values()))
    if isinstance(value, list):
        return any((_contains(x, binding) for x in value))
    return False

def original1030_held_drain(binding, retirement_binding):
    proof = _document(binding)
    retirement = _document(retirement_binding)
    assert proof['schema'] == 'horizon-positive185-original-setup-expired-drained-event-v1'
    ready = metadata_bound(ORIGINAL_ROOT / 'original-ready-native.json', immutable=False)
    context = metadata_bound(ORIGINAL_ROOT / 'original-activation-context.json', immutable=False)
    assert proof['original_ready'] == ready and proof['original_activation'] == context
    r = _document(ready)
    c = _document(context)
    assert proof['original_invocation_id'] == r['original_native']['InvocationID'] == ORIGINAL_IID
    assert proof['original_setup_deadline'] == r['original_setup_deadline'] == ORIGINAL_DEADLINE
    assert proof['recorded_unix_seconds'] >= ORIGINAL_DEADLINE
    assert all((proof[k] is True for k in ['original_setup_expired_without_renewal', 'original_process_absent', 'original_cgroup_empty', 'main_never_started', 'all_run_root_file_artifacts_absent', 'source_package_and_namespace_preserved', 'original_outer_reaped', 'all_original_processes_and_descriptors_drained', 'native_task_registration_and_enrolled_fleet_history_preserved']))
    assert proof['start_request_was_detached_so_no_synthetic_failed_JOB_RESULT_invented'] is True
    assert proof['actual_original_deadline_failure']['at_unix_seconds'] == ORIGINAL_DEADLINE
    assert proof['actual_original_deadline_failure']['elapsed_millis'] >= 600000
    _document(proof['actual_original_start_request_detached'])
    assert proof['run_root_metadata'] == [] and proof['memory_credit_bytes'] == proof['DATA_credit_bytes'] == 0 and (proof['replay_launch_authorized'] is False)
    actor = proof['actor']
    assert actor['Id'] == c['actor'] and actor['InvocationID'] == ORIGINAL_IID
    assert actor['MainPID'] == actor['ControlPID'] == actor['NRestarts'] == actor['ExecMainPID'] == actor['ExecMainStartTimestampMonotonic'] == '0'
    assert actor['Job'] == actor['ControlGroup'] == '' and actor['ActiveState'] == 'failed'
    units = {x['Id']: x for x in proof['native_units']}
    for name in [c['actor'], c['guard'], 'horizon-failed4-current-accounting-reader-20261104-v1.service']:
        n = units[name]
        assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0' and n['Job'] == n['ControlGroup'] == '' and (n['ActiveState'] in ['inactive', 'failed'])
    assert units[c['timer']]['Job'] == '' and units[c['timer']]['ActiveState'] == 'inactive'
    envelope = _document(c['envelope'])
    assert proof['token_destination'] == str(Path(envelope['token_root']) / ORIGINAL_IID) and proof['token_destination_absent'] is True
    assert proof['actual_qualified_failed_reader_retirement'] == retirement_binding
    assert retirement['schema'] == 'horizon-positive185-failed-reader-manager-retirement-v1'
    assert all((retirement[k] is True for k in ['actual_same_shared_retirement_primitive_exercised', 'actual_two_owned_manager_aliases_removed', 'only_failed_reader_reset', 'only_zero_process_keeper_stopped', 'sealed_packages_and_failed_namespaces_preserved']))
    assert retirement['resource_credit_bytes'] == 0 and retirement['input_body_reads'] == 0 and (retirement['replay_launch_authorized'] is False) and (retirement['publication_authorized'] is False)
    assert retirement['final_reader_native']['LoadState'] == 'not-found' and retirement['final_reader_native']['Job'] == ''
    assert retirement['final_keeper_native']['LoadState'] == 'not-found' and retirement['final_keeper_native']['Job'] == ''
    return proof

def _normal_program(program, qualification, seal_binding):
    q = _document(qualification)
    seal = _document(seal_binding)
    assert isinstance(program['path'], str) and re.fullmatch('[a-f0-9]{64}', program['sha256'])
    assert q['production_artifact']['sha256'] == program['sha256']
    if q['schema'] in ['horizon-positive185-final-executor-unit-qualified-v2', 'horizon-positive185-final-executor-unit-qualified-v3']:
        assert q['strict_production_and_test_Clippy_passed'] is True and q['ordinary_tests_passed'] == (25 if q['schema'].endswith('-v3') else 21)
        assert q['original600second_setup_and30second_final_window_unchanged'] is True
        assert q['actual_native_profile_and_release_timing_still_unqualified'] is True and q['full_boundary_and_runtime_route_still_unqualified'] is True
        for original in q['originals']:
            assert _document(original['execution'])['code'] == 0
            n = original['original_native']
            assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == n['ExecMainStatus'] == '0' and n['ControlGroup'] == n['Job'] == '' and (n['Result'] == 'success')
    else:
        assert all((q[k] is True for k in ['prod_clippy_passed', 'test_clippy_passed', 'all_required_tests_passed']))
    if q['schema'] in ['horizon-positive185-current-witness-planner-qualified-artifact-v3','horizon-positive185-current-witness-planner-qualified-artifact-v4']:
        assert q['no_replay_or_admission_authority'] is True
        if program == CURRENT_PLANNER5:
            assert q['ordinary_tests_passed'] == 27 and q['actual_Helper34'] == CURRENT_HELPER34_BINDING
        else:
            assert q['ordinary_tests_passed'] == (24 if q['schema'].endswith('-v4') else 23)
    else:
        assert q['replay_launch_authorized'] is False and q['publication_authorized'] is False
    assert seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1' and seal['destination'] == str(Path(program['path']).parent)
    members = {x['name']: x for x in seal['members']}
    row = members[Path(program['path']).name]
    assert row['sha256'] == program['sha256'] and row['mode'] == '0555'
    assert members['artifact-proof.json']['sha256'] == qualification['sha256'] and members['artifact-proof.json']['mode'] == '0444'
    assert seal['replay_launch_authorized'] is False and seal['publication_authorized'] is False and (seal['r2_mutations'] is False)
    return q

def next_operation_bindings():
    assert ROOT_SUCCESSOR_ARTIFACT_VALIDATOR_INTEGRATED, 'Root actual successor artifact/schema/normal-seal/native-control integration required'
    assert isinstance(FUTURE_NEXT_OPERATION_BINDINGS_SHA256, str) and re.fullmatch('[a-f0-9]{64}', FUTURE_NEXT_OPERATION_BINDINGS_SHA256), 'Actual qualified C2/final2/route/lifecycle/retained-DATA metadata required; no future hash invented'
    assert metadata_bound(MANIFEST, immutable=False)['sha256'] == FUTURE_NEXT_OPERATION_BINDINGS_SHA256
    authority = validate_actual_manifest(json.loads(_raw(MANIFEST, immutable=False)))
    from current0030_guard_addition import with_current0030_guard
    return with_current0030_guard(authority)

def validate_actual_manifest(v):
    if v.get('schema') == 'horizon-current0000-actual-qualified-successor36-bindings-v1':
        return validate_successor36(v)
    assert v['schema'] == 'horizon-current1400-next-qualified-bindings-v1'
    _document(v['helper33_QA_closure'])
    _document(v['helper33_enrollment_composition_control'])
    _document(v['original2130_completion_and_drain'])
    assert v['replay_launch_authorized'] is False and v['new_memory_or_DATA_credit_bytes'] == 0
    op = v['operation']
    q = _normal_program(op, v['qualification'], v['normal_seal'])
    assert q['schema'] == 'horizon-positive185-upstream-original-qualification-v1'
    assert q['finite_metadata_record_limit'] == 16384 and q['exact_successful1630_reader_retirement_qualified'] is True and (q['exact_successful1800_reader_retirement_qualified'] is True)
    retired1530 = _document(v['successful1530_reader_retirement'])
    assert retired1530['schema'] == 'horizon-positive185-successful-reader-manager-retirement-v1' and retired1530['reset_failed_called'] is False
    assert all((retired1530[k] is True for k in ['actual_two_owned_manager_aliases_removed', 'actual_same_shared_retirement_primitive_exercised', 'only_successfully_completed_reader_retired', 'only_zero_process_keeper_stopped', 'sealed_packages_and_successful_namespaces_preserved']))
    assert retired1530['resource_credit_bytes'] == retired1530['input_body_reads'] == 0 and retired1530['replay_launch_authorized'] is False
    intent1530 = _document(retired1530['intent'])
    assert intent1530['original_successful_native']['InvocationID'] == 'a3fdc90e73654ba981797a9a16b076c7' and intent1530['original_successful_native']['ExecMainPID'] == '3455013'
    assert retired1530['final_reader_native']['LoadState'] == retired1530['final_keeper_native']['LoadState'] == 'not-found'
    ended1530 = _document(v['original1530_completion_and_drain'])
    assert ended1530['original_invocation_id'] == 'f3ba06c7d00044e3a462e1d3c45edb0e' and ended1530['original_setup_deadline'] == 1794152948 and (ended1530['main_never_started'] is True) and (ended1530['token_destination_absent'] is True)
    assert q['original_caps_and_clocks_unchanged'] is True and q['authoritative_native_timer_clocks_passed'] is True
    assert q['memory_credit_bytes'] == q['DATA_credit_bytes'] == 0
    final = v['final_executor']
    fq = _normal_program(final, v['final_executor_qualification'], v['final_executor_normal_seal'])
    assert q['actual_Planner4_program']==v['planner'] and q['actual_Planner4_qualification']==v['planner_qualification']
    assert _document(v['planner4_original2230_request_control'])['code']==0
    assert q['actual_final3_profile_and_eight_file_read_passed'] is True and q['final_executor'] == final and (q['final_executor_qualification'] == v['final_executor_qualification'])
    route = _document(v['qualified_route'])
    cap = _document(route['capability_acceptance'])
    assert route['schema'] == 'horizon-positive185-final-qualified-route-v1' and cap['schema'] == 'horizon-positive185-final-route-capability-v2'
    assert cap['executor'] == final and cap['original_setup_seconds'] == 600 and (cap['publication_authorized'] is False)
    assert route['helper']['image'] == v['postreader30']
    hq = _normal_program(v['postreader30'], v['postreader30_qualification'], v['postreader30_normal_seal'])
    assert hq['genuine_current_complete_outer_adapter_passed'] is True
    closed33 = _document(v['helper33_QA_closure'])
    assert closed33['fresh_extra_QA4_bytes_before'] == 4 << 30 and closed33['fresh_extra_QA4_bytes_after'] == 0 and (closed33['normal_pool_bytes'] == 6 << 30)
    assert closed33['no_producer_memory_or_DATA_credit'] is True and closed33['all_source_outputs_and_failed_evidence_retained'] is True
    control33 = _document(v['helper33_enrollment_composition_control'])
    assert control33['code'] == 0 and 'actual2130_plan_composes_complete_transition_with_same_live145_consumer ... ok' in control33['stdout']
    assert hq['actual2130_enrollment_composition_control'] == q['actual_Helper33_composition_control'] == v['helper33_enrollment_composition_control']
    assert q['actual_Helper33_program'] == v['postreader30'] and q['actual_Helper33_QA_closure'] == v['helper33_QA_closure']
    ended2130 = _document(v['original2130_completion_and_drain'])
    assert ended2130['original_IID'] == '387a0dcd086f4f209e087059783107b8' and ended2130['natural_original_deadline'] == 1794174503
    assert ended2130['native_after']['ExecMainPID'] == ended2130['native_after']['MainPID'] == ended2130['native_after']['ControlPID'] == '0'
    assert ended2130['native_after']['ControlGroup'] == '' and ended2130['no_signal_or_reset_or_lease_renewal'] is True
    assert ended2130['memory_credit_bytes'] == ended2130['DATA_credit_bytes'] == 0
    assert cap['prelaunch_reader_image']['sha256'] == 'd00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470'
    assert cap['actual_persistent_reader_lifecycle_control'] == v['reader_lifecycle_control'] == q['actual_reader_lifecycle_control']
    lifecycle = _document(v['reader_lifecycle_control'])
    assert lifecycle['program']['sha256'] == op['sha256'] and lifecycle['actual_postreader_role'] == route['helper'] and (lifecycle['prelaunch_reader_image'] == cap['prelaunch_reader_image'])
    assert cap['split_prelaunch_postreader_roles'] is True and cap['helper'] == v['postreader30']
    assert v['postreader30']['path'] == '/usr/local/lib/jetstreamer/horizon-epoch185-enrollment-composition-postreader-tools-20261108-v33/jetstreamer-r2'
    assert hq['actual_features'] == ['native210-small', 'native227-small']
    policy = cap['original_start_request_policy_source']
    assert policy['path'] == '/usr/local/lib/jetstreamer/horizon-positive185-start-request-policy-source-20261108-v2/start_request.rs' and policy['sha256'] == '7b28a430d3f4179759440bd679005a6231c638b6f808ce673e9933cf7281d4c6'
    policy_seal = _document(cap['original_start_request_policy_normal_seal'])
    assert any((x['name'] == 'start_request.rs' and x['sha256'] == policy['sha256'] and (x['mode'] == '0444') for x in policy_seal['members']))
    common = _document(cap['actual_start_request_common_control'])
    completion = _document(cap['original_start_request_common_qualification'])
    common_seal = _document(cap['start_request_common_control_normal_seal'])
    assert common['same_original_actor_start_request_roundtrip_exercised'] is True and common['actual_pre_task_reload_and_start_job_validator_exercised'] is True
    assert common['input_body_reads'] == 0 and common['replay_launch_authorized'] is False
    assert completion['schema'] == 'horizon-original-start-request-common-policy-qualified-v1' and completion['policy_source'] == policy
    assert completion['actual_common_control']['sha256'] == cap['actual_start_request_common_control']['sha256']
    assert completion['common_policy_only'] is True and completion['same_image_production_launch_qualified'] is False
    assert completion['resource_credit_bytes'] == 0 and completion['replacement_job_native_PID1_done'] is True
    for key in ['actual_start_request_common_control', 'original_start_request_common_qualification']:
        bound = cap[key]
        assert any((x['name'] == Path(bound['path']).name and x['sha256'] == bound['sha256'] and (x['mode'] == '0444') for x in common_seal['members']))
    for proof in [q, fq]:
        graph = _document(proof.get('exact_source_and_compiler_graph', proof.get('source_freeze')))
        if not _contains(graph, policy):
            sources = graph['source']
            mains = [x for x in sources if Path(x['path']).name == 'main.rs']
            assert len(mains) == 1
            main = _source_bytes(mains[0])
            marker = ('#[path = "' + policy['path'] + '"]' + '\nmod start_request;').encode()
            assert ('#[path = "' + policy['path'] + '"]' + '\n').encode() in main and b'mod start_request;' in main
            _source_bytes(policy)
    ledger = _document(v['retained_phase_ledger'])
    booking = _document(v['additive_DATA_booking'])
    assert booking['schema'] == 'horizon-positive185-final2-serial-normal6-QA-booking-v1' and booking['additional_retained_DATA_bytes'] == 536870912
    assert booking['previous_retained_DATA_lower_bound_bytes'] == 5118944555668 and booking['retained_DATA_lower_bound_bytes'] == 5119481426580 and (booking['no_resource_credit'] is True)
    qb = _document(v['helper29_QA_booking'])
    qc = _document(v['helper29_QA_closure'])
    assert qb['new_extra_QA6_bytes'] == 6 << 30 and qb['new_additive_retained_DATA_bytes'] == 4 << 30 and (qb['complete_DATA_lower_bound_bytes'] == RETAINED_DATA_LOWER_BOUND)
    assert qc['booking'] == v['helper29_QA_booking'] and qc['new_QA_memory_released_bytes'] == 6 << 30 and (qc['normal_pool_bytes'] == 6 << 30) and (qc['all_helper29_QA_actors_terminal_and_drained'] is True) and (qc['complete_DATA_bytes'] >= RETAINED_DATA_LOWER_BOUND)
    assert ledger['all_old_memory_DATA_and_raw_producer_promises_retained'] is True
    original1030_held_drain(v['original1030_held_expiry_and_drain'], v['failed1030_reader_retirement'])
    _document(v['frame_phase_argv_template'])
    qb30 = _document(v['helper30_QA_booking'])
    qc30 = _document(v['helper30_QA_closure'])
    assert qb30['new_extra_QA6_bytes'] == 6 << 30 and qb30['new_additive_retained_DATA_bytes'] == 4 << 30 and (qb30['complete_DATA_lower_bound_bytes'] == 5129145102996)
    assert qc30['booking'] == v['helper30_QA_booking'] and qc30['new_QA_memory_released_bytes'] == 6 << 30 and (qc30['normal_pool_bytes'] == 6 << 30)
    assert qc30['all_helper30_and_operation25_26_QA_actors_terminal_and_drained'] is True and qc30['complete_DATA_bytes'] >= 5129145102996
    expired = _document(v['original1230_held_expiry_and_drain'])
    retired = _document(v['failed1230_reader_retirement'])
    assert expired['original_invocation_id'] == 'e23d5bdd40ed4a888e875d7a30de119c' and expired['original_setup_deadline'] == 1794141957
    assert all((expired[k] is True for k in ['original_setup_expired_without_renewal', 'original_process_absent', 'original_cgroup_empty', 'main_never_started', 'all_run_root_file_artifacts_absent', 'all_original_processes_and_descriptors_drained', 'token_destination_absent']))
    assert expired['actual_original_deadline_failure']['at_unix_seconds'] == 1794141957 and expired['actual_original_deadline_failure']['elapsed_millis'] == 599791
    assert expired['actual_elapsed_millis_is_original_not_rounded_up'] is True and expired['actual_qualified_failed_reader_retirement'] == v['failed1230_reader_retirement']
    assert retired['actual_same_shared_retirement_primitive_exercised'] is True and retired['final_reader_native']['LoadState'] == 'not-found' and (retired['resource_credit_bytes'] == 0)
    assert q['actual_completed_writer_fleet_readonly_closure_passed'] is True
    accepted_driver = v['accepted_actor_driver']
    accepted_driver_seal = _document(v['accepted_actor_driver_normal_seal'])
    assert route['driver'] == cap['driver'] == accepted_driver
    assert accepted_driver == {'path': '/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v11/epoch185-guarded-cold', 'sha256': 'bdadc547439d2dbba11797f715c1741772dad693cd54073ac273132a7ba096f2'}
    assert accepted_driver_seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1' and accepted_driver_seal['destination'] == str(Path(accepted_driver['path']).parent)
    assert any((x['name'] == Path(accepted_driver['path']).name and x['sha256'] == accepted_driver['sha256'] and (x['mode'] == '0555') for x in accepted_driver_seal['members']))
    ended = _document(v['original1330_completion_and_drain'])
    cleanup = _document(v['failed1330_reader_retirement'])
    assert ended['schema'] == 'horizon-positive185-original-setup-expired-drained-event-v1'
    assert ended['original_invocation_id'] == 'cb35709d56014888a1b82931c2a20727' and ended['original_setup_deadline'] == 1794146129
    assert all((ended[k] is True for k in ['original_setup_expired_without_renewal', 'original_process_absent', 'original_cgroup_empty', 'main_never_started', 'all_run_root_file_artifacts_absent', 'all_original_processes_and_descriptors_drained', 'token_destination_absent']))
    assert ended['actual_original_deadline_failure']['at_unix_seconds'] == 1794146129 and ended['actual_original_deadline_failure']['elapsed_millis'] == 599457
    assert ended['actual_elapsed_millis_is_original_not_rounded_up'] is True and ended['start_request_was_detached_so_no_synthetic_failed_JOB_RESULT_invented'] is True
    ready = _document(ended['original_ready'])
    ctx = _document(ended['original_activation'])
    assert ready['original_native']['InvocationID'] == ended['actor']['InvocationID'] == ended['original_invocation_id']
    assert ready['original_setup_deadline'] == ended['original_setup_deadline'] and ended['actor']['Id'] == ctx['actor']
    assert cleanup['schema'] == 'horizon-positive185-failed-reader-manager-retirement-v1'
    assert cleanup['actual_same_shared_retirement_primitive_exercised'] is True and cleanup['final_reader_native']['LoadState'] == 'not-found' and (cleanup['resource_credit_bytes'] == 0)
    assert cleanup['final_reader_native']['Job'] == '' and cleanup['final_keeper_native']['LoadState'] == 'not-found' and (cleanup['final_keeper_native']['Job'] == '')
    assert all((cleanup[k] is True for k in ['only_failed_reader_reset', 'only_zero_process_keeper_stopped', 'actual_two_owned_manager_aliases_removed', 'sealed_packages_and_failed_namespaces_preserved']))
    intent = _document(cleanup['intent'])
    failed = intent['original_failed_native']
    assert failed['InvocationID'] == 'eb59940840294679a4e03ce5dd32cca6' and failed['ExecMainPID'] == '3380036'
    historical30 = v['historical_postreader30']
    _normal_program(historical30, v['historical_postreader30_qualification'], v['historical_postreader30_normal_seal'])
    assert historical30 == {'path': '/usr/local/lib/jetstreamer/horizon-epoch185-ready-custody-postreader-tools-20261108-v30/jetstreamer-r2', 'sha256': '51381649ca4a4b353c738d37435bbfc594a36077a01f5d3a510504e8341a670f'}
    assert historical30['sha256'] in failed['ExecStart'] and historical30['path'] in failed['ExecStart']
    assert intent['original_PID_absent'] is True and intent['original_cgroup_empty'] is True
    for original in v['preserved_original_execution_records']:
        _document(original)
    assert q['actual_bounded_coherent_timer_capture_qualified'] is True
    timer_control = _document(q['actual_timer_unset_to_finite_control'])
    assert timer_control['same_original_fire'] is True and timer_control['no_signals_or_clock_extension'] is True
    ended1430 = _document(v['original1430_completion_and_drain'])
    assert ended1430['original_invocation_id'] == '68f5e1bbbe404a888e8fba3fa82177e8' and ended1430['original_setup_deadline'] == 1794149578
    assert ended1430['actual_original_deadline_failure']['elapsed_millis'] == 600211 and ended1430['actual_elapsed_millis_is_original_not_rounded_up'] is True
    assert ended1430['no_native_task_capture_or_postreader_installed'] is True and ended1430['failed_reader_retirement_required'] is False
    assert all((ended1430[k] is True for k in ['original_setup_expired_without_renewal', 'original_process_absent', 'original_cgroup_empty', 'main_never_started', 'all_original_processes_and_descriptors_drained', 'token_destination_absent']))
    q31 = _document(v['helper31_QA_closure'])
    book31 = _document(v['helper31_QA_booking'])
    assert q31['booking'] == v['helper31_QA_booking'] and q31['new_QA_memory_released_bytes'] == 6 << 30 and (q31['normal_pool_bytes'] == 6 << 30) and (q31['complete_DATA_bytes'] == 5133440070292)
    assert book31['new_additive_retained_DATA_bytes'] == 4 << 30 and book31['new_extra_QA6_bytes'] == 6 << 30 and (q31['all_helper31_QA_actors_terminal_and_drained'] is True)
    assert hq['actual_original1630_all_peer_sources_control_passed'] is True
    end1630 = _document(v['original1630_completion_and_drain'])
    clean1630 = _document(v['successful1630_reader_retirement'])
    assert end1630['original_invocation_id'] == '56e8732c576449908e19e099c954a61a' and end1630['original_setup_deadline'] == 1794156381 and (end1630['main_never_started'] is True) and (end1630['token_destination_absent'] is True) and (end1630['no_second_final_attempt'] is True)
    assert clean1630['schema'] == 'horizon-positive185-successful-reader-manager-retirement-v1' and clean1630['reset_failed_called'] is False and (clean1630['resource_credit_bytes'] == 0)
    assert clean1630['final_reader_native']['LoadState'] == clean1630['final_keeper_native']['LoadState'] == 'not-found'
    before1630 = _document(clean1630['intent'])['original_successful_native']
    assert before1630['InvocationID'] == '43dca2b7a35c42e6a67ed1c197be7cc4' and before1630['ExecMainPID'] == '3497331'
    assert op == EXPECTED_OPERATION33 and final == EXPECTED_FINAL3 and (v['postreader30'] == EXPECTED_HELPER32)
    assert v['accepted_actor_driver'] == EXPECTED_DRIVER11 and v['planner'] == EXPECTED_PLANNER3
    _normal_program(v['planner'], v['planner_qualification'], v['planner_normal_seal'])
    assert v['reader_lifecycle_control'] == EXPECTED_LIFECYCLE_CURRENT
    assert v['successful1800_reader_retirement'] == EXPECTED_RETIREMENT1800
    current_retirement = _document(v['successful1800_reader_retirement'])
    assert current_retirement['schema'] == 'horizon-positive185-successful-reader-manager-retirement-v1'
    assert current_retirement['reset_failed_called'] is False and current_retirement['resource_credit_bytes'] == 0
    assert current_retirement['final_reader_native']['LoadState'] == current_retirement['final_keeper_native']['LoadState'] == 'not-found'
    assert q['actual_enrolled_fleet_uses_Helper33'] is True and q['production_enrollment_image_is_Helper33'] is True and (q['fresh_native_first_guard_required'] is True)
    assert q['actual_Helper32_consumer_accepts_original2100_fleet_repair'] is True
    ended2100 = _document(v['original2100_fleet_order_failure_expired_and_drained'])
    assert ended2100['original_invocation_id'] == '32daf31d08974cda8b3d302030fbf3cc' and ended2100['original_setup_deadline'] == 1794172545
    assert ended2100['main_never_started'] is True and ended2100['token_destination_absent'] is True and (ended2100['original_cgroup_empty'] is True) and (ended2100['memory_credit_bytes'] == ended2100['DATA_credit_bytes'] == 0)
    ended2000 = _document(v['original2000_enrollment_failure_expired_and_drained'])
    assert ended2000['original_invocation_id'] == 'def4ca09016f4221ba460b0feb8fec26' and ended2000['original_setup_deadline'] == 1794169203
    assert ended2000['original_setup_expired_without_renewal'] is True and ended2000['main_never_started'] is True and (ended2000['token_destination_absent'] is True) and (ended2000['original_cgroup_empty'] is True)
    assert ended2000['memory_credit_bytes'] == ended2000['DATA_credit_bytes'] == 0 and ended2000['no_final_transaction_attempted'] is True
    assert v['current_complete_DATA_lower_bound_bytes'] >= 5154378035860
    for bound in v['successor_retained_DATA_documents']:
        _document(bound)
    additions = 0
    for bound in v['successor_additive_DATA_bookings']:
        document = _document(bound)
        additions += document.get('new_additive_retained_DATA_bytes', document.get('additional_retained_DATA_bytes', document.get('new_retained_DATA_bytes', 0)))
    assert 5133440070292 + additions == v['current_complete_DATA_lower_bound_bytes'], 'Successor DATA additions must each be retained exactly once'
    driver_proof = _document(v['accepted_actor_driver_qualification'])
    assert driver_proof['artifact']['sha256'] == accepted_driver['sha256'] and driver_proof['no_replay_or_publication_authority'] is True
    _document(driver_proof['source_freeze'])
    _document(driver_proof['actual_QA'])
    return v
EXPECTED_OPERATION33 = {'path': '/usr/local/lib/jetstreamer/horizon-positive185-current-operation-tools-20261108-v35-planner4-r1/operation', 'sha256': '2a46be553c8e07f91e4e8e5e0f378761b5c9a4cacf5008e5542d59380051b543'}
EXPECTED_FINAL3 = {'path': '/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261108-v3/horizon-positive185-final', 'sha256': '47fb5d1fd85e6a19ff31cc493bd4eb660441f4f8f08d6b238b62316d87f50f84'}
EXPECTED_HELPER32 = {'path': '/usr/local/lib/jetstreamer/horizon-epoch185-enrollment-composition-postreader-tools-20261108-v33/jetstreamer-r2', 'sha256': 'b445a1fb3717da5b68984d6598d7d75efcf5131f0bc82091af506d586b8f49fd'}
EXPECTED_DRIVER11 = {'path': '/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v11/epoch185-guarded-cold', 'sha256': 'bdadc547439d2dbba11797f715c1741772dad693cd54073ac273132a7ba096f2'}
EXPECTED_PLANNER3 = {'path': '/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261108-v4-r2/planner', 'sha256': 'ce57c4b8a03278a0e56955d7257bb353cd9fe70addea3aa6538574fea82f8076'}
EXPECTED_LIFECYCLE_CURRENT = {'path': '/usr/local/lib/jetstreamer/horizon-positive185-reader-lifecycle-kernel-control-control-positive-reader-v35-planner4-r1/completion.json', 'sha256': '4064103aa2390b3d2c5be531be3625aabc029f988bbd82d39462c30a24f34e96'}
EXPECTED_RETIREMENT1800 = {'path': '/home/sol/.jetstreamer-private/epoch185-positive-upstream-exact1800-successful31-reader-retirement-20261108-v31-r3/successful-reader-retirement-completion.json', 'sha256': '7f540374459110903fefe1d474669418c6f52bcf34b24c20d8346d4c86125229'}

def _source_bytes(binding):
    import os, stat, hashlib
    p = Path(binding['path'])
    assert p.is_absolute() and p.resolve(strict=True) == p and (p.suffix == '.rs')
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

CURRENT_OPERATION36 = {'path': '/usr/local/lib/jetstreamer/horizon-positive185-current-operation-tools-20261108-v36-helper34-planner5-r1/operation', 'sha256': '369170f2c3e10b21e5c3edae79c1301bdd829d6637c306a52f01dee6c97485f9'}
CURRENT_PLANNER5 = {'path': '/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261108-v5/planner', 'sha256': 'e771306216e1436e3904ab2c11622597298c61c4083a4a7a1b485278bdb139e1'}
CURRENT_HELPER34 = {'path': '/usr/local/lib/jetstreamer/horizon-epoch185-inherited-census-postreader-tools-20261108-v34/jetstreamer-r2', 'sha256': 'dda7f44b24b7d9475c654efea20e2230f8374df9640b3e0bf724e7edac44c389'}
CURRENT_HELPER34_BINDING = {'path': '/home/sol/.jetstreamer-private/epoch185-inherited-census-helper-qa-20261108-v34/ROOT_ACTUAL_QUALIFIED_HELPER34_BINDINGS.json', 'sha256': '5c9413e19e5a5a4f6e54780d069c3ac56a308bb341bd0884c65eb098d507a0d9'}


def validate_successor36(v):
    # All old failures, closures, raw promises and package relationships retain
    # the complete predecessor validator; no current artifact substitutes for it.
    prior = _document(v['predecessor_authority'])
    assert prior['schema'] == 'horizon-current1400-next-qualified-bindings-v1'
    validate_actual_manifest(prior)
    assert v['replay_launch_authorized'] is False and v['new_memory_or_DATA_credit_bytes'] == 0
    assert v['operation'] == CURRENT_OPERATION36 and v['planner'] == CURRENT_PLANNER5
    assert v['postreader30'] == CURRENT_HELPER34 and v['accepted_actor_driver'] == EXPECTED_DRIVER11
    assert v['final_executor'] == EXPECTED_FINAL3
    h = _document(v['helper34_binding']); p = _document(v['planner5_binding']); o = _document(v['operation36_binding'])
    assert v['helper34_binding'] == CURRENT_HELPER34_BINDING
    assert h['program'] == v['postreader30'] and h['qualification'] == v['postreader30_qualification'] and h['normal_seal'] == v['postreader30_normal_seal']
    assert p['program'] == v['planner'] and p['qualification'] == v['planner_qualification'] and p['normal_seal'] == v['planner_normal_seal']
    assert o['program'] == v['operation'] and o['qualification'] == v['qualification'] and o['normal_seal'] == v['normal_seal']
    hq = _normal_program(v['postreader30'],v['postreader30_qualification'],v['postreader30_normal_seal'])
    pq = _normal_program(v['planner'],v['planner_qualification'],v['planner_normal_seal'])
    q = _normal_program(v['operation'],v['qualification'],v['normal_seal'])
    _normal_program(v['final_executor'],v['final_executor_qualification'],v['final_executor_normal_seal'])
    assert hq['ordinary_count'] == 2937 and hq['ignored_count'] == 126
    assert hq['actual_features'] == ['native210-small','native227-small']
    graph = _document(hq['exact_source_and_compiler_graph'])
    assert len(graph['extern_bindings']) == 29 and graph['all29_actual_extern_bindings_preserved']
    assert graph['both_native_features_retained'] and hq['raw_prior_fleet_and_history_preserved']
    for argv in graph['recipes'].values():
        assert argv.count('--extern') == 29 and 'feature="native210-small"' in argv and 'feature="native227-small"' in argv
    assert hq['actual2130_enrollment_composition_control'] == v['helper34_2130_composition_control']
    assert 'actual2130_plan_composes_complete_transition_with_same_live145_consumer ... ok' in _document(v['helper34_2130_composition_control'])['stdout']
    assert hq['actual2300_composed_historical_census_controls'] == v['helper34_2300_composition_controls']
    assert len(v['helper34_2300_composition_controls']) == 3
    for binding in v['helper34_2300_composition_controls']:
        execution = _document(binding)
        assert execution['code'] == 0 and '1 passed; 0 failed;' in execution['stdout']
    assert _document(v['helper34_2300_complete_outer'])['code'] == 0
    assert hq['composed_fixture_is_not_failed_whole_native_census'] and hq['genuine_latest2300_complete_outer_adapter_passed']
    closure = _document(v['helper34_QA_closure'])
    assert closure['actual_closed_booking'] == h['booking'] and h['closure'] == v['helper34_QA_closure']
    assert closure['fresh_extra_QA5_bytes_before'] == 5 << 30 and closure['fresh_extra_QA5_bytes_after'] == 0 and closure['normal_pool_bytes'] == 6 << 30
    assert closure['no_producer_memory_or_DATA_credit'] and len(closure['originals']) == 21
    for row in closure['originals']:
        assert _document(row['execution'])['code'] == 0
        n = row['actual_original_native']
        assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == n['ExecMainStatus'] == '0'
        assert n['Job'] == n['ControlGroup'] == '' and n['Result'] == 'success'
        assert row['original_outer_reaped'] and row['original_cgroup_empty']
    assert pq['ordinary_tests_passed'] == 27 and pq['prelaunch13_nativeCapture34_postreader34_explicit']
    assert pq['actual_Helper34'] == v['helper34_binding'] and pq['actual2300_request_positive_control'] == p['actual2300_positive']
    assert _document(p['actual2300_positive'])['code'] == 0 and p['all_six_actual2300_metadata_controls_passed']
    assert len(pq['actual2300_crossed_helper_and_prelaunch_controls']) == 5
    for binding in pq['actual2300_crossed_helper_and_prelaunch_controls']:
        e = _document(binding); assert e['code'] != 0 and 'metadata185 plan:' in e['stderr']
    view = _document(v['planner5_current_metadata_view']); seal = _document(v['planner5_current_metadata_view_normal_seal'])
    assert view['schema'] == 'horizon-planner5-current-source-and-role-metadata-view-v1'
    assert view['underlying_original_qualification'] == v['planner_qualification'] and view['underlying_original_program'] == v['planner']
    assert view['underlying_original_normal_seal'] == v['planner_normal_seal'] and view['no_production_bytes_changed'] and view['no_old_proof_overwrite']
    assert any(row['name'] == 'current-source-role-view.json' and row['sha256'] == v['planner5_current_metadata_view']['sha256'] and row['mode'] == '0444' for row in seal['members'])
    pgraph = _document(pq['exact_source_and_compiler_graph'])
    current = view['canonical_current_fields']
    assert current['source_freeze'] == p['source_and_recipes'] and current['source_freeze']['sha256'] == pq['exact_source_and_compiler_graph']['sha256']
    assert _document(current['source_freeze']) == pgraph and current['actual_source_files'] == pgraph['source'] and current['exact_recipes'] == pgraph['recipes']
    pseal = _document(v['planner_normal_seal'])
    assert any(row['name'] == 'source-and-recipes.json' and row['sha256'] == p['source_and_recipes']['sha256'] and row['mode'] == '0444' for row in pseal['members'])
    assert current['active_native_capture'] == v['postreader30']
    sequence = _document(pq['current_sequence_roles'])
    assert sequence['native_capture'] == sequence['post_enrollment_reader'] == v['postreader30'] and sequence['prelaunch_reader']['sha256'] == 'd00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470'
    assert sequence['executor_implemented'] is False and sequence['native_calls_performed'] == 0
    for stage in sequence['stages']:
        if 'operation' in stage: assert stage['operation']['program'] == v['postreader30']
    assert q['ordinary_count'] == 63 and q['ignored_native_count'] == 3
    assert q['actual_Planner5_program'] == v['planner'] and q['actual_Planner5_qualification'] == v['planner_qualification']
    assert q['actual_Helper34_program'] == v['postreader30'] and q['actual_Helper34_QA_closure'] == v['helper34_QA_closure']
    assert q['actual_Helper34_current2300_composition_controls'] == v['helper34_2300_composition_controls']
    assert q['actual_final3_profile_and_eight_file_read_passed'] and q['qualified_route'] == v['qualified_route']
    route = _document(v['qualified_route']); cap = _document(route['capability_acceptance']); life = _document(v['reader_lifecycle_control'])
    assert route['helper']['image'] == cap['helper'] == v['postreader30']
    assert route['helper']['artifact'] == v['postreader30_qualification'] and route['helper']['normal_seal'] == v['postreader30_normal_seal']
    assert cap['executor'] == v['final_executor'] and cap['driver'] == route['driver'] == v['accepted_actor_driver']
    assert cap['actual_c71_sol_eight_file_read']['all_eight_exact_bound_files_read'] and cap['fresh_native_first_guard_required']
    assert cap['actual_driver11_native_first_guard_accepted'] is False and cap['original_setup_seconds'] == 600
    assert cap['actual_persistent_reader_lifecycle_control'] == q['actual_reader_lifecycle_control'] == v['reader_lifecycle_control']
    assert life['program']['sha256'] == v['operation']['sha256'] and life['actual_postreader_role'] == route['helper']
    assert life['prelaunch_reader_image'] == cap['prelaunch_reader_image'] and cap['split_prelaunch_postreader_roles']
    for row in q['originals']:
        assert _document(row['execution'])['code'] == 0
        n = row['original_native']; assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == n['ExecMainStatus'] == '0'
        assert n['Job'] == n['ControlGroup'] == '' and n['Result'] == 'success'
    assert q['original_caps_and_clocks_unchanged'] and q['authoritative_native_timer_clocks_passed']
    assert q['memory_credit_bytes'] == q['DATA_credit_bytes'] == 0
    end = _document(v['original2300_completion_and_drain'])
    assert end['original_IID'] == 'dff3a3ef94d943b0bae94634fa9dfc50' and end['natural_original_deadline'] == 1794179964
    assert end['main_never_started'] and end['token_destination_absent'] and end['original_control_pid_absent'] and end['original_cgroup_empty'] and end['no_signal_or_reset_or_lease_renewal']
    assert end['native_after']['ExecMainPID'] == end['native_after']['ExecMainStartTimestampMonotonic'] == '0'
    assert end['memory_credit_bytes'] == end['DATA_credit_bytes'] == 0 and end['no_run_artifacts']
    additions = v['successor_additive_DATA_bookings']; assert len({row['path'] for row in additions}) == len(additions)
    total = 0
    for binding in additions:
        doc = _document(binding); total += doc.get('new_additive_retained_DATA_bytes',doc.get('additional_retained_DATA_bytes',doc.get('new_retained_DATA_bytes',0)))
    assert 5133440070292 + total == v['current_complete_DATA_lower_bound_bytes'] == 5160820486804
    assert h['booking'] in additions and p['booking'] in additions and v['actual_guard0000_booking'] in additions
    guard = _document(v['actual_guard0000_booking']); assert guard['extra_QA5_closed_before_guard_build'] and guard['complete_DATA_bytes'] == 5160820486804
    return v

# Add only the genuinely qualified/booked0100 guard after unchanged strict Root0030 authority.
_Root0030_next_operation_bindings = next_operation_bindings
def next_operation_bindings():
    authority = _Root0030_next_operation_bindings()
    from current0100_guard_addition import with_current0100_guard
    return with_current0100_guard(authority)
