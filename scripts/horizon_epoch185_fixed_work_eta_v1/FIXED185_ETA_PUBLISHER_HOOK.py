
def fixed185_eta_parts(binding, now):
    model = read_bound(binding)
    assert model['schema'] == 'horizon-epoch185-fixed-unexecuted-replay-planning-model-v1' and model['owner'] == '/root'
    basis = read_bound(model['authenticated_full_work_basis'])
    assert basis['authenticated_readback'] and basis['estimate_parts_millis']['full_epoch_replay_using_same_century_peer_rate_with25percent_contingency_millis'] == model['full_replay_fixed_millis']
    parse = lambda s: datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    full_left = model['qualification_original_total_millis'] - int((now-parse(model['qualification_anchor_utc'])).total_seconds())*1000
    spent_control = int((now-parse(model['control_model_issued_at_utc'])).total_seconds())*1000
    control_left = model['control_integration_allocation_millis'] - spent_control
    assert 0 <= spent_control and 0 < control_left <= full_left, 'Explicit new estimate review required; no expired allowance clamp/reset'
    fresh = min(3600000, control_left)
    parts = {'current_planner3_operation31_and_exact1800_retirement_millis':control_left-fresh, 'fresh_full_reader_memory_DATA_and_replay_admission_millis':fresh, 'full_boundary_runtime_native_Frame_successor_qualification_millis':full_left-control_left, 'bootstrap_load_and_warmup_millis':model['bootstrap_millis'], 'full_epoch_replay_using_same_century_peer_rate_with25percent_contingency_millis':model['full_replay_fixed_millis'], 'archive_close_full_plugin_boundary_verification_millis':model['verification_millis'], 'upload_whole_object_readback_and_sidecar_commit_millis':model['delivery_millis']}
    assert all(type(x) is int and x >= 0 for x in parts.values()) and sum(parts.values()) > 0
    return parts, model
