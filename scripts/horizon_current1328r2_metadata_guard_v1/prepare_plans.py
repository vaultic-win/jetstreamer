"""Future data-only preparation; never starts/seals/queries native services or opens reader clock.
Root invokes stages only after reviewing freeze and supplying genuine input-envelope SHA.
"""
import pathlib, json, hashlib, sys, os, re, stat, datetime, time
R = pathlib.Path(__file__).parent
P = R / 'runtime'
T = R / 'native-templates'
BASE = pathlib.Path('/home/sol/.jetstreamer-private')
TEMPLATE_PRIOR = BASE / 'actual2058-postreplay145-native-20261106-v1'
PRIOR = pathlib.Path('/home/sol/.jetstreamer-private/epoch185-offline-retained-input-contract-source-20261106-v1/r5/fresh0728-source/runtime')
OBSERVER = '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261107T132809Z-postcompletion154-v1.json'
FLEET = '/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261107T132809Z-cached145-loaded-terminal-reload-r2-v1.json'
FRAME = '/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261107T132809-cached145-original-terminal-reload-native-r2-v1.json'
FDEST = pathlib.Path('/usr/local/lib/jetstreamer/horizon-postreplay145-current1328r2-fleet-plan-20261107-v1')
RDEST = pathlib.Path('/usr/local/lib/jetstreamer/horizon-retained145-terminal-Frame-current1328r2-plan-20261107-v1')
GUARD = '/usr/local/lib/jetstreamer/horizon-current1328r2-bound-guard-window-tools-20261107-v1/horizon-current1328r2-guard-window'
SEALER = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
SEALER_SHA = 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
ROLE_KEYS = ['observer', 'fleet', 'fleet_plan', 'frame']

def bound(p):
    p = pathlib.Path(p)
    assert p.stat().st_size <= 16 << 20, 'JSON/source exceeds16MiB'
    with p.open('rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
    return {'path': str(p), 'sha256': digest}

def program_bound(p):
    p = pathlib.Path(p)
    assert p.stat().st_size <= 128 << 20, 'Program exceeds128MiB'
    with p.open('rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
    return {'path': str(p), 'sha256': digest}

def load(b):
    assert set(b) == {'path', 'sha256'} and re.fullmatch('[0-9a-f]{64}', b['sha256']) and (bound(b['path']) == b)
    return json.loads(pathlib.Path(b['path']).read_text())

def get(p):
    return json.loads(pathlib.Path(p).read_text())

def save(p, v, mode=384):
    with p.open('x') as f:
        os.fchmod(f.fileno(), mode)
        json.dump(v, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(p.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
    return bound(p)

def original(label, unit):
    n = get(P / (label + '-COMPLETED_NATIVE.json'))
    assert n['Id'] == unit and n['MainPID'] == n['ControlPID'] == n['NRestarts'] == n['ExecMainStatus'] == '0'
    assert n['Result'] == 'success' and n['ActiveState'] == 'active' and (n['SubState'] == 'exited') and (n['Job'] == '') and re.fullmatch('[0-9a-f]{32}', n['InvocationID'])
    rows = get(P / (label + '-PID1.json'))
    assert any((x.get('_PID') == '1' and x.get('INVOCATION_ID') == n['InvocationID'] and (x.get('JOB_RESULT') == 'done') for x in rows))
    execution = get(P / (label + '-ORIGINAL_EXECUTION.json'))
    assert execution['code'] == 0
    return n

def seal_recipe(label, destination, members):
    plan = {'schema': 'jetstreamer-sealed-deployment-plan-v1', 'destination': str(destination), 'members': [{'name': name, 'source': str(source), 'sha256': bound(source)['sha256'], 'mode': 292} for name, source in members]}
    binding = save(P / (label + '_NORMAL_SEAL_PLAN.json'), plan)
    save(P / (label + '_PREWRITTEN_SEAL_ARGV.json'), [SEALER, binding['path'], '--plan-sha256', binding['sha256'], '--self-sha256', SEALER_SHA])

def envelope():
    expected = os.environ.get('HORIZON1328_NATIVE_INPUTS_SHA256', '')
    q = P / 'ROOT1328_NATIVE_INPUTS.json'
    m = q.lstat()
    assert re.fullmatch('[0-9a-f]{64}', expected) and bound(q)['sha256'] == expected
    assert q.resolve() == q and stat.S_ISREG(m.st_mode) and (m.st_uid == m.st_gid == 0) and (m.st_nlink == 1) and (stat.S_IMODE(m.st_mode) == 292)
    v = get(q)
    assert set(v) == {'observer_owner', 'observer_original_native_and_PID1', 'current_capacity_receipt', 'completed_status_cycle', 'current_inventory', 'qualified_current_guard_program', 'qualified_current_guard_artifact_proof', 'observation_bridge_writers', 'qualified_frame_program', 'qualified_frame_artifact_proof', 'qualified_helper_program', 'qualified_helper_artifact_proof'}
    for k in ['qualified_helper_artifact_proof', 'qualified_frame_artifact_proof', 'observer_original_native_and_PID1', 'current_capacity_receipt', 'completed_status_cycle', 'current_inventory', 'qualified_current_guard_artifact_proof']:
        load(v[k])
    helper = v['qualified_helper_program']
    assert helper['path'] == '/usr/local/lib/jetstreamer/horizon-live145-production-census-helper-tools-20261107-v1/jetstreamer-r2' and program_bound(helper['path']) == helper
    static = get(R / 'review/QUALIFIED_STATIC_BINDINGS1328.json')
    assert helper == static['qualified_helper_program'] and v['qualified_helper_artifact_proof'] == static['qualified_helper_artifact_proof']
    hp = load(v['qualified_helper_artifact_proof'])
    hs = load(static['qualified_helper_normal_seal'])
    assert hp['artifact']['sha256'] == helper['sha256']
    assert hp['ordinary_tests_passed'] == 2862 and hp['ignored_tests_retained'] == 115
    assert hp['features'] == ['native210-small', 'native227-small']
    assert static['production_timer_namespace_actual_control_passed'] is True
    control=load(static['qualified_helper_native_production_census_control'])
    assert control['code']==0 and 'test result: ok. 1 passed; 0 failed' in control['stdout']
    assert 'fleet::live145_fleet::production_census_tests::actual_production_unit_census_accepts_complete_live145_family_and_authenticates_it' in control['argv']
    assert hs['destination'] == str(pathlib.Path(helper['path']).parent)
    assert any((x['name'] == 'jetstreamer-r2' and x['sha256'] == helper['sha256'] for x in hs['members']))
    assert all((hs[k] is False for k in ['replay_launch_authorized', 'publication_authorized', 'remote_mutations', 'r2_mutations']))
    frame_program = v['qualified_frame_program']
    assert frame_program == static['qualified_frame_program'] and frame_program['path'] == '/usr/local/lib/jetstreamer/horizon-live145-nested-predecessor-frame-cli-tools-20261107-v1/jetstreamer-horizon-frame' and program_bound(frame_program['path']) == frame_program
    assert v['qualified_frame_artifact_proof'] == static['qualified_frame_artifact_proof']
    g = v['qualified_current_guard_program']
    assert g['path'] == GUARD and program_bound(g['path']) == g
    qa = load(v['qualified_current_guard_artifact_proof'])
    assert qa['source'] == bound(R / 'guard-src/main.rs') and qa['production'] == g
    assert qa['ordinary_tests_passed'] >= 71 and qa['all61_original_names_preserved'] and qa['all67_predecessor_names_preserved'] and qa['all69_predecessor_names_preserved'] and qa['all70_predecessor_names_preserved'] and qa['all7_original_actors_drained'] and qa['no_replay_authority']
    guard_seal = load(qa['normal_seal'])
    assert guard_seal['destination'] == str(pathlib.Path(GUARD).parent)
    assert any((x['name'] == 'horizon-current1328r2-guard-window' and x['sha256'] == g['sha256'] for x in guard_seal['members']))
    observer = bound(OBSERVER)
    sample = load(observer)
    observed_original = load(v['observer_original_native_and_PID1'])
    on = observed_original.get('native', observed_original.get('actual_native'))
    assert observed_original['observer'] == observer and v['observer_owner'] == {'unit': on['Id'], 'invocation_id': on['InvocationID']}
    assert on['Id'] == 'horizon-native154-observer132809-terminal199diag-20261107-v1.service' and re.fullmatch('[0-9a-f]{32}', on['InvocationID'])
    assert on['MainPID'] == on['ControlPID'] == on['NRestarts'] == on['ExecMainStatus'] == '0' and on['Result'] == 'success' and (on['Job'] == '') and (on['ActiveState'] == 'active') and (on['SubState'] == 'exited')
    assert any((row.get('_PID') == '1' and row.get('INVOCATION_ID') == on['InvocationID'] and (row.get('UNIT') == on['Id']) and (row.get('JOB_RESULT') == 'done') for row in observed_original.get('original_PID1', observed_original.get('actual_PID1'))))
    assert sample['schema'] == 'jetstreamer-horizon-live-resource-sample-v2' and sample['recorded_at_utc'] == '2026-11-07T13:28:09Z'
    assert sample['replays'] == [], 'A newly launched replay needs a separately reviewed adaptation'
    assert 0 <= int(time.time()) - int(datetime.datetime.fromisoformat(sample['recorded_at_utc'].replace('Z', '+00:00')).timestamp()) < 1800
    cycle = load(v['completed_status_cycle'])
    assert cycle['observer'] == observer
    bridges = get(R / 'review/ACTUAL_INTERMEDIATE_OBSERVERS.json')
    old = get(PRIOR / 'accepted-frame-selector.json')
    head = old['observer']
    assert v['observation_bridge_writers'] == get(R / 'review/ACTUAL_INTERMEDIATE_WRITERS.json') and len(bridges) == 11
    for row, writer in zip(bridges, v['observation_bridge_writers']):
        o = load(row['observer'])
        c = o['cadence']
        assert c['previous_sample'] == head['path'] and c['previous_sample_sha256'] == head['sha256']
        assert c['routine_minimum_interval_enforced'] and c['minimum_interval_seconds'] == 1800 and (c['observed_interval_seconds'] >= 1800)
        assert writer['observer'] == row['observer']
        assert writer['actual_writer']['MainPID'] == writer['actual_writer']['ControlPID'] == '0'
        proof = load(writer['original_PID1_and_drain'])
        n = proof.get('native', proof.get('actual_native'))
        rows = proof.get('original_PID1', proof.get('actual_PID1'))
        assert n == writer['actual_writer'] and proof['observer'] == row['observer']
        assert n['Result'] == 'success' and n['NRestarts'] == '0' and (n['ExecMainStatus'] == '0') and (n['Job'] == '')
        assert any((x.get('_PID') == '1' and x.get('INVOCATION_ID') == n['InvocationID'] and (x.get('UNIT') == n['Id']) and (x.get('JOB_RESULT') == 'done') for x in rows))
        head = row['observer']
    c = sample['cadence']
    assert c['previous_sample'] == head['path'] and c['previous_sample_sha256'] == head['sha256'] and c['routine_minimum_interval_enforced'] and (c['minimum_interval_seconds'] == 1800) and (c['observed_interval_seconds'] >= 1800)
    return (v, observer, old, bridges)

def native_argv(label, kind, request, planpath, digest):
    source = get(R / 'review/GENUINE0728_SOURCE_BINDINGS.json')
    argv = list(load(source[kind])['argv'])
    previous = list(argv)
    units = {'fleet1328': 'horizon-postreplay145-current1328r2-fleet-20261107-v1.service', 'frame1328-capability': 'horizon-retained145-terminal-Frame-current1328r2-closedfamily-capability-20261107-v1.service', 'frame1328-capture': 'horizon-retained145-terminal-Frame-current1328r2-closedfamily-capture-20261107-v1.service'}
    changed = set()
    for i, x in enumerate(previous):
        if x.startswith('--unit='):
            argv[i] = '--unit=' + units[label]
            changed.add(i)
        elif x == '/usr/local/lib/jetstreamer/horizon-full-reader-qualified-capture-shared-helper-tools-20261107-v2/jetstreamer-r2':
            argv[i] = v['qualified_helper_program']['path']
            changed.add(i)
        elif x == '/usr/local/lib/jetstreamer/horizon-sealed-alias-predecessor-frame-cli-tools-20261107-v2/jetstreamer-horizon-frame':
            argv[i] = v['qualified_frame_program']['path']
            changed.add(i)
        else:
            for prefix in ['StandardOutput=append:', 'StandardError=append:', '--property=StandardOutput=append:', '--property=StandardError=append:']:
                if x.startswith(prefix + str(PRIOR) + '/'):
                    argv[i] = prefix + str(P / (label + '.log'))
                    changed.add(i)
    i = argv.index('--plan-sha256')
    argv[i - 1] = str(planpath)
    argv[i + 1] = digest
    changed.update([i - 1, i + 1])
    if '--self-sha256' in argv:
        i = argv.index('--self-sha256') + 1
        argv[i] = v['qualified_frame_program']['sha256']
        changed.add(i)
    assert len(argv) == len(previous) and all((a == b or i in changed for i, (a, b) in enumerate(zip(previous, argv))))
    # Preserve full-operation native limits; the dual guard window qualifies dispatch only.
    for j,token in enumerate(argv):
     if token.removeprefix('--property=').startswith('TimeoutStartSec='):argv[j]=('--property=' if token.startswith('--property=') else '')+'TimeoutStartSec=300'
     if token.removeprefix('--property=').startswith('TimeoutStopSec='):argv[j]=('--property=' if token.startswith('--property=') else '')+'TimeoutStopSec=5'
    if not any(x.removeprefix('--property=').startswith('TimeoutStopSec=') for x in argv):
     j=next(j for j,x in enumerate(argv) if x in [v['qualified_helper_program']['path'],v['qualified_frame_program']['path']]);argv[j:j]=['-p','TimeoutStopSec=5']
    for token in argv:
        property_token = token.removeprefix('--property=')
        for mutation in ['StandardOutput=', 'StandardError=', 'ReadWritePaths=', 'WorkingDirectory=', 'RuntimeDirectory=', 'StateDirectory=', 'CacheDirectory=', 'LogsDirectory=']:
            if property_token.startswith(mutation):
                assert str(PRIOR) not in property_token, 'Mutation destination points into genuine0728 predecessor'
    b = save(P / (label + '_GUARD_BOUND_ARGV_PLAN.json'), {'schema': 'horizon-original-completed-guard-window-native-argv-plan-v1', 'not_launch_authority': True, 'argv': argv, 'request': request})
    guard = v['qualified_current_guard_program']
    save(P / (label + '_FUTURE_GUARDED_ARGV.json'), [guard['path'], 'run-original', label, b['path'], '--spec-sha256', b['sha256'], '--self-sha256', guard['sha256']])

def fleet_plan_for(observer, old, source):
    retained = load(source['fleet_plan'])
    plan = json.loads(json.dumps(retained))
    additions = ['horizon-extract145-prefix-shared72h-20261107-v8g1.service', 'horizon-guard145-prefix-shared72h-20261107-v8g1.service', 'horizon-guard145-prefix-shared72h-20261107-v8g1.timer']
    assert not any((x in retained['tracked_units'] for x in additions))
    plan.update(observer=observer, output=FLEET, previous_fleet=old['fleet'])
    plan['tracked_units'] = retained['tracked_units'] + additions
    projected = dict(plan)
    for k in ['observer', 'output', 'previous_fleet']:
        projected[k] = retained[k]
    projected['tracked_units'] = projected['tracked_units'][:-3]
    assert projected == retained, 'Historical fleet scalar/path/unit/hash changed'
    assert plan['tracked_units'][:-3] == retained['tracked_units'] and plan['tracked_units'][-3:] == additions
    return plan

def frame_metadata_for(observer, fleet, fplan, n, old, bridges, source, owner):
    priorplan = load(source['Frame_plan'])
    previous = load(source['Frame_transition'])
    tr = json.loads(json.dumps(previous))
    tr.update(fleet_plan=fplan, previous_recovery=old['frame'], prior_fleet_plan=old['fleet_plan'], previous_cohort183_transition=priorplan['cohort183_transition'], observation_bridge=[{'observer': row['observer']} for row in bridges])
    allowed = {'fleet_plan', 'previous_recovery', 'prior_fleet_plan', 'previous_cohort183_transition', 'observation_bridge'}
    assert {k: x for k, x in tr.items() if k not in allowed} == {k: x for k, x in previous.items() if k not in allowed}, 'Historical transition changed'
    return (tr, priorplan)
if __name__ == '__main__':
    assert len(sys.argv) == 2 and sys.argv[1] in ['fleet', 'frame', 'accept']
    v, observer, old, bridges = envelope()
    stage = sys.argv[1]
    source = get(R / 'review/GENUINE0728_SOURCE_BINDINGS.json')
    assert load(source['accepted_selector']) == old
    load(source['genuine_complete_tuple'])
    if stage == 'fleet':
        plan = fleet_plan_for(observer, old, source)
        assert not pathlib.Path(FLEET).exists()
        planb = save(P / 'fleet-plan1158r2.REVIEWED.json', plan)
        save(P / 'FLEET1328_RETAINED_POLICY_EXACT_EQUALITY.json', {'genuine_predecessor_plan': source['fleet_plan'], 'current_plan': planb, 'only_current_fields_changed': ['observer', 'output', 'previous_fleet'], 'old_tracked_units_exact_prefix': True, 'exact3_live145_units_appended': True, 'all_historical_scalars_paths_units_and_hashes_identical': True, 'no_replay_or_resource_credit': True})
        seal_recipe('FLEET1328', FDEST, [('fleet-plan.json', P / 'fleet-plan1158r2.REVIEWED.json')])
        req = {'schema': 'horizon-current1328-native-fleet-metadata-request-v1', 'observer': observer, 'observer_original_IID': v['observer_owner']['invocation_id'], 'source_template': source['fleet_plan'], 'accepted_prior_fleet': old['fleet'], 'accepted_prior_Frame': old['frame'], 'current_capacity': v['current_capacity_receipt'], 'completed1158_cycle': v['completed_status_cycle'], 'qualified_guard_window': v['qualified_current_guard_program'], 'qualified_helper': v['qualified_helper_program'], 'original_failed1158_not_retried': True, 'no_replay_or_release_authority': True}
        rb = save(P / 'ROOT_CURRENT1328_FLEET_METADATA_REQUEST.json', req)
        native_argv('fleet1328', 'fleet_argv', rb, FDEST / 'fleet-plan.json', planb['sha256'])
    elif stage == 'frame':
        fleet = bound(FLEET)
        f = load(fleet)
        fplan = bound(FDEST / 'fleet-plan.json')
        plan = load(fplan)
        assert plan == fleet_plan_for(observer, old, source)
        assert f['observer_receipt'] == observer['path'] and f['observer_sha256'] == observer['sha256'] and (f['plan_sha256'] == fplan['sha256']) and (f['sampled_at_utc'] == '2026-11-07T13:28:09Z')
        n = original('fleet1328', 'horizon-postreplay145-current1328r2-fleet-20261107-v1.service')
        fb = save(P / 'FLEET1328_ACTUAL_ORIGINAL_SUCCESS_ACCEPTED.json', {'fleet': fleet, 'fleet_plan': fplan, 'owner': n, 'original_PID1': bound(P / 'fleet1328-PID1.json'), 'no_resource_credit': True})
        tr, priorplan = frame_metadata_for(observer, fleet, fplan, n, old, bridges, source, v['observer_owner'])
        trb = save(P / 'transition1328.REVIEWED.json', tr)
        fp = json.loads(json.dumps(priorplan))
        fp.update(observer=observer, fleet=fleet, fleet_plan=fplan, fleet_owner={'unit': n['Id'], 'invocation_id': n['InvocationID']}, observer_owner=v['observer_owner'], output=FRAME, prior_recovery=old['frame'], prior_fleet_plan=old['fleet_plan'], cohort183_transition={'path': str(RDEST / 'transition.json'), 'sha256': trb['sha256']})
        allowed = {'observer', 'fleet', 'fleet_plan', 'fleet_owner', 'observer_owner', 'output', 'prior_recovery', 'prior_fleet_plan', 'cohort183_transition'}
        assert {k: x for k, x in fp.items() if k not in allowed} == {k: x for k, x in priorplan.items() if k not in allowed}, 'Historical Frame plan changed'
        assert not pathlib.Path(FRAME).exists()
        fpb = save(P / 'frame-plan1158r2.REVIEWED.json', fp)
        seal_recipe('FRAME1328', RDEST, [('plan.json', P / 'frame-plan1158r2.REVIEWED.json'), ('transition.json', P / 'transition1328.REVIEWED.json')])
        req = {'schema': 'horizon-current1328-qualified-Frame-capability-capture-request-v1', 'observer': observer, 'fleet': fleet, 'fleet_original_success': fb, 'fleet_owner': fp['fleet_owner'], 'frame_plan': {'path': str(RDEST / 'plan.json'), 'sha256': fpb['sha256']}, 'prior_recovery': old['frame'], 'actual_predecessor_Frame_acceptance': source['Frame_acceptance'], 'qualified_guard_window': v['qualified_current_guard_program'], 'normal_pool_bytes': 6442450944, 'serial_native_memory_bytes': 2147483648, 'healthy_exporter_floor_and_all_obligations_preserved': True, 'no_replay_or_release_authority': True}
        rb = save(P / 'ROOT_FRAME1328_QUALIFIED_CAPABILITY_AND_CAPTURE_REQUEST.json', req)
        for label, key in [('frame1328-capability', 'frame_capability_argv'), ('frame1328-capture', 'frame_capture_argv')]:
            native_argv(label, key, rb, RDEST / 'plan.json', fpb['sha256'])
    elif stage == 'accept':
        n = original('frame1328-capture', 'horizon-retained145-terminal-Frame-current1328r2-closedfamily-capture-20261107-v1.service')
        original('frame1328-capability', 'horizon-retained145-terminal-Frame-current1328r2-closedfamily-capability-20261107-v1.service')
        fleet_n = original('fleet1328', 'horizon-postreplay145-current1328r2-fleet-20261107-v1.service')
        selected = {'observer': observer, 'fleet': bound(FLEET), 'fleet_plan': bound(FDEST / 'fleet-plan.json'), 'frame': bound(FRAME)}
        f = load(selected['frame'])
        assert f['bindings']['observer'] == observer and f['bindings']['fleet'] == selected['fleet'] and (f['sampled_at_utc'] == '2026-11-07T13:28:09Z') and (f['self_sha256'] == v['qualified_frame_program']['sha256']) and (len(f['live145_prefix_guard_history']) == 2)
        sb = save(P / 'accepted-frame-selector.json', selected)
        acceptance = dict(selected, schema='horizon-native1328-Frame-accepted-reader-accounting-pending-v1', plan=bound(RDEST / 'plan.json'), accepted_selector=sb, actual_completed_writer=n, original_guard_owned_PID1_journal=bound(P / 'frame1328-capture-PID1.json'), qualified_current_helper=v['qualified_helper_artifact_proof'], qualified1228_guard=v['qualified_current_guard_artifact_proof'], full_current_reader_memory_DATA_pending=True, reader_not_run_in_this_recovery=True, replay_admission_authorized=False, memory_credit_bytes=0, DATA_credit_bytes=0, actual0728_predecessor=source['Frame_acceptance'])
        ab = save(P / 'ROOT_ACTUAL1328_NATIVE_FRAME_READER_CONTRACT_ACCEPTED.json', acceptance)
        capture = get(BASE / 'parent-memory-capture2058-directory-anchor-preparation-20261106-v1/completed145-capture-request-v2.json')
        capture['census_path'] = '/var/lib/jetstreamer/horizon-completed145-parent-memory-census-v2/' + observer['sha256'] + '/census.json'
        cb = save(R / 'parent/completed145-capture-request-v2.json', capture)
        writers = [{'observer': row['observer'], 'actual_writer': proof['actual_writer']} for row, proof in zip(bridges, v['observation_bridge_writers'])]
        live = {'current_Frame_acceptance': ab, 'current_selector': sb, 'current_fleet_writer': fleet_n, 'current_frame_self_sha256': f['self_sha256'], 'current_observer_recorded_at_utc': '2026-11-07T13:28:09Z', 'current_capacity_receipt': v['current_capacity_receipt'], 'completed_status_cycle': v['completed_status_cycle'], 'actual_predecessor_Frame_acceptance': source['Frame_acceptance'], 'actual_predecessor_selector': source['accepted_selector'], 'actual_predecessor_fleet_writer': get(PRIOR / 'FLEET0728_ACTUAL_ORIGINAL_SUCCESS_ACCEPTED.json')['owner'], 'observation_only_bridges': writers, 'completed145_capture_request_v2': cb, 'prewritten_full_sequence': bound(R / 'review/EXACT_FUTURE_SEQUENCE.json'), 'qualified_current_guard_program': v['qualified_current_guard_program'], 'current_inventory': v['current_inventory']}
        save(P / 'ROOT_ACTUAL1328_BINDINGS.json', live, 292)
        print(json.dumps({'binding_envelope': bound(P / 'ROOT_ACTUAL1328_BINDINGS.json'), 'reader_clock_opened': False}))
