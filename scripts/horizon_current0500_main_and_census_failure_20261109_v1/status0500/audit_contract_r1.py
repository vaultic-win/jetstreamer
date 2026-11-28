import pathlib, json, hashlib, os, subprocess, datetime
p = pathlib.Path('/home/sol/.jetstreamer-private/actual1558-observer-root-acceptance-20261107-v1')
o = p.parent / 'actual0718-control-20261102-v1'

def sha(q):
    with q.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def bound(q):
    q = pathlib.Path(q)
    return {'path': str(q), 'sha256': sha(q)}

def read_bound(b):
    q = pathlib.Path(b['path'])
    raw = q.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == b['sha256'], str(q)
    return json.loads(raw)

def save(name, value):
    q = p / name
    with q.open('x') as f:
        os.fchmod(f.fileno(), 384)
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(q.parent, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)

def predecessor():
    b = json.loads((p / 'PREDECESSOR_BINDINGS.json').read_text())
    for v in b['files'].values():
        assert sha(pathlib.Path(v['path'])) == v['sha256'], v['path']
    for k in ['observer', 'fleet', 'frame']:
        read_bound(b[k])
    return b

def observer():
    b = predecessor()
    q = pathlib.Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261107T155809Z-postcompletion154-v1.json')
    v = json.loads(q.read_text())
    c = v['cadence']
    assert v['schema'] == 'jetstreamer-horizon-live-resource-sample-v2' and v['recorded_at_utc'] == b['required_sample_utc']
    assert c['routine_minimum_interval_enforced'] is True and c['minimum_interval_seconds'] == 1800 and (c['observed_interval_seconds'] == 1800)
    assert c['previous_sample'] == b['observer']['path'] and c['previous_sample_sha256'] == b['observer']['sha256']
    rows = [r for r in v['diagnostic_replays'] if r['range'] == '145']
    assert len(rows) == 1
    r = rows[0]
    assert r['status'] == 'unavailable' and r['observation'] is None
    assert r['expected_producer_invocation_id'] == b['healthy145_invocation_id']
    return (q, v)

def native(unit):
    keys = 'Id,InvocationID,MainPID,ControlPID,Result,NRestarts,ActiveState,SubState,ExecMainStatus,Job'
    v = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--no-pager', '--property=' + keys], capture_output=True, text=True, check=True)
    return dict((line.split('=', 1) for line in v.stdout.splitlines()))

def completed(unit):
    n = native(unit)
    assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == n['ExecMainStatus'] == '0' and n['Result'] == 'success' and (n['SubState'] == 'exited') and (n['ActiveState'] == 'active') and (n['Job'] == '') and (len(n['InvocationID']) == 32)
    return n

def seal(label, destination, members):
    program = pathlib.Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
    expected = 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
    assert sha(program) == expected
    plan = {'schema': 'jetstreamer-sealed-deployment-plan-v1', 'destination': destination, 'members': [{'name': name, 'source': str(q), 'sha256': sha(q), 'mode': 292} for name, q in members]}
    save(label + '-seal.json', plan)
    a = [str(program), str(p / (label + '-seal.json')), '--plan-sha256', sha(p / (label + '-seal.json')), '--self-sha256', expected]
    save(label + '-seal-argv.json', a)
    os.umask(18)
    r = subprocess.run(a, capture_output=True, text=True)
    save(label + '-seal-result.json', {'code': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr})
    assert r.returncode == 0, r.stderr

def completed_tuple():
    snapshot = p / 'CURRENT_COMPLETED_TUPLE_AT1458.json'
    if snapshot.is_file():
        current = read_bound(bound(snapshot))
        for key in ['acceptance', 'accepted_selector', 'components', 'four_families', 'memory_selection_acceptance', 'DATA_original_completion_acceptance']:
            read_bound(current[key])
        return current
    choices = read_bound(bound(p / 'COMPLETED_TUPLE_CANDIDATES0758_SOURCE.json'))
    for row in choices['newest_first']:
        component_path = pathlib.Path(row['components_path'])
        completion_path = pathlib.Path(row['DATA_completion_path'])
        required = ['acceptance_path', 'selector_path', 'components_path', 'four_families_path', 'memory_selection_acceptance_path', 'DATA_completion_path']
        if not all((pathlib.Path(row[key]).is_file() for key in required)):
            continue
        acceptance = bound(pathlib.Path(row['acceptance_path']))
        accepted_selector = bound(pathlib.Path(row['selector_path']))
        components = bound(component_path)
        families = bound(pathlib.Path(row['four_families_path']))
        memory_accepted = bound(pathlib.Path(row['memory_selection_acceptance_path']))
        data_completed = bound(completion_path)
        known = read_bound(acceptance)
        selected = read_bound(accepted_selector)
        c = read_bound(components)
        f = read_bound(families)
        m = read_bound(memory_accepted)
        dc = read_bound(data_completed)
        assert known['frame'] == selected['frame'] and known['fleet'] == selected['fleet']
        assert known['observer'] == selected['observer']
        assert selected['observer']['path'].endswith(row['required_observer_leaf'])
        assert f['actual_current_tuple'] == accepted_selector
        assert f['exact_original_families'] == [4, 5, 6, 7]
        assert f['all_four_current_reservations_preserved'] is True
        assert f['all_four_output_censuses_and_before_after_semantic_stability_verified'] is True
        assert f['replay_admission_authorized'] is False
        assert m['current_tuple'] == acceptance and m['actual_selection'] == c['actual_memory_selection']
        assert m['original_reader'] == f['actual_original_reader_proof']
        memory = read_bound(c['actual_memory_selection'])
        data = read_bound(c['actual_DATA_selection'])
        eligibility = read_bound(c['actual_memory_eligibility'])
        original_completion = read_bound(dc['original_completion'])
        assert memory['actual_native_capability_passed'] is True and memory['admission_authorized'] is False
        assert memory['selection']['request']['current'] == {key: selected[key] for key in ['observer', 'fleet', 'fleet_plan', 'frame']}
        assert eligibility['selection'] == c['actual_memory_selection']
        assert data['actual_native_capability_passed'] is True and data['admission_authorized'] is False
        assert data['memory_selection'] == c['actual_memory_selection']
        assert dc['actual_DATA_selection'] == c['actual_DATA_selection']
        assert original_completion['receipt'] == c['actual_DATA_selection']
        assert original_completion['result'] == 'success' and original_completion['exec_main_status'] == 0
        assert original_completion['original_outer_reaped'] is True and original_completion['original_cgroup_empty'] is True
        assert original_completion['original_descriptors_drained'] is True
        assert c['original199_all_DATA_preserved'] is True and c['physical_credit_bytes'] == 0
        observer = read_bound(selected['observer'])
        frame = read_bound(selected['frame'])
        assert frame['bindings']['observer'] == selected['observer']
        current = {'schema': 'horizon-existing-completed-tuple-metadata-binding-v1', 'acceptance': acceptance, 'accepted_selector': accepted_selector, 'components': components, 'four_families': families, 'memory_selection_acceptance': memory_accepted, 'DATA_original_completion_acceptance': data_completed, 'observer': selected['observer'], 'fleet': selected['fleet'], 'frame': selected['frame'], 'sampled_at_utc': observer['recorded_at_utc'], 'effective_existing_memory_bytes': memory['selection']['effective_total_memory_promises_bytes'], 'effective_existing_DATA_bytes': c['effective_DATA_bytes'], 'metadata_only_no_admission_or_new_resource_credit': True}
        save(snapshot.name, current)
        return current
    raise AssertionError('No genuinely completed native full-reader/memory/DATA tuple is available')
