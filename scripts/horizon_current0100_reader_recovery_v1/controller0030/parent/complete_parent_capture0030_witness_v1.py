import pathlib, sys, json, os, stat, time, re, subprocess, hashlib
base = pathlib.Path('/home/sol/.jetstreamer-private')
p = pathlib.Path(__file__).parent
sys.path.insert(0, str(base / 'terminal199-parent-native-timer-parser-clients-20261105-v1'))
import qa_metadata_adapter as a
a.p = p
runtime = pathlib.Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0030-20261109-v1')
parameter_file = runtime / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json'
expected = os.environ.get('HORIZON_CURRENT_NATIVE_CONTINUATION_BINDINGS_SHA256', '')
assert re.fullmatch('[a-f0-9]{64}', expected) and a.b(parameter_file)['sha256'] == expected
parameters = json.loads(parameter_file.read_text())
helper = parameters['qualified_helper_program']

def approved_helper():
    assert a.b(helper['path']) == helper
    proof = json.loads(pathlib.Path(helper['path']).with_name('artifact-proof.json').read_text())
    assert proof['prod_clippy_passed'] and proof['test_clippy_passed'] and proof['all_required_tests_passed']
    assert proof['production_artifact']['sha256'] == helper['sha256']
    assert proof['actual_features'] == ['native210-small', 'native227-small']
    for original in proof['originals']:
        execution = json.loads(pathlib.Path(original['execution']['path']).read_text())
        assert a.b(original['execution']['path']) == original['execution'] and execution['code'] == 0
        assert original['original_outer_reaped'] and original['original_cgroup_empty']
    seal = json.loads(pathlib.Path(helper['path']).with_name('deployment-seal-receipt.json').read_text())
    assert seal['destination'] == str(pathlib.Path(helper['path']).parent)
    assert [r for r in seal['members'] if r['name'] == 'jetstreamer-r2' and r['sha256'] == helper['sha256']]
    return helper

def qualified_helper_bindings():
    approved_helper()
    package = pathlib.Path(helper['path']).parent
    return {'program': helper, 'artifact_proof': a.b(package / 'artifact-proof.json'), 'normal_seal': a.b(package / 'deployment-seal-receipt.json'), 'actual_qualification_acceptance': a.b(package / 'artifact-proof.json')}
accepted = json.loads((runtime / 'ROOT_ACTUAL0030_NATIVE_FRAME_READER_CONTRACT_ACCEPTED.json').read_text())
current = {k: accepted[k] for k in ['observer', 'fleet', 'fleet_plan', 'frame']}
outer = json.loads((runtime / 'ROOT_FAILED4_READER0030_ORIGINAL_OUTER.json').read_text())
assert outer['code'] == 0
rb = json.loads(outer['stdout'])
reader = json.loads(pathlib.Path(rb['path']).read_text())
assert a.b(rb['path']) == rb
assert 0 <= int(time.time()) - reader['recorded_unix_seconds'] <= 300

def native(unit):
    raw = subprocess.check_output(['systemctl', 'show', unit, '--property=Id,InvocationID,MainPID,ControlPID,ActiveState,SubState,Result,ExecMainStatus,NRestarts,Job'], text=True)
    return dict((v.split('=', 1) for v in raw.splitlines()))

def drain_and_journal(label, program, proof, original):
    iid = proof.get('invocation_id', proof.get('actor_invocation_id'))
    unit = proof.get('unit', proof.get('actor_native_before', {}).get('Id'))
    n = native(unit)
    assert original['code'] == 0 and n['MainPID'] == n['ControlPID'] == '0' and (n['Job'] == '') and (n['Result'] == 'success')
    cg = pathlib.Path('/sys/fs/cgroup/system.slice') / unit
    assert not cg.exists() or not any((q.read_text().split() for q in cg.rglob('cgroup.procs')))
    actor_native = proof.get('native_before', proof.get('native', proof.get('actor_native_before')))
    assert not pathlib.Path('/proc/' + actor_native['MainPID']).exists()
    j = subprocess.run(['journalctl', '--all', '--no-pager', '--output=json', '-u', unit, '--since=@' + str(proof['recorded_unix_seconds'] - 5)], capture_output=True, text=True, check=True, timeout=20)
    rows = [json.loads(v) for v in j.stdout.splitlines()]
    rows = [v for v in rows if v.get('INVOCATION_ID') == iid or v.get('_SYSTEMD_INVOCATION_ID') == iid]
    assert any((v.get('_PID') == '1' and v.get('INVOCATION_ID') == iid and ('Deactivated successfully' in v.get('MESSAGE', '')) for v in rows))
    a.save(label + '-original-PID1.json', {'unit': unit, 'invocation_id': iid, 'result': 'success', 'exec_main_status': 0, 'original_rows': rows})
    a.save(label + '-original-drain.json', {'unit': unit, 'invocation_id': iid, 'outer_reaped': True, 'cgroup_empty': True, 'descriptors_drained': True, 'original_process_absent': True, 'actual_terminal_native': n, 'original_outer': original})
    reconciled = dict(n, InvocationID=iid)
    return reconciled

def readonly(label, bindings, writer):
    opened = []
    done = []

    def meta(m):
        return {'dev': m.st_dev, 'ino': m.st_ino, 'uid': m.st_uid, 'gid': m.st_gid, 'nlink': m.st_nlink, 'size': m.st_size, 'mode': stat.S_IMODE(m.st_mode), 'mtime_ns': m.st_mtime_ns, 'ctime_ns': m.st_ctime_ns}
    try:
        for b in bindings:
            q = pathlib.Path(b['path'])
            m = q.lstat()
            assert q.suffix == '.json' and q.resolve() == q and stat.S_ISREG(m.st_mode) and (m.st_uid == m.st_gid == 0) and (m.st_nlink == 1)
            fd = os.open(q, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            assert meta(os.fstat(fd)) == meta(m) and a.b(q) == b
            opened.append((b, q, fd, meta(m)))
        targets = {(m['dev'], m['ino']) for b, q, fd, m in opened}
        refs = []
        errors = []
        at = time.monotonic()
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid():
                continue
            assert time.monotonic() - at < 30
            try:
                for f in (proc / 'fd').iterdir():
                    try:
                        m = f.stat()
                        if (m.st_dev, m.st_ino) in targets:
                            refs.append({'pid': proc.name, 'fd': f.name})
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                    except PermissionError as e:
                        errors.append({'pid': proc.name, 'errno': e.errno})
            except (FileNotFoundError, ProcessLookupError):
                pass
            except PermissionError as e:
                errors.append({'pid': proc.name, 'errno': e.errno})
        assert not refs and (not errors), (refs, errors)
        a.save(label + '-readonly-intent.json', {'writer': writer, 'targets': [{'binding': b, 'before': m} for b, q, fd, m in opened], 'external_references': refs, 'unreadable_checks': errors, 'only_closed_generated_JSON_modes_changed': True, 'no_credit': True})
        for b, q, fd, before in opened:
            assert meta(q.lstat()) == before and a.b(q) == b
            if before['mode'] != 292:
                os.fchmod(fd, 292)
                os.fsync(fd)
                d = os.open(q.parent, os.O_DIRECTORY)
                os.fsync(d)
                os.close(d)
            after = meta(os.fstat(fd))
            assert a.b(q) == b and after['mode'] == 292
            for k in ['dev', 'ino', 'uid', 'gid', 'nlink', 'size', 'mtime_ns']:
                assert before[k] == after[k]
            done.append({'binding': b, 'before': before, 'after': after})
        return a.save(label + '-readonly-completed.json', {'writer': writer, 'files': done, 'all_readonly': True, 'same_inode_bytes_digest_and_mtime': True, 'memory_or_DATA_credit_bytes': 0})
    finally:
        for b, q, fd, m in opened:
            os.close(fd)

def launch(label, av, output):
    unit = next((v.split('=', 1)[1] for v in av if v.startswith('--unit=')))
    unit = unit if unit.endswith('.service') else unit + '.service'
    n = native(unit)
    assert n['MainPID'] == n['ControlPID'] == '0' and n['Job'] == '' and (n['ActiveState'] == 'inactive')
    assert not pathlib.Path(output).exists()
    i = next((i for i, x in enumerate(av) if x.startswith('/usr/local/lib/jetstreamer/') and (not x.endswith('.json'))))
    av[i:i] = ['--property=AppArmorProfile=horizon-witness-test-deny199-20261107-v1']
    a.save(label + '-actual-booking.json', {'argv': av, 'normal_pool_bytes': 6442450944, 'native_memory_bytes': 2147483648, 'Root_bytes': 536870912, 'margin_bytes': 536870912, 'native_outer_booking_seconds': [600, 630, 665], 'one_routine2GiB_may_overlap': True, 'all_compilers_drained': True, 'current_observer': current['observer'], 'metadata_script': a.b(pathlib.Path(__file__)), 'no_resource_credit': True})
    window_program = parameters['qualified_current_guard_program']
    assert a.b(window_program['path']) == window_program
    window_request = a.save(label + '-quiet-window-request.json', {'observer': current['observer'], 'metadata_only': True, 'no_replay_authority': True})
    window_plan = a.save(label + '-quiet-window-plan.json', {'schema': 'horizon-original-completed-guard-window-native-argv-plan-v1', 'not_launch_authority': True, 'request': window_request})
    window_argv = [window_program['path'], 'preflight-only', label + '-quiet', window_plan['path'], '--spec-sha256', window_plan['sha256'], '--self-sha256', window_program['sha256']]
    window_original = subprocess.run(window_argv, capture_output=True, text=True, timeout=80)
    a.save(label + '-quiet-window-original-execution.json', {'argv': window_argv, 'code': window_original.returncode, 'stdout': window_original.stdout, 'stderr': window_original.stderr})
    assert window_original.returncode == 0, window_original.stderr
    window = json.loads(window_original.stdout)
    assert window['metadata_only'] is True and window['command_launched'] is False and (window['no_resource_or_replay_authority'] is True)
    assert window['preflight']['no_guard_timer_or_controller_mutation'] is True
    assert window['preflight']['absolute_next_monotonic_usec'] - time.monotonic_ns() // 1000 >= 8000000, 'Original quiet window consumed before child; do not launch'
    r = subprocess.run(av, capture_output=True, text=True, timeout=665)
    original = {'code': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr, 'native_after': native(unit)}
    a.save(label + '-original-execution.json', original)
    print(json.dumps({'stage': label, **original}), flush=True)
    assert r.returncode == 0, label
    proof = json.loads(pathlib.Path(output).read_text())
    drain_and_journal(label, None, proof, original)
    return proof
n = drain_and_journal('reader0030', reader['image'], reader, outer)
family_contract = a.b('/home/sol/.jetstreamer-private/retained161-all-failure-families-source-20261105-v2/FULL_CURRENT_READER_QUALIFICATION_CONTRACT.SOURCE_ONLY.json')
assert family_contract == {'path': '/home/sol/.jetstreamer-private/retained161-all-failure-families-source-20261105-v2/FULL_CURRENT_READER_QUALIFICATION_CONTRACT.SOURCE_ONLY.json', 'sha256': '82f947c258abce7f2edb1f00d67b4e1c3c04cd8e05c5bfa4d928471a65adf076'}
contract = json.loads(pathlib.Path(family_contract['path']).read_text())
gate = qualified_helper_bindings()
assert reader['image'] == approved_helper() == gate['program']
outputs = {}
family_rows = {}
for role in ['original_raw_builder_before', 'original_raw_builder_after', 'accounting_before', 'accounting']:
    binding = reader[role]
    assert a.b(binding['path']) == binding
    value = json.loads(pathlib.Path(binding['path']).read_text())
    retained145 = value['retained_cached145_guard']
    assert retained145['before'] == retained145['after']
    retained145 = retained145['after']
    assert retained145['floor_bytes'] == 4202184371152
    retained_evidence = retained145['evidence']
    assert retained_evidence['full_parent_and_guard_memory_bytes'] == 206695301120
    assert retained_evidence['retained_DATA_bytes'] == 361850994688
    assert retained_evidence['inherited_guard_floor_bytes'] == 4202184371152
    assert retained_evidence['resource_credit_bytes'] == 0
    for flag in ['current_guard_armed', 'guard_result_claimed_successful', 'live_owner_coverage_claimed', 'success_sample_created', 'replay_launch_authorized', 'publication_authorized', 'r2_mutations']:
        assert retained_evidence[flag] is False
    assert retained_evidence['failed_guard_remains_failed'] is True
    retained_family = retained_evidence['full_native_family']
    assert retained_family['horizon-qualify-145-cached-b2a09f57de39c384-guard.service']['Result'] == 'exit-code'
    assert retained_family['horizon-qualify-145-cached-b2a09f57de39c384-guard.service']['InvocationID'] == 'c79b9108db2d42f1b41d573383a41654'
    assert retained_family['horizon-qualify-145-cached-b2a09f57de39c384-guard.service']['ExecMainStatus'] == '1'
    assert retained_family['horizon-qualify-145-cached-b2a09f57de39c384-guard.timer']['ActiveState'] == 'inactive'
    rows = value['active_peer_allocations']
    assert isinstance(rows, list)
    selected = {}
    for expected in contract['required_family_rows']:
        actual = [row for row in rows if row.get('unit') == expected['unit']]
        assert len(actual) == 1
        row = actual[0]
        assert row['invocation_id'] == expected['original_iid']
        for key in ['state', 'memory_max_bytes', 'data_reservation_bytes', 'ordinary_replay_claim', 'new_allocation_authorized', 'compressed_input_verified', 'repair_backlog_open']:
            assert row[key] == expected[key]
        for key, value in expected['branch_required_flags'].items():
            assert row[key] == value
        assert row['source_bindings'] == expected['required_source_bindings']
        for source in row['source_bindings']:
            assert a.b(source['path']) == source
        journal = expected['required_original_native_journal']
        if journal is not None:
            assert row['native_journal'] == journal
            if expected['family'] == 7:
                assert a.b(journal['journal']['path']) == journal['journal']
        selected[str(expected['family'])] = row
    assert len(selected) == 4
    outputs[role] = binding
    family_rows[role] = selected
assert family_rows['original_raw_builder_before'] == family_rows['original_raw_builder_after']
assert family_rows['accounting_before'] == family_rows['accounting']
assert family_rows['original_raw_builder_before'] == family_rows['accounting_before']
a.save('ROOT_CURRENT_READER0030_FOUR_ORIGINAL_FAMILIES_ACCEPTED.json', {'schema': 'horizon-current-production-reader-four-original-family-acceptance-v1', 'contract': family_contract, 'actual_original_reader_proof': rb, 'actual_original_reader_image': reader['image'], 'actual_original_reader_spec': reader['spec'], 'actual_current_tuple': a.b(runtime / 'accepted-frame-selector.json'), 'actual_original_completion': a.b(p / 'reader0030-original-PID1.json'), 'actual_original_drain': a.b(p / 'reader0030-original-drain.json'), 'original_invocation_id': reader['invocation_id'], 'actual_output_bindings': outputs, 'exact_original_families': [4, 5, 6, 7], 'all_four_current_reservations_preserved': True, 'all_four_output_censuses_and_before_after_semantic_stability_verified': True, 'memory_or_DATA_credit_bytes': 0, 'replay_admission_authorized': False})
root = pathlib.Path(rb['path']).parent
names = {'proof.json', 'raw-accounting.json', 'raw-accounting-before.json', 'raw-builder-before.json', 'raw-builder-after.json', 'captured141-selection.json', 'captured141-selection-before.json'}
assert {q.name for q in root.iterdir()} == names
readonly('reader0030', [a.b(root / name) for name in sorted(names)], {'actual_reader': rb, 'original_outer': a.b(runtime / 'ROOT_FAILED4_READER0030_ORIGINAL_OUTER.json'), 'original_invocation_id': reader['invocation_id']})
dest = '/usr/local/lib/jetstreamer/horizon-parent-memory-reader0030-completion-20261109-v1'
completion = {'schema': 'terminal199-parent-memory-original-reader-completion-v1', 'reader_proof': rb, 'program': reader['image'], 'original_outer_reaped': True, 'original_cgroup_empty': True, 'original_descriptors_drained': True, 'original_native': n, 'original_PID1_journal': {'path': dest + '/journal.json', 'sha256': a.b(p / 'reader0030-original-PID1.json')['sha256']}, 'original_drain': {'path': dest + '/drain.json', 'sha256': a.b(p / 'reader0030-original-drain.json')['sha256']}, 'original_native_provenance': 'Original invocation identity comes from the genuine Rust proof and original PID1 completion. Terminal fields come from the untouched collected native state; raw snapshots and journal remain preserved.'}
a.save('reader0030-completion.json', completion)
a.seal('READER0030_COMPLETION', dest, [('journal.json', p / 'reader0030-original-PID1.json', 292), ('drain.json', p / 'reader0030-original-drain.json', 292), ('completion.json', p / 'reader0030-completion.json', 292)])
gate = qualified_helper_bindings()
assert reader['image'] == approved_helper() == gate['program']
reader_qdest = pathlib.Path('/usr/local/lib/jetstreamer/horizon-parent-memory-reader0030-combined-history-qualification-20261109-v1')
reader_native = {'schema': 'terminal199-parent-memory-current-reader-native-capability-v1', 'scope': 'terminal199-parent-memory-current-reader', 'program': reader['image'], 'actual_native_capability_passed': True, 'memory_credit_bytes': 0, 'DATA_credit_bytes': 0, 'actual_original_full_reader_proof': rb, 'actual_original_full_reader_completion': a.b(pathlib.Path(dest) / 'completion.json'), 'actual_input_tuple': a.b(runtime / 'accepted-frame-selector.json'), 'original_invocation_id': reader['invocation_id'], 'no_additional_reader_execution_claimed': True}
a.save('reader0030-new-image-native-capability.json', reader_native)
reader_qualified = {'schema': 'terminal199-parent-memory-qualified-artifact-v1', 'scope': 'terminal199-parent-memory-current-reader', 'program': reader['image'], 'prod_clippy_passed': True, 'test_clippy_passed': True, 'all_required_tests_passed': True, 'actual_native_capability_passed': True, 'memory_credit_bytes': 0, 'DATA_credit_bytes': 0, 'replay_launch_authorized': False, 'source_and_dependency_freeze': gate['artifact_proof'], 'deployment_seal': gate['normal_seal'], 'actual_source_QA_release_and_seal': gate['actual_qualification_acceptance'], 'actual_native_capability': {'path': str(reader_qdest / 'reader-native-capability.json'), 'sha256': a.b(p / 'reader0030-new-image-native-capability.json')['sha256']}}
a.save('reader0030-new-image-qualified-artifact.json', reader_qualified)
a.seal('READER0030_COMBINED_IMAGE_QUALIFICATION', str(reader_qdest), [('reader-native-capability.json', p / 'reader0030-new-image-native-capability.json', 292), ('reader-qualified-artifact.json', p / 'reader0030-new-image-qualified-artifact.json', 292)])
static = pathlib.Path('/usr/local/lib/jetstreamer/horizon-original199-parent-memory-witness-bootstrap-policy-20261107-v4')
policy = json.loads((static / 'capture-policy.json').read_text())
census_program = policy['census']['program']
capdir = pathlib.Path('/var/lib/jetstreamer/horizon-original199-parent-memory-census-v1') / current['observer']['sha256'] / 'capture-1'
capdir.parent.mkdir(mode=448, parents=True, exist_ok=True)
capdir.mkdir(mode=448)
spec = {'schema': 'terminal199-parent-memory-capture-spec-v1', 'policy': policy, 'current': current, 'current_reader': rb, 'reader_program': {'program': reader['image'], 'qualification': a.b(reader_qdest / 'reader-qualified-artifact.json')}, 'current_reader_acceptance': a.b(pathlib.Path(dest) / 'completion.json'), 'output_directory': str(capdir)}
a.save('capture0030-spec.json', spec)
spdest = '/usr/local/lib/jetstreamer/horizon-original199-parent-memory-capture0030-plan-20261109-v1'
a.seal('CAPTURE0030_SPEC', spdest, [('spec.json', p / 'capture0030-spec.json', 292)])
oldbook = json.loads((base / 'terminal199-parent-native-timer-parser-clients-20261105-v1/ROOT_REPAIRED_BOOTSTRAP_NATIVE_ACTUAL_BOOKING.json').read_text())
av = [census_program['path'] if v == '/usr/local/lib/jetstreamer/horizon-parent-native-timer-parser-census-tools-20261105-v1/parent-memory-census' else v for v in oldbook['argv']]
av[av.index('--self-sha256') + 1] = census_program['sha256']
av = [v.replace('/var/lib/jetstreamer/horizon-original199-parent-memory-bootstrap-20261104-v1', str(capdir)) for v in av]
idx = av.index('controller-probe')
av[idx] = 'capture'
av[idx + 1] = spdest + '/spec.json'
av[av.index('--spec-sha256') + 1] = a.b(pathlib.Path(spdest) / 'spec.json')['sha256']
av[-1] = str(capdir / 'capture-execution.json')
cap = launch('capture0030', av, capdir / 'capture-execution.json')
assert cap['scope'] == 'terminal199-parent-only-memory-census' and cap['program'] == census_program and (not cap['probe_only'])
files = sorted(capdir.iterdir())
assert 2 <= len(files) <= 64 and all((q.name in ['census.json', 'capture-execution.json', 'source-list-before.json', 'source-list-after.json'] or re.fullmatch('launcher-[0-9a-f]{64}-(before|after)\\.json', q.name) for q in files))
readonly('capture0030', [a.b(q) for q in files], {'actual_capture': a.b(capdir / 'capture-execution.json'), 'original_execution': a.b(p / 'capture0030-original-execution.json')})
qdest = '/usr/local/lib/jetstreamer/horizon-parent-memory-census0030-qualification-20261109-v1'
q = {'schema': 'terminal199-parent-memory-qualified-artifact-v1', 'scope': 'terminal199-parent-only-memory-census', 'program': census_program, 'prod_clippy_passed': True, 'test_clippy_passed': True, 'all_required_tests_passed': True, 'actual_native_capability_passed': True, 'source_and_dependency_freeze': a.b(pathlib.Path(census_program['path']).parent / 'artifact-proof.json'), 'actual_native_capability': a.b(capdir / 'capture-execution.json'), 'deployment_seal': a.b(pathlib.Path(census_program['path']).parent / 'deployment-seal-receipt.json'), 'parent_library35_tests': a.b(base / 'terminal199-controller-directory-anchor-source-20261105-v1/ROOT_ALL35_PARENT_LIBRARY_TESTS_AND_CENSUSES_ACCEPTED.json'), 'replay_launch_authorized': False, 'memory_credit_bytes': 0, 'DATA_credit_bytes': 0}
a.save('census0030-qualification.json', q)
a.seal('CENSUS0030_QUALIFICATION', qdest, [('qualification.json', p / 'census0030-qualification.json', 292)])
policy['census']['qualification'] = a.b(pathlib.Path(qdest) / 'qualification.json')
a.save('registration0030.json', policy)
regdest = '/usr/local/lib/jetstreamer/horizon-original199-parent-memory-registration-0030-native-parser-20261109-v1'
a.seal('REGISTRATION0030', regdest, [('registration.json', p / 'registration0030.json', 292)])
request = {'schema': 'terminal199-parent-only-memory-selection-request-v1', 'current': current, 'registration': a.b(pathlib.Path(regdest) / 'registration.json'), 'registration_seal': a.b(pathlib.Path(regdest) / 'deployment-seal-receipt.json'), 'current_reader': rb, 'reader_program': spec['reader_program'], 'current_reader_acceptance': spec['current_reader_acceptance'], 'census': cap['census'], 'baseline': {'kind': 'captured141-only', 'captured141': reader['captured141_selection']}}
completed145_capture_binding = parameters['completed145_capture_request_v2']
assert a.b(completed145_capture_binding['path']) == completed145_capture_binding
capture_request = json.loads(pathlib.Path(completed145_capture_binding['path']).read_text())
assert capture_request['schema'] == 'cached145-completed-parent-capture-request-v2' and 'census' not in capture_request
capture_output = pathlib.Path(capture_request['census_path'])
assert capture_output == pathlib.Path('/var/lib/jetstreamer/horizon-completed145-parent-memory-census-v2') / current['observer']['sha256'] / 'census.json'
assert not capture_output.exists()
capture_output.parent.mkdir(mode=448, parents=True, exist_ok=False)
c145spec = {'schema': 'cached145-completed-parent-census-spec-v2', 'current': current, 'request': capture_request}
a.save('completed145-current0030-census-spec-v2.json', c145spec)
c145dest = '/usr/local/lib/jetstreamer/horizon-completed145-parent-memory-census0030-plan-20261109-v3'
a.seal('COMPLETED145_CENSUS0030_SPEC', c145dest, [('spec.json', p / 'completed145-current0030-census-spec-v2.json', 292)])
c145image = parameters['completed145_census_program']
assert a.b(c145image['path']) == c145image
native_argv = json.loads((base / 'cached145-parent-memory-sealed-alias-qa-20261106-v3-r3/CENSUS_V3_NATIVE_CAPABILITY_PREWRITTEN_ARGV.json').read_text())
native_argv = [c145image['path'] if x == '/usr/local/lib/jetstreamer/horizon-completed145-parent-memory-census-tools-20261106-v3/cached145-census' else x for x in native_argv]
cmd = [x.replace('ReadWritePaths=/var/lib/jetstreamer/horizon-completed145-parent-memory-bootstrap-20261106-v3', 'ReadWritePaths=' + str(capture_output.parent)).replace('CapabilityBoundingSet=CAP_DAC_OVERRIDE', 'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE').replace('AmbientCapabilities=CAP_DAC_OVERRIDE', 'AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE') for x in native_argv]
assert cmd.count(c145image['path']) == 1
idx = cmd.index('native-capability')
cmd[idx] = 'capture'
cmd[idx + 1] = c145dest + '/spec.json'
cmd[cmd.index('--spec-sha256') + 1] = a.b(pathlib.Path(c145dest) / 'spec.json')['sha256']
cmd[cmd.index('--self-sha256') + 1] = c145image['sha256']
cmd[-1] = str(capture_output)
c145 = launch('completed145-census0030', cmd, capture_output)
assert c145['schema'] == 'cached145-completed-parent-current-census-v2' and c145['current'] == current and (c145['request'] == capture_request)
assert c145['program'] == c145image and c145['actor_native_before'] == c145['actor_native_after']
assert c145['archive_body_reads'] == c145['mutations'] == 0
assert stat.S_IMODE(capture_output.stat().st_mode) == 256
completed145_request = {'schema': 'cached145-completed-parent-only-memory-request-v1', 'registration': capture_request['registration'], 'registration_seal': capture_request['registration_seal'], 'census': a.b(capture_output)}
a.save('completed145-actual0030-selection-request-v2.json', completed145_request)
completed145_binding = a.b(p / 'completed145-actual0030-selection-request-v2.json')
request['completed_cached145'] = completed145_request
a.save('selection0030-request.json', request)
reqdest = '/usr/local/lib/jetstreamer/horizon-original199-parent-memory-selection0030-plan-20261109-v1'
a.seal('SELECTION0030_REQUEST', reqdest, [('request.json', p / 'selection0030-request.json', 292)])
seldir = pathlib.Path('/var/lib/jetstreamer/horizon-original199-parent-memory-selection-v1') / current['observer']['sha256'] / 'select-1'
seldir.parent.mkdir(mode=448, parents=True, exist_ok=True)
seldir.mkdir(mode=448)
selector = pathlib.Path(parameters['completed145_selector_program']['path'])
assert a.b(selector) == parameters['completed145_selector_program'], 'New completed145 selector must be actually qualified and normally sealed'
for mode, name in [('select', 'selection.json')]:
    cmd = [v.replace('--unit=horizon-original199-parent-memory-census-20261104-v1.service', '--unit=horizon-original199-parent-memory-select-20261104-v1.service').replace('--property=ReadWritePaths=' + str(capdir), '--property=ReadWritePaths=' + str(seldir)) for v in av]
    cmd[cmd.index(census_program['path'])] = str(selector)
    idx = cmd.index('capture')
    cmd[idx] = mode
    cmd[idx + 1] = reqdest + '/request.json'
    cmd[cmd.index('--spec-sha256') + 1] = a.b(pathlib.Path(reqdest) / 'request.json')['sha256']
    cmd[cmd.index('--self-sha256') + 1] = a.b(selector)['sha256']
    cmd[-1] = str(seldir / name)
    selected = launch('selector0030-' + mode, cmd, seldir / name)
    if mode == 'select':
        e = selected['selection']
        assert e['completed_cached145_parent_retirement_bytes'] == 206158430208
        assert e['completed_cached145_selection']['retained_guard_bytes'] == 536870912 and e['completed_cached145_selection']['retained_DATA_bytes'] == 361850994688
        assert e['completed_cached145_selection']['DATA_credit_bytes'] == e['completed_cached145_selection']['physical_credit_bytes'] == 0 and e['completed_cached145_selection']['live_exporter_limits_changed'] is False
        assert selected['capability_only'] is False and e['original199_parent_retirement_bytes'] == 206158430208 and (e['retained_original199_DATA_bytes'] == 824633720832) and (e['retained_original199_controller_bytes'] == e['retained_original199_guard_bytes'] == 536870912) and (e['DATA_credit_bytes'] == 0) and (not e['replay_launch_authorized'])
        a.save('ROOT_ACTUAL0030_PARENT_ONLY_SELECTION_ACCEPTED_NOT_REPLAY_ADMISSION.json', {'actual_selection': a.b(seldir / name), 'actual_census': cap['census'], 'original_reader': rb, 'current_tuple': a.b(runtime / 'ROOT_ACTUAL0030_NATIVE_FRAME_READER_CONTRACT_ACCEPTED.json'), 'actual_original_reader_completion': request['current_reader_acceptance'], 'completed145_parent_retirement_bytes': e['completed_cached145_parent_retirement_bytes'], 'completed145_registered_request': completed145_binding, 'original199_parent_retirement_bytes': e['original199_parent_retirement_bytes'], 'raw_total_memory_promises_bytes': e['raw_total_memory_promises_bytes'], 'effective_total_memory_promises_bytes': e['effective_total_memory_promises_bytes'], 'retained_original199_DATA_bytes': e['retained_original199_DATA_bytes'], 'all_original_raw_sources_preserved': True, 'fresh_eligibility_enrollment_and_full163_admission_remain_required': True})
        print(json.dumps({'parent_memory_selection': a.b(seldir / name), 'effective_total_memory_promises_bytes': e['effective_total_memory_promises_bytes'], 'retirement_bytes': e['original199_parent_retirement_bytes'], 'replay_admission': False}), flush=True)
