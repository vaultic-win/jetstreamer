from next_operation_bindings import next_operation_bindings
operation_authority = next_operation_bindings()
from pathlib import Path
import json, hashlib, subprocess, re, os
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'combined-runtime'
sha = lambda b: hashlib.sha256(b).hexdigest()

def b(f):
    f = Path(f)
    return dict(path=str(f), sha256=sha(f.read_bytes()))

def save(n, v):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
assert operation_authority['current_complete_DATA_lower_bound_bytes'] >= 5161357357716
records = []
units = set()
for f in q.rglob('*.json'):
    if not any((x in f.name.upper() for x in ['EXECUTION', 'ORIGINAL_RESULT'])):
        continue
    if f.stat().st_size > 20 << 20:
        continue
    try:
        v = json.loads(f.read_text())
    except (ValueError, UnicodeError):
        continue
    if not isinstance(v, dict) or not isinstance(v.get('code'), int):
        continue
    strings = [v.get(k, '') for k in ['stdout', 'stderr', 'original_outer_stdout', 'original_outer_stderr']]
    names = set()
    for s in strings:
        if isinstance(s, str):
            names.update(re.findall('Running as unit: ([A-Za-z0-9_.@-]+\\.service)', s))
    if not names:
        continue
    units.update(names)
    records.append(dict(execution=b(f), code=v['code'], units=sorted(names)))
assert len(units) > 100, len(units)
node_proof = p / 'first128-node-guard-witness-v2/node/PRODUCTION-ORIGINAL-QUALIFICATION.json'
node_originals = json.loads(node_proof.read_text())['originals']
for original in node_originals:
    unit = original['original_native']['Id']
    units.add(unit)
records.append(dict(declared_node_originals=b(node_proof), units=[x['original_native']['Id'] for x in node_originals], original_completed_clippy_metadata_client_failure_preserved=True))
for f in Path('/home/sol/.jetstreamer-private/native163-finalizer-retained-exec-qa-20261108-v2').glob('*.json'):
    try:
        value = json.loads(f.read_text())
    except ValueError:
        continue
    for key in ['original_native', 'actual_original_control']:
        row = value.get(key, {})
        if isinstance(row, dict) and row.get('Id'):
            units.add(row['Id'])
external_qualifications = [Path('/home/sol/.jetstreamer-private/native163-finalizer-retained-exec-qa-20261108-v2/PRODUCTION-ORIGINAL-QUALIFICATION.json'), Path('/home/sol/.jetstreamer-private/epoch185-positive-current-witness-planner-source-20261108-v2/PRODUCTION-ORIGINAL-QUALIFICATION.json')]
external_qualifications.append(Path('/home/sol/.jetstreamer-private/first128-driver-qa-20261108-v3/PRODUCTION-ORIGINAL-QUALIFICATION.json'))
units.update(['horizon-first128-driver-control-actual-20261108-v3-once.service', 'horizon-first128-driver-control-actual-20261108-v3-tick.service', 'horizon-first128-driver-clippy-production-20261108-v2.service'])
for original in json.loads(Path('/home/sol/.jetstreamer-private/first128-driver-qa-20261108-v1/STATIC-ORIGINAL-QUALIFICATION-NOT-PRODUCTION.json').read_text())['originals']:
    units.add(original['original_native']['Id'])
units.add('horizon-positive185-current-operation-clippy-production-20261108-v1.service')
for stage in ['clippy-production', 'clippy-tests', 'test-build', 'release', 'ordinary']:
    units.add('horizon-positive185-current-operation-' + stage + '-20261108-v3.service')
units.add('horizon-positive185-current-operation-clippy-production-20261108-v2.service')
for version in ['v1', 'v2', 'v3', 'v4']:
    for role in ['target', 'reader']:
        units.add('horizon-native163-trace-control-' + role + '-20261108-' + version + '.service')
for external in external_qualifications:
    value = json.loads(external.read_text())
    assert value['all_required_tests_passed']
    for original in value['originals']:
        unit = original['original_native']['Id']
        units.add(unit)
    records.append(dict(external_qualification=b(external), units=[x['original_native']['Id'] for x in value['originals']]))
for version in range(4, 18):
    root = Path('/home/sol/.jetstreamer-private') / f'epoch185-positive-current-operation-qa-20261108-v{version}'
    if not root.exists():
        continue
    for execution in root.glob('*EXECUTION.json'):
        value = json.loads(execution.read_text())
        for text_value in [value.get('stdout', ''), value.get('stderr', '')]:
            units.update(re.findall('Running as unit: ([A-Za-z0-9_.@-]+\\.service)', text_value))
for version in [5, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17]:
    units.add(f'horizon-positive185-reader-lifecycle-actual-20261108-v{version}.service')
    if version != 5:
        units.add(f'horizon-positive185-reader-control-control-positive-reader-v{version}.service')
external_185 = Path('/home/sol/.jetstreamer-private/epoch185-positive-current-operation-qa-20261108-v17-r2/PRODUCTION-ORIGINAL-QUALIFICATION.json')
external_qualifications.append(external_185)
for original in json.loads(external_185.read_text())['originals']:
    units.add(original['original_native']['Id'])
units.update(['horizon-positive185-profile-original-20261108-v16.service', 'horizon-positive185-profile-original-20261108-v16-r2.service', 'horizon-current0600-reader-native-phase-20261108-v15.service', 'horizon-positive185-original-actual0600-20261108-v14.service'])
units.add('horizon-positive185-reader-phase-actual-20261108-v16.service')
units.update(['horizon-positive185-profile-original-20261108-v17.service', 'horizon-positive185-reader-phase-actual-20261108-v17.service', 'horizon-positive185-failed-reader-retirement-control-20261108-v17.service', 'horizon-positive185-failed-reader-retirement-actual0630-20261108-v17.service'])
for execution in Path('/home/sol/.jetstreamer-private/epoch185-positive-current-operation-qa-20261108-v17-r2').glob('*EXECUTION.json'):
    value = json.loads(execution.read_text())
    for output in [value.get('stdout', ''), value.get('stderr', '')]:
        units.update(re.findall('Running as unit: ([A-Za-z0-9_.@-]+\\.service)', output))
original0900_root = Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual1030-original-r3-20261108-v21-c2')
original0900_context = json.loads((original0900_root / 'original-activation-context.json').read_text())
units.update([original0900_context['actor'], original0900_context['guard'], 'horizon-failed4-current-accounting-reader-20261104-v1.service'])
for key in ['qualification', 'final_executor_qualification', 'postreader29_qualification', 'postreader30_qualification', 'planner_qualification']:
    qualification = Path(operation_authority[key]['path'])
    external_qualifications.append(qualification)
    value = json.loads(qualification.read_text())
    if str(qualification) == operation_authority['planner_qualification']['path']:
        current_graph = json.loads(Path(value['exact_source_and_compiler_graph']['path']).read_text())
        current_root = Path(value['production_artifact']['path']).parent.parent
        for label in list(current_graph['recipes']) + ['ORDINARY']:
            actual = json.loads((current_root / (label + '-ORIGINAL-EXECUTION.json')).read_text())
            assert actual['code'] == 0
            argv = json.loads((current_root / (label + '-ORIGINAL-ARGV.json')).read_text())
            unit = next(x.split('=', 1)[1] for x in argv if x.startswith('--unit=')) + '.service'
            units.add(unit)
        for bound in [value['actual2300_request_positive_control']] + value['actual2300_crossed_helper_and_prelaunch_controls']:
            actual = json.loads(Path(bound['path']).read_text())
            assert b(bound['path']) == bound
            argv = actual['argv']
            units.add(next(x.split('=', 1)[1] for x in argv if x.startswith('--unit=')) + '.service')
    else:
        for original in value['originals']:
            native_key = 'actual_original_native' if str(qualification) == operation_authority['postreader30_qualification']['path'] else 'original_native'
            units.add(original[native_key]['Id'])
records.append(dict(actual_original1030_held_expiry_and_drain=operation_authority['original1030_held_expiry_and_drain'], actual_failed1030_reader_retirement=operation_authority['failed1030_reader_retirement'], actual_next_operation_qualification=operation_authority['qualification'], actual_final2_qualification=operation_authority['final_executor_qualification'], actual_final2_DATA_booking=operation_authority['additive_DATA_booking']))
from observer136_data import actual_observer136_closed_booking
observer136_booking, observer136_closure, observer136_book, observer136_closed = actual_observer136_closed_booking()
units.update((row['Id'] for row in observer136_closed['planned_unit_native_absence']))
records.append(dict(actual_observer136_QA2_closure=observer136_closure, actual_observer136_DATA1_booking=observer136_booking))
helper30_close = json.loads(Path(operation_authority['helper30_QA_closure']['path']).read_text())
units.update((row['Id'] for row in helper30_close['actual_terminal_unit_census']))
old1230_ctx = json.loads(Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual1230-original-r3-20261108-v24/original-activation-context.json').read_text())
units.update([old1230_ctx['actor'], old1230_ctx['guard']])
current1330_ended = json.loads(Path(operation_authority['original1330_completion_and_drain']['path']).read_text())
current1330_context = json.loads(Path(current1330_ended['original_activation']['path']).read_text())
units.update([current1330_context['actor'], current1330_context['guard']])
records.append(dict(actual_original1330_completion_and_drain=operation_authority['original1330_completion_and_drain'], actual_failed1330_reader_retirement=operation_authority['failed1330_reader_retirement']))
for original_binding in operation_authority['preserved_original_execution_records']:
    original = json.loads(Path(original_binding['path']).read_text())
    assert b(Path(original_binding['path'])) == original_binding
    names = set()
    for part in [original.get('stdout', ''), original.get('stderr', '')]:
        names.update(re.findall('Running as unit: ([A-Za-z0-9_.@-]+\\.service)', part))
    for arg in original.get('argv', []):
        if arg.startswith('--unit='):
            names.add(arg.split('=', 1)[1].removesuffix('.service') + '.service')
    units.update(names)
    records.append(dict(execution=original_binding, code=original['code'], units=sorted(names), failed_original_preserved=True))
ended1430 = json.loads(Path(operation_authority['original1430_completion_and_drain']['path']).read_text())
ctx1430 = json.loads(Path(ended1430['original_activation']['path']).read_text())
units.update([ctx1430['actor'], ctx1430['guard']])
records.append(dict(original1430_completion_and_drain=operation_authority['original1430_completion_and_drain']))
units.update(['horizon-operation28-coherence-disposable-20261108-v1.service', 'horizon-operation28-disposable-helper-build-20261108-v2.service'])
for binding_key in ['actual_completed_writer_native_control', 'actual_reader_lifecycle_control']:
    original_proof = json.loads(Path(json.loads(Path(operation_authority['qualification']['path']).read_text())[binding_key]['path']).read_text())

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ['Id', 'unit'] and isinstance(item, str) and item.endswith('.service') and item.startswith('horizon-positive185-'):
                    units.add(item)
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(original_proof)
ended1530 = json.loads(Path(operation_authority['original1530_completion_and_drain']['path']).read_text())
ctx1530 = json.loads(Path(ended1530['original_activation']['path']).read_text())
units.update([ctx1530['actor'], ctx1530['guard']])
records.append(dict(actual_original1530_completion_and_drain=operation_authority['original1530_completion_and_drain'], actual_successful1530_reader_retirement=operation_authority['successful1530_reader_retirement'], successful_original_reader_history_preserved=True))
ended1630 = json.loads(Path(operation_authority['original1630_completion_and_drain']['path']).read_text())
ctx1630 = json.loads(Path(ended1630['original_activation']['path']).read_text())
units.update([ctx1630['actor'], ctx1630['guard']])
units.add('horizon-operation32-coherence-disposable-20261108-v4.service')
states = []
for unit in sorted(units):
    z = subprocess.run(['systemctl', 'show', unit, '-pId,MainPID,ControlPID,ControlGroup,NRestarts,ActiveState,SubState,Result,ExecMainStatus,Job'], capture_output=True, text=True)
    n = dict((x.split('=', 1) for x in z.stdout.splitlines()))
    assert n['Id'] == unit and n['MainPID'] == n['ControlPID'] == '0' and (n['ControlGroup'] == n['Job'] == '') and (n['NRestarts'] == '0'), n
    cg = Path('/sys/fs/cgroup/system.slice') / unit
    assert not cg.exists() or all((not x.read_text().strip() for x in cg.rglob('cgroup.procs')))
    states.append(n)
required = [p / 'HELPER27-PRODUCTION-ORIGINAL-QUALIFICATION.json', p / 'CLI5-PRODUCTION-ORIGINAL-QUALIFICATION.json', p / 'current0100-window-20261109-v1/work/ARTIFACT_PROOF_BEFORE_SEAL.json'] + [p / 'small-clients-raw-context-v4' / (x + '-PRODUCTION-ORIGINAL-QUALIFICATION.json') for x in ['original199-census', 'completed145-census', 'memory-selector', 'DATA-selector']]
required += [q / (x + '-raw-context-v4/PRODUCTION-ORIGINAL-QUALIFICATION.json') for x in ['parent-memory', 'parent-DATA']]
required += [node_proof, p / 'first128-node-guard-witness-v2/guard/PRODUCTION-ORIGINAL-QUALIFICATION.json']
required += external_qualifications
for f in required:
    v = json.loads(f.read_text())
    assert v.get('all_required_tests_passed') is True or (v.get('schema') in ['horizon-positive185-final-executor-unit-qualified-v2', 'horizon-positive185-final-executor-unit-qualified-v3'] and v['strict_production_and_test_Clippy_passed'] is True and (v['ordinary_tests_passed'] == (25 if v.get('schema', '').endswith('-v3') else 21)))
proof = dict(schema='native163-full-reader-extra-QA6-closure-v1', extra_QA_memory_bytes=6 << 30, released_bytes=6 << 30, normal_pool_released_bytes=0, all_original_QA_actors_terminal_and_drained=True, all_required_qualification_actors_terminal_successful_and_drained=True, source_and_DATA_promises_retained=True, complete_DATA_bytes=operation_authority['current_complete_DATA_lower_bound_bytes'], normal_pool_bytes=6 << 30, required_final_qualifications=[b(f) for f in required], original_execution_records=records, actual_terminal_unit_census=states, original_wait_client_incident_closed=b(q / 'current1930-r2/ORIGINAL_COMPLETED_METADATA_UNIT_CLOSE_EXECUTION.json'), failed_originals_preserved=True, guard_ordinary14_passed_actual_witness_control_future_and_unstarted=True, helper15_static_compilers_and_ordinary_originals_completed=True, helper15_actual_selected_memory_native_control_unstarted_under_normal_pool=True, guard2_actual_witness_control_unstarted_under_normal_pool=True, native_admission_must_use_later_final_qualification_closure=True, no_replay_or_native_launch_authority=True)
proof.update(extra_QA_booking=operation_authority['helper30_QA_booking'], prior_QA6_release_is_historical_and_not_added=b(p / 'ROOT_HELPER27_QA6_FINAL_CLOSURE.json'), release_applies_only_to_latest_QA6_booking=True, all_helper27_ten_native_controls_completed=True, helper27_actual_closed_native_original_inputs_passed=True, helper27_actual_selected_memory_native_control_passed=True, helper15_actual_selected_memory_native_control_unstarted_under_normal_pool=False, guard2_actual_witness_control_unstarted_under_normal_pool=False, guard_ordinary14_passed_actual_witness_control_future_and_unstarted=False, native_admission_must_use_later_final_qualification_closure=False)
proof['original_extra_QA_release_is_historical_not_added_twice'] = b(p / 'ROOT_HELPER27_QA6_FINAL_CLOSURE.json')
proof['new_QA_memory_released_bytes'] = 0
proof['actual_helper29_QA_booking'] = operation_authority['helper29_QA_booking']
proof['actual_helper29_QA_closure'] = operation_authority['helper29_QA_closure']
proof['actual_postreader30_qualification'] = operation_authority['postreader30_qualification']
proof['actual_failed0630_reader_retirement'] = b(Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-exact0630-failed-reader-retirement-20261108-v17/failed-reader-retirement-completion.json'))
proof['actual_original1030_held_expiry_and_drain'] = operation_authority['original1030_held_expiry_and_drain']
proof['actual_next_operation_qualification'] = operation_authority['qualification']
proof['actual_final2_qualification'] = operation_authority['final_executor_qualification']
proof['actual_failed1030_reader_retirement'] = operation_authority['failed1030_reader_retirement']
proof['actual_final2_DATA_booking'] = operation_authority['additive_DATA_booking']
proof['actual_observer136_QA2_closure'] = observer136_closure
proof['actual_observer136_DATA1_booking'] = observer136_booking
proof.update(actual_helper30_QA_booking=operation_authority['helper30_QA_booking'], actual_helper30_QA_closure=operation_authority['helper30_QA_closure'], actual_original1230_held_expiry_and_drain=operation_authority['original1230_held_expiry_and_drain'], actual_failed1230_reader_retirement=operation_authority['failed1230_reader_retirement'])
proof['actual_original1530_completion_and_drain'] = operation_authority['original1530_completion_and_drain']
proof['actual_successful1530_reader_retirement'] = operation_authority['successful1530_reader_retirement']
proof['actual_helper31_QA_booking'] = operation_authority['helper31_QA_booking']
proof['actual_helper31_QA_closure'] = operation_authority['helper31_QA_closure']
proof['actual_helper33_QA4_closure'] = operation_authority['helper33_QA_closure']
assert json.loads(Path(operation_authority['helper33_QA_closure']['path']).read_text())['fresh_extra_QA4_bytes_after'] == 0
proof['actual_helper34_QA5_closure'] = operation_authority['helper34_QA_closure']
assert json.loads(Path(operation_authority['helper34_QA_closure']['path']).read_text())['fresh_extra_QA5_bytes_after'] == 0
proof['actual_original1630_completion_and_drain'] = operation_authority['original1630_completion_and_drain']
proof['actual_successful1630_reader_retirement'] = operation_authority['successful1630_reader_retirement']
save('ROOT_HELPER27_CURRENT0100_NORMAL_POOL_REVALIDATED_CLOSURE.json', proof)
print('Revalidated normal6GiB; historical extra6GiB release is not credited again; records', len(records), 'original execution records and', len(states), 'terminal/empty original units; retained all DATA and normal6GiB', flush=True)
