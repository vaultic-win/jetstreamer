import pathlib, json, sys, subprocess, time, os
base = pathlib.Path('/home/sol/.jetstreamer-private')
p = pathlib.Path(__file__).parent
sys.path.insert(0, str(base / 'terminal199-controller-directory-anchor-source-20261105-v1'))
import qa_metadata_adapter as a
a.p = p
runtime = p.parent
parameter_file = runtime / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json'
assert a.b(parameter_file)['sha256'] == os.environ['HORIZON_CURRENT_NATIVE_CONTINUATION_BINDINGS_SHA256']
parameters = json.loads(parameter_file.read_text())
accepted = json.loads((p / 'ROOT_ACTUAL0100_PARENT_ONLY_SELECTION_ACCEPTED_NOT_REPLAY_ADMISSION.json').read_text())
selection = accepted['actual_selection']
assert a.b(selection['path']) == selection
outer = json.loads(pathlib.Path(selection['path']).read_text())
current = outer['selection']['request']['current']
memory_outer = json.loads(pathlib.Path(selection['path']).read_text())
journal = p / 'selector0100-select-original-PID1.json'
drain = p / 'selector0100-select-original-drain.json'
j = json.loads(journal.read_text())
d = json.loads(drain.read_text())
iid = memory_outer['invocation_id']
assert j['invocation_id'] == d['invocation_id'] == iid and j['result'] == 'success' and (j['exec_main_status'] == 0)
assert d['outer_reaped'] and d['cgroup_empty'] and d['descriptors_drained'] and d['original_process_absent']
mdest = pathlib.Path('/usr/local/lib/jetstreamer/horizon-epoch163-selector0100-completion-20261109-v1')
memory_completion = {'schema': 'epoch163-parent-memory-selector-original-completion-v1', 'receipt': selection, 'invocation_id': iid, 'result': 'success', 'exec_main_status': 0, 'original_outer_reaped': True, 'original_cgroup_empty': True, 'original_descriptors_drained': True, 'original_PID1_journal': {'path': str(mdest / 'journal.json'), 'sha256': a.b(journal)['sha256']}, 'original_drain': {'path': str(mdest / 'drain.json'), 'sha256': a.b(drain)['sha256']}}
a.save('memory0100-completion.json', memory_completion)
a.seal('MEMORY0100_COMPLETION', str(mdest), [('completion.json', p / 'memory0100-completion.json', 292), ('journal.json', journal, 292), ('drain.json', drain, 292)])
policy_dest = pathlib.Path('/usr/local/lib/jetstreamer/horizon-ended183-DATA-policy-0100-20261109-v1')
inventory = pathlib.Path(parameters['current_inventory']['path'])
policy = {'schema': 'epoch183-explicit-ended-growth-DATA-policy-v1', 'current': current, 'recorded_unix_seconds': int(time.time()), 'terminal_legacy_closure': a.b(pathlib.Path('/usr/local/lib/jetstreamer/horizon-terminal-legacy-memory-closure-20261030-v1/closure.json')), 'authenticated_inventory': {'path': str(policy_dest / 'inventory.json'), 'sha256': a.b(inventory)['sha256']}, 'ready_receipts': [a.b(base / f'r2-receipts/epoch-{e}.r2.json') for e in [183, 184]], 'claim_key': 'epoch183/489e219d38d14d4594d8649ff698f666', 'original_growth_bytes': 824633720832, 'physical_credit_bytes': 0, 'memory_credit_bytes': 0}
a.save('data0100-policy.json', policy)
a.seal('DATA0100_POLICY', str(policy_dest), [('policy.json', p / 'data0100-policy.json', 292), ('inventory.json', inventory, 292)])
output = pathlib.Path('/var/lib/jetstreamer/horizon-ended183-DATA-selection-v1') / current['observer']['sha256']
assert current['observer']['path'].endswith('/sample-20261109T010022Z-postcompletion154-v1.json')
assert not output.exists(), 'Whole current observer DATA output directory must be fresh'
output.parent.mkdir(mode=448, parents=True, exist_ok=True)
output.mkdir(mode=448)
plan = {'schema': 'epoch183-native-current-ended-DATA-selection-plan-v1', 'memory_selection': selection, 'memory_original_completion': a.b(pathlib.Path('/usr/local/lib/jetstreamer/horizon-epoch163-selector0100-completion-20261109-v1/completion.json')), 'data_policy': a.b(policy_dest / 'policy.json'), 'data_policy_seal': a.b(policy_dest / 'deployment-seal-receipt.json'), 'output_directory': str(output)}
a.save('data0100-selection-plan.json', plan)
dest = pathlib.Path('/usr/local/lib/jetstreamer/horizon-ended183-DATA-selection0100-plan-20261109-v1')
a.seal('DATA0100_SELECTION_PLAN', str(dest), [('plan.json', p / 'data0100-selection-plan.json', 292)])
image = pathlib.Path(parameters['completed145_DATA_selector_program']['path'])
assert a.b(image) == parameters['completed145_DATA_selector_program']
unit = 'horizon-epoch183-ended-DATA-select-20261105-v1.service'

def native():
    raw = subprocess.check_output(['/usr/bin/systemctl', 'show', unit, '--property=Id,InvocationID,MainPID,ControlPID,ActiveState,SubState,Result,ExecMainStatus,NRestarts,Job'], text=True)
    return dict((line.split('=', 1) for line in raw.splitlines()))
n = native()
assert n['MainPID'] == n['ControlPID'] == '0' and n['Job'] == '' and (n['ActiveState'] == 'inactive')
av = ['/usr/bin/systemd-run', '--wait', '--pipe', '--unit=' + unit, '--service-type=exec', '-p', 'User=root', '-p', 'Group=root', '-p', 'Restart=no', '-p', 'MemoryAccounting=yes', '-p', 'MemoryHigh=2G', '-p', 'MemoryMax=2G', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=100%', '-p', 'TasksMax=512', '-p', 'RuntimeMaxSec=600', '-p', 'TimeoutStopSec=15', '-p', 'PrivateNetwork=yes', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=read-only', '-p', 'NoNewPrivileges=yes', '-p', 'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', '-p', 'AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', '-p', 'ReadWritePaths=' + str(output), '-p', 'TemporaryFileSystem=/tmp:ro /var/tmp:ro', str(image), 'select', str(dest / 'plan.json'), '--plan-sha256', a.b(dest / 'plan.json')['sha256'], '--self-sha256', a.b(image)['sha256'], '--output', str(output / 'selection.json')]
a.save('ROOT_DATA0100_NATIVE_ACTUAL_BOOKING.json', {'argv': av, 'current': current, 'actual_memory_selection': selection, 'qualified_completed145_DATA_tools': {'artifact_proof': a.b(image.parent / 'artifact-proof.json'), 'normal_seal': a.b(image.parent / 'deployment-seal-receipt.json')}, 'current_capacity': parameters['current_capacity_receipt'], 'normal_pool_bytes': 6442450944, 'native_memory_bytes': 2147483648, 'Root_bytes': 536870912, 'margin_bytes': 536870912, 'one_routine2GiB_may_overlap': True, 'all_compilers_drained': True, 'native_outer_booking_seconds': [600, 630, 665], 'no_full_replay_admission': True})
window_program = pathlib.Path(parameters['qualified_current_guard_program']['path'])
window_sha = parameters['qualified_current_guard_program']['sha256']
assert a.b(window_program)['sha256'] == window_sha
window_request = {'schema': 'horizon-current1800-DATA-completed-window-request-v1', 'observer': current['observer'], 'memory_selection': selection, 'DATA_plan': a.b(dest / 'plan.json'), 'no_replay_authority': True}
a.save('ROOT_DATA0100_COMPLETED_WINDOW_REQUEST.json', window_request)
window_plan = {'schema': 'horizon-original-completed-guard-window-native-argv-plan-v1', 'not_launch_authority': True, 'argv': av, 'request': a.b(p / 'ROOT_DATA0100_COMPLETED_WINDOW_REQUEST.json')}
a.save('ROOT_DATA0100_COMPLETED_WINDOW_ARGV_PLAN.json', window_plan)
guard_av = [str(window_program), 'run-original-data', 'DATA0100-original', str(p / 'ROOT_DATA0100_COMPLETED_WINDOW_ARGV_PLAN.json'), '--spec-sha256', a.b(p / 'ROOT_DATA0100_COMPLETED_WINDOW_ARGV_PLAN.json')['sha256'], '--self-sha256', window_sha]
a.save('ROOT_DATA0100_COMPLETED_WINDOW_ACTUAL_ARGV.json', guard_av)
r = subprocess.run(guard_av, capture_output=True, text=True, timeout=710)
n = native()
a.save('ROOT_DATA0100_NATIVE_ORIGINAL_EXECUTION.json', {'code': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr, 'native_after': n})
print(json.dumps({'stage': 'DATA0100', 'code': r.returncode, 'stdout': r.stdout[-3000:], 'stderr': r.stderr[-2000:]}), flush=True)
assert r.returncode == 0
binding = a.b(output / 'selection.json')
proof = json.loads((output / 'selection.json').read_text())
assert proof['actual_native_capability_passed'] and (not proof['admission_authorized']) and (proof['memory_selection'] == selection)
assert n['MainPID'] == n['ControlPID'] == n['ExecMainStatus'] == '0' and n['Job'] == '' and (n['Result'] == 'success')
cg = pathlib.Path('/sys/fs/cgroup/system.slice') / unit
assert not cg.exists() or not any((q.read_text().split() for q in cg.rglob('cgroup.procs')))
j = subprocess.run(['/usr/bin/journalctl', '--all', '--no-pager', '--output=json', '-u', unit, '--since=@' + str(proof['recorded_unix_seconds'] - 5)], capture_output=True, text=True, check=True, timeout=20)
rows = [json.loads(x) for x in j.stdout.splitlines()]
rows = [x for x in rows if x.get('INVOCATION_ID') == proof['invocation_id'] or x.get('_SYSTEMD_INVOCATION_ID') == proof['invocation_id']]
assert any((x.get('_PID') == '1' and x.get('INVOCATION_ID') == proof['invocation_id'] and ('Deactivated successfully' in x.get('MESSAGE', '')) for x in rows))
a.save('ROOT_DATA0100_ORIGINAL_PID1_AND_DRAIN.json', {'unit': unit, 'invocation_id': proof['invocation_id'], 'original_PID1_rows': rows, 'original_outer_reaped': True, 'original_cgroup_empty': True, 'result': 'success', 'exec_main_status': 0, 'native_after': n})
a.save('ROOT_ACTUAL0100_MEMORY_AND_DATA_COMPONENTS_ACCEPTED_NOT_FULL163_ADMISSION.json', {'actual_DATA_selection': binding, 'original_PID1_and_drain': a.b(p / 'ROOT_DATA0100_ORIGINAL_PID1_AND_DRAIN.json'), 'actual_memory_selection': selection, 'actual_memory_original_completion': a.b(pathlib.Path('/usr/local/lib/jetstreamer/horizon-epoch163-selector0100-completion-20261109-v1/completion.json')), 'raw_DATA_bytes': proof['raw_protected_DATA_bytes'], 'effective_DATA_bytes': proof['effective_protected_DATA_bytes'], 'only_ended183_future_growth_selected': True, 'original199_all_DATA_preserved': True, 'physical_credit_bytes': 0, 'fresh_full163_admission_enrollment_input_and_guard_still_required': True})
