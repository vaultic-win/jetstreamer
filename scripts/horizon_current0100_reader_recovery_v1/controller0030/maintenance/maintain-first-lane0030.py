from pathlib import Path
import os, json, hashlib, subprocess, re, ast
from current_literal_adapter import adapt, literal
base = Path('/home/sol/.jetstreamer-private')
old = base / 'actual000022-visible-root-acceptance-20261109-v1'
p = base / 'actual003022-visible-root-acceptance-20261109-v1'
o = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T003022Z-postcompletion154-v1.json')
sha = lambda b: hashlib.sha256(b).hexdigest()

def b(f):
    f = Path(f)
    return dict(path=str(f), sha256=sha(f.read_bytes()))
v = json.loads(o.read_text())
assert v['recorded_at_utc'] == '2026-11-09T00:30:22Z' and v['cadence']['observed_interval_seconds'] == 1800 and (v['replays'] == [])

def native(u):
    return dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', u, '-pActiveState,SubState,Result,ExecMainStatus,InvocationID,MainPID,ControlPID,NRestarts'], text=True).splitlines()))
n = native('horizon-visible-primary-observer003022-20261109-v1.service')
assert n['Result'] == 'success' and n['ExecMainStatus'] == n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0'
p.mkdir(mode=448)

def save(root, n, v):
    raw = (json.dumps(v, indent=2) + '\n').encode() if not isinstance(v, str) else v.encode()
    fd = os.open(root / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(root, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
s = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(Path(s).read_bytes()) == h
os.umask(18)

def seal(root, label, dest, files):
    f = label + '-SEAL-PLAN.json'
    save(root, f, dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=dest, members=[dict(source=str(root / a), name=a, sha256=sha((root / a).read_bytes()), mode=292) for a in files]))
    z = subprocess.run([s, str(root / f), '--plan-sha256', sha((root / f).read_bytes()), '--self-sha256', h], capture_output=True, text=True)
    save(root, label + '-SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    assert z.returncode == 0, z.stderr
review = json.loads((old / 'status-estimate-review000022.json').read_text())
review['coordinated_observer'] = b(o)
review['current_cycle_reassessment'] = 'Nov9 00:30 cycle. Root strict Helper34/Planner5/Operation36 qualification, source graph, supplementalPlanner5metadata view, QA5closure and historical authority remain actual. MidnightFrame/fullReader13/parent/cached145/memory/DATA passed; both resource predecessors now actual0000, new0030observer directly follows0000, no new bridge. Midnight startup cutoff expired and invoke was not run: no0000actor and noMain0/target5. Fresh0030guard/admission/firstguard/Main remains next. All prior DATA charges includingunused2330guard retained, new0030guard requires a separate512MiB. Root retains normal6/extraQA0 after actualQA5closure. Actual2300terminal PID1/noMain evidence is preserved. Review4 remains bound to actual original19:25:15control anchor/01:28:36deadline inside unchanged17:30:22+24h qualification; unexecutedfull413404206msreplay remainsfuture. Otherhost200-300untouched; original199bodies/FDs/controllerPID2467123FD9protected.'

for row in review['owner_updates_by_epoch'].values():
    row['current_shared_dependency'] = review['current_cycle_reassessment']
audit = json.loads(Path(json.loads(json.loads((old / 'status-audit000022-execution.json').read_text())['stdout'])['audit']).read_text())
for row in audit['outcomes']:
    e = str(row['epoch'])
    pr = json.loads(Path(row['receipt']['path']).read_text())
    review['latest_authenticated_status_by_epoch'][e] = row['receipt']
    review['parts_by_epoch'][e] = pr['estimate_parts_millis']
# The latest targeted event has an authenticated-readback completion, not stdout/audit nesting.
event_file = Path(os.environ.get('HORIZON_LATEST_COMPLETED_STATUS_READBACK', '/home/sol/.jetstreamer-private/current0000-parent-path-and-startup-cutoff-status-event-20261109-v1/AUTHENTICATED-READBACK.json'))
event = json.loads(event_file.read_text())
assert set(event) == {'after_status', 'receipt'}
receipt_binding = event['receipt']
assert b(receipt_binding['path']) == receipt_binding
pr = json.loads(Path(receipt_binding['path']).read_text())
assert pr['epoch'] == 185 and pr['authenticated_readback'] is True
assert pr['after_status'] == event['after_status']
wire = event['after_status']
assert set(wire) == {'epoch', 'jet_size_bytes', 'elapsed_execution_millis', 'estimated_remaining_millis', 'sampled_at_utc', 'phase'}
assert wire['epoch'] == 185 and wire['phase'] == 'verification'
assert all(type(wire[k]) is int and 0 <= wire[k] < 2**64 for k in ['epoch', 'jet_size_bytes', 'elapsed_execution_millis', 'estimated_remaining_millis'])
assert all(type(x) is int and x >= 0 for x in pr['estimate_parts_millis'].values())
assert sum(pr['estimate_parts_millis'].values()) == wire['estimated_remaining_millis']
expected_model = {'path': '/home/sol/.jetstreamer-private/actual2230-planner4-explicit-control-review3-event185-20261108-v1/FIXED185_ETA_MODEL_EXPLICIT_CONTROL_REVIEW3.json', 'sha256': '7277c044bde1cd513ba1c03e2ffc807ebdc1a3ef633511e0634497683ce66edc'}
assert b(pr['owner_evidence']['fixed_work_eta_model']['path']) == pr['owner_evidence']['fixed_work_eta_model']
assert b(expected_model['path']) == expected_model
original_model = json.loads(Path(expected_model['path']).read_text())
model_binding_file = os.environ.get('HORIZON_FIXED185_ETA_MODEL_BINDING_FILE', '/home/sol/.jetstreamer-private/epoch185-explicit-control-review4-model-20261109-next-v1/MODEL_BINDING.json')
if model_binding_file:
    expected_model = json.loads(Path(model_binding_file).read_text())
    assert b(expected_model['path']) == expected_model
    reviewed_model = json.loads(Path(expected_model['path']).read_text())
    assert reviewed_model['schema'] == original_model['schema'] and reviewed_model['owner'] == '/root'
    for key in ['qualification_anchor_utc', 'qualification_original_total_millis', 'full_replay_fixed_millis', 'authenticated_full_work_basis']:
        assert reviewed_model[key] == original_model[key], ('Original full-work ETA authority changed', key)

review['predecessor_review'] = b(old / 'status-estimate-review000022.json')
review.pop('latest_completed_event_execution', None)
review['latest_completed_event_readback'] = b(event_file)
baseline = json.loads(Path(review['latest_authenticated_status_by_epoch']['185']['path']).read_text())
if pr['sampled_at_utc'] > baseline['sampled_at_utc']:
    review['latest_authenticated_status_by_epoch']['185'] = receipt_binding
    review['parts_by_epoch']['185'] = pr['estimate_parts_millis']
booking_file = Path('/home/sol/.jetstreamer-private/epoch185-inherited-census-helper-qa-20261108-v34/ROOT_FRESH_EXTRA_QA5_COMPILER8_DATA4_BOOKING.json')
booking = json.loads(booking_file.read_text())
assert booking['normal_pool_bytes'] == 6 << 30 and booking['new_extra_QA5_bytes'] == 5 << 30
assert booking['one_serial_compiler_bytes'] + booking['ordinary_observer_bytes'] + booking['Root_and_status_bytes'] == booking['total_external_pool_bytes'] == 11 << 30
assert booking['previous_complete_DATA_lower_bound_bytes'] + booking['new_additive_retained_DATA_bytes'] == booking['complete_DATA_lower_bound_bytes'] == 5158673003156
assert booking['no_credit_from_old_QA_releases'] is True
# Root supplies the latest actual complete DATA record; this source never creates or closes bookings.
data_binding = json.loads((Path(__file__).resolve().parent / 'ROOT_ACTUAL_CURRENT0030_DATA_BINDING.json').read_text())
assert b(data_binding['path']) == data_binding
current_DATA_document = json.loads(Path(data_binding['path']).read_text())
complete_DATA = current_DATA_document.get('complete_DATA_lower_bound_bytes', current_DATA_document.get('complete_DATA_bytes'))
assert type(complete_DATA) is int and complete_DATA >= 5160820486804
for row in review['owner_updates_by_epoch'].values():
    row.update(actual_Helper34_fresh_extraQA5_booking=b(booking_file), complete_current_DATA_bytes=complete_DATA, current_complete_DATA_authority=data_binding)

review['owner_updates_by_epoch']['185']['actual_Helper34_QA5_closure'] = b('/home/sol/.jetstreamer-private/epoch185-inherited-census-helper-qa-20261108-v34/ROOT_FRESH_EXTRA_QA5_CLOSED_NORMAL6_DATA_RETAINED.json')
review['owner_updates_by_epoch']['185']['fixed_work_eta_model'] = expected_model
review['owner_updates_by_epoch']['185']['current_task'] = review['current_cycle_reassessment']
save(p, 'status-estimate-review003022.json', review)
for name in ['audit_contract_r1.py', 'CURRENT_COMPLETED_TUPLE_AT1458.json', 'INITIAL163_SOURCE_BINDINGS.json', 'ROOT_ORIGINAL145_TERMINAL_FAILURE_AND_NO_RELEASE.json']:
    save(p, name, (old / name).read_text())
save(p, 'PREDECESSOR_BINDINGS.json', dict(observer=b(Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T000022Z-postcompletion154-v1.json'))))
save(p, 'live145_metadata.py', adapt((old / 'live145_metadata.py').read_text()))
source = adapt((old / 'status_audit000022.py').read_text())
assert source.count('_current = completed_tuple()') == 1
source = source.replace('_current = completed_tuple()', "_current = {'accepted_selector': {'path': '/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0000-20261109-v1/accepted-frame-selector.json', 'sha256': '909fbec0e2e49aa6e2996a933415c5dead5107b787e45bb27d3ce4b483dde8a0'}, 'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T000022Z-postcompletion154-v1.json', 'sha256': 'bc600b6b088e11199516cd5094b1972988bd7870bb5a683f6f456a53a833bb1e'}}\n_memory0000 = read_bound({'path': '/var/lib/jetstreamer/horizon-original199-parent-memory-selection-v1/bc600b6b088e11199516cd5094b1972988bd7870bb5a683f6f456a53a833bb1e/select-1/selection.json', 'sha256': '506040caf7aa427e64475b8f3203e7341cb635b305b068a51757595ce278f5a4'})\n_DATA0000 = read_bound({'path': '/var/lib/jetstreamer/horizon-ended183-DATA-selection-v1/bc600b6b088e11199516cd5094b1972988bd7870bb5a683f6f456a53a833bb1e/selection.json', 'sha256': '8ccacdd4a5e55d14f64f8019e1d3ae9244ce4312657631fbdfdf42fc98673b2c'})\n_selector0000 = read_bound(_current['accepted_selector'])\nassert _memory0000['selection']['request']['current'] == _selector0000 and _DATA0000['data_selection']['current'] == _selector0000")
assert source.count('complete_current_DATA_bytes=5160820486804') == 1
source = source.replace('complete_current_DATA_bytes=5160820486804', 'complete_current_DATA_bytes=' + str(complete_DATA))
source = source.replace("fixed_binding = p['owner_evidence']['fixed_work_eta_model']", "fixed_binding = review['owner_updates_by_epoch']['185']['fixed_work_eta_model']")
assert source.count('def fixed185_eta_parts(') == 1
assert source.count('parts, fixed_model = fixed185_eta_parts(fixed_binding, NOW)') == 1
ast.parse(source)
save(p, 'status_audit003022.py', source)
a = [literal(x) for x in json.loads((old / 'inventory000022-argv.json').read_text())]
save(p, 'inventory003022-argv.json', a)
z = subprocess.run(a, capture_output=True, text=True, timeout=330)
save(p, 'inventory003022-execution.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
seal(p, 'STATUS', '/usr/local/lib/jetstreamer/horizon-visible003022-status-continuation-20261109-v1', ['status_audit003022.py', 'audit_contract_r1.py', 'live145_metadata.py'])
a = [literal(x) for x in json.loads((old / 'status-audit000022-argv.json').read_text())]
save(p, 'status-audit003022-argv.json', a)
z = subprocess.run(a, capture_output=True, text=True, timeout=210)
save(p, 'status-audit003022-execution.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print(z.stdout)
print(z.stderr[-3000:])
assert z.returncode == 0
print('CurrentNov9 00:30:22 all11 original status readbacks complete; no observer timer changed', flush=True)
