from pathlib import Path
import json, os, hashlib, subprocess, re
packet = Path(__file__).resolve().parent
v = json.loads((packet / 'SOURCE_ONLY_MANIFEST.json').read_text())
p = Path(v['root_QA_directory'])
sha = lambda raw: hashlib.sha256(raw).hexdigest()
# Root must book this delta before any guard build; this script does not create a booking.
booking_input = packet / 'ROOT_ACTUAL_GUARD0200_BOOKING_BINDING.json'
binding = json.loads(booking_input.read_text())
booking_path = Path(binding['path'])
assert sha(booking_path.read_bytes()) == binding['sha256']
booking = json.loads(booking_path.read_text())
assert booking['new_retained_DATA_bytes'] == 536870912
assert booking['previous_retained_DATA_lower_bound_bytes'] >= 5162967970452, 'Root must book after all actual Final4/Operation37 additions'
assert booking['complete_DATA_bytes'] == booking['previous_retained_DATA_lower_bound_bytes'] + 536870912
assert booking['normal_pool_bytes'] == 6 << 30 and booking['extra_QA5_closed_before_guard_build'] is True
p.mkdir(mode=448)
(p / 'source').mkdir(mode=448)
(p / 'work').mkdir(mode=448)
(p / 'work/tmp').mkdir(mode=448)
sha = lambda b: hashlib.sha256(b).hexdigest()

def b(f):
    f = Path(f)
    return dict(path=str(f), sha256=sha(f.read_bytes()))

def save(n, x):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(x, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
raw = (packet / 'source/main.rs').read_bytes()
assert sha(raw) == v['source_sha256']
fd = os.open(p / 'source/main.rs', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
with os.fdopen(fd, 'wb') as f:
    f.write(raw)
    f.flush()
    os.fsync(f.fileno())
save('ROOT_QA_EXACT_BOOKING.json', booking)

originals = []

def run(label, a):
    save(label + '-ORIGINAL-ARGV.json', a)
    z = subprocess.run(a, capture_output=True, text=True, timeout=330)
    save(label + '-ORIGINAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    print(label, z.returncode, z.stderr[-1500:] if z.returncode else '', flush=True)
    assert z.returncode == 0, z.stderr
    unit = next((x.split('=', 1)[1] for x in a if x.startswith('--unit='))) + '.service'
    n = dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', unit, '-pMainPID,ControlPID,ControlGroup,NRestarts,Result,ExecMainStatus'], text=True).splitlines()))
    assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == n['ExecMainStatus'] == '0' and n['Result'] == 'success' and (n['ControlGroup'] == '')
    lo = (p / (label + '-ORIGINAL-ARGV.json')).stat().st_mtime_ns // 1000
    hi = (p / (label + '-ORIGINAL-EXECUTION.json')).stat().st_mtime_ns // 1000 + 2000000
    rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', unit], text=True).splitlines()]
    rows = [x for x in rows if lo <= int(x.get('__REALTIME_TIMESTAMP', '0')) <= hi]
    done = [x for x in rows if x.get('_PID') == '1' and x.get('_UID') == '0' and (x.get('UNIT') == unit) and (x.get('MESSAGE_ID') == '7ad2d189f7e94e70a38c781354912448')]
    assert len(done) == 1
    originals.append(dict(execution=b(p / (label + '-ORIGINAL-EXECUTION.json')), original_native=n, original_PID1_success=done[0], original_outer_reaped=True, original_cgroup_empty=True))
    return z
for stage, name in v['recipes'].items():
    run(stage, json.loads((packet / 'recipes' / name).read_text())['argv'])
s = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(Path(s).read_bytes()) == h
os.umask(18)

def seal(label, plan):
    for row in plan['members']:
        row['sha256'] = sha(Path(row['source']).read_bytes())
    save(label + '-NORMAL-SEAL-PLAN.json', plan)
    f = p / (label + '-NORMAL-SEAL-PLAN.json')
    z = subprocess.run([s, str(f), '--plan-sha256', sha(f.read_bytes()), '--self-sha256', h], capture_output=True, text=True)
    save(label + '-NORMAL-SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    assert z.returncode == 0, z.stderr
seal('TEST', json.loads((packet / 'TEST_NORMAL_SEAL_PLAN.UNSTARTED.json').read_text()))
counts = {}
for name in ['census-all', 'census-ignored', 'all61']:
    a = json.loads((packet / 'recipes' / (name + '-ARGV.UNSTARTED.json')).read_text())['argv']
    z = run(name, a)
    if name != 'all61':
        counts[name] = [x[:-6] for x in z.stdout.splitlines() if x.endswith(': test')]
    else:
        assert len(counts['census-all']) == 65 and (not counts['census-ignored']) and ('test result: ok. 65 passed; 0 failed; 0 ignored;' in z.stdout)
proof = p / 'work/ARTIFACT_PROOF_BEFORE_SEAL.json'
save('work/ARTIFACT_PROOF_BEFORE_SEAL.json', dict(schema='horizon-current0600-qualified-guard-v1', source=b(p / 'source/main.rs'), production=b(p / 'work/horizon-current0600-guard-window'), actual_test_census=counts, ordinary_tests_passed=65, all_original_61_names_preserved=True, all_original_actors_drained=True, prod_clippy_passed=True, test_clippy_passed=True, all_required_tests_passed=True, originals=originals, sample_utc=v['sample_utc'], sample_unix=v['sample_unix'], native_guard_window_still_required=True, replay_launch_authorized=False, memory_credit_bytes=0, DATA_credit_bytes=0))
seal('PRODUCTION', json.loads((packet / 'PRODUCTION_NORMAL_SEAL_PLAN.UNSTARTED.json').read_text()))
print('Normally sealed current0600 guard-window', flush=True)
