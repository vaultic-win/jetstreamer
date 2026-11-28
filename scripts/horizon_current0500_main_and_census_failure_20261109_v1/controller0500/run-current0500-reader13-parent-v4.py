from actual0230_predecessors import actual0230_predecessors
actual0230_predecessors()
from successful0230_reader_dependency import require_qualified0230_reader_retirement
require_qualified0230_reader_retirement()
from next_operation_bindings import next_operation_bindings
operation_authority = next_operation_bindings()
from pathlib import Path
import json, os, time, datetime, hashlib, subprocess, re
from qualified_bindings import helper27, current_guard, closure27
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0500-20261109-v1'
c = q / 'combined-runtime'
old = Path('/home/sol/.jetstreamer-private/epoch185-offline-retained-input-contract-source-20261106-v1/r5/fresh0728-source/runtime')
sha = lambda b: hashlib.sha256(b).hexdigest()

def b(f):
    return dict(path=str(f), sha256=sha(Path(f).read_bytes()))

def save(n, v):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
accepted = json.loads((p / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json').read_text())
current = {k: accepted[k] for k in ['observer', 'fleet', 'fleet_plan', 'frame']}
save('accepted-frame-selector.json', current)
save('ROOT_ACTUAL0500_NATIVE_FRAME_READER_CONTRACT_ACCEPTED.json', dict(accepted, accepted_selector=b(p / 'accepted-frame-selector.json'), full_current_reader_memory_DATA_pending=True))
spec = json.loads((old / 'FAILED4_READER_ACTUAL0728_SPEC.json').read_text())
prior = json.loads((old / 'accepted-frame-selector.json').read_text())
counts = {k: 0 for k in current}

def replace(v):
    if isinstance(v, dict):
        for k in current:
            if v == prior[k]:
                counts[k] += 1
                return current[k]
        return {k: replace(x) for k, x in v.items()}
    if isinstance(v, list):
        return [replace(x) for x in v]
    return v
spec = replace(spec)
assert all((counts[k] > 0 for k in current))
spec['resource_accounting'] = json.loads((p / 'GENUINE0500_ACCOUNTING_ADAPTER_SOURCE_BUNDLE.json').read_text())['resource_accounting']
spec['output_directory'] = '/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/' + current['observer']['sha256']
assert not Path(spec['output_directory']).exists()
arpath = Path('/home/sol/.jetstreamer-private/native1428-reader-memory-DATA-continuation-source-20261107-v1/runtime/CURRENT1428_SAME_END_READER_BOOKING_ARITHMETIC.json')
ar = json.loads(arpath.read_text())
obs = json.loads(Path(current['observer']['path']).read_text())
ends = {}
for side in ['before', 'after']:
    x = obs['host_resident_memory'][side]
    assert x['status'] == 'observed' and x['rss']['census_stable']
    ends[side] = dict(other_with_kernel_bytes=x['rss']['aggregate_rss_bytes'] + sum(x['kernel_components_bytes'].values()))
delta = max(ar['positive_uncovered_delta_bytes'], max((x['other_with_kernel_bytes'] for x in ends.values())) - ar['uncovered_baseline_bytes'])
host = obs['host_memory']['total_kib'] * 1024
total = ar['raw_historical_memory_bytes'] + (6 << 30) + delta
assert total < host
helper27()
current_guard()
closure_binding = closure27()
closure = Path(closure_binding['path'])
save('ROOT_CURRENT0500_READONLY_POOL_CAPACITY.json', dict(observer=current['observer'], host_total_bytes=host, total_reserved_bytes=total, positive_uncovered_delta_bytes=delta, headroom_bytes=host - total, complete_retained_DATA_bytes=operation_authority['current_complete_DATA_lower_bound_bytes'], normal_external_pool_bytes=6 << 30, extra_QA6_closure=closure_binding, same_end_accounting=ends, no_new_resource_observation=True, no_new_credit_or_replay=True))
parameters = json.loads((p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS_TEMPLATE.json').read_text())
parameters['current_capacity_receipt'] = b(p / 'ROOT_CURRENT0500_READONLY_POOL_CAPACITY.json')
save('ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json', parameters)
ar.update(observer=current['observer'], current_same_end_capacity=b(p / 'ROOT_CURRENT0500_READONLY_POOL_CAPACITY.json'), prior_raw_historical_and_baseline=b(arpath), same_end_accounting=ends, positive_uncovered_delta_bytes=delta, total_reserved_bytes=total, host_total_bytes=host, headroom_bytes=host - total, recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
save('CURRENT0500_SAME_END_READER_BOOKING_ARITHMETIC.json', ar)
booking = json.loads((old / 'FAILED4_READER_ACTUAL0728_EXTERNAL_BOOKING.json').read_text())
at = int(time.time())
assert at - 1794200422 < 1650, 'Insufficient original Frame freshness for genuine reader; no launch'
booking.update(current=current, output_directory=spec['output_directory'], accepted_tuple=b(p / 'ROOT_ACTUAL0500_NATIVE_FRAME_READER_CONTRACT_ACCEPTED.json'), resource_arithmetic=b(p / 'CURRENT0500_SAME_END_READER_BOOKING_ARITHMETIC.json'), accounting_sources_serde_json_sha256=sha(json.dumps(spec['resource_accounting'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()), recorded_unix_seconds=at, expires_unix_seconds=at + 600)
save('FAILED4_READER_ACTUAL0500_EXTERNAL_BOOKING.json', booking)
spec['external_booking'] = b(p / 'FAILED4_READER_ACTUAL0500_EXTERNAL_BOOKING.json')
save('FAILED4_READER_ACTUAL0500_SPEC.json', spec)
s = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(Path(s).read_bytes()) == h
os.umask(18)
dest = Path('/usr/local/lib/jetstreamer/horizon-failed4-current-accounting-reader-plan-actual0500-20261109-v13')
save('READER-NORMAL-SEAL-PLAN.json', dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=str(dest), members=[dict(source=str(p / 'FAILED4_READER_ACTUAL0500_SPEC.json'), name='spec.json', sha256=b(p / 'FAILED4_READER_ACTUAL0500_SPEC.json')['sha256'], mode=292)]))
f = p / 'READER-NORMAL-SEAL-PLAN.json'
z = subprocess.run([s, str(f), '--plan-sha256', sha(Path(f).read_bytes()), '--self-sha256', h], capture_output=True, text=True)
save('READER-NORMAL-SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
unit = 'horizon-failed4-current-accounting-reader-20261104-v1.service'
n = dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', unit, '-pId,InvocationID,MainPID,ControlPID,ExecMainPID,ActiveState,SubState,Result,ExecMainStatus,NRestarts,Job,ControlGroup'], text=True).splitlines()))
assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0' and n['ControlGroup'] == n['Job'] == '' and (n['ActiveState'] == 'inactive') and (n['Result'] == 'success') and (n['ExecMainStatus'] == '0')
assert n['ExecMainPID'] == '0' or not Path('/proc/' + n['ExecMainPID']).exists()
rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', unit], text=True).splitlines()]
save('ORIGINAL_RETIRED1030_READER_ROLE_AND_DRAIN_BEFORE_DISTINCT0500.json', dict(native=n, original_journal=rows, original_process_absent=True, original_cgroup_empty=True, no_same_sample_retry=True, new_qualified_helper=b(Path('/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2'))))
from next_operation_bindings import next_operation_bindings
authority = next_operation_bindings()
retirement = authority['actual_successful0230_reader_retirement']
require_qualified0230_reader_retirement()
# Historical1800 remains in strict authority; it is not the current retirement.
save('ORIGINAL_READER_ROLE_CLOSED_BY_QUALIFIED38_NOT_RESET_AGAIN.json', dict(native=n, actual_successful0230_reader_retirement=retirement, all_originals_preserved=True, no_new_reset_or_signal=True))
image = Path('/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2')
assert b(image)['sha256'] == json.loads((c / 'HELPER13-PRODUCTION-ORIGINAL-QUALIFICATION.json').read_text())['production_artifact']['sha256']
a = json.loads((old / 'ROOT_READER0728_NATIVE_ARGV.json').read_text())
i = next((i for i, x in enumerate(a) if x.endswith('/jetstreamer-r2')))
a[i] = str(image)
a[a.index('read-failed4-current-accounting') + 1] = str(dest / 'spec.json')
a[a.index('--spec-sha256') + 1] = b(dest / 'spec.json')['sha256']
a[a.index('--self-sha256') + 1] = b(image)['sha256']
a[i:i] = ['-p', 'AppArmorProfile=horizon-witness-test-deny199-20261107-v1']
save('ROOT_READER0500_NATIVE_ARGV.json', a)
phase_root = Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-current0500-reader-phase-20261109-v15')
phase_root.mkdir(mode=448)
phase_request = dict(operation_root=str(phase_root), generation='positive-reader-0500-v15', reader_spec=b(dest / 'spec.json'), reader_argv=b(p / 'ROOT_READER0500_NATIVE_ARGV.json'))
save('ROOT_PHASE_GATED_READER_REQUEST.json', phase_request)
from prelaunch_phase199_binding import qualified_prelaunch_phase
phase_binding = qualified_prelaunch_phase()
phase_image = Path(phase_binding['program']['path'])
assert b(phase_image) == phase_binding['program']
assert time.time() < 1794201322, 'Original0500 startup cutoff expired; no launch'
phase_argv = ['/usr/bin/systemd-run', '--wait', '--pipe', '--service-type=exec', '--unit=horizon-current0500-reader-native-phase-20261109-v15']
for prop in ['User=root', 'Group=root', 'Restart=no', 'UMask=0077', 'MemoryMax=512M', 'MemorySwapMax=0', 'CPUQuota=100%', 'TasksMax=512', 'RuntimeMaxSec=710', 'TimeoutStopSec=15', 'NoNewPrivileges=yes', 'PrivateNetwork=yes', 'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_PTRACE', 'AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_PTRACE', 'LimitNOFILE=1048576:1048576', 'AppArmorProfile=horizon-witness-test-deny199-20261107-v1']:
    phase_argv += ['-p', prop]
phase_argv += [str(phase_image), 'read-current-original-between-guard-fires', str(p / 'ROOT_PHASE_GATED_READER_REQUEST.json'), '--request-sha256', b(p / 'ROOT_PHASE_GATED_READER_REQUEST.json')['sha256'], '--self-sha256', b(phase_image)['sha256']]
save('ROOT_PHASE_GATED_READER_ORIGINAL_ARGV.json', phase_argv)
z = subprocess.run(phase_argv, capture_output=True, text=True, timeout=725)
save('ROOT_PHASE_GATED_READER_ORIGINAL_OUTER.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('PHASE GATED READER', z.returncode, z.stdout, z.stderr[-3000:], flush=True)
assert z.returncode == 0, z.stderr
phase_result = json.loads(z.stdout)
original_binding = phase_result['original_reader_outer']
assert b(original_binding['path']) == original_binding
original = json.loads(Path(original_binding['path']).read_text())
assert original['exit_code'] == 0 and original['exit_signal'] is None and (original['stdout_read_error'] is None) and (original['stderr_read_error'] is None) and (not original['stdout_overflow']) and (not original['stderr_overflow'])
original_stdout = bytes(original['stdout_bytes']).decode()
original_stderr = bytes(original['stderr_bytes']).decode()
assert json.loads(original_stdout) == phase_result['actual_reader_result']
save('ROOT_FAILED4_READER0500_ORIGINAL_OUTER.json', dict(code=original['exit_code'], stdout=original_stdout, stderr=original_stderr, actual_owned_reader_child=original_binding, actual_phase_gated_outer=b(p / 'ROOT_PHASE_GATED_READER_ORIGINAL_OUTER.json'), actual_phase=phase_result['actual_native_start_phase'], original_stdout_and_stderr_preserved=True))
parent = p / 'parent/complete_parent_capture0500_witness_v1.py'
parent_env = dict(os.environ, HORIZON_CURRENT_NATIVE_CONTINUATION_BINDINGS_SHA256=sha((p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json').read_bytes()))
parent_argv = ['/usr/bin/python3', str(parent)]
save('ROOT_PARENT_CAPTURE0500_PREWRITTEN_ARGV.json', dict(argv=parent_argv, bindings=b(p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json'), metadata_source=b(parent), normal_pool_bytes=6 << 30, native_actor_bytes=2 << 30, no_replay_authority=True))
z = subprocess.run(parent_argv, capture_output=True, text=True, timeout=2200, env=parent_env)
save('ROOT_PARENT_CAPTURE0500_ORIGINAL_OUTER.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('PARENT', z.returncode, z.stdout[-6000:], z.stderr[-4000:], flush=True)
assert z.returncode == 0, z.stderr
data = p / 'parent/run_data_after0500_witness_memory_v1.py'
save('ROOT_DATA0500_PREWRITTEN_CONTINUATION_ARGV.json', dict(argv=['/usr/bin/python3', str(data)], bindings=b(p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json'), metadata_source=b(data)))
z = subprocess.run(['/usr/bin/python3', str(data)], capture_output=True, text=True, timeout=900, env=parent_env)
save('ROOT_DATA0500_CONTINUATION_ORIGINAL_OUTER.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('DATA', z.returncode, z.stdout[-6000:], z.stderr[-4000:], flush=True)
assert z.returncode == 0, z.stderr
