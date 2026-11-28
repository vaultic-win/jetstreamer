from pathlib import Path
import os, json, hashlib, subprocess, re
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0030-20261109-v1'
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

def native(u):
    return dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', u, '-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,ControlGroup,NRestarts,Result,ExecMainStatus,ExecMainPID'], text=True).splitlines()))
dest = '/usr/local/lib/jetstreamer/horizon-first-lane-current0030-chain128-frame-plan-20261109-v5'
f = Path(dest) / 'plan.json'
v = json.loads(f.read_text())
fleetplan = json.loads(Path(v['fleet_plan']['path']).read_text())
fleet = Path(v['fleet']['path'])
fp = Path(v['fleet_plan']['path'])
o = Path(v['observer']['path'])
cli = '/usr/local/lib/jetstreamer/horizon-first-lane-chain128-witness-frame-cli-tools-20261107-v5/jetstreamer-horizon-frame'
ch = '70b82a16f8c5d71257305a0873440deccf8746f78b09fc33ee23f5c691e29fe4'
assert b(Path(cli))['sha256'] == ch
cmd = [cli, str(f), '--plan-sha256', b(f)['sha256'], '--self-sha256', ch]
assert not Path(v['output']).exists(), 'Fresh0030 output must be absent; no Frame overwrite allowed'
original_plan = b(f)
manifest = Path('/tmp/continuations1330-v1/ROOT_ACTUAL_QUALIFIED_OPERATION26_BINDINGS.json')
assert b(manifest)['sha256'] == 'a06acb734661773ce1c9a7b937364d19bd8318cddac13eccdbfa5426f617abad'
authority = json.loads(manifest.read_text())
for key in ['qualification', 'normal_seal', 'frame_phase_argv_template']:
    assert b(Path(authority[key]['path'])) == authority[key]
qualification = json.loads(Path(authority['qualification']['path']).read_text())
assert qualification['all_required_tests_passed'] is True and qualification['actual_native_reader_phase_control_passed'] is True
assert qualification['production_artifact']['sha256'] == authority['operation']['sha256']
seal = json.loads(Path(authority['normal_seal']['path']).read_text())
assert seal['destination'] == str(Path(authority['operation']['path']).parent)
assert any((x['name'] == 'operation' and x['sha256'] == authority['operation']['sha256'] and (x['mode'] == '0555') for x in seal['members']))
phase_image = authority['operation']['path']
assert b(Path(phase_image)) == authority['operation']
phase_template = authority['frame_phase_argv_template']
assert b(Path(phase_template['path'])) == phase_template
phase_base = json.loads(Path(phase_template['path']).read_text())

def phase(label):
    root = Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-current0030-frame-' + label + '-r3-20261109-v24')
    root.mkdir(mode=448)
    request = dict(operation_root=str(root), generation='positive-frame-' + label + '-0030-r3-v24', metadata_control_only=True)
    name = 'FRAME5-R3-' + label + '-PHASE-REQUEST.json'
    save(name, request)
    a = list(phase_base)
    idx = a.index('qualify-current-reader-start-phase')
    a[idx - 1] = phase_image
    a[idx + 1] = str(p / name)
    a[a.index('--request-sha256') + 1] = b(p / name)['sha256']
    a[a.index('--self-sha256') + 1] = b(Path(phase_image))['sha256']
    a = ['--unit=horizon-current0030-frame-' + label + '-phase-r3-20261109-v24' if x.startswith('--unit=') else x for x in a]
    save('FRAME5-R3-' + label + '-PHASE-ARGV.json', a)
    z = subprocess.run(a, capture_output=True, text=True, timeout=255)
    save('FRAME5-R3-' + label + '-PHASE-EXECUTION.json', dict(argv=a, code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    assert z.returncode == 0, z.stderr
    assert b(f) == original_plan
    print('Qualified original guard phase authenticated for0030', label, flush=True)
for label, argv in [('capability', [cli, '--capability-probe'] + cmd[1:]), ('capture', cmd)]:
    phase(label)
    unit = 'horizon-first-lane-current0030-chain128-witness-frame-' + label + '-r3-20261109-v5.service'
    a = ['systemd-run', '--service-type=oneshot', '--unit=' + unit]
    for prop in ['User=root', 'Group=root', 'RemainAfterExit=yes', 'Restart=no', 'MemoryAccounting=yes', 'MemoryHigh=1536M', 'MemoryMax=2G', 'MemorySwapMax=0', 'CPUQuota=100%', 'TasksMax=512', 'TimeoutStartSec=240', 'TimeoutStopSec=15', 'NoNewPrivileges=yes', 'PrivateNetwork=yes', 'ProtectSystem=strict', 'ProtectHome=read-only', 'ReadWritePaths=/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1 ' + str(p), 'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', 'AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', 'AppArmorProfile=horizon-witness-test-deny199-20261107-v1', 'StandardOutput=file:' + str(p / ('frame5-r3-' + label + '.stdout')), 'StandardError=file:' + str(p / ('frame5-r3-' + label + '.stderr'))]:
        a += ['-p', prop]
    a += argv
    save('FRAME5-R3-' + label + '-ORIGINAL-ARGV.json', a)
    z = subprocess.run(a, capture_output=True, text=True, timeout=270)
    save('FRAME5-R3-' + label + '-ORIGINAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    print(label, z.returncode, z.stderr[-1000:], (p / ('frame5-r3-' + label + '.stderr')).read_text()[-5000:], flush=True)
    assert z.returncode == 0
    n = native(unit)
    assert n['Result'] == 'success' and n['ExecMainStatus'] == n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0' and (n['SubState'] == 'exited')
    rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', unit], text=True).splitlines()]
    assert any((x.get('_PID') == '1' and x.get('_UID') == '0' and (x.get('INVOCATION_ID') == n['InvocationID']) and (x.get('JOB_RESULT') == 'done') for x in rows))
    save('FRAME5-R3-' + label + '-ORIGINAL-NATIVE-PID1.json', dict(native=n, original_journal=rows, outer_reaped=True, cgroup_empty=n['ControlGroup'] == ''))
actual = Path(v['output'])
av = json.loads(actual.read_text())
assert av['self_sha256'] == ch and av['epoch199_terminal_context'] == fleetplan['epoch199_terminal_context']
assert len(av['live145_prefix_guard_history']) == 2 and all((x['lifecycle'] == 'terminal-retained-failed74' for x in av['live145_prefix_guard_history']))
save('ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_PENDING_FINAL_DRAINS.json', dict(frame=b(actual), plan=b(f), fleet=b(fleet), fleet_plan=b(fp), observer=b(o), actual_completed_writer=n, CLI_program=dict(path=cli, sha256=ch), original_final_drains_pending=True, complete_reader_pending=True, replay_launch_authorized=False, memory_credit_bytes=0, DATA_credit_bytes=0))
print('GENUINE FRAME CAPTURE', b(actual), flush=True)
