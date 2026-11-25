"""Admit the single, private epoch 230 checkpoint continuation experiment."""

import ast
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

BASE = Path('/var/lib/jetstreamer')
STATE = BASE / 'horizon230-checkpoint-continuation-fit-v1'
CONTROL = BASE / 'horizon-seven-publication-controller-v222'
TOKENS = BASE / 'horizon230-checkpoint-continuation-fit-tokens-v1'
GUARDS = STATE / 'guard-receipts'
UNIT = 'horizon-qualify-230-checkpoint-continuation-fit-v1.service'
GUARD = 'horizon-230-checkpoint-continuation-fit-protective-v1.service'
TIMER = GUARD.replace('.service', '.timer')
CAPACITY = BASE / 'horizon226-suffix-v1/capacity-epoch230-fit-v1.py'
CAPACITY_SHA = 'a305b724c810c7953bfebde698d9914fc80299f23417ece68e367b74ce0c480a'
REPO = Path('/home/ubuntu/workspace/jetstreamer')
SOURCE = Path('scripts/horizon_foundation_delivery247_20261124')
ADAPTER = 'diagnostic230_checkpoint_continuation.py'
PATCH = 'epoch230-checkpoint-continuation-cadence.patch'
INPUT = 'horizon230-checkpoint-continuation-fit-inputs-v1/inputs.json'
INPUT_SHA = '1737aebe6a78b35cac20aa906145748dff4ec10381c4f296af53a613a82f7971'
TEMPLATE_SHA = 'a24b8d9925ca78492e773a155e5cd2f047ade4be311c2d6cba487e2918967107'
FLEET_SHA = 'e05883d679b942cf2c41f83577401a42c4d9021b678024cf4884857ade293013'
STATIC_GUARD = 'horizon230-checkpoint-continuation-fit-guard-static-v1/static-guard-check.json'
STATIC_GUARD_SHA = '5b5e3192a343f3cfe1aac131a43ee1c801a72e91bda057ffca1fedb9f2e314a1'


def git(*args):
    return subprocess.check_output(['runuser', '-u', 'ubuntu', '--', 'git', '-C', str(REPO), *args], timeout=20)


def helper():
    info = CAPACITY.lstat()
    assert CAPACITY.resolve() == CAPACITY and info.st_uid == 0 and info.st_nlink == 1
    assert not info.st_mode & 0o222 and hashlib.sha256(CAPACITY.read_bytes()).hexdigest() == CAPACITY_SHA
    spec = importlib.util.spec_from_file_location('accepted_capacity', CAPACITY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory(kit):
    image = kit.ops.checked_image(kit.ops.R2)
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
               '--unit=foundation-230-continuation-inventory-v1', '--property=Type=exec',
               '--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env',
               '--setenv=TOKIO_WORKER_THREADS=2', '--', image, 'inventory', '/home/ubuntu/horizon',
               '--epochs', '230-230', '--receipt-directory', str(kit.measure.PRIVATE / 'r2-receipts')]
    result = json.loads(subprocess.check_output(command, timeout=45))
    row, = result['entries']
    assert result['schema'] == 'jetstreamer-horizon-r2-inventory-v1' and result['anomalies'] == 0
    assert (row['epoch'], row['state']) == (230, 'missing')
    return row


def deploy_cadence(cap, kit, remote):
    targets = ('cycle.py', 'native_binding_replays.py')
    original = {name: (CONTROL / name).read_bytes() for name in targets}
    assert not (CONTROL / ADAPTER).exists()
    with tempfile.TemporaryDirectory(prefix='foundation230-cadence-') as temp:
        temp = Path(temp)
        for name, data in original.items():
            (temp / name).write_bytes(data)
        for name in (ADAPTER, PATCH):
            data = git('show', f'{remote}:{SOURCE / name}')
            (temp / name).write_bytes(data)
        subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p0', '-i', PATCH],
                       cwd=temp, check=True, stdout=subprocess.DEVNULL)
        updated = {name: (temp / name).read_bytes() for name in (*targets, ADAPTER)}
    for name, data in updated.items():
        ast.parse(data, filename=name)
    assert (b'diagnostic229_bank_delta, diagnostic226_suffix)' in updated['native_binding_replays.py']
            and b'diagnostic230_checkpoint_continuation.register(plan)' in updated['cycle.py'])
    backups = STATE / 'cadence-before'
    backups.mkdir(mode=0o700)
    for name, data in original.items():
        (backups / name).write_bytes(data)
        (backups / name).chmod(0o400)

    def put(path, data):
        with tempfile.NamedTemporaryFile(dir=CONTROL, delete=False) as staged:
            os.fchmod(staged.fileno(), 0o400)
            staged.write(data)
            staged.flush()
            os.fsync(staged.fileno())
        os.replace(staged.name, path)

    try:
        for name in (ADAPTER, *targets):
            put(CONTROL / name, updated[name])
        fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return kit.ops.funds.put(STATE / 'cadence-deployment.json', {
            'source_commit': remote, 'installed': {name: cap.binding(CONTROL / name) for name in updated},
            'previous': {name: cap.binding(backups / name) for name in original}, 'publication_authorized': False,
        })
    except Exception:
        for name, data in original.items():
            put(CONTROL / name, data)
        (CONTROL / ADAPTER).unlink(missing_ok=True)
        raise


def start(cap, kit, producer, guard, template, inputs, fit, remote_inventory, deployment):
    ops, runner, startup = kit.ops, kit.replay, kit.startup
    assert time.time() - fit['sampled_unix_seconds'] < 20
    assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == fit['tmpfs_shortfall_bytes'] == 0
    plan_ref = cap.fixed(STATE / 'producer-template.json', TEMPLATE_SHA)
    launch = ops.funds.put(STATE / 'admission.json', {
        'epoch': 230, 'inputs': inputs, 'producer': plan_ref, 'fit': fit, 'inventory': remote_inventory,
        'deployment': deployment, 'admitted': True, 'publication_authorized': False,
    })
    props, argv = startup.start_props(UNIT, producer)
    prestart, = [row for row in producer.read_text().splitlines() if row.startswith('ExecStartPre=')]
    assert '--setenv=JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1' in props
    assert argv[1] == '230' and '--qualification-end-slot=99383572' in argv
    startup.systemd_run(UNIT, [*props, '--property=' + prestart], argv, '--slice=system.slice')

    def held():
        row = ops.props(UNIT, ['InvocationID', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'NRestarts'])
        if (row['ActiveState'], row['SubState'], row['MainPID']) == ('activating', 'start-pre', '0'):
            assert int(row['ControlPID']) > 0 and row['NRestarts'] == '0'
            return row
        return None

    iid = startup.until(held, 12)['InvocationID']
    assert re.fullmatch('[0-9a-f]{32}', iid)
    plan = ops.funds.put(STATE / 'guard-plan.json', dict(template, invocation_id=iid))
    guard_props = ['--property=Type=oneshot', '--property=User=root', '--property=UMask=0077',
                   '--property=Restart=no', '--property=MemoryMax=1G', '--property=MemorySwapMax=0',
                   '--property=CPUQuota=100%', '--property=TasksMax=256', '--property=TimeoutStartSec=90',
                   '--property=ProtectSystem=strict', '--property=ProtectHome=read-only', '--property=PrivateNetwork=yes',
                   '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE',
                   '--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', f'--property=ReadWritePaths={GUARDS}']
    runner.PRODUCER, runner.GUARD_UNIT, runner.TIMER, runner.RECEIPTS = UNIT, GUARD, TIMER, GUARDS
    runner.GUARD_SHA = guard['sha256']
    startup.systemd_run(GUARD, guard_props, [guard['path'], plan['path'], '--plan-sha256', plan['sha256'],
                        '--self-sha256', guard['sha256']], '--on-active=1s', '--on-unit-inactive=60s',
                       '--timer-property=AccuracySec=1s', '--timer-property=RandomizedDelaySec=0')

    def guard_completed():
        reading = runner.first_guard(iid, plan)
        if reading is None:
            return None
        _, sample = reading
        result = ops.props(GUARD, ['ActiveState', 'InvocationID', 'Result', 'ExecMainStatus', 'MainPID'])
        if result['ActiveState'] != 'inactive':
            return None
        assert result['InvocationID'] == sample['guard_invocation_id'] and result['Result'] == 'success'
        assert result['ExecMainStatus'] == result['MainPID'] == '0'
        return reading, result

    (first, sample), completed = startup.until(guard_completed, 32)
    clock, next_tick = startup.until(runner.timer_ready, 10)
    assert held()['InvocationID'] == iid and sample['root_physical_observation_error'] is None
    token_dir = TOKENS / iid
    token_dir.mkdir(mode=0o755)
    token_dir.chmod(0o755)
    token = ops.funds.put(token_dir / 'guard-admission.json', {
        'epoch': 230, 'unit': UNIT, 'invocation_id': iid, 'first_guard': first, 'completed_guard': completed,
        'guard_plan': plan, 'guard_timer_invocation': clock['InvocationID'], 'next_guard_monotonic_usec': next_tick,
        'admission': launch, 'publication_authorized': False,
    })

    def running():
        row = ops.props(UNIT, ['InvocationID', 'MainPID', 'ActiveState', 'SubState', 'NRestarts', 'LoadState', 'Result'])
        if (row['ActiveState'], row['SubState']) != ('active', 'running'):
            return None
        pid = int(row['MainPID'])
        assert row['InvocationID'] == iid and row['NRestarts'] == '0' and pid > 0
        assert (Path('/proc') / str(pid) / 'exe').samefile(argv[0])
        for path in GUARDS.glob('sample-*.json'):
            reference = cap.binding(path)
            sample = cap.read(reference)
            assert sample['producer_invocation_id'] == iid and sample['plan_sha256'] == plan['sha256']
            assert sample['guard_sha256'] == guard['sha256'] and sample['trip_reason'] is None
            if sample['producer']['active'] == 'active':
                assert sample['producer']['pid'] == pid and sample['worker_observation_error'] is None
                assert sample['root_physical_observation_error'] is None
                return row, pid, reference
        return None

    row, pid, active_guard = startup.until(running, 105)
    assert startup.until(runner.timer_ready, 10)[0]['InvocationID'] == clock['InvocationID']
    unit = dict(unit=UNIT, invocation_id=iid, main_pid=pid, active_state=row['ActiveState'], sub_state=row['SubState'],
                load_state=row['LoadState'], result=row['Result'], restarts=0)
    work = cap.read(cap.read(inputs)['runtime'])['worker']
    return ops.funds.put(STATE / 'cadence-registration.json', {
        'schema': 'jetstreamer-historical-performance-launch-receipt-v1',
        'kind': 'epoch230-bounded-checkpoint-continuation', 'epoch': 230, 'unit': UNIT, 'invocation_id': iid,
        'main_pid': pid, 'node_path': argv[0], 'run_root': template['worker_root'], 'worker_sha256': work['sha256'],
        'bootstrap_slot': 99375855, 'first_slot': 99375856, 'last_slot': 99383572, 'launched': True,
        'entry_replay_requested': True, 'canonical_epoch_publication_authorized': False,
        'full_continuation_peak_qualified': False, 'remote_mutations': False, 'r2_mutations': False,
        'admission': launch, 'guard_plan': plan, 'launch_token': token, 'active_guard': active_guard,
        'evidence': {'units': [unit]},
    })


def main():
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    cap = helper()
    kit = cap.load_existing()
    assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    remote = git('rev-parse', 'origin/account-updates').decode().strip()
    assert Path(__file__).read_bytes() == git('show', f'{remote}:{SOURCE / Path(__file__).name}')
    with kit.partition.take(), (CONTROL / 'cycle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
            'ActiveState': 'inactive', 'Job': ''}
        for name in (UNIT, GUARD, TIMER):
            assert kit.ops.props(name, ['LoadState', 'ActiveState', 'Job']) == {
                'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}, name
        assert not list(TOKENS.iterdir()) and not list(GUARDS.iterdir()) and not (STATE / 'admission.json').exists()
        profile = cap.read(cap.fixed(STATE / 'producer-template.json', TEMPLATE_SHA))
        assert cap.read(profile['namespace'])['result']['namespace_verified']
        producer = cap.checked(profile['producer'])
        check = cap.read(cap.fixed(BASE / STATIC_GUARD, STATIC_GUARD_SHA))
        guard = check['guard']
        template = cap.read(check['plan'])
        assert cap.checked(guard) and check['result']['validated'] and template['unit'] == UNIT
        assert template['receipt_directory'] == str(GUARDS) and template['maximum_root_physical_bytes'] == 150_000_000_000
        inputs = cap.fixed(BASE / INPUT, INPUT_SHA)
        runtime = cap.read(cap.read(inputs)['runtime'])
        assert all(cap.checked(runtime[name]) for name in ('node', 'worker'))
        assert cap.checked(cap.read(cap.fixed(STATE / 'fleet-tool.json', FLEET_SHA))['artifact'])
        remote_inventory = inventory(kit)
        fit = cap.capacity(kit, candidate_epoch=230)
        assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == fit['tmpfs_shortfall_bytes'] == 0
        deployment = deploy_cadence(cap, kit, remote)
        try:
            print(json.dumps(start(cap, kit, producer, guard, template, inputs, fit, remote_inventory, deployment)))
        except Exception as error:
            observed = {name: kit.ops.props(name, ['LoadState', 'ActiveState', 'InvocationID', 'Result', 'MainPID'])
                        for name in (UNIT, GUARD, TIMER)}
            kit.ops.funds.put(STATE / 'launch-failure.json', {'error': str(error), 'observed': observed})
            for name in (UNIT, TIMER, GUARD):
                if observed[name]['LoadState'] != 'not-found':
                    current = kit.ops.props(name, ['InvocationID'])
                    assert current['InvocationID'] == observed[name]['InvocationID']
                    subprocess.run(['systemctl', 'stop', name], check=True, timeout=200)
            raise


if __name__ == '__main__':
    main()
