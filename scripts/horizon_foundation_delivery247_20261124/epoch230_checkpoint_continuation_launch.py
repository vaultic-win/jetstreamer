"""Admit the single, private epoch 230 checkpoint continuation experiment."""

import ast
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE = Path('/var/lib/jetstreamer')
PREVIOUS = BASE / 'horizon230-checkpoint-continuation-fit-v2'
STATE = BASE / 'horizon230-checkpoint-continuation-fit-v3'
CONTROL = BASE / 'horizon-seven-publication-controller-v222'
TOKENS = BASE / 'horizon230-checkpoint-continuation-fit-tokens-v3'
GUARDS = STATE / 'guard-receipts'
UNIT = 'horizon-qualify-230-checkpoint-continuation-fit-v3.service'
GUARD = 'horizon-230-checkpoint-continuation-fit-protective-v3.service'
TIMER = GUARD.replace('.service', '.timer')
CAPACITY = BASE / 'horizon226-suffix-v1/capacity-epoch230-fit-v3.py'
CAPACITY_SHA = 'ad829e77cb25c5e77ca65516541d7a7c57df375355beab371ea0a87b7295265f'
REPO = Path('/home/ubuntu/workspace/jetstreamer')
SOURCE = Path('scripts/horizon_foundation_delivery247_20261124')
ADAPTER = 'diagnostic230_checkpoint_continuation.py'
INPUT = 'horizon230-checkpoint-continuation-fit-inputs-v3/inputs.json'
INPUT_SHA = '8aa61a6982e597daf9c0c97a93f39c00d536740939a6e6aebf398d958c583739'
TEMPLATE_SHA = 'd85676f4d8ff5292aa2c927985cdae736fa3f6fa0282e26f1c8d0252233d603b'
STATIC_GUARD_SHA = 'f9265269f87cf0535a3bfba7b9730cdecf5da8b4341f77464c55c5e2270ad4c8'
PREVIOUS_DEPLOYMENT_SHA = 'd335e212a119ed40a398d5c6e361ef829ac318ac767c9a7816bcc09af7218aa0'
PREVIOUS_TERMINAL_SHA = '86f8c6dadfc0519b21baac0767a99675c74a2a3be5d2555127eb2df7a6b92cff'


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


def inventory(kit, epoch=230, unit="foundation-230-continuation-inventory-v3"):
    image = kit.ops.checked_image(kit.ops.R2)
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
               f'--unit={unit}', '--property=Type=exec',
               '--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env',
               '--setenv=TOKIO_WORKER_THREADS=2', '--', image, 'inventory', '/home/ubuntu/horizon',
               '--epochs', f'{epoch}-{epoch}', '--receipt-directory', str(kit.measure.PRIVATE / 'r2-receipts')]
    result = json.loads(subprocess.check_output(command, timeout=45))
    row, = result['entries']
    assert result['schema'] == 'jetstreamer-horizon-r2-inventory-v1' and result['anomalies'] == 0
    assert (row['epoch'], row['state']) == (epoch, 'missing')
    return row


def deploy_cadence(cap, kit, remote):
    previous = cap.fixed(PREVIOUS / 'cadence-deployment.json', PREVIOUS_DEPLOYMENT_SHA)
    last_deployment = cap.read(previous)
    active = cap.checked(last_deployment['installed'])
    assert active == CONTROL / ADAPTER
    initial = cap.read(last_deployment['previous'])['installed']
    for name in ('cycle.py', 'native_binding_replays.py'):
        assert cap.checked(initial[name]) == CONTROL / name
    original = active.read_bytes()
    updated = git('show', f'{remote}:{SOURCE / ADAPTER}')
    ast.parse(updated, filename=ADAPTER)

    def put(path, data):
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as staged:
            os.fchmod(staged.fileno(), 0o400)
            staged.write(data)
            staged.flush()
            os.fsync(staged.fileno())
        os.replace(staged.name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    backup = STATE / 'cadence-adapter-before.py'
    assert not backup.exists()
    put(backup, original)
    try:
        put(active, updated)
        return kit.ops.funds.put(STATE / 'cadence-deployment.json', {
            'source_commit': remote, 'installed': cap.binding(active), 'previous': previous,
            'previous_adapter_copy': cap.binding(backup), 'publication_authorized': False,
        })
    except Exception:
        put(active, original)
        raise


def guard_sample(ops, path):
    info = path.lstat()
    assert path.is_file() and path.resolve() == path and info.st_uid == 0 and info.st_nlink == 1
    assert not info.st_mode & 0o022, 'guard receipt is writable by another account'
    reference = ops.ref(path)
    return reference, ops.bound(reference)


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
    source = cap.read(inputs)
    bootstrap_path = Path(cap.read(source['bootstrap_receipt'])['snapshot']['path'])
    checkpoints = cap.checked(source['epoch_hashes'])
    assert f'--snapshot-archive={bootstrap_path}' in argv and f'--epoch-hashes={checkpoints}' in argv
    assert checkpoints.read_text().splitlines() == [bootstrap_path.name, Path(source['terminal_checkpoint']['name']).name]
    unit, plan, token, active_guard = activate_guarded(
        kit, 230, STATE, TOKENS, UNIT, GUARD, guard, template, launch, props, prestart, argv)
    iid, pid = unit['invocation_id'], unit['main_pid']
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


def activate_guarded(kit, epoch, state, tokens, producer_unit, guard_unit, guard, template, launch,
                     props, prestart, argv):
    ops, runner, startup = kit.ops, kit.replay, kit.startup
    receipts = state / 'guard-receipts'
    timer_unit = guard_unit.replace('.service', '.timer')
    startup.systemd_run(producer_unit, [*props, '--property=' + prestart], argv, '--slice=system.slice')

    def held():
        row = ops.props(producer_unit, ['InvocationID', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'NRestarts'])
        if (row['ActiveState'], row['SubState'], row['MainPID']) == ('activating', 'start-pre', '0'):
            assert int(row['ControlPID']) > 0 and row['NRestarts'] == '0'
            return row
        return None

    iid = startup.until(held, 12)['InvocationID']
    assert re.fullmatch('[0-9a-f]{32}', iid)
    plan = ops.funds.put(state / 'guard-plan.json', dict(template, invocation_id=iid))
    guard_props = ['--property=Type=oneshot', '--property=User=root', '--property=UMask=0077',
                   '--property=Restart=no', '--property=MemoryMax=1G', '--property=MemorySwapMax=0',
                   '--property=CPUQuota=100%', '--property=TasksMax=256', '--property=TimeoutStartSec=90',
                   '--property=ProtectSystem=strict', '--property=ProtectHome=read-only', '--property=PrivateNetwork=yes',
                   '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE',
                   '--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', f'--property=ReadWritePaths={receipts}']
    runner.PRODUCER, runner.GUARD_UNIT, runner.TIMER, runner.RECEIPTS = producer_unit, guard_unit, timer_unit, receipts
    runner.GUARD_SHA = guard['sha256']
    startup.systemd_run(guard_unit, guard_props, [guard['path'], plan['path'], '--plan-sha256', plan['sha256'],
                        '--self-sha256', guard['sha256']], '--on-active=1s', '--on-unit-inactive=60s',
                       '--timer-property=AccuracySec=1s', '--timer-property=RandomizedDelaySec=0')

    def guard_completed():
        reading = runner.first_guard(iid, plan)
        if reading is None:
            return None
        _, sample = reading
        result = ops.props(guard_unit, ['ActiveState', 'InvocationID', 'Result', 'ExecMainStatus', 'MainPID'])
        if result['ActiveState'] != 'inactive':
            return None
        assert result['InvocationID'] == sample['guard_invocation_id'] and result['Result'] == 'success'
        assert result['ExecMainStatus'] == result['MainPID'] == '0'
        return reading, result

    (first, sample), completed = startup.until(guard_completed, 32)
    clock, next_tick = startup.until(runner.timer_ready, 10)
    assert held()['InvocationID'] == iid and sample['root_physical_observation_error'] is None
    token_dir = tokens / iid
    token_dir.mkdir(mode=0o755)
    token_dir.chmod(0o755)
    token = ops.funds.put(token_dir / 'guard-admission.json', {
        'epoch': epoch, 'unit': producer_unit, 'invocation_id': iid, 'first_guard': first, 'completed_guard': completed,
        'guard_plan': plan, 'guard_timer_invocation': clock['InvocationID'], 'next_guard_monotonic_usec': next_tick,
        'admission': launch, 'publication_authorized': False,
    })

    def running():
        row = ops.props(producer_unit, ['InvocationID', 'MainPID', 'ActiveState', 'SubState', 'NRestarts', 'LoadState', 'Result'])
        if (row['ActiveState'], row['SubState']) != ('active', 'running'):
            return None
        pid = int(row['MainPID'])
        assert row['InvocationID'] == iid and row['NRestarts'] == '0' and pid > 0
        assert (Path('/proc') / str(pid) / 'exe').samefile(argv[0])
        for path in receipts.glob('sample-*.json'):
            reference, sample = guard_sample(ops, path)
            assert sample['producer_invocation_id'] == iid and sample['plan_sha256'] == plan['sha256']
            assert sample['guard_sha256'] == guard['sha256'] and sample['trip_reason'] is None
            assert sample['producer_stop_enabled'] is True
            if sample['producer']['active'] == 'active':
                assert sample['producer']['pid'] == pid and sample['worker_observation_error'] is None
                assert sample['root_physical_observation_error'] is None
                return row, pid, reference
        return None

    row, pid, active_guard = startup.until(running, 105)
    assert startup.until(runner.timer_ready, 10)[0]['InvocationID'] == clock['InvocationID']
    unit = dict(unit=producer_unit, invocation_id=iid, main_pid=pid, active_state=row['ActiveState'], sub_state=row['SubState'],
                load_state=row['LoadState'], result=row['Result'], restarts=0)
    return unit, plan, token, active_guard


def start_vote_boundary(kit, roster_ref, remote):
    """Admit the sealed vote-boundary repair through the existing guarded startup."""
    assert __debug__ and os.geteuid() == 0 and os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    ops = kit.ops
    state = BASE / 'horizon230-vote-boundary-runtime-v1'
    tokens = BASE / 'horizon230-vote-boundary-tokens-v1'
    source = ops.ref(state / 'profile.json')
    assert source['sha256'] == 'd7df4effe7e674aa0dcdcf2978c0aed4b30630878d79192ba20e3ac07aff28f8'
    profile = ops.bound(source)
    root = Path(profile['run_root'])
    producer, guard = profile['unit'], profile['guard_unit']
    template_ref = profile['static_guard_plan']
    template = ops.bound(template_ref)
    namespace = ops.ref(state / 'namespace-validation.json')
    assert namespace['sha256'] == 'a81ea8fcca0b8df1fc6b9ef5798a36543c2d269b943e23ee684fb4e580c46adc'
    assert ops.bound(namespace)['profile'] == source
    node = ops.checked_image(profile['node'])
    worker = ops.checked_image(profile['worker'])
    ops.checked_image(profile['guard'])
    hook = BASE / 'horizon230-final-tail-tokens-v1/pre-start.sh'
    ops.checked_image({'path': str(hook), 'sha256': '14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0'})
    assert profile['argv'][0] == node and profile['argv'][1] == '230'
    assert ops.ref(Path(profile['epoch_hashes']['path'])) == profile['epoch_hashes']
    bootstrap = profile['bootstrap']
    live_bootstrap = Path(bootstrap['path']).lstat()
    assert (live_bootstrap.st_dev, live_bootstrap.st_ino, live_bootstrap.st_size) == tuple(
        bootstrap[field] for field in ('device', 'inode', 'size'))
    assert remote['epoch'] == 230 and remote['state'] == 'missing'
    roster = ops.bound(roster_ref)
    fit = roster['capacity']
    candidate = profile['memory_max_bytes'] + (1 << 30) + (256 << 20)
    cpus = set(range(72, 80))
    assert profile['allowed_cpus'] == '72-79'

    def expand(value):
        ranges = [token.split('-') for token in value.replace(',', ' ').split()]
        return {cpu for r in ranges for cpu in range(int(r[0]), int(r[-1]) + 1)}

    with kit.partition.take(), (CONTROL / 'cycle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {'ActiveState': 'inactive', 'Job': ''}
        assert 0 <= time.time() - roster['recorded_unix_seconds'] <= 60
        assert not roster['admission_issued'] and cpus <= expand(Path('/sys/devices/system/cpu/online').read_text())
        listed = subprocess.check_output(['systemctl', 'list-units', '--type=service', '--state=running,activating',
                                          '--plain', '--no-legend', '--no-pager'], text=True, timeout=10)
        periodic = {g['unit'] for g in roster['periodic_guards'].values()}
        owners = {line.split()[0] for line in listed.splitlines()
                  if line.startswith(('horizon-', 'foundation-', 'archive-', 'jetstreamer-'))}
        assert owners - periodic == set(roster['owners'])
        for unit in (producer, guard, guard.replace('.service', '.timer')):
            assert ops.props(unit, ['LoadState', 'ActiveState', 'Job']) == {'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}
        fields = ['Id', 'ActiveState', 'SubState', 'InvocationID', 'MainPID', 'AllowedCPUs', 'MemoryMax']
        for unit, item in roster['owners'].items():
            current = ops.props(unit, fields)
            assert all(current[key] == item['systemd'][key] for key in fields)
            assert cpus.isdisjoint(expand(current['AllowedCPUs']))
        for directory in (root / 'scratch', root / 'state', state / 'guard-receipts'):
            assert not any(directory.iterdir())
        assert root.parent.is_mount() and not tokens.exists()
        fs = os.statvfs(root.parent.parent)
        free = min(fit['available_disk_bytes'], fs.f_bavail * fs.f_frsize)
        hard = fit['required_hard_memory_bytes'] - fit['candidate_total_memory_bytes'] + candidate
        remaining = fit['required_remaining_memory_bytes'] - fit['candidate_total_memory_bytes'] + candidate
        assert hard <= fit['host_total_memory_bytes'] and remaining <= fit['available_memory_bytes']
        assert free >= fit['protected_existing_disk_bytes'] + profile['root_receipt_reservation_bytes']

        tokens.mkdir(mode=0o755)
        tokens.chmod(0o755)
        properties = {
            'Type': 'exec', 'User': 'ubuntu', 'Group': 'ubuntu', 'UMask': '0077', 'Restart': 'no',
            'KillMode': 'control-group', 'Delegate': 'no', 'OOMPolicy': 'kill',
            'MemoryHigh': profile['memory_high_bytes'], 'MemoryMax': profile['memory_max_bytes'], 'MemorySwapMax': '0',
            'AllowedCPUs': profile['allowed_cpus'], 'CPUAffinity': profile['allowed_cpus'], 'CPUQuota': '800%', 'TasksMax': '512',
            'RuntimeMaxSec': profile['runtime_max_seconds'], 'TimeoutStopSec': '180', 'TimeoutStartSec': '180',
            'ProtectSystem': 'strict', 'ProtectHome': 'read-only', 'ProtectControlGroups': 'yes',
            'PrivateTmp': 'yes', 'NoNewPrivileges': 'yes', 'RestrictAddressFamilies': 'AF_UNIX AF_INET AF_INET6',
            'ReadWritePaths': str(root), 'WorkingDirectory': str(root),
            'ReadOnlyPaths': ' '.join([str(tokens), node, worker, profile['bootstrap']['path'], profile['epoch_hashes']['path']]),
            'BindReadOnlyPaths': ' '.join(f'{b["source"]}:{b["destination"]}' for b in profile['binds']),
            'UnsetEnvironment': 'HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_PUBLIC_BASE_URL',
        }
        environment = {
            'JETSTREAMER_ALLOW_CANDIDATE_RUNTIME': '1', 'JETSTREAMER_CLEAR_ACCOUNTS_ON_START': '1',
            'JETSTREAMER_ENFORCE_ARCHIVE_HASH': '1', 'JETSTREAMER_PRIVATE_RUN_ROOT': str(root / 'state'),
            'JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS': '0', 'JETSTREAMER_SKIP_SNAPSHOT_VERIFY': '0',
            'JETSTREAMER_VERIFY_SNAPSHOTS': '1', 'JETSTREAMER_NETWORK': 'mainnet',
            'JETSTREAMER_FORCE_LEGACY_INDEX': '1', 'RUST_LOG': 'info', 'JETSTREAMER_RIPGET_THREADS': '1',
            'SOLANA_RAYON_THREADS': '8', 'RAYON_NUM_THREADS': '8', 'JETSTREAMER_HISTORICAL_POH_THREADS': '8',
            'TOKIO_WORKER_THREADS': '8', 'JETSTREAMER_REPLAY_THREADS': '8', 'RUST_MIN_STACK': '134217728',
            'TMPDIR': str(root / 'tmp'), 'CLOUDSDK_CONFIG': str(root / 'tmp/isolated-empty-gcloud'),
            'CLOUDSDK_CORE_DISABLE_PROMPTS': '1', 'CLOUDSDK_CORE_DISABLE_FILE_LOGGING': '1',
            profile['worker_environment']: worker, 'JETSTREAMER_HISTORICAL_TRACE': '1',
        }
        props = [f'--property={key}={value}' for key, value in properties.items()]
        props += [f'--setenv={key}={value}' for key, value in environment.items()]
        admission = ops.funds.put(state / 'admission.json', {
            'schema': 'foundation-epoch230-vote-boundary-admission-v1', 'epoch': 230, 'profile': source,
            'namespace': namespace, 'roster': roster_ref, 'static_guard_plan': template_ref, 'inventory': remote,
            'argv': profile['argv'], 'properties': properties, 'environment': environment,
            'fit': {'available_bytes': free, 'required_hard_memory_bytes': hard, 'required_remaining_memory_bytes': remaining,
                    'candidate_memory_bytes': candidate, 'cpus': sorted(cpus)},
            'admitted': True, 'publication_authorized': False,
        })
        identity, plan, token, active_guard = activate_guarded(
            kit, 230, state, tokens, producer, guard, profile['guard'], template, admission,
            props, f'ExecStartPre=/usr/bin/bash {hook} 60 {tokens}', profile['argv'])
        return ops.funds.put(state / 'cadence-registration.json', {
            'schema': 'jetstreamer-historical-performance-launch-receipt-v1',
            'kind': 'epoch230-vote-boundary-demotion', 'epoch': 230, 'unit': producer,
            'invocation_id': identity['invocation_id'], 'main_pid': identity['main_pid'],
            'node_path': node, 'run_root': str(root), 'worker_sha256': profile['worker']['sha256'],
            'bootstrap_slot': 99_430_284, 'first_slot': profile['first_slot'], 'target_slot': profile['target_slot'],
            'last_slot': profile['last_slot'], 'launched': True, 'entry_replay_requested': True,
            'canonical_epoch_publication_authorized': False, 'full_continuation_peak_qualified': False,
            'remote_mutations': False, 'r2_mutations': False, 'admission': admission, 'guard_plan': plan,
            'launch_token': token, 'active_guard': active_guard, 'evidence': {'units': [identity]},
        })


def main():
    assert os.geteuid() == 0 and __debug__
    assert len(sys.argv) == 2 and re.fullmatch('[0-9a-f]{64}', sys.argv[1]), 'provide the sealed fleet-tool receipt hash'
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
        assert profile['previous_terminal'] == cap.fixed(PREVIOUS / 'terminal.json', PREVIOUS_TERMINAL_SHA)
        namespace = cap.read(profile['namespace'])['result']
        assert namespace['namespace_verified'] and namespace['checkpoint_entries'] == 2
        producer = cap.checked(profile['producer'])
        check = cap.read(cap.fixed(STATE / 'static-guard-check.json', STATIC_GUARD_SHA))
        guard = check['guard']
        template = cap.read(check['plan'])
        assert cap.checked(guard) and check['result']['validated'] and template['unit'] == UNIT
        assert template['receipt_directory'] == str(GUARDS) and template['maximum_root_physical_bytes'] == 150_000_000_000
        inputs = cap.fixed(BASE / INPUT, INPUT_SHA)
        assert profile['inputs'] == inputs
        runtime = cap.read(cap.read(inputs)['runtime'])
        assert all(cap.checked(runtime[name]) for name in ('node', 'worker'))
        assert cap.checked(cap.read(cap.fixed(STATE / 'fleet-tool.json', sys.argv[1]))['artifact'])
        remote_inventory = inventory(kit)
        fit = cap.capacity(kit, candidate_epoch=230)
        assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == fit['tmpfs_shortfall_bytes'] == 0
        deployment = deploy_cadence(cap, kit, remote)
        try:
            print(json.dumps(start(cap, kit, producer, guard, template, inputs, fit, remote_inventory, deployment)))
        except Exception as error:
            observed = {name: kit.ops.props(name, ['LoadState', 'ActiveState', 'InvocationID', 'Result', 'MainPID'])
                        for name in (UNIT, GUARD, TIMER)}
            kit.ops.funds.put(STATE / 'launch-failure.json', {'error': repr(error), 'observed': observed})
            for name in (UNIT, TIMER, GUARD):
                current = kit.ops.props(name, ['InvocationID', 'LoadState', 'ActiveState'])
                if current['LoadState'] == 'not-found' and current['ActiveState'] == 'inactive':
                    continue
                assert current['InvocationID'] == observed[name]['InvocationID'], name
                subprocess.run(['systemctl', 'stop', name], check=True, timeout=200)
            raise


if __name__ == '__main__':
    main()
