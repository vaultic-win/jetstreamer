"""Prepare the private, bounded epoch 288 shrink-debt comparison."""

import argparse
import ast
from datetime import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import time


V = Path('/var/lib/jetstreamer')
CONTROL = V / 'horizon-seven-publication-controller-v222'
SOURCE = Path('/home/ubuntu/workspace/jetstreamer')
SOURCE_DIRECTORY = Path('scripts/horizon_foundation_delivery247_20261124')
ORIGINAL = V / 'horizon288-full-v303'
ORIGINAL_ROOT = Path('/home/ubuntu/.jetstreamer-private/qualification-288-root-v303')
PREPARATION = V / 'horizon288-worker-shrink-debt-v327'
PACKAGE = V / 'horizon288-shrink-debt-comparison-v327'
RECEIPTS = PACKAGE / 'guard-receipts'
TOKENS = V / 'horizon288-shrink-debt-comparison-tokens-v327'
RUN = Path('/home/ubuntu/.jetstreamer-private/qualification-288-shrink-debt-compare-v327')
UNIT = 'horizon-perf-epoch288-shrink-debt@v327.service'
GUARD_UNIT = 'horizon-288-shrink-debt-protective-v327.service'
CAP = 501_073_741_824
FLOOR = 3_770_104_987_645
MEMORY = 225_000_000_000
CPUS = frozenset(range(64, 72))
ADAPTER = 'diagnostic288_shrink_debt'
PLAN_SHA = 'b345c5da0e420df8455793e5c1373fcd20dc385aabd85901a1818566ff7db30d'
TERMINAL229 = V / 'horizon229-trace-ram-v325/terminal.json'
TIMER_CORRECTION229 = TERMINAL229.with_name('terminal-timer-correction.json')
RETIREMENT288 = V / 'horizon288-unpacked-retirement-v328/batch-039-completion.json'
BANK_DELTA229_UNIT = 'horizon-perf-epoch229-bank-delta@v334.service'
BANK_DELTA229_GUARDS = V / 'horizon229-bank-delta-v334/guard-receipts'
EXTRACT226_UNIT = 'horizon-qualify-226-checkpoint-continuation-extract-v2.service'
EXTRACT226_BROKER = 'foundation-226-original225-broker-v2.service'
EXTRACT226_STATE = V / 'horizon226-extract-v2'
SUFFIX226_UNIT = 'horizon-qualify-226-checkpoint-continuation-suffix-v1.service'
SUFFIX226_STATE = V / 'horizon226-suffix-v1'
CONTINUATION230_UNIT = 'horizon-qualify-230-checkpoint-continuation-fit-v2.service'
CONTINUATION230_STATE = V / 'horizon230-checkpoint-continuation-fit-v2'
CONTINUATION230_TMPFS = Path('/home/ubuntu/.jetstreamer-private/epoch230-continuation-tmpfs-v1')
CONTINUATION230_RAM_CAP = 150_000_000_000
CONTINUATION230_TMPFS_FLOOR = 2 << 30
GUARDS = {
    226: V / 'horizon226-extract-v2/guard-receipts',
    229: V / 'horizon229-trace-ram-v325/guard-receipts',
    230: V / 'horizon230-program-demotion-ram-v328/guard-receipts',
    252: V / 'horizon252-regional-full-guard-receipts-v1',
    257: V / 'horizon257-full-guard-receipts-v1',
    261: V / 'horizon261-full-guard-receipts-v1',
    292: V / 'horizon292-full-guard-receipts-v322',
}


def binding(path):
    with path.open('rb') as stream:
        return dict(path=str(path), sha256=hashlib.file_digest(stream, 'sha256').hexdigest())


def checked(reference):
    path = Path(reference['path'])
    info = path.stat()
    assert path.resolve() == path and stat.S_ISREG(info.st_mode)
    assert info.st_uid == 0 and not info.st_mode & 0o222
    assert binding(path)['sha256'] == reference['sha256'], path
    if 'device' in reference:
        assert (info.st_dev, info.st_ino, info.st_size) == (
            reference['device'], reference['inode'], reference.get('size', reference.get('bytes'))), path
    return path


def read(reference):
    return json.loads(checked(reference).read_bytes())


def fixed(path, sha):
    return dict(path=str(path), sha256=sha)


def plan_inputs():
    proposed = fixed(PREPARATION / 'guarded-comparison-plan.json', PLAN_SHA)
    plan = read(proposed)
    assert plan['schema'] == 'foundation-epoch288-guarded-storage-comparison-plan-v327'
    assert (plan['epoch'], plan['bootstrap_slot'], plan['threshold_slot'], plan['verification_slot']) == (
        288, 124415782, 124429562, 124435861)
    assert plan['argv'] == [plan['node']['path'], '288', str(RUN / 'output'), '--verify',
                            f"--snapshot-archive={plan['bootstrap']['path']}", f'--epoch-hashes={RUN}/epoch-hashes.txt',
                            '--qualification-end-slot=124435861',
                            f'--horizon-output={RUN}/output/epoch-288-shrink-debt-control.jet']
    assert plan['maximum_comparison_cap_bytes'] == plan['previous_peak_limit_bytes'] == CAP
    assert plan['original_root_physical_bytes'] > CAP
    assert plan['requires_fresh_capacity'] and not plan['publication_authorized']
    candidate = read(plan['candidate'])
    assert candidate['sealed_worker'] == plan['worker'] and candidate['epoch'] == 288
    assert not candidate['production_replay_started'] and not candidate['live_storage_comparison_passed']
    source = read(fixed(ORIGINAL / 'namespace-inputs.json',
                        'fdf7516c0661bf46be894b9ff3b2e8e5c9816ded47a4fcbc343c517573630feb'))
    assert (source['node'], source['snapshot']) == (plan['node'], plan['bootstrap'])
    checked(plan['worker'])
    checked(plan['node'])
    checked(source['map'])
    bootstrap = plan['bootstrap']
    path = Path(bootstrap['path'])
    stamp = path.stat()
    # Preserve the already qualified bootstrap's exact read-only inode. The
    # replay also compares the initialized account hash with the pinned root.
    assert path.resolve() == path and stat.S_ISREG(stamp.st_mode)
    assert (stamp.st_dev, stamp.st_ino, stamp.st_size, stamp.st_uid, stat.S_IMODE(stamp.st_mode)) == (
        bootstrap['device'], bootstrap['inode'], bootstrap['bytes'], bootstrap['uid'], bootstrap['mode'])
    mounts = plan['same_source_mounts']
    expected = {p.replace(str(ORIGINAL_ROOT), str(RUN)): row for p, row in source['bindings'].items()}
    expected[str(RUN / 'epoch-hashes.txt')] = mounts[str(RUN / 'epoch-hashes.txt')]
    assert mounts == expected
    for row in mounts.values():
        checked(row)
    names = checked(mounts[str(RUN / 'epoch-hashes.txt')]).read_text().splitlines()
    checkpoint_ref = plan['checkpoint_receipt']
    checkpoint_path = Path(checkpoint_ref['path'])
    stamp = checkpoint_path.stat()
    # This authenticated GCS receipt was sealed by the login user.
    assert checkpoint_path.resolve() == checkpoint_path and stamp.st_uid == 1000 and not stamp.st_mode & 0o222
    assert binding(checkpoint_path) == checkpoint_ref
    checkpoint = json.loads(checkpoint_path.read_bytes())
    basename, generation = checkpoint['versioned_uri'].rsplit('/', 1)[1].rsplit('#', 1)
    assert generation == '1647637015038234' and checkpoint['exact_generation_metadata_matches']
    assert checkpoint['finalized_slot']['id'] == plan['verification_slot']
    assert names == [path.name, basename]
    terminal = read(plan['terminal'])
    assert terminal['epoch'] == 288 and terminal['root_preserved'] and not terminal['publication_authorized']
    assert terminal['root_physical_bytes_at_trip'] == plan['original_root_physical_bytes']
    return proposed, plan, source


def rendered_unit(plan, source):
    predecessor = fixed(ORIGINAL / 'producer.service',
                        '0a4b8ccf9d5b25889a5b74cbf515be4ae3e406da302a1ad02eb46a358a947a2c')
    base = checked(predecessor).read_text().replace(str(ORIGINAL_ROOT), str(RUN))
    replacement = {
        'Description': 'Private epoch 288 bounded shrink-debt comparison',
        'AllowedCPUs': '64-71',
        'CPUAffinity': '64-71',
        'ReadOnlyPaths': ' '.join(map(str, (TOKENS, RUN / 'output/compact-indexes',
                                         plan['bootstrap']['path'], Path(plan['node']['path']).parent,
                                         plan['worker']['path'], source['map']['path']))),
        'BindReadOnlyPaths': ' '.join(f'{row["path"]}:{dest}' for dest, row in plan['same_source_mounts'].items()),
        'ExecStart': shlex.join(plan['argv']),
    }
    for key, new in replacement.items():
        old, = (line for line in base.splitlines() if line.startswith(key + '='))
        base = base.replace(old, key + '=' + new)
    worker, = (line for line in base.splitlines() if line.startswith('Environment="JETSTREAMER_HISTORICAL_WORKER_V1_8_11='))
    base = base.replace(worker, f'Environment="JETSTREAMER_HISTORICAL_WORKER_V1_8_11={plan["worker"]["path"]}"')
    fields = base.splitlines()
    assert f'MemoryMax={MEMORY}' in fields and 'CPUQuota=800%' in fields and 'Restart=no' in fields
    assert f'Environment="JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256={source["map"]["sha256"]}"' in fields
    assert str(ORIGINAL_ROOT) not in base and '--root-checkpoint-cohort' not in base
    return base


def static_guard_plan():
    return dict(schema='jetstreamer-horizon-standalone-guard-plan-v1', unit=UNIT,
                invocation_id='0' * 32, filesystem='/', worker_root=str(RUN),
                receipt_directory=str(RECEIPTS), maximum_worker_vmas=3_500_000,
                minimum_free_bytes=FLOOR, maximum_root_physical_bytes=CAP)


def load_existing():
    prior = V / 'horizon292-full-v322/admit.py'
    spec = importlib.util.spec_from_file_location('accepted_entry', prior)
    kit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kit)
    return kit


def stopped_diagnostic229(row, ops):
    terminal_ref = fixed(TERMINAL229, '1c9b2aa1cfd21c57bcfc9f91a6d94bd458ca8ad94a57c3073148299671cdc9bd')
    terminal = read(terminal_ref)
    state = terminal['producer']
    assert terminal['epoch'] == 229 and terminal['schema'] == 'foundation-epoch229-slot-hash-v325-terminal'
    assert not terminal['publication_authorized'] and row['phase'] == 'diagnostic-qualification'
    assert row['launch_receipt_sha256'] == terminal['registration']['sha256']
    assert (state['Id'], state['InvocationID']) == (row['producer']['Id'], row['producer']['InvocationID'])
    assert state['ActiveState'] == 'failed' and state['MainPID'] == state['ControlPID'] == '0'
    assert not state['ControlGroup'] and ops.props(state['Id'], list(state)) == state
    correction_ref = fixed(TIMER_CORRECTION229, '9a9bd77d1eb3c54a4cfab6f861fa85660b85496359c881804cd72bfea6f0fb64')
    correction = read(correction_ref)
    assert correction['original_terminal'] == terminal_ref and correction['invocation_id'] == state['InvocationID']
    token = read(correction['launch_token'])
    clock = correction['guard_timer_before']
    assert clock['InvocationID'] == token['guard_timer_invocation'] and token['invocation_id'] == state['InvocationID']
    for name, recorded in ((clock['Unit'], correction['guard_service_drained']),
                           (clock['Id'], correction['guard_timer_drained'])):
        assert recorded['ActiveState'] == 'inactive' and not recorded['Job']
        assert ops.props(name, list(recorded)) == recorded
    return dict(terminal=terminal_ref, timer_correction=correction_ref)


def completed_extraction226(ops):
    path = EXTRACT226_STATE / 'control/success-drain-completion.json'
    if not path.exists():
        return None
    receipt = binding(path)
    row = read(receipt)
    assert row['schema'] == 'foundation-epoch226-extraction-success-drain-v1'
    assert row['epoch'] == 226 and row['prefix_retained'] is True and row['remote_mutations'] is False
    intent = read(row['intent'])
    assert intent['schema'] == 'foundation-epoch226-extraction-success-drain-intent-v1'
    assert row['handoff'] == intent['handoff']
    launch = read(intent['original_launch'])
    assert (launch['epoch'], launch['operation'], launch['unit'], launch['broker_unit']) == (
        226, 'extract', EXTRACT226_UNIT, EXTRACT226_BROKER)
    assert (row['producer']['Id'], row['after']['broker']['Id']) == (EXTRACT226_UNIT, EXTRACT226_BROKER)
    for unit in (EXTRACT226_UNIT, EXTRACT226_BROKER):
        current = ops.props(unit, ['ActiveState', 'MainPID', 'ControlPID', 'ControlGroup', 'Job'])
        assert current['ActiveState'] in ('inactive', 'failed') and current['MainPID'] == current['ControlPID'] == '0'
        assert not current['ControlGroup'] and not current['Job']
        assert not (Path('/sys/fs/cgroup/system.slice') / unit).exists()
    return dict(completion=receipt, launch=intent['original_launch'], invocation_id=launch['invocation_id'])


def latest_accepted_fleet(kit):
    prefix = 'horizon-foundation-seven-lane-v'
    completed = (path for path in kit.measure.DIAGNOSTICS.glob(prefix + '*')
                 if path.name.removeprefix(prefix).isdigit() and (path / 'completion.json').is_file())
    directory = max(completed, key=lambda path: int(path.name.removeprefix(prefix)))
    completion = binding(directory / 'completion.json')
    done = read(completion)
    fleet_ref = done['fleet']
    fleet_path = directory / 'fleet.json'
    assert fleet_ref['path'] == str(fleet_path) and fleet_path.resolve() == fleet_path
    metadata = fleet_path.stat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022
    fleet = kit.ops.bound(fleet_ref)
    assert (fleet['first_epoch'], fleet['last_epoch'], len(fleet['epochs'])) == (201, 300, 100)
    assert fleet['inventory']['anomalies'] == 0
    assert (fleet['observer_receipt'], fleet['observer_sha256']) == (done['observer']['path'], done['observer']['sha256'])
    sampled = datetime.fromisoformat(fleet['sampled_at_utc']).timestamp()
    assert 0 <= time.time() - sampled < 1800, 'accepted campaign observation is stale'
    return completion, fleet_ref, fleet


def capacity(kit, candidate_epoch=288):
    terminal226 = completed_extraction226(kit.ops)
    if candidate_epoch == 226:
        assert terminal226 is not None, 'epoch 226 extraction and its broker have not drained'
        profile = read(binding(SUFFIX226_STATE / 'static-prestart-qualification.json'))
        assert profile['epoch'] == 226 and profile['unit'] == SUFFIX226_UNIT and profile['guard_static_validation']['validated']
        guard = read(profile['guard_plan_fixture'])
        assert guard['unit'] == SUFFIX226_UNIT and guard['minimum_free_bytes'] == FLOOR
        candidate_disk = guard['maximum_root_physical_bytes']
        template = checked(profile['producer_template']).read_text().splitlines()
        memory, = [line.split('=', 1)[1] for line in template if line.startswith('MemoryMax=')]
        affinity, = [line.split('=', 1)[1] for line in template if line.startswith('AllowedCPUs=')]
        candidate_memory = int(memory)
        candidate_cpus = kit.measure.source.helper.cpus(affinity)
    elif candidate_epoch == 230:
        candidate_disk, candidate_memory, candidate_cpus = 0, MEMORY, frozenset(range(72, 80))
    else:
        candidate_disk, candidate_memory, candidate_cpus = CAP, MEMORY, CPUS
    completion, fleet_ref, fleet = latest_accepted_fleet(kit)
    assert [(r['epoch'], r['state']) for r in fleet['inventory']['entries'] if r['epoch'] == candidate_epoch] == [(candidate_epoch, 'missing')]
    helper = kit.measure.source.helper
    owners, growth, guard_paths, reconciled = {}, {}, {}, {}
    for row in fleet['active']:
        epoch, producer = row['epoch'], row['producer']
        assert epoch in GUARDS and epoch not in owners and epoch not in reconciled
        if epoch == 229 and producer['InvocationID'] == '505abb8828c54c138078e97f9277b817':
            reconciled[epoch] = stopped_diagnostic229(row, kit.ops)
            continue
        if producer['Id'] == EXTRACT226_UNIT and terminal226 is not None:
            assert epoch == 226 and row['phase'] == 'private-held-extraction'
            assert producer['InvocationID'] == terminal226['invocation_id']
            assert row['launch_receipt_sha256'] == terminal226['launch']['sha256']
            reconciled[epoch] = terminal226
            continue
        assert epoch != candidate_epoch, 'comparison candidate already has a live owner'
        owner = helper.active_props(producer['Id'], producer['InvocationID'])
        assert owner['MainPID'] == producer['MainPID']
        owners[epoch] = owner
        if producer['Id'] == BANK_DELTA229_UNIT:
            guard_paths[epoch] = BANK_DELTA229_GUARDS
        elif producer['Id'] == SUFFIX226_UNIT:
            guard_paths[epoch] = SUFFIX226_STATE / 'guard-receipts'
        elif producer['Id'] == CONTINUATION230_UNIT:
            guard_paths[epoch] = CONTINUATION230_STATE / 'guard-receipts'
        else:
            guard_paths[epoch] = GUARDS[epoch]
        growth[epoch] = kit.measure.source.growth_for(epoch, owner, guard_paths[epoch])
    broker = None
    live = list(owners.values())
    if terminal226 is None:
        broker_record = kit.ops.bound(kit.ops.ref(EXTRACT226_STATE / 'held-broker.json'))
        broker = kit.ops.props(EXTRACT226_BROKER, ['Id', 'ActiveState', 'SubState', 'MainPID', 'InvocationID',
                                                  'ControlGroup', 'AllowedCPUs', 'MemoryMax', 'MemoryCurrent'])
        assert (broker['ActiveState'], broker['SubState'], int(broker['MainPID'])) == ('active', 'running', broker_record['broker_pid'])
        live.append(broker)
    census = subprocess.check_output(['systemctl', 'list-units', '--type=service', '--state=running,activating',
        '--no-pager', '--no-legend', '--plain', 'horizon-qualify-*', 'horizon-perf-*', 'horizon-upload-*',
        'horizon-restore-*', 'foundation-*-broker-*'], text=True, timeout=10)
    assert {line.split()[0] for line in census.splitlines() if line.strip()} == {row['Id'] for row in live}, census
    assert all(r['AllowedCPUs'] and not (candidate_cpus & helper.cpus(r['AllowedCPUs'])) for r in live)
    mem = {k: int(value.split()[0]) * 1024 for k, value in
           (line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
           if k in ('MemAvailable', 'MemTotal')}
    memory_commitments = sum(max(0, int(row['MemoryMax']) - int(row['MemoryCurrent'])) for row in live)
    memory_room = mem['MemAvailable'] - mem['MemTotal'] // 10 - memory_commitments
    root_device = Path('/').stat().st_dev
    for epoch in (229, 230):
        if epoch in growth:
            diagnostic = kit.ops.bound(kit.ops.ref(guard_paths[epoch].parent / 'guard-plan.json'))
            assert Path(diagnostic['filesystem']).stat().st_dev != root_device
    disk_growth = {epoch: row for epoch, row in growth.items() if epoch not in (229, 230)}
    floor = max(row['floor_bytes'] for row in disk_growth.values())
    assert floor == FLOOR
    device = os.statvfs(RUN.parent)
    assert RUN.parent.stat().st_dev == root_device
    free = device.f_bavail * device.f_frsize
    protected = floor + sum(row['remaining_growth_bytes'] for row in disk_growth.values()) + helper.PUBLICATION_SCRATCH
    retirement_ref = None
    if candidate_epoch == 288:
        retirement_ref = fixed(RETIREMENT288, '7867cca9dea1f76def23cae3630941d73ae36241e6637bc6e212458f5b3ee008')
        retirement = read(retirement_ref)
        retired = read(retirement['check'])
        assert retirement['retirement_complete'] and retirement['end'] == retired['matching_files'] == 322833
        assert retired['matching_allocated_bytes'] == 51_918_905_344 and retired['protected_files'] == 7757
    result = dict(epoch=candidate_epoch, fleet=fleet_ref, completion=completion, sampled_unix_seconds=int(time.time()),
                live_units=owners, broker=broker, guards=growth, free_bytes=free, protected_disk_bytes=protected,
                reconciled_terminal_owners=reconciled, selective_retirement=retirement_ref, extraction226_terminal=terminal226,
                guard_minimum_free_bytes=floor, memory_room_bytes=memory_room, candidate_cap_bytes=candidate_disk,
                candidate_memory_max_bytes=candidate_memory, candidate_cpus=sorted(candidate_cpus),
                disk_shortfall_bytes=max(0, protected + candidate_disk - free),
                memory_shortfall_bytes=max(0, candidate_memory - memory_room),
                publication_authorized=False)
    if candidate_epoch == 230:
        assert CONTINUATION230_TMPFS.is_mount() and CONTINUATION230_TMPFS.stat().st_dev != root_device
        mount = os.statvfs(CONTINUATION230_TMPFS)
        tmpfs_available_bytes = mount.f_bavail * mount.f_frsize
        result.update(tmpfs_available_bytes=tmpfs_available_bytes, candidate_ram_cap_bytes=CONTINUATION230_RAM_CAP,
                      tmpfs_shortfall_bytes=max(0, CONTINUATION230_RAM_CAP + CONTINUATION230_TMPFS_FLOOR
                                                - tmpfs_available_bytes))
    return result


def cadence_changes():
    marker = 'diagnostic229_slot_hash_ram'
    plan_hook = '    inactive229.adopt({}, plan[\'gates\'][\'230\'][\'evidence\'], epoch=230)'
    replacements = {
        'cycle.py': [(f'import {marker}\n', f'import {marker}\nimport {ADAPTER}\n'),
                     (f"cfg['diagnostic_replays'] += {marker}.configuration()",
                      f"cfg['diagnostic_replays'] += {marker}.configuration()\ncfg['diagnostic_replays'] += {ADAPTER}.configuration()"),
                     (plan_hook, plan_hook + f'\n    {ADAPTER}.gate(plan)'),
                     (f'and not {marker}.owns(r)', f'and not {marker}.owns(r) and not {ADAPTER}.owns(r)')],
        'native_binding_replays.py': [(f'import {marker}\n', f'import {marker}\nimport {ADAPTER}\n'),
                                      (f', {marker}', f', {ADAPTER}, {marker}')],
    }
    changes = {}
    for filename, substitutions in replacements.items():
        path = CONTROL / filename
        old = path.read_text()
        new = old
        for before, after in substitutions:
            assert new.count(before) == 1, (filename, before)
            new = new.replace(before, after)
        ast.parse(new, filename=filename)
        changes[filename] = (old, new)
    return changes


def remote_source(guard_source):
    prefix = ['runuser', '-u', 'ubuntu', '--', 'git', '-C', str(SOURCE)]

    def git(*args):
        return subprocess.check_output([*prefix, *args], timeout=15)

    branch = git('rev-parse', 'origin/account-updates').decode().strip()
    for revision in ('83659c40', 'e66470be', guard_source['commit']):
        git('merge-base', '--is-ancestor', revision, branch)
    launcher = Path(__file__)
    adapter = launcher.with_name(ADAPTER + '.py')
    parent = launcher.parent.stat()
    assert parent.st_uid == 0 and not parent.st_mode & 0o222
    for file in (launcher, adapter):
        relative = SOURCE_DIRECTORY / file.name
        committed = git('show', f'{branch}:{relative}')
        checked(fixed(file, hashlib.sha256(committed).hexdigest()))
    sources = guard_source['compiled_source_sha256']
    expected = {f'jetstreamer-utils/src/horizon_standalone_guard_{part}.rs' for part in ('bin', 'handoff', 'native227', 'root')}
    assert set(sources) == expected
    for name, digest in sources.items():
        committed = git('show', f"{guard_source['commit']}:{name}")
        assert hashlib.sha256(committed).hexdigest() == digest, name
    return branch


def sealed_file(path, content, mode=0o400):
    with path.open('xb') as out:
        os.fchmod(out.fileno(), mode)
        out.write(content)
        out.flush()
        os.fsync(out.fileno())
    descriptor = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return binding(path)


def create_private_tree(mounts):
    RUN.mkdir(mode=0o700)
    for relative in ('tmp/isolated-empty-gcloud', 'state', 'output/compact-indexes/287', 'output/compact-indexes/288'):
        (RUN / relative).mkdir(parents=True, mode=0o700)
    for destination in map(Path, mounts):
        if destination.is_relative_to(RUN):
            destination.touch(mode=0o400, exist_ok=False)
    for path in [RUN, *RUN.rglob('*')]:
        os.chown(path, 1000, 1000)


NAMESPACE_PROBE = r'''
import hashlib, json, os, sys
from pathlib import Path
data = json.loads(sys.argv[1]); assert os.getuid() == 1000
for destination, row in data['mounts'].items():
    path = Path(destination); st = path.stat()
    assert os.statvfs(path).f_flag & os.ST_RDONLY, path
    if 'device' in row:
        assert (st.st_dev, st.st_ino, st.st_size) == (row['device'], row['inode'], row['size']), path
    with path.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256'], path
for item in ('worker', 'node'):
    row = data[item]; image = Path(row['path'])
    assert os.statvfs(image).f_flag & os.ST_RDONLY and os.access(image, os.X_OK)
    with image.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256'], image
row = data['snapshot']; path = Path(row['path']); st = path.stat()
assert os.statvfs(path).f_flag & os.ST_RDONLY
assert (st.st_dev, st.st_ino, st.st_size) == (row['device'], row['inode'], row['bytes'])
assert os.environ['JETSTREAMER_HISTORICAL_WORKER_V1_8_11'] == data['worker']['path']
assert os.environ['JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256'] == data['manifest']['sha256']
assert os.access(data['root'] + '/state', os.W_OK)
print(json.dumps(dict(namespace_verified=True, replay_started=False, mounts=len(data['mounts']))))
'''


def prepare(kit, guard_source_ref):
    guard_source_receipt = read(guard_source_ref)
    branch = remote_source(guard_source_receipt)
    guard = checked(guard_source_receipt['guard'])
    proposed, plan, source = plan_inputs()
    PACKAGE.mkdir(mode=0o700)
    RECEIPTS.mkdir(mode=0o700)
    TOKENS.mkdir(mode=0o755)
    TOKENS.chmod(0o755)
    old_token = fixed(V / 'horizon288-full-tokens-v303/pre-start.sh',
                      '14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0')
    token = sealed_file(TOKENS / 'pre-start.sh', checked(old_token).read_bytes(), 0o555)
    create_private_tree(plan['same_source_mounts'])
    producer = sealed_file(PACKAGE / 'producer.service', rendered_unit(plan, source).encode())
    static = kit.ops.funds.put(PACKAGE / 'static-guard-plan.json', static_guard_plan())
    guard_sha = guard_source_receipt['guard']['sha256']
    verdict = json.loads(subprocess.check_output([guard, static['path'], '--plan-sha256', static['sha256'],
        '--self-sha256', guard_sha, '--validate-plan-only'], timeout=20))
    assert verdict['validated'] and verdict['plan_sha256'] == static['sha256'] and verdict['self_sha256'] == guard_sha
    properties, argv = kit.startup.start_props(UNIT, Path(producer['path']))
    assert argv == plan['argv']
    mount_properties = tuple('--property=' + key + '=' for key in (
        'ReadWritePaths', 'ReadOnlyPaths', 'BindReadOnlyPaths', 'ProtectHome', 'ProtectSystem', 'WorkingDirectory'))
    namespace_properties = [p for p in properties if p.startswith((*mount_properties, '--setenv='))]
    probe = dict(mounts=plan['same_source_mounts'], worker=plan['worker'], node=plan['node'],
                 manifest=source['map'], snapshot=plan['bootstrap'], root=str(RUN))
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=foundation-288-shrink-debt-namespace-v327',
        '--property=Type=exec', '--property=User=ubuntu', '--property=Group=ubuntu', '--property=PrivateNetwork=yes',
        '--property=NoNewPrivileges=yes', '--property=CPUQuota=100%', '--property=MemoryMax=1G',
        '--property=MemorySwapMax=0', '--property=RuntimeMaxSec=25', *namespace_properties,
        '--', '/usr/bin/python3', '-I', '-B', '-c', NAMESPACE_PROBE, json.dumps(probe)]
    result = json.loads(subprocess.check_output(command, timeout=35))
    assert result['namespace_verified'] and not result['replay_started']
    return kit.ops.funds.put(PACKAGE / 'profile.json', dict(epoch=288, proposal=proposed, argv=argv,
        producer=producer, token=token, guard=guard_source_receipt['guard'], guard_provenance=guard_source_ref,
        branch=branch, guard_template=static, guard_validation=verdict, namespace=result, publication_authorized=False))


def deploy_cadence(kit):
    adapter = Path(__file__).with_name(ADAPTER + '.py')
    target = CONTROL / adapter.name
    changes = cadence_changes()
    assert not target.exists()
    old = [sealed_file(PACKAGE / (name + '.previous'), original.encode()) for name, (original, _) in changes.items()]
    installed = [sealed_file(target, adapter.read_bytes())]
    for name, (_, content) in changes.items():
        with tempfile.NamedTemporaryFile(dir=CONTROL, delete=False) as out:
            os.fchmod(out.fileno(), 0o400)
            out.write(content.encode())
            out.flush()
            os.fsync(out.fileno())
        path = CONTROL / name
        os.replace(out.name, path)
        installed.append(binding(path))
    descriptor = os.open(CONTROL, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return kit.ops.funds.put(PACKAGE / 'cadence-deployment.json', dict(previous=old, installed=installed))


def exact_inventory(kit):
    image = kit.ops.checked_image(kit.ops.R2)
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=foundation-288-shrink-debt-inventory-v327',
        '--property=Type=exec', '--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env',
        '--setenv=TOKIO_WORKER_THREADS=2', '--', image, 'inventory', '/home/ubuntu/horizon', '--epochs', '288-288',
        '--receipt-directory', str(kit.measure.PRIVATE / 'r2-receipts')]
    result = json.loads(subprocess.check_output(command, timeout=45))
    row, = result['entries']
    assert result['schema'] == 'jetstreamer-horizon-r2-inventory-v1' and result['anomalies'] == 0
    assert (row['epoch'], row['state']) == (288, 'missing')
    return row


def guarded_start(kit, profile_ref, fit, inventory, deployment):
    profile = read(profile_ref)
    worker = read(profile['proposal'])['worker']
    assert time.time() - fit['sampled_unix_seconds'] < 20
    assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == 0
    registration = PACKAGE / 'cadence-registration.json'
    ops, runner, startup = kit.ops, kit.replay, kit.startup
    timer = GUARD_UNIT.replace('.service', '.timer')
    admission = ops.funds.put(PACKAGE / 'admission.json', dict(epoch=288, profile=profile_ref, fit=fit, inventory=inventory,
        deployment=deployment, admitted=True, publication_authorized=False))
    properties, argv = startup.start_props(UNIT, checked(profile['producer']))
    assert argv == profile['argv']
    properties.append(f'--property=ExecStartPre=/usr/bin/bash {checked(profile["token"])} 60 {TOKENS}')
    startup.systemd_run(UNIT, properties, argv, '--slice=system.slice')

    def held():
        state = ops.props(UNIT, ['InvocationID', 'ActiveState', 'SubState', 'MainPID', 'ControlPID'])
        return state if (state['ActiveState'], state['SubState'], state['MainPID']) == ('activating', 'start-pre', '0') and int(state['ControlPID']) > 0 else None

    invocation = startup.until(held, 12)['InvocationID']
    guard = profile['guard']
    template = read(profile['guard_template'])
    plan = ops.funds.put(PACKAGE / 'guard-plan.json', dict(template, invocation_id=invocation))
    guard_properties = ['--property=Type=oneshot', '--property=User=root', '--property=UMask=0077',
        '--property=Restart=no', '--property=MemoryMax=1G', '--property=MemorySwapMax=0', '--property=CPUQuota=100%',
        '--property=TasksMax=256', '--property=TimeoutStartSec=90', '--property=ProtectSystem=strict',
        '--property=ProtectHome=read-only', '--property=PrivateNetwork=yes', '--property=NoNewPrivileges=yes',
        '--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE',
        '--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE', f'--property=ReadWritePaths={RECEIPTS}']
    runner.PRODUCER, runner.GUARD_UNIT, runner.TIMER, runner.RECEIPTS = UNIT, GUARD_UNIT, timer, RECEIPTS
    runner.GUARD_SHA = guard['sha256']
    startup.systemd_run(GUARD_UNIT, guard_properties, [guard['path'], plan['path'], '--plan-sha256', plan['sha256'],
        '--self-sha256', guard['sha256']], '--on-active=1s', '--on-unit-inactive=60s', '--timer-property=AccuracySec=1s',
        '--timer-property=RandomizedDelaySec=0')
    first, sample = startup.until(lambda: runner.first_guard(invocation, plan), 35)
    clock, next_guard = startup.until(runner.timer_ready, 12)
    assert held()['InvocationID'] == invocation and sample['root_physical_observation_error'] is None
    token_dir = TOKENS / invocation
    token_dir.mkdir(mode=0o755)
    token_dir.chmod(0o755)
    token = ops.funds.put(token_dir / 'guard-admission.json', dict(epoch=288, unit=UNIT, invocation_id=invocation,
        first_guard=first, guard_plan=plan, guard_timer_invocation=clock['InvocationID'],
        next_guard_monotonic_usec=next_guard, admission=admission, publication_authorized=False))

    def started():
        state = ops.props(UNIT, ['Id', 'InvocationID', 'MainPID', 'ActiveState', 'SubState', 'NRestarts', 'LoadState', 'Result'])
        if (state['ActiveState'], state['SubState']) != ('active', 'running'):
            return None
        assert state['InvocationID'] == invocation and state['NRestarts'] == '0'
        pid = int(state['MainPID'])
        assert pid > 0 and (Path('/proc') / str(pid) / 'exe').samefile(argv[0])
        for path in sorted(RECEIPTS.glob('sample-*.json'), key=lambda p: p.stat().st_mtime_ns, reverse=True):
            ref = binding(path)
            observation = read(ref)
            assert observation['producer_invocation_id'] == invocation and observation['plan_sha256'] == plan['sha256']
            assert observation['guard_sha256'] == guard['sha256'] and observation['trip_reason'] is None
            if observation['producer']['active'] == 'active' and observation['workers']:
                assert observation['producer']['pid'] == pid and observation['worker_observation_error'] is None
                (worker_pid, _), = observation['workers']
                process = Path('/proc') / str(worker_pid)
                assert (process / 'exe').readlink().is_relative_to(RUN)
                assert f'0::/system.slice/{UNIT}' in (process / 'cgroup').read_text().splitlines()
                assert binding(process / 'exe')['sha256'] == worker['sha256']
                return state, pid, worker_pid, ref
        return None

    state, pid, worker_pid, active_guard = startup.until(started, 220)
    identity = dict(unit=UNIT, active_state='active', sub_state='running', main_pid=pid, invocation_id=invocation,
                    restarts=0, load_state=state['LoadState'], result=state['Result'])
    return ops.funds.put(registration, dict(schema='jetstreamer-historical-performance-launch-receipt-v1',
        kind='epoch288-bounded-shrink-debt-storage-comparison', epoch=288, unit=UNIT, invocation_id=invocation, main_pid=pid,
        node_path=argv[0], worker=worker, worker_pid=worker_pid, run_root=str(RUN),
        bootstrap_slot=124415782, target_slot=124429562, terminal_slot=124435861,
        launched=True, entry_replay_requested=True, canonical_epoch_publication_authorized=False, remote_mutations=False,
        r2_mutations=False, admission=admission, guard_plan=plan, launch_token=token, active_guard=active_guard,
        evidence=dict(units=[identity])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'capacity', 'capacity-suffix226', 'capacity-continuation230',
                                          'prepare', 'launch'))
    parser.add_argument('reference', nargs='?')
    parser.add_argument('sha256', nargs='?')
    options = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    if options.action == 'capacity':
        print(json.dumps(capacity(load_existing())))
        return
    if options.action == 'capacity-suffix226':
        print(json.dumps(capacity(load_existing(), candidate_epoch=226)))
        return
    if options.action == 'capacity-continuation230':
        print(json.dumps(capacity(load_existing(), candidate_epoch=230)))
        return
    if options.action in ('prepare', 'launch'):
        kit = load_existing()
        assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
        os.umask(0o077)
        assert options.reference and options.sha256
        ref = fixed(Path(options.reference), options.sha256)
        with kit.partition.take(), (CONTROL / 'cycle.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert kit.partition.locked(kit.partition.LOCK, os.getpid())
            assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
                'ActiveState': 'inactive', 'Job': ''}
            if options.action == 'prepare':
                print(json.dumps(prepare(kit, ref)))
                return
            assert ref['path'] == str(PACKAGE / 'profile.json')
            profile = read(ref)
            assert profile['epoch'] == 288 and not profile['publication_authorized'] and profile['namespace']['namespace_verified']
            remote_source(read(profile['guard_provenance']))
            assert checked(profile['guard']) and checked(profile['producer']) and checked(profile['token'])
            assert not any(RECEIPTS.iterdir()) and list(TOKENS.iterdir()) == [Path(profile['token']['path'])]
            assert not (PACKAGE / 'admission.json').exists()
            for unit in (UNIT, GUARD_UNIT, GUARD_UNIT.replace('.service', '.timer')):
                assert kit.ops.props(unit, ['LoadState', 'ActiveState', 'Job']) == {
                    'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}, unit
            plan_inputs()
            inventory = exact_inventory(kit)
            fit = capacity(kit)
            assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == 0, fit
            deployment = deploy_cadence(kit)
            fit = capacity(kit)
            print(json.dumps(guarded_start(kit, ref, fit, inventory, deployment)))
            return
    proposed, plan, source = plan_inputs()
    service = rendered_unit(plan, source)
    changes = cadence_changes()
    print(json.dumps(dict(plan=proposed, service=service, controller_sources=sorted(changes),
                          guard_unit=GUARD_UNIT, static_guard_plan=static_guard_plan(),
                          replay_started=False, publication_authorized=False)))


if __name__ == '__main__':
    main()
