"""Prepare and admit the isolated epoch 230 tail without publishing it."""

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import epoch288_shrink_debt_comparison as capacity
from epoch230_checkpoint_continuation_launch import activate_guarded, inventory


STATE = capacity.TAIL230_STATE
UNIT = capacity.TAIL230_UNIT
GUARD_UNIT = 'horizon-230-final-tail-protective-v1.service'
MOUNT = capacity.TAIL230_MOUNT
ROOT = MOUNT / 'run'
TOKENS = capacity.V / 'horizon230-final-tail-tokens-v1'
STATIC = capacity.V / 'horizon230-final-tail-static-v1'
INPUTS = capacity.fixed(STATIC / 'inputs.json',
    '91faca00759d243930050e2fa824e890953f9b329606675cba573d0f103fefc3')
PAIR = capacity.V / 'horizon230-final-tail-node-v1/pair.json'
GUARD = capacity.V / 'horizon230-final-tail-guard-41a5fb72-v1'
ADAPTER = 'diagnostic230_checkpoint_continuation.py'
TOKEN = capacity.fixed(capacity.V / 'horizon231-demotion-tokens-v1/pre-start.sh',
    '14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0')
REQUIRED_BUILD_INPUTS = {
    'Cargo.toml', 'Cargo.lock', 'jetstreamer-node/Cargo.toml', 'jetstreamer-node/build.rs',
    'jetstreamer-node/src/main.rs', 'jetstreamer-node/src/historical.rs',
    'jetstreamer-node/src/called_program_demotion.rs', 'jetstreamer-node/src/called_program_demotion/epoch231.rs',
}


def git(*args):
    return subprocess.check_output(['runuser', '-u', 'ubuntu', '--', 'git', '-C', str(capacity.SOURCE), *args],
                                   timeout=15)


def deployment(branch, pair_ref):
    pair = capacity.read(pair_ref)
    inputs = capacity.read(INPUTS)
    assert pair['schema'] == 'foundation-epoch230-final-tail-node-pair-v1'
    assert pair['worker'] == inputs['worker'] and pair['focused_release_tests_passed'] == 3
    assert pair['feature'] == 'epoch230-final-tail-demotion-qualification'
    assert pair['replay_launch_authorized'] is False and pair['publication_authorized'] is False
    git('merge-base', '--is-ancestor', pair['source_commit'], branch)
    assert REQUIRED_BUILD_INPUTS <= pair['compiled_input_sha256'].keys()
    for name, digest in pair['compiled_input_sha256'].items():
        assert hashlib.sha256(git('show', f'{pair["source_commit"]}:{name}')).hexdigest() == digest, name
        assert hashlib.sha256(git('show', f'{branch}:{name}')).hexdigest() == digest, name
    node = capacity.checked(pair['node'])
    engine = capacity.checked(pair['worker'])
    capability = json.loads(subprocess.check_output(
        ['runuser', '-u', 'ubuntu', '--', 'env', f'JETSTREAMER_HISTORICAL_WORKER_EPOCH231_DEMOTION={engine}',
         str(node), '--epoch230-final-tail-demotion-capability'], timeout=30))
    assert capability['schema'] == 'jetstreamer-private-epoch230-tail-demotion-parent-capability-v1'
    assert (capability['epoch'], capability['bootstrap_slot'], capability['output_slot_start'],
            capability['terminal_slot']) == (230, 99_791_404, 99_791_405, 99_803_089)
    assert capability['run_root'] == str(ROOT) and capability['worker_sha256'] == pair['worker']['sha256']
    assert capability['worker_spawned'] is False and capability['publication_authorized'] is False
    guard_ref = capacity.binding(GUARD / 'guard-release.json')
    guarded = capacity.read(guard_ref)
    git('merge-base', '--is-ancestor', guarded['source_commit'], branch)
    assert guarded['overlay_sha256'] == capacity.binding(GUARD / 'epoch230-final-tail-guard.patch')['sha256']
    overlay = git('show', f'{branch}:{capacity.SOURCE_DIRECTORY / "epoch230-final-tail-guard.patch"}')
    assert hashlib.sha256(overlay).hexdigest() == guarded['overlay_sha256']
    checked = capacity.read(capacity.fixed(GUARD / 'static-validation.json', guarded['static_validation_sha256']))
    assert checked['validated'] and checked['self_sha256'] == guarded['guard']['sha256']
    assert checked['plan_sha256'] == inputs['outputs']['static-guard-plan.json']['sha256']
    capacity.checked(guarded['guard'])
    return dict(pair=pair_ref, inputs=INPUTS, guard_release=guard_ref, guard=guarded['guard'],
                node=pair['node'], capability=capability)


NAMESPACE = r'''
import json, os, sys
from pathlib import Path
spec=json.loads(sys.argv[1]); assert os.geteuid()==1000
root=Path(spec['root']); assert root.stat().st_uid==1000
assert root.resolve()==root and root.stat().st_mode&0o777==0o700
assert not os.statvfs(root).f_flag&os.ST_RDONLY
for dest, source in spec['mounts'].items():
    p=Path(dest); original=Path(source['path']); seen=p.stat(); expected=original.stat()
    assert seen.st_dev==expected.st_dev and seen.st_ino==expected.st_ino
    assert seen.st_size==expected.st_size and os.statvfs(p).f_flag&os.ST_RDONLY
    with p.open('rb') as data: assert data.read(1)
checkpoints=(root/'epoch-hashes.txt').read_text().splitlines()
assert [int(i.split('-')[1]) for i in checkpoints]==[99791404,99791517,99803089]
assert (root/'output/genesis.tar.bz2').is_file()
assert not list((root/'state').iterdir())
print(json.dumps(dict(namespace_verified=True, mount_count=len(spec['mounts']),
    checkpoint_count=len(checkpoints), replay_started=False)))
'''


def prepare(kit, branch, deploy):
    profile = STATE / 'profile.json'
    if profile.is_file():
        reference = capacity.binding(profile)
        saved = capacity.read(reference)
        assert saved['deployment'] == deploy and saved['namespace']['namespace_verified']
        assert saved['launch_started'] is False and MOUNT.is_mount()
        capacity.checked(saved['token'])
        capacity.checked(saved['producer'])
        return reference
    assert not STATE.exists() and not TOKENS.exists() and not MOUNT.exists()
    inputs = capacity.read(INPUTS)
    probe = capacity.capacity(kit, candidate_epoch=230, probe230=True)
    assert probe['memory_room_bytes'] >= 225_000_000_000 + (1 << 30)
    assert probe['free_bytes'] - probe['protected_disk_bytes'] >= capacity.TAIL230_HANDOFF_BYTES
    STATE.mkdir(mode=0o700)
    (STATE / 'guard-receipts').mkdir(mode=0o700)
    TOKENS.mkdir(mode=0o755)
    TOKENS.chmod(0o755)
    token = capacity.sealed_file(TOKENS / 'pre-start.sh', capacity.checked(TOKEN).read_bytes(), 0o555)
    MOUNT.mkdir(mode=0o700)
    subprocess.run(['mount', '-t', 'tmpfs', '-o',
                    'rw,exec,nosuid,nodev,noswap,size=153000001536,uid=1000,gid=1000,mode=0700',
                    'horizon230-final-tail-v1', str(MOUNT)], check=True, timeout=15)
    assert MOUNT.is_mount() and MOUNT.stat().st_dev != STATE.stat().st_dev
    for path in (ROOT, ROOT / 'output', ROOT / 'output/compact-indexes', ROOT / 'output/compact-indexes/230',
                 ROOT / 'output/compact-indexes/231', ROOT / 'state', ROOT / 'tmp', ROOT / 'tmp/isolated-empty-gcloud'):
        path.mkdir(mode=0o700)
        os.chown(path, 1000, 1000)
    for path in map(Path, inputs['mounts']):
        assert path.is_relative_to(ROOT)
        path.touch(mode=0o400, exist_ok=False)
        os.chown(path, 1000, 1000)
    template = capacity.checked(inputs['outputs']['producer.service.template']).read_text()
    assert template.count('__SEALED_EPOCH230_TAIL_NODE__') == 2
    rendered = template.replace('__SEALED_EPOCH230_TAIL_NODE__', deploy['node']['path'])
    producer = capacity.sealed_file(STATE / 'producer.service', rendered.encode())
    props, argv = kit.startup.start_props(UNIT, Path(producer['path']))
    assert argv == [deploy['node']['path'], *inputs['args'][1:]]
    mount_keys = tuple('--property=' + key + '=' for key in (
        'ReadOnlyPaths', 'ReadWritePaths', 'BindReadOnlyPaths', 'ProtectHome', 'ProtectSystem', 'WorkingDirectory'))
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
               '--unit=foundation-230-final-tail-namespace-v1', '--property=Type=exec',
               '--property=User=ubuntu', '--property=PrivateNetwork=yes', '--property=NoNewPrivileges=yes',
               '--property=MemoryMax=256M', '--property=CPUQuota=50%', '--property=RuntimeMaxSec=20s',
               *(p for p in props if p.startswith(mount_keys)), '--', '/usr/bin/python3', '-I', '-B', '-c',
               NAMESPACE, json.dumps(dict(root=str(ROOT), mounts=inputs['mounts']))]
    namespace = json.loads(subprocess.check_output(command, timeout=30))
    assert namespace == dict(namespace_verified=True, mount_count=6, checkpoint_count=3, replay_started=False)
    return kit.ops.funds.put(STATE / 'profile.json', dict(schema='foundation-epoch230-final-tail-profile-v1',
        branch=branch, deployment=deploy, token=token, producer=producer, argv=argv, namespace=namespace,
        launch_started=False, publication_authorized=False))


def deploy_cadence(kit, branch):
    current = capacity.CONTROL / ADAPTER
    original = capacity.binding(current)
    old_source = capacity.checked(original).read_bytes()
    expected_old = git('show', f'f1e742e2:{capacity.SOURCE_DIRECTORY / ADAPTER}')
    assert old_source == expected_old
    new_source = git('show', f'{branch}:{capacity.SOURCE_DIRECTORY / ADAPTER}')
    compile(new_source, ADAPTER, 'exec')
    backup = capacity.sealed_file(STATE / 'cadence-adapter-before.py', old_source)
    template = current.with_name('.diagnostic230-final-tail-v1.pending')
    capacity.sealed_file(template, new_source)
    os.replace(template, current)
    fd = os.open(current.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return kit.ops.funds.put(STATE / 'cadence-deployment.json', dict(branch=branch, original=original,
        backup=backup, installed=capacity.binding(current), publication_authorized=False))


def start(kit, branch, deploy):
    assert not (STATE / 'admission.json').exists()
    assert not list((STATE / 'guard-receipts').iterdir())
    for unit in (UNIT, GUARD_UNIT, GUARD_UNIT.replace('.service', '.timer')):
        assert kit.ops.props(unit, ['LoadState', 'ActiveState', 'Job']) == {
            'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}, unit
    profile_ref = capacity.binding(STATE / 'profile.json')
    profile = capacity.read(profile_ref)
    assert profile['deployment'] == deploy and profile['namespace']['namespace_verified']
    assert profile['launch_started'] is False and profile['publication_authorized'] is False
    producer = capacity.checked(profile['producer'])
    inputs = capacity.read(INPUTS)
    template = capacity.read(inputs['outputs']['static-guard-plan.json'])
    assert template['unit'] == UNIT and Path(template['worker_root']) == ROOT
    remote_inventory = inventory(kit, unit='foundation-230-final-tail-inventory-v1')
    quote = capacity.capacity(kit, candidate_epoch=230, tail230=True)
    assert quote['disk_shortfall_bytes'] == quote['memory_shortfall_bytes'] == quote['tmpfs_shortfall_bytes'] == 0
    props, argv = kit.startup.start_props(UNIT, producer)
    prestart, = [line for line in producer.read_text().splitlines() if line.startswith('ExecStartPre=')]
    assert argv == profile['argv'] and str(TOKENS) in prestart
    installed = deploy_cadence(kit, branch)
    assert time.time() - quote['sampled_unix_seconds'] < 20
    admission = kit.ops.funds.put(STATE / 'admission.json', dict(epoch=230, inputs=INPUTS, profile=profile_ref,
        node=deploy['node'], capacity=quote, inventory=remote_inventory, cadence=installed, admitted=True,
        publication_authorized=False))
    owner, guard_plan, token, guard = activate_guarded(
        kit, 230, STATE, TOKENS, UNIT, GUARD_UNIT, deploy['guard'], template, admission, props, prestart, argv)
    return kit.ops.funds.put(STATE / 'cadence-registration.json', dict(
        schema='jetstreamer-historical-performance-launch-receipt-v1', kind='epoch230-final-tail', epoch=230,
        unit=UNIT, invocation_id=owner['invocation_id'], main_pid=owner['main_pid'], node_path=argv[0],
        run_root=str(ROOT), worker_sha256=inputs['worker']['sha256'], bootstrap_slot=99_791_404,
        first_slot=99_791_405, last_slot=99_803_089, admissible_canonical_last_slot=99_791_999,
        launched=True, entry_replay_requested=True, canonical_epoch_publication_authorized=False,
        full_continuation_peak_qualified=False, remote_mutations=False, r2_mutations=False, admission=admission,
        guard_plan=guard_plan, launch_token=token, active_guard=guard, evidence={'units': [owner]}))


def main():
    assert os.geteuid() == 0 and __debug__ and len(sys.argv) == 3
    action, digest = sys.argv[1:]
    assert action in ('prepare', 'launch') and re.fullmatch('[0-9a-f]{64}', digest)
    branch = git('rev-parse', 'origin/account-updates').decode().strip()
    for file in (Path(__file__), Path(capacity.__file__), Path(__file__).with_name('epoch230_checkpoint_continuation_launch.py')):
        assert file.read_bytes() == git('show', f'{branch}:{capacity.SOURCE_DIRECTORY / file.name}'), file
        assert capacity.checked(capacity.binding(file)) == file
    kit = capacity.load_existing()
    assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    os.umask(0o077)
    deploy = deployment(branch, capacity.fixed(PAIR, digest))
    with kit.partition.take(), (capacity.CONTROL / 'cycle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
            'ActiveState': 'inactive', 'Job': ''}
        print(json.dumps((prepare if action == 'prepare' else start)(kit, branch, deploy)))


if __name__ == '__main__':
    main()
