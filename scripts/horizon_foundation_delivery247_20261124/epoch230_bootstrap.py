"""Admit the Foundation read-only epoch 230 capped restart probe."""

import fcntl
import hashlib
import json
import os
import subprocess
from pathlib import Path

import epoch288_shrink_debt_comparison as capacity


TOOLS = capacity.V / 'horizon230-native-restart-tools-v1'
STATE = capacity.BOOTSTRAP230
UNIT = capacity.BOOTSTRAP230_UNIT
BINARY = TOOLS / 'probe'
SCRATCH = '/tmp/foundation-230-bootstrap'
SNAPSHOT = capacity.V / ('horizon230-successor-99383572-input-v1/'
                         'snapshot-99383572-HAsyNGf1oLCESAqbCQ8K445g2aw9paY5QScx9maA4wbz.tar.zst')
WORKER = capacity.V / 'horizon231-232-capped-worker-d1d48400-v1/jetstreamer-historical-worker-v1-6-20'
SOURCES = {'tools/horizon_epoch230_bootstrap.rs', 'jetstreamer-node/src/historical.rs',
           str(capacity.SOURCE_DIRECTORY / Path(__file__).name),
           str(capacity.SOURCE_DIRECTORY / Path(capacity.__file__).name)}


def deployment():
    def git(*args):
        return subprocess.check_output(
            ['runuser', '-u', 'ubuntu', '--', 'git', '-C', str(capacity.SOURCE), *args], timeout=15)

    source_ref = capacity.binding(TOOLS / 'build.json')
    source = capacity.read(source_ref)
    branch = git('rev-parse', 'origin/account-updates').decode().strip()
    commit = source['commit']
    git('merge-base', '--is-ancestor', commit, branch)
    assert source['schema'] == 'foundation-epoch230-bootstrap-build-v1' and set(source['sources']) == SOURCES
    for name, sha in source['sources'].items():
        assert hashlib.sha256(git('show', f'{commit}:{name}')).hexdigest() == sha, name
        assert hashlib.sha256(git('show', f'{branch}:{name}')).hexdigest() == sha, name
    seal_ref = capacity.binding(TOOLS / 'deployment-seal-receipt.json')
    seal = capacity.read(seal_ref)
    assert seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1' and seal['destination'] == str(TOOLS)
    expected = {
        'probe': source['binary_sha256'], 'build.json': source_ref['sha256'],
        'prefix.json': '8a8526835aec9e23dd3d83959ec464f6c04d0afd6489f50369023f699d439438',
        'genesis.tar.bz2': '133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945',
        **{Path(name).name: sha for name, sha in source['sources'].items() if name.endswith('.py')},
    }
    assert {row['name']: row['sha256'] for row in seal['members']} == expected
    for name, digest in expected.items():
        capacity.checked(capacity.fixed(TOOLS / name, digest))
    worker = capacity.read(capacity.fixed(WORKER.parent / 'qualification.json',
        'e8fd8eec6f5e837c28ec15095e099360171183fc2a945f4d7238d02a5695c3e3'))
    git('merge-base', '--is-ancestor', worker['source_commit'], branch)
    assert worker['features'] == ['capped-shrink-candidate'] and worker['worker']['path'] == str(WORKER)
    original = capacity.read(capacity.fixed(SNAPSHOT.parent.parent /
        'horizon230-continuation-99383572-source-v1/completion.json',
        '06eaf9135af94e61e07f62dda7d93d5e9ff3e79da12459d2f8a261199823d6b5'))
    assert original['snapshot']['path'] == str(SNAPSHOT) and original['generation'] == 1633495957369677
    assert original['snapshot']['bytes'] == 10_147_321_177 and original['snapshot']['inode'] == SNAPSHOT.stat().st_ino
    return dict(branch=branch, build=source_ref, seal=seal_ref, binary=capacity.fixed(BINARY, expected['probe']))


def admit(kit, source):
    assert kit.ops.props(UNIT, ['LoadState', 'ActiveState', 'Job']) == {
        'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}
    assert not STATE.exists()
    fit = capacity.capacity(kit, candidate_epoch=230, probe230=True)
    assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == 0
    assert fit['candidate_cpus'] == [118, 119, 120, 121] and fit['candidate_memory_max_bytes'] == 160 << 30
    properties = {
        'Type': 'exec', 'User': 'ubuntu', 'Group': 'ubuntu', 'UMask': '0077', 'Restart': 'no',
        'AllowedCPUs': '118-121', 'CPUQuota': '400%', 'MemoryMax': str(160 << 30), 'MemorySwapMax': '0',
        'RuntimeMaxSec': '30min', 'TasksMax': '256', 'ProtectSystem': 'strict', 'ProtectHome': 'read-only',
        'PrivateNetwork': 'yes', 'NoNewPrivileges': 'yes', 'PrivateTmp': 'yes',
        'ReadOnlyPaths': f'{TOOLS} {STATE} {WORKER} {SNAPSHOT}',
        'TemporaryFileSystem': f'{SCRATCH}:rw,exec,nosuid,nodev,noswap,size=150G,uid=1000,gid=1000,mode=0700',
    }
    command = ['systemd-run', '--quiet', '--unit=' + UNIT,
               *(f'--property={key}={value}' for key, value in properties.items()),
               '--setenv=RAYON_NUM_THREADS=4', '--setenv=SOLANA_RAYON_THREADS=4',
               '--setenv=JETSTREAMER_HISTORICAL_POH_THREADS=4', '--', str(BINARY)]
    STATE.mkdir(mode=0o755)
    os.chmod(STATE, 0o755)
    admission = dict(schema='foundation-epoch230-capped-bootstrap-admission-v1', fit=fit, deployment=source,
                     unit=UNIT, admitted=True, command=command, replay_launch_authorized=False,
                     publication_authorized=False)
    admission_ref = capacity.sealed_file(STATE / 'admission.json', (json.dumps(admission) + '\n').encode())
    subprocess.run(command, check=True, timeout=15)
    owner = kit.ops.props(UNIT, ['Id', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'ControlGroup',
                                 'AllowedCPUs', 'MemoryMax', 'MemorySwapMax'])
    assert (owner['Id'], owner['ActiveState'], owner['SubState']) == (UNIT, 'active', 'running')
    assert owner['AllowedCPUs'] == '118-121' and int(owner['MemoryMax']) == 160 << 30 and owner['MemorySwapMax'] == '0'
    assert Path('/proc', owner['MainPID'], 'exe').samefile(BINARY)
    start = dict(schema='foundation-epoch230-capped-bootstrap-start-v1', owner=owner, binary=source['binary'],
                 admission=admission_ref, cpus='118-121', memory_max_bytes=160 << 30, replay_launch_authorized=False)
    pending, final = STATE / 'start.pending', STATE / 'start.json'
    capacity.sealed_file(pending, (json.dumps(start) + '\n').encode(), 0o444)
    os.link(pending, final)
    pending.unlink()
    descriptor = os.open(STATE, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return capacity.binding(final)


def main():
    assert os.geteuid() == 0 and __debug__
    kit = capacity.load_existing()
    assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    os.umask(0o077)
    source = deployment()
    with kit.partition.take(), (capacity.CONTROL / 'cycle.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
            'ActiveState': 'inactive', 'Job': ''}
        print(json.dumps(admit(kit, source)))


if __name__ == '__main__':
    main()
