"""Admit a read-only copy of the stopped epoch 229 v1 AccountsDb."""

import fcntl
import hashlib
import json
import os
import subprocess
from pathlib import Path

import epoch288_shrink_debt_comparison as fit


ROOT = Path('/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v1/run')
DEPLOYMENT = fit.V / 'horizon229-closed-accounts-stage-tools-v1'
BINARY = DEPLOYMENT / 'horizon-epoch288-appendvec-stage'
CENSUS = '1ba93110f4fc2228ff4d5112f3e6b6b4a3c9748569473c6bebceaa2fc00b6306'
CRATE = Path('tools/horizon-epoch288-appendvec-stage')
INPUTS = {
    str(CRATE / path) for path in ('Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/epoch229.rs')
} | {
    'jetstreamer-horizon-observe/src/process_references.rs',
    str(fit.SOURCE_DIRECTORY / Path(__file__).name),
    str(fit.SOURCE_DIRECTORY / Path(fit.__file__).name),
}


def approved_source():
    def git(*args):
        return subprocess.check_output(
            ['runuser', '-u', 'ubuntu', '--', 'git', '-C', str(fit.SOURCE), *args], timeout=15)

    provenance_ref = fit.binding(DEPLOYMENT / 'source.json')
    provenance = fit.read(provenance_ref)
    assert provenance['schema'] == 'foundation-epoch229-closed-accounts-build-v1'
    branch = git('rev-parse', 'origin/account-updates').decode().strip()
    commit = provenance['commit']
    git('merge-base', '--is-ancestor', commit, branch)
    assert set(provenance['inputs']) == INPUTS
    for path, digest in provenance['inputs'].items():
        assert hashlib.sha256(git('show', f'{commit}:{path}')).hexdigest() == digest, path
        assert hashlib.sha256(git('show', f'{branch}:{path}')).hexdigest() == digest, path
        if Path(path).name in (Path(__file__).name, Path(fit.__file__).name):
            fit.checked(fit.fixed(DEPLOYMENT / Path(path).name, digest))
    binary = fit.fixed(BINARY, provenance['binary_sha256'])
    fit.checked(binary)
    seal_ref = fit.binding(DEPLOYMENT / 'deployment-seal-receipt.json')
    seal = fit.read(seal_ref)
    assert seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1'
    assert seal['destination'] == str(DEPLOYMENT)
    members = {row['name']: row['sha256'] for row in seal['members']}
    for reference in (binary, provenance_ref, fit.binding(Path(__file__)), fit.binding(Path(fit.__file__))):
        assert members[Path(reference['path']).name] == reference['sha256']
    return dict(branch=branch, source=provenance_ref, seal=seal_ref, binary=binary)


def launch(kit, source):
    state = fit.STAGE229
    unit = fit.STAGE229_UNIT
    assert kit.ops.props(unit, ['LoadState', 'ActiveState', 'Job']) == {
        'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}
    assert not state.exists()
    capacity = fit.capacity(kit, candidate_epoch=229, stage229=True)
    assert capacity['disk_shortfall_bytes'] == capacity['memory_shortfall_bytes'] == 0
    assert capacity['candidate_cpus'] == [78, 79] and capacity['staging229'] is None
    assert capacity['candidate_memory_max_bytes'] == 2 << 30
    assert capacity['candidate_cap_bytes'] == fit.STAGE229_CAP + fit.STAGE229_METADATA
    state.mkdir(mode=0o700)
    admission = dict(schema='foundation-epoch229-local-accounts-stage-admission-v1',
                     recorded_unix_seconds=capacity['sampled_unix_seconds'], unit=unit,
                     source_census_sha256=CENSUS, maximum_bundle_bytes=fit.STAGE229_CAP,
                     protected_free_bytes=capacity['protected_disk_bytes'] + fit.STAGE229_METADATA,
                     admitted=True, capacity=capacity, deployment=source,
                     remote_mutations=False, retirement_authorized=False)
    admission_ref = fit.sealed_file(state / 'admission.json', (json.dumps(admission) + '\n').encode())
    properties = {
        'Type': 'exec', 'AllowedCPUs': '78-79', 'CPUQuota': '200%', 'Nice': '8',
        'MemoryMax': str(2 << 30), 'MemorySwapMax': '0', 'LimitFSIZE': str(fit.STAGE229_CAP),
        'RuntimeMaxSec': '90min', 'Restart': 'no', 'UMask': '0077', 'PrivateNetwork': 'yes',
        'ProtectSystem': 'strict', 'ProtectHome': 'read-only', 'NoNewPrivileges': 'yes',
        'ReadOnlyPaths': str(ROOT), 'ReadWritePaths': str(state),
    }
    command = ['systemd-run', '--quiet', '--unit=' + unit,
               *(f'--property={key}={value}' for key, value in properties.items()),
               '--', str(BINARY), 'stage-229']
    subprocess.run(command, check=True, timeout=15)
    owner = kit.ops.props(unit, ['Id', 'ActiveState', 'SubState', 'MainPID', 'InvocationID',
                                 'ControlGroup', 'AllowedCPUs', 'MemoryMax', 'MemorySwapMax'])
    assert (owner['Id'], owner['ActiveState'], owner['SubState']) == (unit, 'active', 'running')
    assert owner['ControlGroup'] == '/system.slice/' + unit
    assert owner['AllowedCPUs'] == '78-79' and int(owner['MemoryMax']) == 2 << 30
    assert owner['MemorySwapMax'] == '0' and int(owner['MainPID']) > 0
    assert Path('/proc', owner['MainPID'], 'exe').samefile(BINARY)
    start = dict(schema='foundation-epoch229-local-accounts-stage-start-v1', owner=owner,
                 admission=admission_ref, binary=source['binary'], argv=command,
                 remote_mutations=False, retirement_authorized=False)
    # Publish the invocation-bound token atomically before the producer can start copying.
    partial = state / 'start.pending'
    fit.sealed_file(partial, (json.dumps(start) + '\n').encode())
    ready = state / 'start.json'
    os.link(partial, ready)
    partial.unlink()
    descriptor = os.open(state, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return fit.binding(ready)


def main():
    assert os.geteuid() == 0 and __debug__
    kit = fit.load_existing()
    assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    os.umask(0o077)
    source = approved_source()
    with kit.partition.take(), (fit.CONTROL / 'cycle.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
            'ActiveState': 'inactive', 'Job': ''}
        print(json.dumps(launch(kit, source)))


if __name__ == '__main__':
    main()
