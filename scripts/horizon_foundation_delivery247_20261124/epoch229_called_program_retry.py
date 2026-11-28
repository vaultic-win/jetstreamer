"""Qualify and launch the separate bounded replay after the first epoch 229 scratch trip."""

import argparse
import ast
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time

import epoch229_called_program_launch as original

BASE = Path('/var/lib/jetstreamer')
STATE = BASE / 'horizon229-called-program-demotion-v2'
SUPPORT = BASE / 'horizon229-demotion-retry-c94d60f7-v2'
OLD = original.STATE
CONTROL = original.CONTROL
QUOTE = BASE / 'horizon226-suffix-v1/capacity-epoch229-demotion-v2.py'
ROOT = Path('/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v2/run')
TOKENS = BASE / 'horizon229-called-program-demotion-tokens-v2'
IMAGES = BASE / 'horizon229-called-program-demotion-qualified-v2'
UNIT = 'horizon-qualify-229-called-program-demotion-v2.service'
GUARD = 'horizon-229-called-program-demotion-protective-v2.service'
TIMER = GUARD.replace('.service', '.timer')
FEATURE = 'epoch229-called-program-demotion-retry'
OLD_TERMINAL_SHA = 'cd8eb4a2ae2da0210ac54f954858be2b59f09304193d9383466c50f45f66c2b6'


def fixed_package(cap, kit):
    old_terminal = cap.fixed(OLD / 'terminal.json', OLD_TERMINAL_SHA)
    terminal = cap.read(old_terminal)
    assert terminal['trip_reason'] == 'root-physical-budget'
    assert terminal['last_replay_slot'] == 98935730 and terminal['target_slot'] == 98939266
    assert not terminal['terminal_accounts_root_verified']
    assert terminal['guard_timer_drained']['ActiveState'] == 'inactive'
    assert kit.ops.props(terminal['guard_timer_before']['Id'], ['ActiveState', 'Job']) == {
        'ActiveState': 'inactive', 'Job': ''}
    remount = cap.read(cap.fixed(SUPPORT / 'tmpfs-complete.json',
                                 '758f151558828a7b41624ce6867ccc194a35a8170579412749287f5286c4d3f4'))
    assert ROOT.parent.is_mount() and ROOT.parent.stat().st_dev == remount['device']
    static = cap.read(cap.fixed(SUPPORT / 'static-guard-complete.json',
                                '0d3de0cfd119bbcc15ef0290a517e46714dfe0e3261f1cc06c61fff7e58d1710'))
    assert static['proof']['validated'] and not static['producer_started']
    plan = cap.read(static['plan'])
    assert (plan['unit'], plan['worker_root'], plan['maximum_root_physical_bytes']) == (
        UNIT, str(ROOT), 425_000_000_000)
    old_parent = cap.read(cap.fixed(OLD / 'parent-qualification.json', original.PARENT_SHA))
    old_profile = cap.read(old_parent['preparation'])
    worker = cap.read(old_parent['worker_qualification'])
    for member in (worker['artifact'], old_profile['producer'], static['guard'], old_profile['prestart']):
        cap.checked(member)
    return old_terminal, remount, static, old_parent, old_profile, worker


def verify_namespace(kit, producer, node, worker, snapshot, binds):
    props, argv = kit.startup.start_props(UNIT, producer)
    assert argv[:3] == [str(node), '229', str(ROOT / 'output')]
    proof = {
        'binds': binds, 'root': str(ROOT), 'node': str(node), 'snapshot': snapshot,
        'worker': worker, 'argv': argv,
    }
    program = r"""
from pathlib import Path
import json, os, stat, subprocess, sys
p = json.loads(sys.argv[1])
root = Path(p['root'])
assert os.getuid() == 1000
assert list((root / 'state').iterdir()) == [] and list((root / 'bank-trace').iterdir()) == []
for path, b in p['binds'].items():
    path = Path(path)
    s = path.stat()
    assert path.resolve() == path and stat.S_ISREG(s.st_mode)
    assert (s.st_dev, s.st_ino, s.st_size) == (b['device'], b['inode'], b['bytes'])
    assert os.statvfs(path).f_flag & os.ST_RDONLY
    with path.open('rb') as f:
        assert f.read(1)
snapshot = p['snapshot']
s = Path(snapshot['path']).stat()
assert (s.st_dev, s.st_ino, s.st_size, s.st_ctime_ns) == (
    snapshot['device'], snapshot['inode'], snapshot['size'], snapshot['ctime_ns'])
verified = json.loads(subprocess.check_output([p['node'], '--epoch229-demotion-capability'], text=True))
assert (verified['epoch'], verified['bootstrap_slot'], verified['bank_hash_slot'], verified['terminal_slot']) == (
    229, 98927417, 98931633, 98939266)
assert verified['run_root'] == p['root'] and not verified['worker_spawned']
assert verified['worker_sha256'] == p['worker']['sha256']
assert '--horizon-output=' + str(root / 'output' / verified['output_leaf']) in p['argv']
print(json.dumps({'capability': verified, 'input_namespace_verified': True,
                  'readonly_inputs': len(p['binds']), 'replay_started': False}))
"""
    blocked = ('--property=PrivateNetwork=', '--property=MemoryHigh=', '--property=MemoryMax=',
               '--property=RuntimeMaxSec=')
    sandbox = [item for item in props if not item.startswith(blocked)]
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--expand-environment=no',
               '--unit=foundation-229-demotion-namespace-v2', *sandbox,
               '--property=PrivateNetwork=yes', '--property=MemoryMax=2G', '--property=RuntimeMaxSec=45',
               '/usr/bin/python3', '-I', '-B', '-c', program, json.dumps(proof)]
    return json.loads(subprocess.check_output(command, text=True, timeout=60))


def prepare(cap, kit, build_ref, remote, inputs):
    predecessor, mount, static, old_parent, old_profile, worker = inputs
    build = cap.read(build_ref)
    assert build['feature'] == FEATURE and build['node_test_passed'] and build['fleet_test_passed']
    assert not build['replay_started']
    for source in (build['node_source'], build['fleet_source'], worker['source_commit']):
        original.git('merge-base', '--is-ancestor', source, remote)
    node = cap.checked(build['node'])
    cap.checked(build['fleet'])
    assert node == IMAGES / 'jetstreamer-node'

    producer = STATE / 'producer.service.template'
    text = cap.checked(old_profile['producer']).read_text()
    for old, new in (
        (old_profile['run_root'], str(ROOT)),
        (old_profile['tokens'], str(TOKENS)),
        (old_parent['artifact']['path'], str(node)),
        ('MemoryHigh=320000000000', 'MemoryHigh=450000000000'),
        ('MemoryMax=395000000000', 'MemoryMax=475000000000'),
    ):
        assert old in text
        text = text.replace(old, new)
    if producer.exists():
        assert producer.read_text() == text
    else:
        original.replace(producer, text.encode())
    namespace = verify_namespace(kit, producer, node, worker['artifact'], old_profile['bootstrap'],
                                 mount['bindings'])
    assert namespace['input_namespace_verified'] and not namespace['replay_started']
    terminal = cap.read(predecessor)
    assert Path(terminal['partial']['path']).stat().st_ino == terminal['partial']['inode']
    parent = kit.ops.funds.put(STATE / 'parent-qualification.json', {
        'epoch': 229, 'artifact': build['node'], 'capability': namespace['capability'],
        'namespace': namespace, 'build': build_ref, 'worker_qualification': old_parent['worker_qualification'],
        'predecessor': predecessor, 'producer': cap.binding(producer), 'publication_authorized': False})
    fleet = kit.ops.funds.put(STATE / 'fleet-tool.json', {
        'schema': 'foundation-epoch229-called-program-demotion-fleet-tool-v1',
        'artifact': build['fleet'], 'source_commit': build['fleet_source'], 'build': build_ref})
    return kit.ops.funds.put(STATE / 'profile.json', {
        'parent_qualification': parent, 'fleet_tool': fleet, 'producer': cap.binding(producer),
        'predecessor': predecessor, 'static_guard': static['plan'], 'guard': static['guard'],
        'namespace_verified': True, 'cpu': list(range(80, 88)), 'memory_max_bytes': 475_000_000_000,
        'publication_authorized': False})


def launch(cap, kit, shared, profile_ref, remote, inputs):
    predecessor, _, static, _, _, worker = inputs
    profile = cap.read(profile_ref)
    assert profile['predecessor'] == predecessor and profile['static_guard'] == static['plan']
    assert profile['namespace_verified'] and not profile['publication_authorized']
    parent = cap.read(profile['parent_qualification'])
    fleet = cap.read(profile['fleet_tool'])
    cap.checked(parent['artifact'])
    cap.checked(fleet['artifact'])
    original.git('merge-base', '--is-ancestor', fleet['source_commit'], remote)
    producer = cap.checked(profile['producer'])
    props, argv = kit.startup.start_props(UNIT, producer)
    prestart, = [line for line in producer.read_text().splitlines() if line.startswith('ExecStartPre=')]
    assert argv[0] == parent['artifact']['path'] and argv[:3] == [
        parent['artifact']['path'], '229', str(ROOT / 'output')]
    assert prestart.endswith(str(TOKENS)) and not any(TOKENS.iterdir())
    assert not any((STATE / 'guard-receipts').iterdir()) and not (STATE / 'admission.json').exists()
    for name in (UNIT, GUARD, TIMER):
        assert kit.ops.props(name, ['LoadState', 'ActiveState', 'Job']) == {
            'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}
    inventory = shared.inventory(kit, 229, 'foundation-229-demotion-inventory-v2')
    fit = cap.capacity(kit, candidate_epoch=229, demotion_retry=True)
    assert fit['candidate_cpus'] == profile['cpu'] and fit['candidate_memory_max_bytes'] == profile['memory_max_bytes']
    assert fit['disk_shortfall_bytes'] == fit['tmpfs_shortfall_bytes'] == fit['memory_shortfall_bytes'] == 0
    adapter = CONTROL / original.ADAPTER
    old_adapter = adapter.read_bytes()
    assert old_adapter == original.git('show', f'9e88cbaf:{original.SOURCE / original.ADAPTER}')
    next_adapter = original.git('show', f'{remote}:{original.SOURCE / original.ADAPTER}')
    ast.parse(next_adapter, str(adapter))
    old_copy = STATE / 'cadence-adapter-before.py'
    assert not old_copy.exists()
    original.replace(old_copy, old_adapter)
    original.replace(adapter, next_adapter)
    deployment = kit.ops.funds.put(STATE / 'cadence-deployment.json', {
        'source_commit': remote, 'installed': cap.binding(adapter), 'previous': cap.binding(old_copy)})
    assert time.time() - fit['sampled_unix_seconds'] < 20
    admission = kit.ops.funds.put(STATE / 'admission.json', {
        'epoch': 229, 'predecessor': predecessor, 'parent_qualification': profile['parent_qualification'],
        'fit': fit, 'inventory': inventory, 'fleet_tool': profile['fleet_tool'],
        'deployment': deployment, 'admitted': True, 'publication_authorized': False})
    try:
        actor, plan, token, sample = shared.activate_guarded(
            kit, 229, STATE, TOKENS, UNIT, GUARD, profile['guard'], cap.read(profile['static_guard']),
            admission, props, prestart, argv)
        receipt = dict(schema='jetstreamer-historical-performance-launch-receipt-v1',
                       kind='epoch229-called-program-demotion', epoch=229, unit=UNIT,
                       invocation_id=actor['invocation_id'], main_pid=actor['main_pid'], node_path=argv[0],
                       run_root=str(ROOT), worker_sha256=worker['artifact']['sha256'],
                       bootstrap_slot=98927417, first_replay_slot=98927418, divergent_bank_slot=98931633,
                       terminal_slot=98939266, launched=True, entry_replay_requested=True,
                       canonical_epoch_publication_authorized=False, remote_mutations=False, r2_mutations=False,
                       admission=admission, guard_plan=plan, launch_token=token, active_guard=sample,
                       evidence={'units': [actor]})
        return kit.ops.funds.put(STATE / 'cadence-registration.json', receipt)
    except Exception as error:
        fields = ['LoadState', 'ActiveState', 'InvocationID', 'Result', 'MainPID']
        observed = {name: kit.ops.props(name, fields) for name in (TIMER, UNIT, GUARD)}
        kit.ops.funds.put(STATE / 'launch-failure.json', {'error': repr(error), 'observed': observed})
        for name, row in observed.items():
            if row['LoadState'] == 'not-found' and row['ActiveState'] == 'inactive':
                continue
            assert kit.ops.props(name, ['InvocationID'])['InvocationID'] == row['InvocationID']
            subprocess.run(['systemctl', 'stop', name], check=True, timeout=200)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'launch'))
    parser.add_argument('path', type=Path)
    parser.add_argument('sha256')
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    remote = original.git('rev-parse', 'origin/account-updates').decode().strip()
    for file, source in ((Path(__file__), Path(__file__).name),
                         (QUOTE, 'epoch288_shrink_debt_comparison.py'),
                         (Path(original.__file__), Path(original.__file__).name),
                         (OLD / original.SHARED, original.SHARED)):
        stamp = file.lstat()
        assert file.resolve() == file and stamp.st_uid == 0 and not stamp.st_mode & 0o222
        assert file.read_bytes() == original.git('show', f'{remote}:{original.SOURCE / source}')
    cap = original.module(QUOTE)
    shared = original.module(OLD / original.SHARED)
    kit = cap.load_existing()
    assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    with kit.partition.take(), (CONTROL / 'cycle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
            'ActiveState': 'inactive', 'Job': ''}
        pointer = cap.fixed(args.path, args.sha256)
        inputs = fixed_package(cap, kit)
        if args.action == 'prepare':
            result = prepare(cap, kit, pointer, remote, inputs)
        else:
            assert args.path == STATE / 'profile.json'
            result = launch(cap, kit, shared, pointer, remote, inputs)
        print(json.dumps(result))


if __name__ == '__main__':
    main()
