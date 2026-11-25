"""Start the private epoch 229 called-program replay from its qualified artifacts."""

import ast
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

STATE = Path('/var/lib/jetstreamer/horizon229-called-program-demotion-v1')
CONTROL = STATE.parent / 'horizon-seven-publication-controller-v222'
QUOTE = STATE.parent / 'horizon226-suffix-v1/capacity-epoch229-demotion-v1.py'
QUOTE_SHA = 'a6fd4e791d4c6102533488708865ddde38feffb8e1294f1bd2c3f8d0f8b51ce6'
PARENT_SHA = '060d1807204f66d65854438334847c52a5f3b4c3264fc32fb60243bc42128cfa'
SHARED = 'epoch230_checkpoint_continuation_launch.py'
SOURCE = Path('scripts/horizon_foundation_delivery247_20261124')
REPO = Path('/home/ubuntu/workspace/jetstreamer')
UNIT = 'horizon-qualify-229-called-program-demotion-v1.service'
ADAPTER = 'diagnostic229_bank_delta.py'


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def git(*args):
    return subprocess.check_output(['runuser', '-u', 'ubuntu', '--', 'git', '-C', str(REPO), *args], timeout=20)


def replace(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(stream.name, path)
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install_controller(cap, kit, commit):
    cycle = CONTROL / 'cycle.py'
    adapter = CONTROL / ADAPTER
    for path, digest in ((cycle, 'd765309d8bcc71345d2efa3ae2ce61f4faddd5460390da8068ffdbffede4441c'),
                         (adapter, '1f88f9b29321946c0c00340620af57ad4bce04b6d895b23506071a2789c6d6d5')):
        cap.checked(cap.fixed(path, digest))
    before = {path: path.read_bytes() for path in (adapter, cycle)}
    anchor = b'        fleet_image = Path(publication_handoff.checked_image(continuation_image))\n'
    assert before[cycle].count(anchor) == 1
    hook = (b'    demotion_image = diagnostic229_bank_delta.register_demotion(plan)\n'
            b'    if demotion_image is not None:\n'
            b'        fleet_image = Path(publication_handoff.checked_image(demotion_image))\n')
    after = {adapter: git('show', f'{commit}:{SOURCE / ADAPTER}'),
             cycle: before[cycle].replace(anchor, anchor + hook)}
    for path, data in after.items():
        ast.parse(data, str(path))
        backup = STATE / ('before-' + path.name)
        assert not backup.exists()
        replace(backup, before[path])
    try:
        for path, data in after.items():
            replace(path, data)
        return kit.ops.funds.put(STATE / 'cadence-deployment.json', {
            'source_commit': commit, 'installed': {p.name: cap.binding(p) for p in after},
            'before': {p.name: cap.binding(STATE / ('before-' + p.name)) for p in before}})
    except Exception:
        for path, data in before.items():
            replace(path, data)
        raise


def main():
    assert __debug__ and os.geteuid() == 0 and len(sys.argv) == 2 and re.fullmatch('[a-f0-9]{64}', sys.argv[1])
    os.umask(0o077)
    commit = git('rev-parse', 'origin/account-updates').decode().strip()
    for path in (Path(__file__), STATE / SHARED, QUOTE):
        name = 'epoch288_shrink_debt_comparison.py' if path == QUOTE else path.name
        stamp = path.lstat()
        assert path.resolve() == path and stamp.st_uid == 0 and not stamp.st_mode & 0o222
        assert path.read_bytes() == git('show', f'{commit}:{SOURCE / name}')
    assert hashlib.sha256(QUOTE.read_bytes()).hexdigest() == QUOTE_SHA
    cap, shared = module(QUOTE), module(STATE / SHARED)
    kit = cap.load_existing()
    assert os.environ['CODEX_THREAD_ID'] == kit.replay.THREAD
    parent_ref = cap.fixed(STATE / 'parent-qualification.json', PARENT_SHA)
    parent = cap.read(parent_ref)
    profile = cap.read(parent['preparation'])
    namespace = cap.read(parent['input_namespace'])
    assert namespace['preparation'] == parent['preparation'] and namespace['namespace']['input_namespace_verified']
    assert namespace['worker_qualification'] == parent['worker_qualification'] and parent['systemd_static_verified']
    worker = cap.read(parent['worker_qualification'])
    assert parent['capability']['worker_sha256'] == worker['artifact']['sha256']
    for image in (worker['artifact'], parent['artifact'], profile['guard'], profile['prestart'], profile['trusted_hashes']):
        cap.checked(image)
    for source in (worker['source_commit'], parent['source_commit']):
        git('merge-base', '--is-ancestor', source, commit)
    plan = cap.read(profile['static_guard_plan'])
    guard, tokens = profile['guard_unit'], Path(profile['tokens'])
    timer = guard.replace('.service', '.timer')
    assert plan['unit'] == profile['unit'] == UNIT and profile['guard_validation']['validated']
    assert plan['maximum_root_physical_bytes'] == profile['ram_scratch_cap_bytes'] == 170_000_000_000
    assert plan['filesystem'] == str(Path(profile['run_root']).parent)
    assert plan['receipt_directory'] == str(STATE / 'guard-receipts')
    producer = cap.checked(profile['producer'])
    props, argv = kit.startup.start_props(UNIT, producer)
    prestart, = [line for line in producer.read_text().splitlines() if line.startswith('ExecStartPre=')]
    assert argv[:3] == [parent['artifact']['path'], '229', profile['run_root'] + '/output']
    assert '--qualification-end-slot=98939266' in argv and '--verify' in argv
    assert '--snapshot-archive=' + profile['bootstrap']['path'] in argv
    stamp = Path(profile['bootstrap']['path']).stat()
    boot = profile['bootstrap']
    assert (stamp.st_dev, stamp.st_ino, stamp.st_size, stamp.st_ctime_ns) == (
        boot['device'], boot['inode'], boot['size'], boot['ctime_ns'])
    fleet_ref = cap.fixed(STATE / 'fleet-tool.json', sys.argv[1])
    fleet = cap.read(fleet_ref)
    cap.checked(fleet['artifact'])
    git('merge-base', '--is-ancestor', fleet['source_commit'], commit)
    with kit.partition.take(), (CONTROL / 'cycle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert kit.partition.locked(kit.partition.LOCK, os.getpid())
        assert kit.ops.props('foundation-publication-cadence-v222.service', ['ActiveState', 'Job']) == {
            'ActiveState': 'inactive', 'Job': ''}
        for name in (UNIT, guard, timer):
            assert kit.ops.props(name, ['LoadState', 'ActiveState', 'Job']) == {
                'LoadState': 'not-found', 'ActiveState': 'inactive', 'Job': ''}, name
        assert not list(tokens.iterdir()) and not list((STATE / 'guard-receipts').iterdir())
        assert not (STATE / 'admission.json').exists()
        inventory = shared.inventory(kit, 229, 'foundation-229-demotion-inventory-v1')
        fit = cap.capacity(kit, candidate_epoch=229)
        assert fit['candidate_cpus'] == profile['cpu'] and fit['candidate_memory_max_bytes'] == profile['memory_max_bytes']
        assert fit['disk_shortfall_bytes'] == fit['memory_shortfall_bytes'] == fit['tmpfs_shortfall_bytes'] == 0
        deployment = install_controller(cap, kit, commit)
        assert time.time() - fit['sampled_unix_seconds'] < 20
        admission = kit.ops.funds.put(STATE / 'admission.json', {
            'epoch': 229, 'source_commit': commit, 'parent_qualification': parent_ref, 'fit': fit,
            'inventory': inventory, 'fleet_tool': fleet_ref, 'deployment': deployment, 'admitted': True,
            'publication_authorized': False})
        try:
            actor, guard_plan, token, sample = shared.activate_guarded(
                kit, 229, STATE, tokens, UNIT, guard, profile['guard'], plan, admission, props, prestart, argv)
            record = dict(schema='jetstreamer-historical-performance-launch-receipt-v1',
                          kind='epoch229-called-program-demotion', epoch=229, unit=UNIT,
                          invocation_id=actor['invocation_id'], main_pid=actor['main_pid'], node_path=argv[0],
                          run_root=plan['worker_root'], worker_sha256=worker['artifact']['sha256'],
                          bootstrap_slot=98927417, first_replay_slot=98927418, divergent_bank_slot=98931633,
                          terminal_slot=98939266, launched=True, entry_replay_requested=True,
                          canonical_epoch_publication_authorized=False, remote_mutations=False, r2_mutations=False,
                          admission=admission, guard_plan=guard_plan, launch_token=token, active_guard=sample,
                          evidence={'units': [actor]})
            print(json.dumps(kit.ops.funds.put(STATE / 'cadence-registration.json', record)))
        except Exception as error:
            fields = ['LoadState', 'ActiveState', 'InvocationID', 'Result', 'MainPID']
            observed = {name: kit.ops.props(name, fields) for name in (UNIT, timer, guard)}
            kit.ops.funds.put(STATE / 'launch-failure.json', {'error': repr(error), 'observed': observed})
            for name, row in observed.items():
                if row['LoadState'] == 'not-found' and row['ActiveState'] == 'inactive':
                    continue
                assert kit.ops.props(name, ['InvocationID'])['InvocationID'] == row['InvocationID']
                subprocess.run(['systemctl', 'stop', name], check=True, timeout=200)
            raise


if __name__ == '__main__':
    main()
