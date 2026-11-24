"""Prepare and admit the sealed epoch 288 root replay through the existing cadence."""

import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import ModuleType

V = Path('/var/lib/jetstreamer')
CONTROL = V / 'horizon-seven-publication-controller-v222'
ROOT = V / 'horizon288-full-v303'
SCRATCH = Path('/home/ubuntu/.jetstreamer-private/qualification-288-root-v303')
UNIT = 'horizon-qualify-288-root-singleton-v303.service'
TOKENS = V / 'horizon288-full-tokens-v303'
GUARD_RECEIPTS = V / 'horizon288-full-guard-receipts-v303'
PROOF = ROOT / 'cadence-registration.json'
PREPARED = ROOT / 'producer-prepared.json'
OLD = V / 'horizon275-full-v301-a2'
CAP = 501_073_741_824
MEMORY = 225_000_000_000
CPUS = list(range(72, 80))
REPOSITORY = '/home/ubuntu/workspace/jetstreamer'
SOURCE = 'scripts/horizon_foundation_delivery247_20261124/rooted288.py'

sys.path[:0] = [str(CONTROL), str(V / 'horizon249-delivery-v214-tools'), str(V / 'horizon230-full-v291')]
from ordinary249.delivery248 import bound, funds, props, ref


def checked(path, sha256):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha256, path
    return data


def source_pin():
    git = ['sudo', '-n', '-u', 'ubuntu', 'git', '-C', REPOSITORY]
    branch = subprocess.check_output([*git, 'rev-parse', 'origin/account-updates'], text=True, timeout=10).strip()
    subprocess.run([*git, 'merge-base', '--is-ancestor', '83659c40', branch], check=True, timeout=10)
    assert subprocess.check_output([*git, 'show', f'{branch}:{SOURCE}'], timeout=10) == Path(__file__).read_bytes()
    return branch


def sealed_text(path, content, mode=0o400):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return ref(path)


def replace_line(text, directive, line):
    lines = text.splitlines()
    position, = (index for index, value in enumerate(lines) if value.startswith(directive + '='))
    lines[position] = directive + '=' + line
    return '\n'.join(lines) + '\n'


def prepare():
    commit = source_pin()
    namespace = dict(path=str(ROOT / 'namespace.json'), sha256='369800a0385d4383d28ae3c4bf7d7297467c57e538c4cbe556e81a6f8aa800d8')
    ns = bound(namespace)
    inputs = bound(ns['namespace'])
    assert ns['result']['namespace_verified'] and not ns['result']['started_replay']
    assert ns['membership'] == inputs['bindings'] and ns['run_root'] == str(SCRATCH)
    assert ns['epoch'] == 288 and ns['terminal_slot'] == 124846819
    old_profile = bound(dict(path=str(OLD / 'profile.json'), sha256='906d455cbdbad8a0d187e2d69d1983ff42516dee3796197fb916e1f9cb242cb0'))
    service = checked(OLD / 'producer.service', '7fdc6c6934cbe977548ad25cbba4ac0caba23dc9177d91256f82c6b5b14f5c89').decode()
    service = service.replace(str(old_profile['run_root']), str(SCRATCH))
    service = service.replace('epoch 275', 'epoch 288')
    service = replace_line(service, 'AllowedCPUs', '72-79')
    service = replace_line(service, 'CPUAffinity', '72-79')
    service = replace_line(service, 'ReadOnlyPaths', ' '.join(map(str, (
        TOKENS, SCRATCH / 'output/compact-indexes', inputs['snapshot']['path'], Path(inputs['node']['path']).parent))))
    service = replace_line(service, 'BindReadOnlyPaths', ' '.join(f"{item['path']}:{dest}" for dest,item in inputs['bindings'].items()))
    service = replace_line(service, 'ExecStart', shlex.join(inputs['argv']))
    for key, value in [('JETSTREAMER_HISTORICAL_WORKER_V1_8_11', inputs['worker']['path']),
                       ('JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST', inputs['map']['path']),
                       ('JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256', inputs['map']['sha256'])]:
        earlier, = (row for row in service.splitlines() if row.startswith(f'Environment="{key}='))
        service = service.replace(earlier, f'Environment="{key}={value}"')
    assert '275' not in '\n'.join(line for line in service.splitlines() if line.startswith(('ExecStart=', 'BindReadOnlyPaths=', 'ReadOnlyPaths=')))
    for directory, mode in ((TOKENS, 0o755), (GUARD_RECEIPTS, 0o700)):
        directory.mkdir(mode=mode)
        directory.chmod(mode)
    token = sealed_text(TOKENS/'pre-start.sh', checked(Path(old_profile['token']['path']), old_profile['token']['sha256']), 0o555)
    producer = sealed_text(ROOT/'producer.service', service.encode())
    model = ref(Path('/home/ubuntu/.codex/diagnostics/horizon-rooted-singletons-v223-a1/assessment.json'))
    original = bound(model)['full_disk_models']['288']
    terms = original['terms']
    assert terms['private_bootstrap'] == inputs['snapshot']['bytes']
    assert CAP == sum(terms[k] for k in ('capped_scratch_scenario', 'archive_scenario', 'control'))
    capacity = funds.put(ROOT/'capacity-basis.json', dict(full_disk_models={'288':dict(
        original=original, incremental_disk=CAP, local_bootstrap=ns['source_restore'], local_index_proof=namespace)}, source=model))
    guard = old_profile['guard']
    template = dict(schema='jetstreamer-horizon-standalone-guard-plan-v1', unit=UNIT, invocation_id='a'*32,
        filesystem='/', worker_root=str(SCRATCH), receipt_directory=str(GUARD_RECEIPTS), maximum_worker_vmas=3500000,
        minimum_free_bytes=3770104987645, maximum_root_physical_bytes=CAP)
    plan = funds.put(ROOT/'static-guard-plan.json', template)
    validation = json.loads(subprocess.check_output([guard['path'], plan['path'], '--plan-sha256', plan['sha256'],
        '--self-sha256', guard['sha256'], '--validate-plan-only'], timeout=20))
    assert validation['validated'] and validation['unit'] == UNIT and validation['self_sha256'] == guard['sha256']
    static = funds.put(ROOT/'static-guard-validation.json', dict(plan=plan, validation=validation))
    profile = funds.put(ROOT/'profile.json', dict(schema='foundation-epoch288-full-replay-profile-v303', epoch=288,
        unit=UNIT, run_root=str(SCRATCH), worker_root=str(SCRATCH), disk_cap_bytes=CAP, memory_max_bytes=MEMORY,
        cpu_affinity=CPUS, argv=inputs['argv'], node=inputs['node'], worker=inputs['worker'], snapshot=inputs['snapshot'],
        namespace=namespace, mounts=inputs['bindings'], guard=guard, guard_receipts=str(GUARD_RECEIPTS),
        producer=producer, token=token, static_guard=static, capacity_basis=capacity, terminal_slot=ns['terminal_slot'],
        publication_authorized=False))
    return funds.put(PREPARED, dict(profile=profile, launcher=ref(Path(__file__)), branch=commit,
                                   namespace=namespace, registration_issued=False))


def specialized(filename, checksum):
    """Apply the epoch's parameters to the exact running 275 implementation."""
    prepared = bound(ref(PREPARED))
    assert prepared['profile']['path'] == str(ROOT/'profile.json')
    base = checked(OLD/filename, checksum).decode()
    # The sealed base has no epoch number embedded in these integrity digests.
    for digest in ('906d455cbdbad8a0d187e2d69d1983ff42516dee3796197fb916e1f9cb242cb0',
                   '938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d'):
        assert digest.replace('275','288') == digest
    body = base.replace('275','288').replace('v301','v303').replace('root-v303-a2','root-v303').replace('full-v303-a2','full-v303')
    body = body.replace('906d455cbdbad8a0d187e2d69d1983ff42516dee3796197fb916e1f9cb242cb0', prepared['profile']['sha256'])
    body = body.replace('519855086681', str(CAP)).replace('119231999','124847999').replace('118799104','124415782')
    body = body.replace('432000+895','432000+217').replace('896 slots','218 slots')
    target = ModuleType('foundation_rooted288_' + filename.removesuffix('.py'))
    target.__file__ = str(ROOT/filename)
    exec(compile(body, str(OLD/filename), 'exec'), target.__dict__)
    assert target.PROFILE_SHA == prepared['profile']['sha256'] and target.ROOT in (ROOT, SCRATCH)
    return target


def adapter():
    value = specialized('replay275.py', '54f6c3d63fa51312afb7eea75f8c9dd4cdeae1acdd57161806dec3e511d51944')
    assert value.UNIT == UNIT and value.CAP == CAP and value.PROOF == PROOF
    return value


def config():
    return adapter().config() if PROOF.exists() else []


def verify_replays(rows, configured):
    if PROOF.exists():
        adapter().verify_replays(rows, configured)
    else:
        assert not rows and not configured


def gate(plan, configured):
    if PROOF.exists():
        adapter().gate(plan, configured)


def retained_status_allowed():
    return adapter().retained_status_allowed()


def refresh(previous, sample, cycle):
    adapter().refresh(previous, sample, cycle)


def measure_fit(legacy, profile):
    import replay275
    measure = legacy.measure
    original = measure.source.latest
    receipt, fleet_ref, fleet = original()
    live = fleet['active']
    closed = [(row, bound(ref(V/'horizon230-slot-hashes-v304/terminal.json'))) for row in live if row['epoch']==230]
    for row, terminal in closed:
        owner = terminal['producer']
        assert (row['producer']['Id'], row['producer']['InvocationID']) == (owner['Id'], owner['InvocationID'])
        assert row['launch_receipt_sha256'] == terminal['registration']['sha256']
        assert props(owner['Id'], list(owner)) == owner and terminal['timer_drained'] == {'ActiveState':'inactive','Job':''}
    live = [row for row in live if row['epoch']!=230]
    registration, _, _, _ = replay275.evidence()
    owner = next(row['producer'] for row in live if row['epoch']==275)
    assert (owner['Id'],owner['InvocationID']) == (registration['producer'],registration['invocation_id'])
    row, = (row for row in fleet['inventory']['entries'] if row['epoch']==288)
    assert row['state']=='missing'
    measure.source.GUARDS[275] = replay275.GUARD_RECEIPTS
    try:
        measure.source.latest = lambda: (receipt, fleet_ref, dict(fleet, active=live))
        return measure.current(profile)
    finally:
        measure.source.latest = original


def install_cadence():
    edits = {'guarded_replays.py': [('import replay275\n','import replay275\nimport rooted288\n'),
                                   ('275: replay275}','275: replay275, 288: rooted288}')],
             'cycle.py': [('(229, 230, 252, 271, 275)', '(229, 230, 252, 271, 275, 288)'),
                          ('(229, 230, 271, 275)', '(229, 230, 271, 275, 288)'),
                          ("        plan['gates']['288']['next_action'] = (", "        if not (staged288/'cadence-registration.json').exists():\n            plan['gates']['288']['next_action'] = (")]}
    files = {}
    for filename, replacements in edits.items():
        original = CONTROL/filename
        old = original.read_text()
        content = old
        for marker, replacement in replacements:
            assert content.count(marker)==1, (filename, marker)
            content = content.replace(marker,replacement)
        ast.parse(content, filename=filename)
        files[original] = (old, content)
    previous, installed = [], []
    for original, (old, content) in files.items():
        previous.append(sealed_text(ROOT/(original.name+'.previous'),old.encode()))
        with tempfile.NamedTemporaryFile(dir=CONTROL, delete=False, mode='w') as staged:
            os.fchmod(staged.fileno(),0o400)
            staged.write(content)
            staged.flush()
            os.fsync(staged.fileno())
            name = staged.name
        os.replace(name,original)
        installed.append(ref(original))
    descriptor = os.open(CONTROL, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    funds.put(ROOT/'cadence-deployment.json', dict(previous=previous, installed=installed,
                                                   adapter=ref(Path(__file__)), publication_authorized=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare','check','launch'))
    action = parser.parse_args().operation
    assert os.geteuid()==0 and os.environ['CODEX_THREAD_ID']=='01a1f8f4-293b-7a91-a36e-2e7658bba721'
    os.umask(0o077)
    source_pin()
    if action=='prepare':
        with (CONTROL/'cycle.lock').open('a+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            print(prepare())
        return
    legacy = specialized('admit.py','a069ca99197b56c8c177f135489f805bbed059618d24c39eb6c7f38d5c69ba2c')
    assert legacy.PRODUCER==UNIT and legacy.REGISTRATION==PROOF and legacy.TOKENS==TOKENS
    with legacy.partition.take(), (CONTROL/'cycle.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert legacy.partition.locked(legacy.partition.LOCK,os.getpid())
        assert props('foundation-publication-cadence-v222.service',['ActiveState','Job'])=={'ActiveState':'inactive','Job':''}
        assert not (ROOT/'cadence-deployment.json').exists()
        profile, properties, argv = legacy.inputs()
        inventory = legacy.inventory()
        fit = measure_fit(legacy,profile)
        guard = legacy.guard_template(profile,fit)
        forecast = legacy.initial_eta(fit)
        missing = (fit['disk_shortfall_bytes'], fit['memory_shortfall_bytes'])
        print(dict(shortfall=missing, headroom=fit['free_bytes']-fit['protected_disk_bytes']-CAP),flush=True)
        if action=='launch':
            assert missing==(0,0)
            assert (CONTROL/'rooted288.py').samefile(__file__)
            install_cadence()
            legacy.start(profile,properties,argv,fit,inventory,guard,forecast)


if __name__=='__main__':
    main()
