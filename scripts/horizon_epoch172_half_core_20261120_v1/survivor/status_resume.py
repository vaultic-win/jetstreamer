"""Resume the interrupted November 23 cadence publication under the original lock."""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import time

ROOT = Path('/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1')
PACKAGE = ROOT / 'tools-cold168-retry4-resume-v1'
TAG = 'COLD168_RETRY4_V1_STATUS_'
PRIOR = ROOT / (TAG + 'ACTIVE.json')
INTENT = ROOT / (TAG + 'RESUME_INTENT.json')
ACTIVE = ROOT / (TAG + 'RESUME_ACTIVE.json')
PRIOR_SHA = '16cd7406abfd04bee0ae5ad8120e095507eeb7928f3ce670a8bb83328fc414ff'
OLD_PACKAGE_SHA = 'f376852cea39bbe1739a7b388c026e4a630842f9fb3c480082ec72fd9070019d'
WRITER_IID = 'e83c7741fbb843029b110f1369e973a4'
REJECTED_IID = 'd3c726dc3143441b80687e0c9504221b'
OBSERVER_IID = '4841114e224e46818d421bc9a10ce01e'
CUT = '2026-11-23T23:47:57Z'
FLEET_SHA = '7e45aafe0709ddd977f622a8a3ad1041678852bce5755d7268245cf07c90c037'
SAMPLE_SHA = '8ea7d08de19c26038d88f69a4f7df04e90df4b6cc45c3a7a4b65ebba8e05094c'
PUT_INTENT_SHA = 'a5dc7f5895f83b4ea3d9f3f26e9f2f8b81f46c1275e9bbde812376a6b2a6837b'
OWNER_CHECK = ROOT / 'retry13-170-switch-v2/handoff_cold167.py'
OWNER_CHECK_SHA = '7f189ae92d13bca515099267852c1551fa43f159387eee7af5ec48839933260d'
BOOT = '763ea84ca81f4dddad364b1ea2ba36dd'


def need(condition, why):
    if not condition:
        raise ValueError(why)


def journal(unit, iid, message_id, seq, result):
    query = ['/usr/bin/journalctl', '--no-pager', '-ojson', '_BOOT_ID=' + BOOT, '_PID=1',
             'UNIT=' + unit, 'INVOCATION_ID=' + iid, 'MESSAGE_ID=' + message_id]
    row, = [json.loads(line) for line in subprocess.check_output(query, timeout=15).splitlines()]
    need(row['_BOOT_ID'] == BOOT and row['_PID'] == '1' and row['UNIT'] == unit
         and row['INVOCATION_ID'] == iid and row['MESSAGE_ID'] == message_id
         and row['__CURSOR'].split(';')[1] == 'i=' + seq
         and (not result or (row['COMMAND'], row['EXIT_CODE'], row['EXIT_STATUS']) == ('ExecStart','exited','1')),
         'different PID1 recovery event')
    return {key: row[key] for key in ('__CURSOR', '__REALTIME_TIMESTAMP', 'UNIT', 'INVOCATION_ID', 'MESSAGE_ID')}


def previous(c):
    ref = c['bound'](PRIOR)
    need(ref['sha256'] == PRIOR_SHA, 'historical retry4 adoption changed')
    old = c['checked'](ref)['new']
    need(old['invocation_id'] == WRITER_IID and old['unit'] == c['CONTROLLER']
         and old['lock']['inode'] == 100222432 and old['lock']['device'] == 64512,
         'different original writer or consumer lock')
    return ref, old


def prior_sealer():
    from evidence import SEALER
    return SEALER


def package(c, seal_ref, old):
    seal = c['checked'](seal_ref)
    prior_ref = c['bound'](Path(old['program']).parent / 'deployment-seal-receipt.json')
    need(prior_ref['sha256'] == OLD_PACKAGE_SHA and seal_ref['path'] == str(PACKAGE / 'deployment-seal-receipt.json')
         and seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1'
         and seal['sealer_sha256'] == prior_sealer() and seal['destination'] == str(PACKAGE)
         and seal['remote_mutations'] is False, 'different resume deployment')
    prior = c['checked'](prior_ref)
    original = {m['name']: m for m in prior['members']}
    members = {m['name']: m for m in seal['members']}
    need(len(members) == len(seal['members']) and set(members) == set(original) | {'status_resume.py'},
         'unexpected resume members')
    for name, member in members.items():
        need(Path(name).name == name and c['bound'](PACKAGE / name)['sha256'] == member['sha256'],
             'different sealed resume member ' + name)
        need(member['mode'] == '0444' and (name in ('status_cycle.py', 'status_resume.py')
             or member['sha256'] == original[name]['sha256']), 'changed inherited cadence logic ' + name)


def pending(c):
    """Freeze the completed native sample and only the already prepared status products."""
    paths = c['names'](CUT)
    head = dict(path=str(c['names']('2026-11-23T23:17:57Z')['out'] / 'ROOT_COMPLETE_OPERATIONAL_FLEET.json'),
                sha256=FLEET_SHA)
    fleet = c['checked'](head)
    config = fleet['sole_next_observer']
    cfg = c['sealed'](config)
    sample = dict(path=str(paths['sample']), sha256=SAMPLE_SHA)
    native = c['checked'](sample)
    need(fleet['sole_next_timer'] == paths['timer'] and cfg['not_before_utc'] == CUT
         and cfg['output'] == sample['path'] and c['check_sample'](fleet, native, cfg) == CUT,
         'different pending observer sample')
    out = paths['out']
    need(not any((out / name).exists() for name in ('ROOT_COMPLETE_OPERATIONAL_FLEET.json', 'NEXT_DUE.json'))
         and not c['timer_names'](), 'pending sample is already sealed or another timer is armed')
    products = {}
    for name, digest, key in (
        ('FULL172_OBSERVATION.json','5dd48236e49cfcaaaffa86bca96e445c21766551aab2d7372e3a0cf580544130','fleet'),
        ('CYCLE_OBSERVATION.json','4f1e3ebc7b3410a7f75e9aa3515ec2e9b84b5ce71d8045b876bd72fbe397077c','fleet_predecessor'),
        ('RECOVERED_WORKERS.json','d5fd95cc80e349dab54ebc69972876719400cde1405e6acb93c2fc25f33c1b2a','fleet'),
    ):
        ref = dict(path=str(out / name), sha256=digest)
        product = c['checked'](ref)
        need(product[key] == head and product.get('observer', product.get('sample')) == sample,
             'different original cycle product')
        products[name] = ref
    plans = {}
    for path in sorted(paths['statuses'].glob('epoch-*.intent.json')):
        ref = c['bound'](path)
        plan = c['checked'](ref)
        epoch = plan['epoch']
        need(path.name == f'epoch-{epoch}.intent.json' and str(epoch) in fleet['complete_active_status_receipts']
             and plan['observer'] == sample and plan['fleet_predecessor'] == head,
             'different partial status intent')
        item = {'intent': ref}
        published = path.with_name(f'epoch-{epoch}.receipt.json')
        if published.is_file():
            item['receipt'] = c['bound'](published)
            receipt = c['checked'](item['receipt'])
            need(isinstance(receipt['after_etag'], str) and receipt == dict(
                plan, after_etag=receipt['after_etag'], authenticated_readback=True), 'different partial status receipt')
        plans[str(epoch)] = item
    need(len(plans) >= 15 and plans.get('172', {}).get('intent', {}).get('sha256') == PUT_INTENT_SHA,
         'missing original interrupted status intent')
    observer = paths['timer'].removesuffix('.timer') + '.service'
    completed = journal(observer, OBSERVER_IID, '7ad2d189f7e94e70a38c781354912448', '3940027', False)
    need(c['owners'].show(observer, ('ActiveState', 'MainPID', 'Job')) ==
         dict(ActiveState='inactive', MainPID='0', Job=''), 'original observer still live')
    return dict(fleet=head, config=config, completed_sample=sample, observer=completed,
                products=products, previous_status_products=plans)


def recover_intent(c, seal_ref):
    prior, old = previous(c)
    package(c, seal_ref, old)
    exits = [journal(old['unit'], iid, '98e322203f7a4ed290d09fe03c09fe15', seq, True)
             for iid, seq in ((WRITER_IID,'394009d'), (REJECTED_IID,'3940106'))]
    return dict(schema='horizon-retry4-status-resume-intent-v1', prior_active=prior, old=old,
                package=seal_ref, terminal=exits, schedule=pending(c))


def exclusive(old, fd):
    lock = old['lock']
    path = Path(lock['path'])
    held = os.fstat(fd)
    current = path.lstat()
    need(os.path.samestat(held, current) and (held.st_dev, held.st_ino) == (lock['device'], lock['inode']),
         'different sole consumer.lock')


def assert_actor(old, actor, unit, pid, start_ticks, fd):
    lock = dict(old['lock'], fd=fd)
    need(actor['unit'] == old['unit'] == unit['Id'] and actor['program'] == str(PACKAGE / 'status_cycle.py')
         and actor['pid'] == pid == int(unit['MainPID']) and actor['start_ticks'] == start_ticks
         and actor['invocation_id'] == unit['InvocationID']
         and re.fullmatch('[a-f0-9]{32}', actor['invocation_id'])
         and actor['invocation_id'] not in (WRITER_IID, REJECTED_IID)
         and actor['lock'] == lock, 'unregistered resumed cadence owner')


def mark_intent(c, seal_ref):
    _, old = previous(c)
    lockfd = c['lock'](Path(old['lock']['path']))
    try:
        exclusive(old, lockfd)
        props = ('ActiveState','SubState','InvocationID','Result','ExecMainStatus','MainPID','ControlPID','Job','ControlGroup')
        mgr = c['owners'].show(old['unit'],props)
        need(mgr == dict(ActiveState='failed', SubState='failed', InvocationID=REJECTED_IID,
                         Result='exit-code', ExecMainStatus='1', MainPID='0', ControlPID='0', Job='',
                         ControlGroup='') and not ACTIVE.exists(), 'different drained cadence incumbent')
        c['durable'](INTENT, recover_intent(c, seal_ref))
        return c['bound'](INTENT)
    finally:
        os.close(lockfd)


def mark_active(c, seal_ref):
    intent_ref = c['bound'](INTENT)
    intent = c['checked'](intent_ref)
    need(intent == recover_intent(c, seal_ref), 'changed interrupted sample or registration')
    need(c['bound'](OWNER_CHECK)['sha256'] == OWNER_CHECK_SHA, 'changed native publisher inspection')
    actor = runpy.run_path(str(OWNER_CHECK))['publisher'](c, PACKAGE / 'status_cycle.py', True)
    state = c['owners'].show(c['CONTROLLER'], ('Id','MainPID','InvocationID'))
    assert_actor(intent['old'], actor, state, int(state['MainPID']), c['owners'].ticks(actor['pid']), actor['lock']['fd'])
    c['durable'](ACTIVE, dict(schema='horizon-retry4-status-resume-active-v1', intent=intent_ref, new=actor))
    return c['bound'](ACTIVE)


def await_owner(c, seal_ref, unit, fd):
    intent_ref = c['bound'](INTENT)
    intent = c['checked'](intent_ref)
    need(intent == recover_intent(c, seal_ref), 'changed interrupted sample or registration')
    exclusive(intent['old'], fd)
    deadline = time.monotonic() + 90
    while not ACTIVE.exists():
        need(time.monotonic() < deadline, 'resumed cadence owner was not registered')
        time.sleep(0.10)
    active = c['checked'](c['bound'](ACTIVE))
    pid = os.getpid()
    need(active['schema'] == 'horizon-retry4-status-resume-active-v1' and active['intent'] == intent_ref
         and c['bound'](INTENT) == intent_ref and pending(c) == intent['schedule'], 'different resume ACTIVE or sample')
    assert_actor(intent['old'], active['new'], unit, pid, c['owners'].ticks(pid), fd)
    return intent['schedule']
