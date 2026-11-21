"""Keep the committed private diagnostic and its entire booking in the campaign inventory."""
from pathlib import Path
from evidence import checked, need

FIELD = 'focused169_terminal'
GUARD = 'focused169_guard_retirement'
HISTORY = 'historical_focused169_worker'
UNIT = 'horizon-qualify-169-focused-20261120-v4.service'
IID = '0dfa0d36fbc246c28443a1c90a82c9cb'
CAP = 96 << 30
DISPOSITIONS = {'completed-private-span', 'diagnosed-target-mismatch', 'interrupted-or-unclassified'}


def original(fleet, proof):
    for name in ('terminal','guard_retirement'):
        ref=proof.get(name)
        need(isinstance(ref,dict) and set(ref)=={'path','sha256'} and isinstance(ref['path'],str)
             and isinstance(ref['sha256'],str) and len(ref['sha256'])==64,'missing private diagnostic '+name)
    rows = [r for r in fleet['actual_active_private_diagnostics'] if r['epoch'] == 169]
    if FIELD in fleet or GUARD in fleet:
        need(not rows and fleet.get(FIELD) == proof['terminal'] and
             fleet.get(GUARD) == proof['guard_retirement'], 'changed accepted diagnostic or live owner')
        row = fleet[HISTORY]
    else:
        need(len(rows) == 1, 'missing original private 169 owner')
        row = rows[0]
    need(row['epoch'] == 169 and not row['canonical_replay_claimed'] and not row['archive_publication_authorized']
         and row['admission'] == fleet['focused169_admission'] == proof['admission']
         and row['first_guard'] == proof['first_guard'] and
         (row['unit']['Id'], row['unit']['InvocationID']) == (UNIT, IID) and
         proof['producer_invocation_id'] == IID and row['guard_timer']['Id'] == proof['timer_unit'] and
         row['guard_timer']['InvocationID'] == proof['timer_invocation_id'] and
         proof['disposition'] in DISPOSITIONS and proof['resource_credit_bytes'] == 0,
         'foreign focused diagnostic admission, guard or outcome')
    return row


def retained(fleet, proof):
    row = original(fleet, proof)
    admission = checked(proof['admission'])
    plan = checked(proof['actual_guard_plan'])
    capacity=checked(admission['post_guard_capacity'])
    need(proof['actual_guard_plan']['sha256']=='3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58' and
         capacity['epoch169_tree']['focused_root_cap']==CAP and capacity['epoch169_tree']['whole_lane']==plan['worker_root']
         and capacity['armed_guard_floor_bytes']==plan['minimum_free_bytes'] and
         row['post_guard_capacity'] == admission['post_guard_capacity'] and
         plan['maximum_root_physical_bytes'] == CAP and plan['unit'] == UNIT and
         plan['invocation_id'] == IID and plan['filesystem'] == '/home/sol', 'foreign retained focused booking')
    return dict(terminal=proof['terminal'], guard_retirement=proof['guard_retirement'], admission=proof['admission'],
                disposition=proof['disposition'], root=plan['worker_root'], retained_root_cap_bytes=CAP,
                actual_guard_plan=proof['actual_guard_plan'], post_guard_capacity=row['post_guard_capacity'],
                resource_credit_bytes=0, reservation_ending_bytes=0)


def observation(c, proof):
    row = original(c.fleet, proof)
    old = row['observer_config']
    configured = [r for r in c.cfg['diagnostic_replays'] if r['range'] == '169']
    samples = [r for r in c.sample['diagnostic_replays'] if r['range'] == '169']
    need((not configured and FIELD in c.fleet) or configured == [old], 'foreign diagnostic registration')
    need(len(samples) == len(configured), 'missing private diagnostic result')
    if samples:
        sample = samples[0]
        need(all(sample[k] == old[k] for k in ('producer_unit','expected_producer_invocation_id','scratch_path'))
             and all(sample[k] is False for k in ('ordinary_replay_claim','publication_authorized',
                                                  'replay_launch_authorized','r2_mutations')),
             'foreign diagnostic result or public outcome')
    result = dict(epoch=169, phase=proof['disposition'], admission=proof['admission'], terminal=proof['terminal'],
                  guard_retirement=proof['guard_retirement'], original_unit=UNIT, original_invocation_id=IID,
                  observer_diagnostic_result=samples[0] if samples else None, current_coordinated_observer=c.sample_ref,
                  live_owner_claimed=False, canonical_replay_claimed=False, transaction_replay_claimed=False,
                  archive_publication_authorized=False, retained_booking=retained(c.fleet, proof))
    path = c.paths['out']/'FOCUSED169_OBSERVATION.json'
    if path.exists():
        from evidence import bound
        ref = bound(path)
        captured = checked(ref)
        need(captured['current_coordinated_observer'] == c.sample_ref and captured['admission'] == proof['admission']
             and captured['first_guard'] == proof['first_guard'] and captured['unit']['InvocationID'] == IID and
             configured == [captured['scheduled_config']] and samples == [captured['observer_diagnostic_result']],
             'different private worker in frozen sample')
        result['historical_capture'] = ref
    return result


def install(c, fleet, row):
    proof = c.focused_terminal
    oldest = original(c.fleet, proof)
    need(c.diagnostic169['terminal'] == proof['terminal'] and c.diagnostic169['live_owner_claimed'] is False,
         'different terminal diagnostic at fleet acceptance')
    fleet[FIELD] = proof['terminal']
    fleet[GUARD] = proof['guard_retirement']
    fleet[HISTORY] = oldest
    fleet['current_private_169_observer_result'] = c.diagnostic169
    fleet.pop('focused169_preselected_config', None)
    if any(r['range'] == '169' for r in c.next_cfg['diagnostic_replays']):
        fleet['focused169_preselected_config'] = fleet['sole_next_observer']
    row.pop('current_private_diagnostic', None)
    row.update(no_live_producer_claimed=True, current_repair_owner='/root', repair_open=True, state='verification')
    row[FIELD] = proof['terminal']
    row[GUARD] = proof['guard_retirement']
    row['current_status_scope'] = 'The original focused diagnostic has ended. Canonical epoch 169 remains in repair.'


def authority():
    import runpy
    from evidence import BASE, bound
    root = BASE/'epoch169-focused-terminal-20261121-v1/closure-tools'
    seal = checked(dict(path=str(root/'deployment-seal-receipt.json'),
                        sha256='63b5ba5c870820feae7bcbc15b61f2872a0c13b6b3b22295775873cbfab676b3'))
    members = {m['name']: m['sha256'] for m in seal['members']}
    need(seal['destination'] == str(root) and all(members[n] == bound(root/n)['sha256'] for n in
         ('closure169.py','original169.py')),'changed private terminal receiver')
    return runpy.run_path(str(root/'closure169.py'))


def capture(fleet):
    import os
    import select
    import time
    from terminal_event import Changes
    route = authority()
    term, done = route['TERM'], route['DONE']
    if not term.exists() and not done.exists():
        need(FIELD not in fleet and GUARD not in fleet, 'registered 169 diagnostic terminal disappeared')
        parent = Path('/proc')/str(route['o']['PID'])
        try:
            info = (parent/'stat').read_text().rsplit(')',1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            info = []
        if info and info[0] not in ('X','Z') and int(info[19]) == 353303886:
            return None
    changes = Changes()
    try:
        changes.watch(route['T'])
        deadline = time.monotonic()+240
        while not done.exists():
            remaining = deadline-time.monotonic()
            need(remaining > 0 and select.select([changes.fd], [], [], remaining)[0],
                 'original diagnostic exit handler has not confirmed its guard retirement')
            os.read(changes.fd,65536)
    finally:
        changes.close()
    proof = route['inspect']()
    original(fleet, proof)
    retained(fleet, proof)
    return proof


def count(c):
    return int(bool(getattr(c,'focused_terminal',None)))


def accepted_summary(c, summary, expected_private, expected_producers):
    if summary['coordinated_private_diagnostic_169'] == c.diagnostic169:
        return (summary['active_private_diagnostic_count'], summary['active_producer_count']) == (
            expected_private, expected_producers)
    old = c.diagnostic169.get('historical_capture') if count(c) else None
    return bool(old and checked(old) == summary['coordinated_private_diagnostic_169'] and
                (summary['active_private_diagnostic_count'], summary['active_producer_count']) ==
                (expected_private+1, expected_producers+1))


def remove_preselected(c, previous):
    if not count(c):
        return previous
    rows = previous['diagnostic_replays']
    removed = [r for r in rows if r['range'] == '169']
    if removed:
        need(removed == [original(c.fleet, c.focused_terminal)['observer_config']],
             'different private diagnostic in preselected config')
    return dict(previous, diagnostic_replays=[r for r in rows if r['range'] != '169'])
