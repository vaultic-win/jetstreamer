"""Adopt the exact cold retry4 local commit on the sole status cadence."""
from pathlib import Path
import runpy
import time

from evidence import BASE, bound, checked, need

DELIVERY = BASE / 'epoch168-cold-delivery-20261123-v4'
SOURCE = BASE / 'epoch168-retry4-rebook-20261123-v1'
TERMINAL = DELIVERY / 'TERMINAL_SUCCESS.json'
DRAINED = DELIVERY / 'TERMINAL_GUARD_DRAINED.json'
UNIT = 'horizon-qualify-168-full-metered-cold-v4-20261123.service'
IID = '913443d7f9f44d7e9d3e0eec420acfab'
TIMER = 'horizon-guard-168-full-metered-cold-v4-20261123.timer'
TIMER_IID = 'd5fe86a9086e417490eb8c5993c60e97'
FIELD = 'cold168_local_commit'
DRAIN = 'cold168_guard_retirement'
HISTORY = 'historical_cold168_retry4_owner'
OWNERS = 'current_homefloor_cold166_167_168_170_owners'
LIVE = dict(path=str(DELIVERY/'LIVE.json'), sha256='0ab0e88e1182f1672c5abfb612256722b101ce6beb7a78abf361f445516598d8')
ADMISSION = dict(path=str(SOURCE/'ACTUAL_ADMISSION_AND_PROTECTION.json'),
                 sha256='35ca20f8e092902e8e48c2ebd7b36d1350f6d9019904622d97c90c9e926f0e5f')
FIRST = dict(path=str(SOURCE/'FIRST_PROTECTED_WORKER.json'),
             sha256='b5ebc85757f4795d8938bf55599de02488fa49db7ff115cce3a57b5c53338fe0')
CAP = 288 << 30
STOP = '1fba7a686be4387737b8c7776a5ed92a59bff82c15ced77496e9214c94710f62'
SHARED = BASE / 'epoch170-cold-delivery-20261122-v13/guard-closure-tools'
FAILED_FIELD = 'cold168_retry4_root_physical_stop'
FAILED_INTENT = dict(path=str(SOURCE/'guard-receipts/stop-intent.json'),
                     sha256='b3dab5e0a743cfd42a7380cfa623db61c978e15c1d9b0b034d7760eead1d2926')
FAILED_COMPLETION = dict(path=str(SOURCE/'guard-receipts/stop-completion.json'),
                         sha256='b0538a4dee05df924a8d04f8562866df701c03996498963552a932059826cdab')
RETRY5_STOP_FIELD = 'cold168_retry5_physical_scan_stop'


def retry5_scan_stop(fleet, config, route):
    """Bind a retry5 guard stop before the first observer enrollment."""
    intent_ref = bound(route.ROOT/'guard-receipts/stop-intent.json')
    terminal_ref = bound(route.ROOT/'guard-receipts/stop-completion.json')
    admission_ref = bound(route.ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
    first_ref = bound(route.ROOT/'FIRST_PROTECTED_WORKER.json')
    intent, stopped = checked(intent_ref), checked(terminal_ref)
    admission, first = checked(admission_ref), checked(first_ref)
    plan_ref = admission['actual_guard_plan']
    plan, post = checked(plan_ref), checked(admission['post_guard_capacity'])
    terminal, sample = stopped['terminal'], intent['sample']
    iid = admission['producer_invocation_id']
    cap = route.CAP_GIB << 30
    need(route.ATTEMPT == 5
         and intent['schema'] == 'jetstreamer-horizon-standalone-stop-intent-v1'
         and stopped['schema'] == 'jetstreamer-horizon-standalone-stop-completion-v1'
         and stopped['intent'] == intent_ref['path']
         and stopped['plan_sha256'] == intent['plan_sha256'] == sample['plan_sha256'] == plan_ref['sha256']
         and stopped['producer_invocation_id'] == intent['producer_invocation_id']
         == sample['producer_invocation_id'] == terminal['invocation_id'] == plan['invocation_id']
         == first['producer_invocation_id'] == iid
         and admission['producer_unit'] == first['producer_unit'] == plan['unit'] == route.UNIT
         and admission['timer_unit'] == route.TIMER and first['admission'] == admission_ref
         and intent['reason'] == sample['trip_reason'] == 'root-physical-observation-failed'
         and sample['root_physical_observation_error'] == 'physical scan time bound exceeded'
         and plan['maximum_root_physical_bytes'] == sample['maximum_root_physical_bytes']
         == post['bookings']['168']['cap_bytes'] == cap
         and post['fits'] is True and post['bookings']['168']['root'] == plan['worker_root']
         and terminal['active'] == 'inactive' and terminal['sub'] == 'dead' and terminal['pid'] == 0
         and terminal['restart_policy'] == 'no' and terminal['restarts'] == 0
         and stopped['scratch_deleted'] is stopped['r2_mutations'] is stopped['remote_mutations'] is False,
         'different epoch 168 retry5 filesystem scan stop')
    from owners import show
    for unit in (route.UNIT, route.TIMER.removesuffix('.timer') + '.service'):
        fields = ('ActiveState', 'MainPID', 'ControlPID', 'ControlGroup', 'Job', 'InvocationID')
        need(show(unit, fields) == dict(ActiveState='inactive', MainPID='0', ControlPID='0',
                                        ControlGroup='', Job='', InvocationID=''),
             'epoch 168 retry5 producer or guard remains present')
    need(show(route.TIMER, ('ActiveState', 'Job', 'InvocationID')) ==
         dict(ActiveState='inactive', Job='', InvocationID='')
         and not Path('/sys/fs/cgroup/system.slice', route.UNIT).exists(),
         'epoch 168 retry5 timer or cgroup remains present')
    need(not fleet.get(OWNERS, {}).get('168')
         and not any(row['epoch'] == 168 for field in (
             'actual_executing_replays', 'actual_active_bootstraps', 'actual_active_private_diagnostics'
         ) for row in fleet[field])
         and not any(row['range'] == '168' for row in config['replays']),
         'retry5 stopped after observer enrollment')
    proof = dict(terminal=terminal_ref, stop_intent=intent_ref, admission=admission_ref,
                 first_worker=first_ref, producer_invocation_id=iid, retired_guard_timer=route.TIMER,
                 retained_cap_bytes=cap, resource_credit_bytes=0, reservation_ending_bytes=0)
    need(fleet.get(RETRY5_STOP_FIELD, proof) == proof, 'changed adopted retry5 scan stop')
    return proof


def closure():
    receipt = checked(dict(path=str(SHARED/'deployment-seal-receipt.json'),
                           sha256='54222b83d9d87dc900cb6a0e97a8c4e9e7e0d8763c429bb6e678f7033135a8d0'))
    member, = (row for row in receipt['members'] if row['name'] == 'closure.py')
    path = SHARED/'closure.py'
    need(receipt['destination'] == str(SHARED) and member['mode'] == '0444'
         and bound(path)['sha256'] == member['sha256'], 'unsealed shared guard closure')
    shared = runpy.run_path(str(path))
    guard = shared['GuardClosure'](
        168, DELIVERY, SOURCE, UNIT, IID, TIMER, TIMER_IID,
        LIVE['sha256'], ADMISSION['sha256'], 0o444, FIRST['sha256'],
        '9b81b519d62027b770229eb2595d7907044bbf1bffb6e13f9b1f589d5b59aab7',
        witness_mode=0o400,
    )
    return guard, shared


def check_owner(owner):
    live = checked(LIVE)
    actor = dict(producer_unit=UNIT, producer_invocation_id=IID,
                 producer_pid=live['native']['parent']['pid'], start_ticks=live['native']['parent']['start_ticks'])
    need(owner and owner['actor'] == actor and owner['admission'] == ADMISSION
         and owner['first_worker'] == FIRST, 'different cold168 retry4 owner')
    return owner


def check_scheduled(fleet, config):
    rows = [row for row in config['replays'] if row['range'] == '168']
    need(not rows or (FIELD not in fleet and rows == [checked(FIRST)['observer_row']]),
         'different scheduled cold168 retry4 worker')


def bind(fleet, proof):
    term = proof['terminal']
    need(term['path'] == str(TERMINAL) and proof['live'] == LIVE
         and proof['admission'] == ADMISSION and proof['first_worker'] == FIRST
         and proof['producer_invocation_id'] == IID and proof['timer_unit'] == TIMER
         and proof['timer_invocation_id'] == TIMER_IID and proof['resource_credit_bytes'] == 0,
         'foreign cold168 terminal')
    groups = ('actual_executing_replays', 'actual_active_bootstraps', 'actual_active_private_diagnostics')
    rows = [row for key in groups for row in fleet[key] if row['epoch'] == 168]
    owner = fleet.get(OWNERS, {}).get('168')
    if FIELD in fleet:
        check_owner(fleet.get(HISTORY))
        need(not rows and owner is None and fleet[FIELD] == term and fleet[DRAIN] == proof['guard_retirement'],
             'cold168 terminal or guard changed after adoption')
    else:
        owner = check_owner(owner)
        need(len(rows) == 1 and rows[0]['admission'] == ADMISSION and rows[0]['unit']['Id'] == UNIT
             and rows[0]['unit']['InvocationID'] == IID and rows[0]['start_ticks'] == owner['actor']['start_ticks']
             and DRAIN not in fleet and HISTORY not in fleet, 'prior fleet did not own cold168 retry4')
    if 'guard_retirement' in proof:
        need(proof['guard_retirement']['path'] == str(DRAINED), 'foreign cold168 guard retirement')


def known_exit():
    """Only wait for the subscriber when the exact producer can be exiting."""
    from owners import show
    producer = show(UNIT, ('Id', 'ActiveState', 'MainPID', 'ControlPID', 'Job', 'InvocationID'))
    return (producer['Id'] == UNIT and producer['InvocationID'] in ('', IID) and not producer['Job']
            and producer['ActiveState'] in ('inactive', 'deactivating')
            and producer['MainPID'] == producer['ControlPID'] == '0')


def current(fleet, config=None):
    if not TERMINAL.exists():
        need(FIELD not in fleet and not DRAINED.exists(), 'registered cold168 terminal disappeared')
        if fleet.get(OWNERS, {}).get('168') and known_exit():
            check_owner(fleet[OWNERS]['168'])
            deadline = time.monotonic() + 30
            while not TERMINAL.exists() and time.monotonic() < deadline:
                time.sleep(0.25)
        if not TERMINAL.exists():
            return None

    if config is not None:
        check_scheduled(fleet, config)
    guard, shared = closure()
    if FIELD in fleet:
        # The accepted drain binds the original native inspection. Later custody
        # or local retirement can remove the original archive and its checksum.
        intent, intent_ref = shared['document'](guard.intent_path, 0o400)
        done, drain_ref = shared['document'](guard.completion_path, 0o400)
        need(done['intent'] == intent_ref and done['binding'] == intent['binding']
             and intent['binding']['terminal'] == bound(TERMINAL), 'cold168 drain evidence changed')
        guard.expected_timer(intent['before'])
        shared['drained'](guard.guard_timer)
        shared['drained'](guard.guard_service)
        proof = dict(done['binding'], guard_retirement=drain_ref)
    else:
        proof = guard.inspect() if DRAINED.exists() else guard.committed()
        bind(fleet, proof)
        # Validate the retained production booking before touching the guard.
        retained_booking(proof)
        if 'guard_retirement' not in proof:
            drained = guard.retire()
            need(all(drained.get(k) == v for k, v in proof.items()), 'cold168 terminal changed during drain')
            proof = drained
    bind(fleet, proof)
    return proof


def retained_booking(proof):
    admission = checked(proof['admission'])
    fit = checked(admission['post_guard_capacity'])
    plan = checked(admission['actual_guard_plan'])
    booking = fit['bookings']['168']
    need(fit['epoch'] == 168 and fit['fits'] and booking['cap_bytes'] == plan['maximum_root_physical_bytes'] == CAP
         and booking['root'] == plan['worker_root'] and plan['invocation_id'] == IID and plan['unit'] == UNIT
         and admission['resource_credit_bytes'] == 0, 'cold168 retained booking changed')
    return dict(terminal=proof['terminal'], guard_retirement=proof.get('guard_retirement'),
                admission=ADMISSION, post_guard_capacity=admission['post_guard_capacity'],
                retained_cap_bytes=CAP, resource_credit_bytes=0, reservation_ending_bytes=0)


def guard_stop(fleet, config, *, successor=None):
    from owners import show

    intent, stopped = checked(FAILED_INTENT), checked(FAILED_COMPLETION)
    admission, first = checked(ADMISSION), checked(FIRST)
    plan = checked(admission['actual_guard_plan'])
    terminal, sample = stopped['terminal'], intent['sample']
    observed = sample['root_physical_observation']
    need(intent['schema'] == 'jetstreamer-horizon-standalone-stop-intent-v1'
         and stopped['schema'] == 'jetstreamer-horizon-standalone-stop-completion-v1'
         and stopped['intent'] == FAILED_INTENT['path']
         and stopped['plan_sha256'] == intent['plan_sha256'] == sample['plan_sha256']
         == admission['actual_guard_plan']['sha256']
         and first['admission'] == ADMISSION and plan['unit'] == UNIT and admission['timer_unit'] == TIMER
         and admission['timer_invocation_id'] == TIMER_IID
         and stopped['producer_invocation_id'] == intent['producer_invocation_id']
         == sample['producer_invocation_id'] == terminal['invocation_id'] == plan['invocation_id']
         == first['producer_invocation_id'] == IID
         and intent['reason'] == sample['trip_reason'] == 'root-physical-budget'
         and plan['maximum_root_physical_bytes'] == observed['maximum_physical_bytes'] == CAP
         and observed['exceeds_budget'] and observed['conservative_physical_bytes'] > CAP
         and terminal['active'] == 'inactive' and terminal['sub'] == 'dead' and terminal['pid'] == 0
         and terminal['restarts'] == 0 and terminal['restart_policy'] == 'no'
         and stopped['scratch_deleted'] is False and stopped['r2_mutations'] is False
         and stopped['remote_mutations'] is False and not TERMINAL.exists() and not DRAINED.exists(),
         'different epoch 168 retry4 guard stop')
    for unit in (UNIT, TIMER.removesuffix('.timer') + '.service'):
        fields = ('ActiveState', 'MainPID', 'ControlPID', 'ControlGroup', 'Job', 'InvocationID')
        state = show(unit, fields)
        need(state['ActiveState'] == 'inactive' and state['MainPID'] == state['ControlPID'] == '0'
             and not state['Job'] and not state['ControlGroup'] and not state['InvocationID'],
             'epoch 168 producer or guard is present after the stop')
    need(show(TIMER, ('ActiveState', 'Job', 'InvocationID')) ==
         dict(ActiveState='inactive', Job='', InvocationID=''), 'epoch 168 timer remains active')
    need(not Path('/sys/fs/cgroup/system.slice', UNIT).exists(), 'epoch 168 cgroup remains present')
    result = dict(terminal=FAILED_COMPLETION, stop_intent=FAILED_INTENT, admission=ADMISSION,
                  first_worker=FIRST, producer_invocation_id=IID, retired_guard_timer=TIMER,
                  measured_physical_bytes=observed['conservative_physical_bytes'],
                  retained_cap_bytes=CAP, resource_credit_bytes=0, reservation_ending_bytes=0)
    retained_booking(result)
    live = [row for rows in ('actual_executing_replays', 'actual_active_bootstraps',
                             'actual_active_private_diagnostics') for row in fleet[rows] if row['epoch'] == 168]
    scheduled = [row for row in config['replays'] if row['range'] == '168']
    owner = fleet.get(OWNERS, {}).get('168')
    if FAILED_FIELD in fleet:
        check_owner(fleet.get(HISTORY))
        need(fleet[FAILED_FIELD] == result, 'changed adopted epoch 168 guard stop')
        if successor is None:
            need(not owner and not live and not scheduled, 'stopped epoch 168 still has a live row')
        else:
            successor.verify_retained_population(result, owner, live, scheduled)
    else:
        need(successor is None, 'retry5 requires the previously adopted retry4 stop')
        check_owner(owner)
        need(len(live) == 1 and live[0]['admission'] == ADMISSION and live[0]['unit']['Id'] == UNIT
             and live[0]['unit']['InvocationID'] == IID
             and live[0]['start_ticks'] == owner['actor']['start_ticks']
             and scheduled == [first['observer_row']], 'different pre-stop epoch 168 census')
    return result


def install_guard_stop(predecessor, fleet, proof):
    need(not fleet.get(OWNERS, {}).get('168'), 'stopped epoch 168 still has a live owner')
    previous_owner = predecessor.get(HISTORY) if FAILED_FIELD in predecessor else predecessor[OWNERS]['168']
    fleet[HISTORY] = check_owner(previous_owner)
    fleet[FAILED_FIELD] = proof
    row = next(item for item in fleet['epochs'] if item['epoch'] == 168)
    prior_stop = row.pop('current_home_floor_stop', row.get('original_home_floor_stop'))
    need(prior_stop['completion']['sha256'] == STOP, 'lost epoch 168 predecessor')
    row.pop('current_replay', None)
    row.update(original_home_floor_stop=prior_stop, state='failed-needs-repair',
               no_live_producer_claimed=True, repair_open=True, current_repair_owner='/root',
               current_status_scope='Epoch 168 retry4 stopped when its replay tree exceeded its disk budget.',
               next_action='Qualify an exact guarded replay from the retained bootstrap.',
               **{FAILED_FIELD: proof})


def install(predecessor, fleet, proof):
    need(not fleet.get(OWNERS, {}).get('168'), 'committed cold168 still has a current owner')
    row = next(item for item in fleet['epochs'] if item['epoch'] == 168)
    previous = row.pop('current_home_floor_stop', row.get('original_home_floor_stop'))
    need(previous['completion']['sha256'] == STOP, 'lost stopped predecessor of committed cold168')
    owner = predecessor.get(HISTORY) if FIELD in predecessor else predecessor.get(OWNERS, {}).get('168')
    fleet.update({FIELD: proof['terminal'], DRAIN: proof['guard_retirement'], HISTORY: check_owner(owner),
                  'retained_cold168_retry4_reservation': retained_booking(proof)})
    row.update(original_home_floor_stop=previous, cold168_local_commit=proof['terminal'],
               cold168_guard_retirement=proof['guard_retirement'], state='verification',
               no_live_producer_claimed=True, repair_open=False, current_repair_owner='/root',
               current_status_scope='Epoch 168 retry4 committed locally and awaits archive verification and delivery.',
               next_action='Verify the retained epoch 168 archive before public delivery.')
