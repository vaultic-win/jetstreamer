"""Price the three guarded survivors after the captured epoch 170 growth stop."""
from pathlib import Path
import os
import runpy


G = 1 << 30
PREV = 'horizon-qualify-170-from-73746882-20261127-v1.service'
NEXT = 'horizon-qualify-170-from-73766969-20261127-v1.service'
IID = 'c3ab30cfeb05428bb8f5c48a5a44822c'
GUARD = '94796cd68618a38945f895c1dfc7c962b9c714c9334467d974c7656f0cd55ae5'
SIGTERM = '18ccc679eb54249a194df0dfc54876138dedb78db117373d6fee7b61e4468252'
INTENT = 'ff710bee1b228a99ee11121378d87fc1030986259ca40c226e819e0ce405ea01'
COMPLETION = '68148f92fdbad715b40200416efb1ac6dc040111bb167d0d5d5ceb33241ed680'
REFUSAL = '260cb827a5d466d8fdfa963660568ffb8002520c4da055c39cdaa0e6d72c09a7'
ARMED = '250c37834a4f1550e04f60d771aeca1e70976ab0a7459ff9e83ca3143974a66a'
TERMINAL169 = '07e7f475687fecb9cb5fbd154951d84443e4a134c8889f0ce1d8857b884aef3e'


def stopped(core, current, fleet):
    prior_dir = current['DEP']
    next_dir = current['NEXT_DIRECTORY']
    guard_dir = prior_dir.parent/'guard-receipts'
    exit_row, exit_ref = core.read(next_dir/'predecessor-exit/PID1_EXIT.json', SIGTERM)
    intent, intent_ref = core.read(guard_dir/'stop-intent.json', INTENT)
    end, end_ref = core.read(guard_dir/'stop-completion.json', COMPLETION)
    failure, failure_ref = core.read(next_dir/'DISPATCH_REFUSED_1795825324994665690.json', REFUSAL)
    handlers, handlers_ref = core.read(next_dir/'SPLIT_WRITER_CHAIN_TURNOVER_ARMED.json', ARMED)
    progress, _ = core.read(prior_dir/'FIRST_PROTECTED_PROGRESS.json',
                            '51aaa67e0eeb7bd1da0ed85e718ade911a6ae425e21be20383cb0f715c834d02')
    release = core.bound(progress['release'])
    actor = core.bound(progress['actor'])
    plan = core.bound(release['guard_plan'])
    raw = exit_row['properties']
    sample = intent['sample']
    upper = sample['root_physical_observation']['conservative_physical_bytes']
    core.need(release['actor'] == progress['actor'] and exit_row['release'] == progress['release']
              and exit_row['actor'] == actor and raw['Id'] == plan['unit'] == actor['unit'] == PREV
              and raw['InvocationID'] == actor['producer_invocation_id'] == end['producer_invocation_id'] == IID
              and raw['ExecMainPID'] == str(actor['producer_pid']) and raw['ExecMainCode'] == '2'
              and raw['ExecMainStatus'] == '15' and raw['MainPID'] == raw['ControlPID'] == '0'
              and actor['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
              and intent['reason'] == sample['trip_reason'] == 'root-physical-budget'
              and plan['maximum_root_physical_bytes'] == sample['maximum_root_physical_bytes'] == 349442555904
              and plan['maximum_root_physical_bytes'] < upper <= 384*G
              and sample['producer_stop_enabled'] and sample['producer_invocation_id'] == plan['invocation_id'] == IID
              and sample['plan_sha256'] == end['plan_sha256'] == release['guard_plan']['sha256'] == GUARD
              and end['intent'] == intent_ref['path'] and not end['scratch_deleted']
              and end['terminal']['pid'] == 0 and plan['worker_root'] == str(core.TREE)
              and failure['stage'] == 'close' and failure['error'] == 'predecessor did not exit cleanly'
              and not failure['retry_on_new_accepted_fleet'] and not failure['archive_publication_authorized'],
              'unconfirmed private epoch 170 guard stop')
    for name in (PREV, NEXT, *(x['service']['Id'] for x in handlers['armed'])):
        state = core.inactive(name)
        core.need(not state['ControlGroup'] and not (Path('/sys/fs/cgroup/system.slice')/name/'cgroup.procs').exists(),
                  'stopped 170 owner is still draining '+name)
    for name in ('CLOSED_READ_ACCEPTANCE.json','CLOSED_PREDECESSOR_COMPARISON.json','SUCCESSOR_ACTOR.json',
                 'SUCCESSOR_START_INTENT.json','SUCCESSOR_RELEASE.json','barrier/allow'):
        core.need(not os.path.lexists(next_dir/name), 'the blocked fourth window changed '+name)
    for arm in handlers['armed']:
        prior = arm['trigger']
        keys = 'Id,Paths,Triggers,InvocationID,ActiveState,SubState,Job'
        now = core.state(prior['Id'],keys)
        core.need(all(now[k] == prior[k] for k in ('Id','Paths','Triggers','InvocationID','Job'))
                  and now['ActiveState'] in ('active','failed') and now['SubState'] in ('waiting','failed'),
                  'epoch 170 operator path changed')
    scope = core.bound(release['interface'])
    timer = core.state(scope['expected_guard_timer'],'Id,ActiveState,InvocationID,Triggers,Job')
    guard = core.state(scope['expected_guard_unit'])
    core.need(timer['ActiveState'] == 'active' and timer['InvocationID'] == release['guard_timer_invocation_id']
              and timer['Triggers'] == guard['Id'] and not timer['Job'] and guard['MemoryMax'] == str(G)
              and guard['MemorySwapMax'] == '0' and guard['CPUQuotaPerSecUSec'] == '1s',
              'changed retained epoch 170 guard')
    row = fleet['current_private170_bounded_successor']
    core.need(row['actor'] == actor and row['release'] == progress['release']
              and row['phase'] in ('worker','terminal') and not row['archive_publication_authorized'],
              'fleet retained a different epoch 170 actor')
    return dict(pid1_exit=exit_ref, stop_intent=intent_ref, stop_completion=end_ref,
                denied_comparison=failure_ref, turnover=handlers_ref, invocation_id=IID,
                actual_guard_plan=release['guard_plan'], tree=str(core.TREE), guard_timer=timer,
                pending_replay_growth_bytes=0, retained_following_growth_bytes=36*G,
                retained_producer_ram=48*G, retained_guard_ram=G, resource_credit_bytes=0)


def observations(core, fleet, raw, first):
    rows = fleet['actual_executing_replays'] + fleet['actual_active_private_diagnostics'] + fleet['actual_active_bootstraps']
    native = {r['epoch']:r['unit'] for r in rows if r['epoch'] not in (143,162,169,170)}
    core.need(set(native) == {146,167,172} and first['row169']['phase'] == 'terminal'
              and first['row169']['terminal']['sha256'] == TERMINAL169,
              'different surviving roster or 169 terminal')
    if raw['replacement143']:
        r = raw['replacement143']
        native[143] = dict(Id=r['unit'],InvocationID=r['iid'])
    if first['row162'] and first['row162']['phase'] != 'terminal':
        native[162] = first['row162']['unit']
    actual = {line.split()[0] for line in core.cmd('/usr/bin/systemctl','list-units','--plain','--no-legend',
              '--type=service','--state=running,activating,deactivating,reloading','horizon-qualify-*').splitlines()}
    core.need(actual == {v['Id'] for v in native.values()}, 'survivors differ from native replay owners')
    for n, saved in native.items():
        props = core.state(saved['Id'])
        core.need(props['ActiveState']=='active' and not props['Job'] and props['InvocationID']==saved['InvocationID'],
                  'survivor invocation changed '+str(n))
    return [dict(epoch=n,unit=v['Id'],invocation_id=v['InvocationID']) for n,v in sorted(native.items())]


def ram_handoff(static, guard, old_reference, producer):
    """Leave the prior 159 overlap and the 169 guard charged independently."""
    if (static,guard,old_reference,producer) != (69*G,G,48*G,68*G):
        raise ValueError('different epoch 169 reservation')
    return static - guard - old_reference


def released169(core, first, paid, issuer):
    """The sealed one-shot producer cannot run again on its retained grant."""
    row = first['row169']
    grant = core.bound(first['grant'])
    start = core.bound(row['hourly169_start_intent'])
    end = core.bound(row['terminal'])
    lineage = paid['old_six_owner_lineage']
    core.need(row['phase']=='terminal' and row['terminal']['sha256']==TERMINAL169
              and row['pid1_result']=='interrupted'
              and row['invocation_id']==end['invocation_id']==grant['invocation_id']==start['producer_invocation_id']
              and end['grant_sha256']==first['grant']['sha256'] and start['unit']==grant['unit']==end['unit']
              and grant['memory_max']==start['actor_memory_bytes'] and lineage['same_169_compute']
              and lineage['retained_146_donor_memory']==69*G and not row['resource_credit_bytes']
              and end['archive'] is None and not end['private_span'] and not end['canonical_publication_authorized'],
              'different epoch 169 terminal or donor')
    unit = core.state(start['unit'],'Id,ControlGroup,MainPID,ControlPID,Job,ActiveState,TriggeredBy,Restart')
    core.need(unit['ActiveState']=='inactive' and not unit['ControlGroup'] and not unit['TriggeredBy']
              and not unit['Job'] and unit['MainPID']==unit['ControlPID']=='0' and unit['Restart']=='no',
              'the previous 169 producer can still be triggered')
    # Returning this part of the dedicated slot must not displace the old 169,
    # 136, 145 or 159 bindings in the original six-owner reconstruction.
    check_idle = runpy.run_path(str(issuer/'split_booking.py'))['check_idle']
    for name, before in lineage['actual_idle_units'].items():
        exited = before['InvocationID'] if before['SubState']=='exited' else None
        check_idle(name,exited)
    for name in (start['guard']['Id'],start['watcher']['properties']['Id']):
        check_idle(name)
    timer = core.state(start['timer']['Id'],'Id,ActiveState,Job')
    core.need(timer['ActiveState']=='inactive' and not timer['Job'], '169 guard timer is still booked')
    return dict(terminal=row['terminal'], start=row['hourly169_start_intent'], grant=first['grant'],
                retained_159_ram=lineage['temporary159_loan_memory'], retained_guard_ram=start['guard_memory_bytes'],
                available_producer_ram=ram_handoff(lineage['static_169_memory'],start['guard_memory_bytes'],
                         lineage['temporary159_loan_memory'],start['actor_memory_bytes']),
                retained_169_output_bytes=8*G)


def price(helper, directory):
    current = runpy.run_path(str(directory/'continuation_price.py'))
    core = current['prior']
    first, operations = helper['snapshot'](core)
    cap = operations[0]['capacity']
    fleet = core.bound(first['fleet'])
    old = core.bound(first['post'])
    previous = old['native']['raw']['joint']
    paid = old['accounting']
    stopped_ref = stopped(core,current,fleet)
    handback = released169(core, first, paid, helper['ISSUED'])
    before = core.availability()
    raw = current['price']('stopped', native169=first['row169'], native162=first['row162'])
    after = core.availability()
    legacy = runpy.run_path(str(directory/'after_assembly.py'))
    assembly, ar = core.read(legacy['PHASE_END'],legacy['END_SHA'])
    joint = raw['joint']
    core.need(assembly['native_terminal']['INVOCATION_ID']=='f097aed2a8f647398854fa6139f02d32'
              and raw['priced_170_invocation'] is None and raw['assembly168']['state']=='queued-or-drained'
              and raw['phase170_first'] is None and not raw['resource_credit_bytes'] and raw['fleet'] == first['fleet']
              and not joint['resource_credit_bytes'] and all(joint[k] == previous[k] for k in
                  ('interface','charged_167','return140','booking140','loan140','producer_allowance',
                   'guard_sibling_allowance','producer_quota_micros'))
              and joint['required_ram']+joint['resident_lower_bytes'] >= paid['old_six_owner_lineage']['bounded_167_base']
              and raw['candidate_170_growth_bytes'] == raw['required_home']-raw['guard_floor'] == 36*G
              and raw['concurrent_143_growth_bytes'] == raw['guarded_hourly_remaining'],
              'three-survivor price lost protected future work')
    # The failed producer cannot extend its tree. The full future reservation
    # remains in both screens, including throughout a separately admitted scan.
    raw.update(failed_170=stopped_ref, reserved_following_170_growth_bytes=36*G, candidate_170_growth_bytes=0)
    home = min(before[0],after[0],raw['available_home'])
    ram = min(before[1],after[1],raw['available_ram'])
    owners = observations(core,fleet,raw,first)
    required_ram = raw['required_ram'] - handback['available_producer_ram']
    native = dict(raw=raw,available_home=home,available_ram=ram,required_home=raw['required_home'],
              required_ram=required_ram,ram_margin=ram-required_ram,stopped_169_compute_handoff=handback,
              home_margin=min(raw['historical_home_margin'],home-raw['required_home']),
              historical_home_margin=raw['historical_home_margin'],observed_actors=owners,
              failed_170=stopped_ref,guarded_170_remaining=0,realized_170_anon=0,
              confirmed_168_terminal=ar, other_resident=dict(kernel=0,audit=0),resource_credit_bytes=0)
    verification = cap['verification168'](fleet['retry9_auxiliary_commitments'])
    answer = legacy['budget169'](core,native,first,operations,paid,verification,helper['package_home'](),helper)
    core.need(stopped(core,current,fleet)==stopped_ref and observations(core,fleet,raw,first)==owners
              and released169(core,first,paid,helper['ISSUED'])==handback
              and helper['current_writer'](core,first['provider'])==first['writer']
              and core.current_fleet()[1]==first['fleet'], 'ownership or stopped envelope changed during quote')
    return answer
