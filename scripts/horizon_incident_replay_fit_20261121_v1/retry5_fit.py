"""Price epoch 168 retry5 against the retained retry4 and complete host bookings."""
import json
import os
from pathlib import Path
import subprocess

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
FAMILY = R / 'epoch145-semantic-continuity-20261121-v1'
V7_HANDOFF = FAMILY / 'v7-168-stop-name-handoff'
CHECKER = FAMILY / 'tools-v7-168-stop-v2'
CHECKER_SHA = '589d1da9f51c305be8699a9dc01e443c9ec2367d1f67e7905ba67fdeb0d35c7b'
START_SHA = '4c83262f7bb705f30f1850dcc1274a549b2f08b80618bc23c3c9955fae4f4163'
I145 = 'f7043fd6595a4151b659d4b098bede11'


def drained145(s, fit, load):
    manager = s.show(fit.A145)
    group = Path('/sys/fs/cgroup/system.slice') / fit.A145
    s.need(manager['ActiveState'] == 'inactive' and manager['SubState'] == 'dead' and
           manager['MainPID'] == manager['ControlPID'] == '0' and
           manager['InvocationID'] in ('', I145) and not manager['ControlGroup'] and
           not manager['Job'] and not fit.members(fit.A145) and not group.exists(),
           'epoch 145 V7 verifier has not drained')
    load(CHECKER, CHECKER_SHA)
    saved, completion = s.read(V7_HANDOFF / 'SEMANTIC_COMPLETION.json')
    start = V7_HANDOFF / 'START_RESULT.json'
    proof = json.loads(subprocess.check_output(
        ['/usr/bin/python3', '-IB', CHECKER / 'v5v_semantic_completion.py', start, START_SHA],
        timeout=20))
    s.need(proof == saved and proof['invocation_id'] == I145 and
           proof['start'] == s.ref(start, START_SHA) and proof['publication_authorized'] is False and
           s.show(fit.A145) == manager and not fit.members(fit.A145) and not group.exists(),
           'changed epoch 145 V7 terminal or native owner')
    return dict(Id=fit.A145, MainPID='0', stage='v7-semantic-complete-drained',
                completed_invocation_id=I145, completion=completion,
                checker_seal=s.ref(CHECKER / 'deployment-seal-receipt.json', CHECKER_SHA))


def retained(s, fit, fleet, cold168):
    stop, source = cold168['retry5_stop'](s, fit)
    capacity_ref = fleet['current_home_cycle_capacity']
    capacity = s.bound(capacity_ref, Path(capacity_ref['path']))
    s.need(stop == fleet['cold168_retry4_root_physical_stop'] ==
           capacity['retained_cold168_retry4_reservation'] and
           not fleet.get('cold168_local_commit') and not fleet.get('metered168_local_commit'),
           'retained retry4 is not bound to the accepted fleet')
    return stop, source


def donor_cover(s, donor, before, native, fleet):
    """Price the paid donor with the V12 roster while retaining all old claims."""
    after = donor['snapshot']()
    fits = (native['fits'] and native['schema'] == 'horizon-incident-replay-fit-v1' and
            native['resource_credit_bytes'] == 0 and not native['replay_launch_authorized'] and
            native['complete_cpu_quota_micros'] == 64_000_000 and
            native['complete_memory_plus_reserve_bytes'] == 810_658_050_048)
    s.need(before == after and before['invocation_id'] == donor['IID'] and
           before['grant_sha256'] == donor['GRANT'] and before['driver_exit'] == donor['EXIT'] and fits,
           'incomplete native retry5 or donor price')

    g, m = donor['GIB'], donor['MIB']
    loan = native['candidate136']
    retry4 = native['stopped_cold168']
    fail166, fail170 = native['failed_cold166'], native['failed_cold170']
    old = native['bookings']['168']
    s.need(not loan['occupied'] and not loan['loan_micros'] and
           native['status_registration']['consumer_seal']['sha256'] ==
           '6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac' and
           retry4['resource_credit_bytes'] == retry4['reservation_ending_bytes'] == 0 and
           old['cap_bytes'] == retry4['retained_cap_bytes'] == 288 * g and
           old['remaining_bytes'] == max(0, old['cap_bytes'] - old['physical_bytes']) and
           old['measurement'] == 'two complete stopped-tree walks' and
           old['unreconciled_stop_bytes'] ==
               max(0, retry4['measured_physical_bytes'] - max(old['cap_bytes'], old['physical_bytes'])) and
           fail166 == fleet['cold166_retry11_write_version_failure'] and
           fail170 == fleet['cold170_retry13_execution_failure'] and
           fail166['reservation_ending_bytes'] == fail170['reservation_ending_bytes'] == 0,
           'changed stopped replay booking or V12 cadence')
    for epoch, cap in (('166', 288*g), ('170', 384*g)):
        booking = native['bookings'][epoch]
        s.need(booking['cap_bytes'] == booking['physical_bytes'] + booking['remaining_bytes'] == cap and
               booking['measurement'] == 'two complete stopped-tree walks', 'changed retained ' + epoch)

    fit168 = native['epoch'] == 168
    phases = {'v7-semantic-complete-drained'}
    if native['epoch'] == 145:
        phases |= {'v5j-semantic-complete', 'post-full', 'publish'}
    peers = native['replacements']
    own = native['candidate'] if fit168 else peers.get('168')
    roster = fleet['actual_executing_replays']
    scoped = [row for row in roster if row['epoch'] == 168]
    s.need(native['epoch'] in (145, 168) and native['phase145']['stage'] in phases and
           native['retry5_retained_source']['sha256'] ==
           '488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2' and
           len(scoped) <= 1 and fleet['canonical_producer_count'] == len(roster) == 2 + len(scoped) and
           {row['epoch'] for row in roster if row['epoch'] != 168} == {167, 172} and
           set(peers) - {'168'} == {'167'} and set(native['survivors']) == {'172'} and
           ('168' not in peers or own == peers['168']) and
           all(own and row['unit']['Id'] == own['producer_unit'] and
               row['unit']['InvocationID'] == own['producer_invocation_id'] and
               row['admission'] == own['admission'] for row in scoped),
           'changed protected replay population in the donor census')

    orig, _ = donor['bound'](donor['ROOT'] / 'HEAD131757-132005-donor.json', donor['PRICE'])
    shared = orig['reserved_hourly']
    booked = {
        'guard_cpu_micros': 1_000_000, 'guard_memory': g, 'producer_cpu_micros': 3_000_000,
        'producer_memory': 68*g, 'future_staging': 6_589_353_984, 'private_workspace': 68_117_473_606,
    }
    s.need(all(shared[key] == value for key, value in booked.items()) and orig['charged_reference'] == {
        'cpu_cores': 2, 'memory_bytes': 48*g, 'other_home_bytes': 32*m, 'scratch_bytes': 24*g, 'swap_bytes': 0,
    }, 'changed original 169 or 159 resources')
    obligations = native['recovery_obligations']
    workers = obligations['public_workers']
    s.need(len({(w['pid'], w['start_ticks']) for w in workers}) == len(workers) and
           sum(w['required_bytes'] for w in obligations['mirror_inputs']) == obligations['missing_mirror_bytes'],
           'incomplete public audit')
    public = max(obligations['public_storage']['remaining_DATA_growth_bytes'],
                 fleet['active_ready_range_audit_obligation']['current_storage']['remaining_DATA_growth_bytes'])
    vfs = os.statvfs(donor['HOME'])
    available = min(vfs.f_bavail*vfs.f_frsize, native['available_HOME_bytes'],
                    fleet['complete_cycle_conservative_available_DATA_bytes'])
    required = native['complete_required_HOME_bytes'] + public + shared['future_staging'] + shared['private_workspace'] + 32*m
    margin = min(available - required, orig['remaining_home_bytes'])
    s.need(margin >= 0 and native['available_memory_bytes'] >= native['required_available_memory_bytes'],
           'insufficient HOME or general-slot memory')
    return dict(schema='horizon-145-drained-159-donor-cover-v1', diagnostic=after, fleet=native['fleet'],
                native_recorded_unix_seconds=native['recorded_unix_seconds'], original_donor_price_sha256=donor['PRICE'],
                build_HOME_bytes=0, build_RAM_bytes=0, remaining_home_bytes=margin,
                native_home_required=required, native_home_available=available,
                general_slot_cpu_micros=1_000_000, general_slot_memory_bytes=2*g,
                original_guard_memory_bytes=g, original_guard_cpu_micros=1_000_000,
                original_producer_cpu_micros=3_000_000, original_producer_memory_bytes=68*g,
                credited_retirement_bytes=0, replay_launch_authorized=False)


def price(s, native, current, ret, donor, cold168):
    """Add retry5 growth once, after the entire incumbent floor has been priced."""
    cap = cold168['CAP']
    lag = cold168['OUTSIDE_CAP_STOP_ALLOWANCE']
    charge = max(ret['physical_bytes'], native['stopped_cold168']['measured_physical_bytes'])
    s.need(ret['remaining_bytes'] == 0 and charge <= current['physical_bytes'] <= cap
           and current['remaining_bytes'] == cap - current['physical_bytes'],
           'invalid retained retry4 or retry5 physical booking')
    candidate = native['epoch'] == 168
    retained_floor = donor['native_home_required'] + lag
    protected = retained_floor if candidate else max(retained_floor, native['active168_guard_floor'])
    required = protected + current['remaining_bytes']
    available = donor['native_home_available']
    details = dict(schema='horizon-168-retry5-complete-booking-v1',
                   retained_guard_floor_bytes=0 if candidate else native['active168_guard_floor'],
                   previous_producer_physical_charge_bytes=charge,
                   prior_stop=native['stopped_cold168']['terminal'],
                   outside_cap_stop_allowance_bytes=lag,
                   retained_source=native['retry5_retained_source'],
                   retained_base_HOME_bytes=donor['native_home_required'],
                   protected_raw_floor_bytes=protected, complete_required_HOME_bytes=required,
                   candidate_remaining_bytes=current['remaining_bytes'],
                   producer_cpu_quota_micros=9_000_000, producer_memory_bytes=68 << 30,
                   guard_cpu_quota_micros=250_000, guard_memory_bytes=1 << 30,
                   producer_swap_bytes=0, guard_swap_bytes=0,
                   funded=available >= required)
    native.update(protected_raw_floor_bytes=protected if candidate else required,
                  complete_required_HOME_bytes=required,
                  available_HOME_bytes=available, retry5_complete_booking=details,
                  fits=native['fits'] and details['funded'], epoch159_donor_cover=donor)
    native['bookings']['168'] = current
    return native
