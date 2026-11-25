"""Price epoch 168 retry5 against the retained retry4 and complete host bookings."""
import json
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


def price(s, native, current, ret, donor, cold168):
    """Add retry5 growth once, after the entire incumbent floor has been priced."""
    cap = cold168['CAP']
    lag = cold168['OUTSIDE_CAP_STOP_ALLOWANCE']
    charge = max(ret['physical_bytes'], native['stopped_cold168']['measured_physical_bytes'])
    s.need(ret['remaining_bytes'] == 0 and charge <= current['physical_bytes'] <= cap
           and current['remaining_bytes'] == cap - current['physical_bytes'],
           'invalid retained retry4 or retry5 physical booking')
    protected = donor['native_home_required'] + lag
    required = protected + current['remaining_bytes']
    available = donor['native_home_available']
    details = dict(schema='horizon-168-retry5-complete-booking-v1',
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
    native.update(protected_raw_floor_bytes=protected, complete_required_HOME_bytes=required,
                  available_HOME_bytes=available, retry5_complete_booking=details,
                  fits=native['fits'] and details['funded'], epoch159_donor_cover=donor)
    native['bookings']['168'] = current
    return native
