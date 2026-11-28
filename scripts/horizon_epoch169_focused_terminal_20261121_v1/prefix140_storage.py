"""Charge the unspent part of the one bounded HOME allocation for the private 140 verifier."""
from pathlib import Path

from evidence import BASE, bound, checked, need
from owners import show
from ready_audit_growth import forecast

REGISTRATION = BASE/'ready-idle-cpu-20261121-v1/REGISTERED_PREFIX140_HOME_AND_CHILD.json'
REGISTRATION_SHA = '9f82d164a0727d03b0ed0271cfd287b477aa71edeca6a7d12b554d97750562dd'
CONTROL = BASE/'epoch140-prefix-control-20261122-v1'

def storage():
    reg_ref=bound(REGISTRATION)
    need(reg_ref['sha256']==REGISTRATION_SHA,'foreign prefix140 registration')
    reg=checked(reg_ref)
    plan=checked(reg['plan'])
    policy=reg['aggregate_home_allocation']
    need(reg['unit']==plan['unit'] and policy['maximum_host_allocation_bytes']==16<<20,'invalid prefix140 HOME cap')
    allocation=forecast([policy])[0]
    unit=show(plan['unit'],('Id','InvocationID','MainPID','ControlPID','ActiveState','SubState','Result','ExecMainStatus','Job','ControlGroup'))
    result=Path(plan['output'])
    record=None
    if not unit['Job'] and unit['MainPID']==unit['ControlPID']=='0' and unit['SubState']=='exited' and unit['Result']=='success' and result.exists():
        candidate=bound(result)
        data=checked(candidate)
        need(data['schema']=='jetstreamer-epoch140-private-selected-prefix-audit-v1' and data['epoch']==140
             and data['unit']==unit['Id'] and data['invocation_id']==unit['InvocationID']
             and data['plan_sha256']==reg['plan']['sha256'] and data['self_sha256']==reg['executable']['sha256'],
             'foreign completed 140 prefix result')
        record=candidate
    remaining=0 if record else allocation['remaining_growth_bytes']
    need(not allocation['observed_over_cap_bytes'],'prefix140 HOME allocation exceeded registered cap')
    return dict(schema='private-epoch140-bounded-home-allocation-v1',registration=reg_ref,
                child=unit,host_allocation=allocation,remaining_DATA_growth_bytes=remaining,
                complete_result=record,maximum_HOME_allocation_bytes=16<<20,archive_staging_bytes=0,
                additional_cpu_quota_micros=0,additional_memory_bytes=0,resource_credit_bytes=0)

def reconcile(fleet, capacity):
    active=capacity['private_epoch140_verifier']
    ready=fleet['active_ready_range_audit_obligation']['current_storage']['remaining_DATA_growth_bytes']
    subtotal=fleet['complete_DATA_bytes']+ready
    need(fleet['complete_DATA_with_remaining_audit_growth_bytes']==subtotal,'unexpected ready-only fleet subtotal')
    fleet['complete_DATA_with_ready_audit_only_bytes']=subtotal
    fleet['current_private_prefix140_obligation']=active
    fleet['complete_DATA_with_remaining_audit_growth_bytes']=subtotal+active['remaining_DATA_growth_bytes']
