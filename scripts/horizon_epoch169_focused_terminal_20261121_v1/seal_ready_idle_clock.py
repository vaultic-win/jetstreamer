"""Verify idle-only CPU profiles and the missing transient service recovery case."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
OLD=R/'ready-audit-growth-20261121-v1/cadence-tools'
ROOT=R/'ready-idle-cpu-20261121-v1'
sys.path.insert(0,str(OLD))
from evidence import bound,checked,durable,ensure_dir,need

def qualify_profile(source):
    cpu=runpy.run_path(str(source/'idle_audit_cpu.py'))
    profile,policy=cpu['profile'],cpu['POLICY']
    assert profile()=='paid-four'
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        t=Path(folder); reg=t/'assignment.json'
        values={'cpu.max':'400000 100000','cpu.idle':'0','memory.high':str(20<<30),
                'memory.max':str(24<<30),'memory.swap.max':'0','pids.max':'512'}
        for name,value in values.items():(t/name).write_text(value)
        assert profile(t,reg)=='paid-four'
        (t/'cpu.idle').write_text('1');assert profile(t,reg)=='paid-four'
        (t/'cpu.max').write_text('1200000 100000')
        def refusal():
            try:profile(t,reg)
            except ValueError:return
            raise AssertionError('unregistered CPU profile')
        refusal()
        reg.write_text(json.dumps(policy));reg.chmod(0o400)
        assert profile(t,reg)=='idle-twelve'
        checks=['missing assignment']
        for name,crossed in {'cpu.max':'800000 100000','cpu.idle':'0','memory.high':'max','memory.max':'max',
                             'memory.swap.max':'1','pids.max':'1024'}.items():
            original=(t/name).read_text();(t/name).write_text(crossed);refusal();(t/name).write_text(original);checks.append(name)
        reg.chmod(0o666);refusal();reg.chmod(0o400);checks.append('writable assignment')
        reg.write_text(json.dumps(dict(policy,paid_cpu_quota_micros=12_000_000)));refusal();checks.append('foreign entitlement')
        reg.write_text(json.dumps(policy))
        native=runpy.run_path(str(R/'incident-replay-fit-20261121-v1/tools-v15/post-stop-fit'));fit=native['fit']
        snapshot=bound(R/'epoch145-semantic-continuity-20261121-v1/incident-build-72c2b7ce7b6d488183ca1b02623f0523/before.json')
        assert snapshot['sha256']=='968ba48e53cc30bc087ecd6498525d9a4c0ffe427fb4d697058965cdb948c8db'
        old=checked(snapshot);fleet=checked(old['fleet'])
        evaluator=runpy.run_path(str(source/'idle_floor.py'))['floor']
        data=(fleet,native['bound'](fit.BOOK),old['bookings']['168'],old['survivors'])
        expected=old['original_aggregate_HOME_bytes']
        assert fit.floor(*data)[0]+old['epoch170_extension']['extra_bytes']==expected
        evaluator.__globals__['observe_cpu']=lambda:profile(t,reg)
        assert evaluator(*data)[0]+old['epoch170_extension']['extra_bytes']==expected
        return dict(crossed_profiles=checks,real_historical_snapshot=snapshot,historical_native_floor=expected,
                    both_four_and_twelve_reproduce_baseline=True,widened_case_is_isolated_fixture=True)

def main():
    assert os.geteuid()==0 and sys.flags.isolated and __debug__
    source=ROOT/'staging';oldseal=bound(OLD/'deployment-seal-receipt.json')
    assert checked(bound(OLD.parent/'QUALIFIED.json'))['package_seal']==oldseal
    clock=source/'resident_clock.py';scope=source/'idle_audit_cpu.py'
    delta=subprocess.run(['diff','-u',str(OLD/'resident_clock.py'),str(clock)],capture_output=True,text=True)
    assert delta.returncode==1 and 'existing_timer' in delta.stdout
    previous=(OLD/'public_witness.py').read_text(); start=previous.index('    if row["CPUQuotaPerSecUSec"] != "4s":')
    stop=previous.index('    return row\n',start)
    out=source/'public_witness.py';out.write_text(previous[:start]+'''    from idle_audit_cpu import profile
    actual=profile()
    need(row['CPUQuotaPerSecUSec']==('4s' if actual=='paid-four' else '12s'),
         'audit manager and kernel CPU ceilings disagree')
'''+previous[stop:]);out.chmod(0o400)
    items=[]
    for m in checked(oldseal)['members']:
        name=m['name'];p=OLD/name;assert bound(p)['sha256']==m['sha256']
        items.append((name,{'public_witness.py':out,'resident_clock.py':clock}.get(name,p),int(m['mode'],8)))
    items.append((scope.name,scope,0o444))
    pkg=ROOT/'cadence-tools'
    seal=runpy.run_path(str(R/'resident-observer-20261121-v1/source/seal_resident_cadence.py'))['seal'](ROOT,pkg,items)
    cpu_qa=qualify_profile(source)
    # Exercise real systemd replies, including a not-found transient .service with no ExecStart field.
    new_clock=runpy.run_path(str(pkg/'resident_clock.py'))
    absent='horizon-observer-unused-idle-clock-qualification-20261121-v1'
    assert new_clock['existing_timer'](absent,[],[]) is False
    try:new_clock['existing_timer'](absent,['competing.timer'],[])
    except ValueError:pass
    else:raise AssertionError('competing timer accepted')
    actual=checked(bound(OLD.parent/'RECOVERED_231010_SCHEDULE.json'))
    timer=actual['single_registered_successor']['Id'];cmd=actual['command']
    assert new_clock['existing_timer'](timer.removesuffix('.timer'),[timer],cmd) is True
    try:new_clock['existing_timer'](timer.removesuffix('.timer'),[timer],['/unregistered-command'])
    except ValueError:pass
    else:raise AssertionError('competing native command accepted')
    durable(ROOT/'QUALIFIED.json',dict(schema='horizon-ready-idle-clock-qualified-v1',package_seal=seal,
        predecessor=oldseal,source_bindings={n:bound(source/n) for n in ('idle_audit_cpu.py','idle_floor.py','resident_clock.py')},
        real_absent_service_case=True,registered_running_clock_readback=True,crossed_real_timer_refusals=2,
        cpu=cpu_qa,synthetic_scheduler_witness_sha='a050f8204963d3aedc8073ad20ce9f1d76d34112af83245abde283ce72142071',
        actual_cpu_profile='paid-four',live_limits_changed=False,extra_host_observations=0))
    print(json.dumps(bound(ROOT/'QUALIFIED.json')))
if __name__=='__main__':main()
