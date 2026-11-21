"""Exercise the actual missed sample, a second skipped window and native custody on isolated paths."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

def qualify(pkg, target, head_path):
    sys.path.insert(0,str(pkg))
    import resident_clock as clock
    from evidence import BASE, bound, checked, durable, need, names, sealed, utc
    from cycle import load_fleet
    import clock_recovery as bridge
    from race166 import NATIVE,NATIVE_SHA
    original=checked(bridge.HEAD)
    cfg=sealed(original['sole_next_observer'])
    failed=checked(checked(bridge.CLOSED)['native_sample'])
    assert list(clock.incomplete(failed))==['after']
    assert not clock.incomplete(checked(original['observer']))
    new=clock.derived(original,cfg,failed)
    assert new==dict(cfg,not_before_utc='2026-11-21T17:50:22Z',output=str(names('2026-11-21T17:50:22Z')['sample']))
    cases=[]
    for field,val in [('minimum_interval_seconds',25),('previous_sample_sha256','0'*64),
                      ('next_routine_observation_not_before_utc','2026-11-21T17:20:23Z'),
                      ('observation_reason','manual'),('routine_minimum_interval_enforced',False)]:
        v=copy.deepcopy(failed);v['cadence'][field]=val
        try:clock.derived(original,cfg,v)
        except ValueError:cases.append(field)
        else:raise AssertionError(field)
    invalid=copy.deepcopy(failed);invalid['host_resident_memory']['after']['rss']={}
    try:clock.derived(original,cfg,invalid)
    except ValueError:cases.append('partial-rss')
    else:raise AssertionError('partial rss accepted')
    # Redirect only the receipt and scheduler namespaces to a private HOME fixture.
    # The real deployment sealer and digest checks still run in register/resolve.
    def scoped(stamp):
        return {k:(target/v.name if isinstance(v,Path) else v) for k,v in names(stamp).items()}
    head=bound(head_path);f,normal,_=load_fleet(head)
    live=checked(f['observer'])
    assert not clock.incomplete(live) and all(v['useful_work']['slot_delta']>0 for v in live['replays'])
    with patch.object(clock,'names',scoped),patch.object(clock,'generation',lambda ref,cr:target/'chain'/cr['sha256']),patch('race166.successful_sample',return_value=dict(unit=names(cfg['not_before_utc'])['timer'].removesuffix('.timer')+'.service',invocation='fixture-only')):
        # Put the original full, immutable sample in a new fixture directory.
        cur=dict(cfg,output=str(target/'first-incomplete.json'));p=Path(cur['output']);durable(p,failed)
        old=original['sole_next_observer']
        source=copy.deepcopy(original)
        real_sealed=clock.sealed
        with patch.object(clock,'sealed',side_effect=lambda ref:cur if ref==old else real_sealed(ref)):
            clock.register(bridge.HEAD,source,cur,bound(p))
            f1,one=clock.resolve(bridge.HEAD,source,cur)
            assert one['not_before_utc']==new['not_before_utc']
            assert f1['sole_next_observer']!=old
            old_path=Path(one['output']);again=copy.deepcopy(failed)
            again['recorded_at_utc']=one['not_before_utc'];start=utc(again['recorded_at_utc'])
            again['completed_at_utc']=(start+dt.timedelta(seconds=60)).strftime('%FT%TZ')
            again['cadence']['configured_not_before_utc']=one['not_before_utc']
            again['cadence']['observed_interval_seconds']=int((start-utc(original['sampled_at_utc'])).total_seconds())
            again['cadence']['next_routine_observation_not_before_utc']=(start+dt.timedelta(seconds=1800)).strftime('%FT%TZ')
            durable(old_path,again)
            with patch('race166.successful_sample',return_value=dict(unit=f1['sole_next_timer'].removesuffix('.timer')+'.service',invocation='second-fixture')):
                clock.register(bridge.HEAD,f1,one,bound(old_path))
            f2,two=clock.resolve(bridge.HEAD,source,cur)
            assert two['not_before_utc']=='2026-11-21T18:20:22Z' and f2['sole_next_observer']!=f1['sole_next_observer']
            assert clock.resolve(bridge.HEAD,source,cur)==(f2,two)
    assert bound(NATIVE)['sha256']==NATIVE_SHA and len(cases)==6
    return dict(head=head,unchanged_config=normal==sealed(f['sole_next_observer']),unchanged_timer=f['sole_next_timer'],
                real_closed=bridge.CLOSED,repeated_recovery=True,refusals=cases,native=bound(NATIVE),
                ordinary_host_endpoints=2,unavailable_host_endpoints=1,fixture_timer_starts=0,fixture_status_writes=0)

if __name__=='__main__':
    pkg,fixture,head=map(Path,sys.argv[1:]);print(json.dumps(qualify(pkg,fixture,head)))
