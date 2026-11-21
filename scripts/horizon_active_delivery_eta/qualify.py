"""Replay an authenticated 19-status interval in an isolated local conditional store."""
import copy
import datetime as dt
import json
import sys
from pathlib import Path
from unittest.mock import patch

pkg, old_fleet, completed, output=map(Path,sys.argv[1:])
sys.path.insert(0,str(pkg))
import delivery_eta, replay167_event, replay167_rate, status
from cycle import Cycle
from evidence import bound, checked, durable, utc

previous=bound(old_fleet)
accepted=checked(bound(completed))
c=Cycle(previous['path'],previous['sha256'],accepted['observer']['sha256'])
done=checked(accepted['authenticated_status_audit'])
real={int(k):checked(v) for k,v in done['receipts'].items()}
assert len(real)==19 and done['authenticated_readback'] and c.terminal166 is None
live=(166,167,170,172)

class CapturedStore:
    def __init__(self):
        self.objects={e:(r['before_etag'],status.body(r['before_status'])) for e,r in real.items()}
        self.puts=[]
    def get(self,e):
        return self.objects[e]
    def put(self,e,tag,body):
        assert self.get(e)[0]==tag
        tag='"fixture-'+status.digest(body)+'"'
        self.objects[e]=(tag,body)
        self.puts.append(e)
        return tag

store=CapturedStore()
output.mkdir(mode=0o700)
directory=output/'statuses'
directory.mkdir(mode=0o700)
with (patch.object(c,'unchanged'),patch.object(c,'public_fresh'),
      patch.object(status,'observed_archive',side_effect=lambda _,e:real[e]['archive_sample'])):
    completed_ref=status._publish(c,store,directory,done['ready_epochs'])
    assert status._publish(c,store,directory,done['ready_epochs'])==completed_ref
    assert sorted(store.puts)==sorted(real)
    result=checked(completed_ref)
    observed={}
    for k,ref in result['receipts'].items():
        e=int(k)
        r=checked(ref)
        assert r['authenticated_readback'] and r['after_sha256']==status.digest(store.get(e)[1])
        assert r['before_etag']==real[e]['before_etag'] and r['before_status']==real[e]['before_status']
        if e not in live:
            assert r['after_status']==real[e]['after_status'] and 'delivery_forecast' not in r
            continue
        before=real[e]['after_status']
        after=r['after_status']
        quote=r['delivery_forecast']
        tail=quote['total_millis']
        assert tail>delivery_eta.LEGACY_TAIL
        assert after==dict(before,estimated_remaining_millis=before['estimated_remaining_millis']-delivery_eta.LEGACY_TAIL+tail)
        if e==167:
            assert r['rolling_rate_evidence']['samples']==real[e]['rolling_rate_evidence']['samples']
            assert r['rolling_rate_evidence']['estimated_remaining_millis']==after['estimated_remaining_millis']
        observed[e]=dict(tail_millis=tail,estimated_remaining_millis=after['estimated_remaining_millis'])
        # Two successive no-progress samples: legacy 167 holds its duration,
        # others retain their established countdown. Neither receives the tail twice.
        stall=copy.copy(c)
        stall.advancing=dict(c.advancing)
        stall.advancing[e]=False
        stall.full172_row=dict(c.full172_row,measured_progress=False)
        last=after
        for offset in (1800,3600):
            stall.now=c.now+dt.timedelta(seconds=offset)
            stall.stamp=stall.now.strftime('%Y-%m-%dT%H:%M:%SZ')
            with patch.object(replay167_rate,'recovery',return_value=(False,None)):
                value,_=status.forecast(stall,e,last,dict(after_status=last,delivery_forecast=quote))
            assert value['estimated_remaining_millis']==after['estimated_remaining_millis']-(0 if e==167 else offset*1000)
            last=value
    # Local commit uses actual bytes and omits assembly. The old replay time has
    # ended. A second verification cycle preserves the first absolute forecast.
    terminal=output/'local-terminal.json'
    epoch=166
    original=real[epoch]['after_status']
    finish=round(c.now.timestamp()*1000)-45000
    archive=dict(size=91000000000,path='/fixture/local-166.jet',device=12,inode=321,sha256='ab'*32)
    durable(terminal,dict(epoch=epoch,manager_terminal={'__REALTIME_TIMESTAMP':str(finish*1000)},local_archive=archive,resource_credit_bytes=0,canonical_r2_verified=False))
    fake=copy.copy(c)
    fake.terminal166=bound(terminal)
    value,_=status.forecast(fake,epoch,original,real[epoch])
    terminal_quote=fake.delivery_forecasts[epoch]
    assert terminal_quote['projected_archive_bytes']==archive['size'] and 'assembly_close_import' not in terminal_quote['phase_milliseconds']
    assert value['phase']=='verification' and value['estimated_remaining_millis']==terminal_quote['total_millis']-45000
    fake.now=c.now+dt.timedelta(seconds=1800)
    fake.stamp=fake.now.strftime('%Y-%m-%dT%H:%M:%SZ')
    next_value,_=status.forecast(fake,epoch,value,dict(after_status=value,delivery_forecast=terminal_quote))
    assert next_value['estimated_remaining_millis']==value['estimated_remaining_millis']-1800000
legacy=checked(bound(replay167_event.EVENT/'RECEIPT.json'))
assert replay167_event.follow(replay167_event.PREVIOUS,legacy['after_etag'],status.body(legacy['after_status']))[1]==legacy
print(json.dumps(dict(active=observed,legacy_167_historical_event_verified=True,terminal=terminal_quote,
    same_interval_retry_puts=0,two_stalled_intervals_each=4,all_status_readbacks=19,production_writes=0)))
