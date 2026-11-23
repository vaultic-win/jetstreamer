"""Exercise the actual failed 168 generation and refuse altered receipts and native states."""
from pathlib import Path
from types import SimpleNamespace
import json
import runpy
import sys

base=Path('/var/lib/jetstreamer/horizon_runtime_data')
sys.path.insert(0,str(base/'epoch168-full-metered-20261121-v1/session-v4-registered136'))
import fit
import status168 as s


def check():
    mod=runpy.run_path(str(Path(__file__).resolve().with_name('closed_retry3.py')))
    original=mod['settled'](s,fit)
    cases=[]
    def deny(label,fn):
        try:fn()
        except ValueError:cases.append(label)
        else:raise AssertionError(label+' was accepted')
    for filename,field,value in [
        ('RELEASED_NODE_STARTUP_FAILURE_20261123.json','bootstrap_admission',False),
        ('RELEASED_NODE_STARTUP_FAILURE_20261123.json','no_admission_record',True),
        ('RELEASED_NODE_STARTUP_FAILURE_20261123.json','replay_claimed',True),
        ('RELEASED_NODE_STARTUP_FAILURE_20261123.json','guard_samples',[]),
        ('ACTUAL_ADMISSION_AND_PROTECTION.json','producer_pid',1),
        ('ACTUAL_ADMISSION_AND_PROTECTION.json','start_ticks',1),
        ('ACTUAL_ADMISSION_AND_PROTECTION.json','intent',{})]:
        def changed(path,digest):
            data,ref=s.read(path,digest)
            if path.name==filename:data=dict(data,**{field:value})
            return data,ref
        actor=SimpleNamespace(read=changed,need=s.need,bound=s.bound,show=s.show)
        deny(filename+'/'+field,lambda:mod['settled'](actor,fit))
    for actor,field,value in [
        (mod['UNIT'],'InvocationID','1'*32),(mod['UNIT'],'NRestarts','1'),(mod['UNIT'],'ExecMainStatus','0'),
        (mod['UNIT'],'MainPID','42'),(mod['UNIT'],'Job','42'),(mod['TIMER'],'ActiveState','active')]:
        def changed(unit):
            observed=s.show(unit)
            return dict(observed,**{field:value}) if unit==actor else observed
        evidence=SimpleNamespace(read=s.read,need=s.need,bound=s.bound,show=changed)
        deny(actor+'/'+field,lambda:mod['settled'](evidence,fit))
    deny('native residual process',lambda:mod['settled'](s,SimpleNamespace(members=lambda _: (999,))))
    assert mod['settled'](s,fit)==original
    return dict(terminal=original,declined=cases,mutation=False,positive_native_checks=2)


if __name__=='__main__':
    print(json.dumps(check(),sort_keys=True))
