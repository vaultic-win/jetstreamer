"""Offline fit, custody and namespace fixtures. No credentials, service, filesystem pricing or network."""
import importlib.util
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
o=module('booked268');c=module('custody')
M=o.M
sample=dict(complete_fit=dict(owners={k:{} for k in o.OWNERS},mem={'MemTotal':1212136964096,'MemAvailable':1042867757056},
                              free=4208904486912,charged_memory={'a':146222673920,'b':95795466240,'c':10720604160},
                              stopped228=dict(memory_retained=120000000000,released_memory=0,released_disk=0),
                              stopped266=dict(memory_retained=176000000000,released_memory=0,released_disk=0)),
            finite_memory=dict(baseline_hard=o.HARD),registered_ledger={'sha256':o.BASE_LEDGER},
            minimum_free_bytes=4247813416960,floor=dict(minimum_free=4247813416960,registered_independent_floor=4213923166208),
            allocated_backing={'228':dict(free=4208904486912),'266':dict(free=4208904486912)})
def rejects(f):
    try:f()
    except ValueError:return
    raise AssertionError('negative case passed')
def tests():
    for phase,values in o.PHASES.items():
        funds=(values[0]+values[1])*M
        x=o.price(sample,phase,600*M,funds,0);y=o.price(sample,phase,600*M,0,0)
        assert x['hard_margin']==72495104-values[2]*M and x['fits']==(phase!='restore') and not y['fits']
    parked = o.price(sample, 'park', 656*M, (320+64+40)*M, 0)
    assert parked['fits'] and parked['new_tmpfs'] == 40*M
    assert parked['hard_margin'] == sample['complete_fit']['mem']['MemTotal'] - o.HARD - 656*M
    rejects(lambda:o.price(sample,'park',656*M,(320+64+41)*M,0))
    rejects(lambda:o.price(sample,'build',656*M,(384+64+40)*M,0))
    assert o.price(sample,'restore',600*M,384*M,0)['disk_margin']==-51074620218
    assert not o.price(sample,'park',600*M,384*M,1)['fits']
    import copy
    for mutate in [lambda x:x['complete_fit']['owners'].update(extra={}),lambda x:x['complete_fit']['stopped228'].update(released_disk=1),
                   lambda x:x['registered_ledger'].update(sha256='00')]:
        changed=copy.deepcopy(sample);mutate(changed);rejects(lambda:o.price(changed,'verify',0,0,0))
    r=dict(epoch=268,kind='cid-to-offset-and-size',sha256=o.SHA,manifest_sha256='a'*64,bytes=o.SIZE,
           parts=363,capacity_credit=0,canonical_publication=False)
    pc,vc=({'invocation':z*32} for z in ('a','b'))
    def actor(i):
        return dict(booking={'path':i},worker={'sha256':'b'*64},result=dict(r,operation=i))
    a,v=map(actor,('park','verify'));b=dict(authenticated_endpoint_sha256='b'*64)
    def pair():return c.pair({'path':'p','sha256':'1'*64},{'path':'v','sha256':'2'*64})
    with patch.object(c,'native_completion',side_effect=[(pc,a,b),(vc,v,b)]):
        assert pair()['original_removal_authorized']==False
    with patch.object(c,'native_completion',side_effect=[(pc,a,b),(pc,v,b)]):rejects(pair)
    with patch.object(c,'native_completion',side_effect=[(pc,a,b),(vc,v,{'authenticated_endpoint_sha256':'c'*64})]):rejects(pair)
    c.gate(a['result'],'park');rejects(lambda:c.gate(dict(a['result'],epoch=267),'park'))
    rejects(lambda:c.gate(dict(a['result'],manifest_sha256='A'*64),'park'))
    with tempfile.TemporaryDirectory() as t:
        target=Path(t)/'custody.json';c.save(target,{'phase':'verified'});i=target.stat().st_ino
        c.save(target,{'phase':'verified'});assert target.stat().st_ino==i and target.stat().st_mode&0o777==0o400
        rejects(lambda:c.save(target,{'phase':'other'}));assert target.stat().st_ino==i
    print('Offline fixture groups passed: complete-fit and retained accounting; additive/serial and disk thresholds; roster/ledger/terminal drift; independent park/verify custody; original remote endpoint; exact profile; durable no-replace/idempotence.')
if __name__=='__main__':tests()

def retirement_tests(epoch=268):
    r=module('retire268')
    if epoch==267:
        r.c.select_epoch267()
        actual=dict(operation='verify',kind='cid-to-offset-and-size',epoch=267,bytes=10_392_794_246,sha256=r.op.SHA,parts=310,manifest_sha256='a'*64,capacity_credit=0,canonical_publication=False)
        r.c.gate(actual,'verify')
        rejects(lambda:r.c.gate(dict(actual,epoch=268),'verify'))
        rejects(lambda:r.c.gate(dict(actual,parts=363),'verify'))
    import hashlib
    secret=b'fixture closed bytes'
    class Crash(Exception):pass
    for cut in ('intent','quarantine','unlink-intent','unlink',None):
        with tempfile.TemporaryDirectory() as t:
            s=Path(t)/'source';q=Path(t)/'state';s.mkdir();q.mkdir();src=s/'body';src.write_bytes(secret)
            src.chmod(0o400);ino=src.stat().st_ino;neighbor=s/'other';neighbor.write_bytes(b'keep')
            def validate(p,original,full):
                if p.stat().st_ino!=ino or full and hashlib.sha256(p.read_bytes()).digest()!=hashlib.sha256(secret).digest():raise ValueError('bad')
            def checkpoint(label):
                if label==cut:raise Crash(label)
            args=(src,q,{'sha256':o.SHA},validate,lambda:None,lambda:999)
            try:r.transition(*args,checkpoint)
            except Crash:pass
            if cut:rejects(lambda:r.transition(src,q,{'sha256':'different'},validate,lambda:None,lambda:999))
            result=r.transition(*args);assert r.transition(*args)==result
            assert result['capacity_credit']==0 and not src.exists() and neighbor.read_bytes()==b'keep'
    with tempfile.TemporaryDirectory() as t:
        s=Path(t)/'source';s.write_bytes(secret);q=Path(t)/'state';q.mkdir()
        def deny():raise ValueError('live ref')
        rejects(lambda:r.transition(s,q,{},lambda *_:None,deny,lambda:999))
        assert s.read_bytes()==secret and not list(q.iterdir())
    with tempfile.TemporaryDirectory() as t:
        src=Path(t)/'source';src.write_bytes(secret);state=Path(t)/'state';state.mkdir()
        def same_mount_rename(a,b):
            assert a.parent==b.parent
            os.rename(a,b)
        def stop_after_rename(point):
            if point=='quarantine':raise Crash(point)
        def validate(p,original,full):
            assert p.read_bytes()==secret
        args=(src,state,{'sha256':o.SHA},validate,lambda:None,lambda:999)
        with patch.object(r,'rename',same_mount_rename):
            try:r.transition(*args,stop_after_rename)
            except Crash:pass
        adjacent=src.with_name(f'.horizon{epoch}-quarantine-{r.op.SHA[:8]}.body')
        legacy=state/f'quarantine-{r.op.SHA[:8]}.body'
        legacy.write_bytes(b'conflict')
        rejects(lambda:r.transition(*args))
        legacy.unlink();adjacent.rename(legacy)
        assert r.transition(*args)['quarantine_name_absent'] and not legacy.exists()
    print('Retirement fixtures passed: interruption at all four durable boundaries, exact-identity binding, conflicting operation, repeated success, live-reference rejection and neighbor preservation.')
if __name__=='__main__':
    retirement_tests()
    retirement_tests(267)
