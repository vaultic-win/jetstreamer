"""Qualify conditional 140 cadence alongside the exact frozen nineteen native consumers."""
import json,os,runpy,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
OLD=R/'prefix140-cadence-20261122-v1/cadence-tools'
ROOT=R/'prefix140-status-cadence-20261122-v1'
sys.path.insert(0,str(OLD))
from evidence import EPOCHS, bound, checked, digest, durable, need

def edit(source, old, new):
    need(source.count(old)==1,'predecessor text changed')
    return source.replace(old,new)

def qualify(mod):
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        d=Path(tmp);first=d/'first';second=d/'second';first.mkdir();second.mkdir()
        prior=dict(epoch=140,jet_size_bytes=0,phase='verification',sampled_at_utc='2026-11-22T00:15:58Z',
                   elapsed_execution_millis=0,estimated_remaining_millis=90_000_000)
        class Store:
            def __init__(self):self.data=mod.body(prior);self.etag='"first"';self.writes=0
            def get(self,e):assert e==140;return self.etag,self.data
            def put(self,e,etag,data):
                assert e==140 and etag==self.etag
                self.writes+=1;self.data=data;self.etag='"'+digest(data)+'"';return self.etag
        store=Store()
        c=SimpleNamespace(fleet={},stamp='2026-11-22T00:40:10Z',sample_ref={'sample':1},fleet_ref={'fleet':1},paths={'statuses':first})
        def emit(directory):
            file=directory/'COMPLETED.json';durable(file,dict(receipts={str(k):{'epoch':k} for k in EPOCHS},ready_epochs=[101,102]));return bound(file)
        legacy=emit(first)
        with patch.object(mod,'ROOT',d):
            mod.listed(c,set(EPOCHS));assert not c.private140_listed and mod.refresh(c,store,first,legacy)==legacy and not store.writes
            try:mod.listed(c,set(EPOCHS)|{150})
            except ValueError:pass
            else:raise ValueError('foreign 21st status admitted')
            initial=d/'event.json';durable(initial,dict(epoch=140,key=mod.KEY,after_status=prior,after_etag=store.etag,after_sha256=digest(store.data),authenticated_readback=True,conditional_header='If-None-Match'))
            durable(d/'INITIAL.json',dict(receipt=bound(initial)));mod.listed(c,set(EPOCHS)|{140})
            mod.refresh(c,store,first,legacy);assert store.writes==1
            mod.refresh(c,store,first,legacy);assert store.writes==1
            f={};mod.reconcile(c,f,legacy);assert f['complete_active_status_count']==20 and len(f['complete_active_status_receipts'])==20
            c.fleet=f;c.fleet_ref={'fleet':2};c.sample_ref={'sample':2};c.stamp='2026-11-22T01:10:10Z';c.paths={'statuses':second}
            next_legacy=emit(second);mod.listed(c,set(EPOCHS)|{140})
            def put_without_receipt(path,v):
                if path==second/'epoch-140.receipt.json':raise RuntimeError('injected interruption')
                return durable(path,v)
            with patch.object(mod,'durable',put_without_receipt):
                try:mod.refresh(c,store,second,next_legacy)
                except RuntimeError:pass
                else:raise ValueError('interrupted conditional write unexpectedly completed')
            mod.refresh(c,store,second,next_legacy);assert store.writes==2
            store.etag='"foreign"'
            try:mod.refresh(c,store,second,next_legacy)
            except ValueError:pass
            else:raise ValueError('foreign remote state accepted')
            try:mod.listed(c,set(EPOCHS))
            except ValueError:pass
            else:raise ValueError('registered 140 silently removed')
            return dict(two_native_simulated_cycles=True,duplicate_retry_writes=0,interrupted_put_recovered=True,wrong_remote_etag_refused=True,missing_registered_status_refused=True,foreign_epoch_refused=True)

def main():
    need(os.geteuid()==0 and sys.flags.isolated,'root isolated Python required')
    source=ROOT/'source';old=bound(OLD/'deployment-seal-receipt.json');assert checked(bound(OLD.parent/'QUALIFIED.json'))['package_seal']==old
    def status(s):
        s=edit(s,'    need(statuses==set(EPOCHS) and ready==','    from private140_status import listed\n    listed(c,statuses)\n    need(ready==')
        return edit(s,'    try:return _publish(c,storage,out,ready)','    try:\n        from private140_status import refresh\n        return refresh(c,storage,out,_publish(c,storage,out,ready))')
    def reconcile(s):
        a='    prefix140_reconcile(f, capacity)'
        return edit(s,a,a+'\n    from private140_status import reconcile as private140_status_reconcile\n    private140_status_reconcile(c,f,statusref)')
    changes={'status.py':status,'reconcile.py':reconcile};members=[]
    for row in checked(old)['members']:
        name=row['name'];p=OLD/name;assert bound(p)['sha256']==row['sha256']
        if name in changes:
            data=changes[name](p.read_text());p=source/name;p.write_text(data);p.chmod(0o400)
        members.append((name,p,int(row['mode'],8)))
    members.append(('private140_status.py',source/'private140_status.py',0o444));pkg=ROOT/'cadence-tools'
    seal=runpy.run_path(str(R/'resident-observer-20261121-v1/source/seal_resident_cadence.py'))['seal'](ROOT,pkg,members)
    sys.path.insert(0,str(pkg))
    import private140_status as mod
    test=qualify(mod)
    assert not (ROOT/'INITIAL.json').exists()
    q=ROOT/'QUALIFIED.json';durable(q,dict(schema='horizon-private140-status-registration-qualification-v1',base=old,package_seal=seal,controls=test,remote_mutations=0))
    print(json.dumps(bound(q)))
if __name__=='__main__':main()
