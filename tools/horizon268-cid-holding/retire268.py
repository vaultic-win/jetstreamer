"""Main's exact local single-inode retirement. Durable intent, quarantine, unlink and recovery."""
import argparse
import ctypes
import importlib.util
import json
import os
import stat
from pathlib import Path
spec=importlib.util.spec_from_file_location('cid268_custody',Path(__file__).with_name('custody.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
op=c.op

def rename(src,dst):
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.renameat2(-100,os.fsencode(src),-100,os.fsencode(dst),1)!=0:
        raise OSError(ctypes.get_errno(),'no-replace quarantine')

def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def exists(path):
    # A dangling symlink is an occupied name.
    try:path.lstat();return True
    except FileNotFoundError:return False

def contents(path):
    m=path.lstat()
    op.need(path.resolve()==path and stat.S_ISREG(m.st_mode) and m.st_uid==os.geteuid() and
            m.st_nlink==1 and stat.S_IMODE(m.st_mode)==0o400 and m.st_size<=65536,'unsafe durable retirement record')
    return json.loads(path.read_bytes())

def transition(src,state,key,validate,closure,free,checkpoint=lambda _:None):
    """State is root private and same-device. The funded owner serializes all writers externally."""
    # Two separately writable systemd bind mounts can report the same st_dev
    # while renameat2 between them fails with EXDEV. Keep new renames within
    # the original directory and resume an already quarantined older run.
    legacy=state/f'quarantine-{op.SHA[:8]}.body'
    adjacent=src.parent/f'.horizon{op.EPOCH}-quarantine-{op.SHA[:8]}.body'
    op.need(not (exists(legacy) and exists(adjacent)), 'two occupied quarantine names')
    q=legacy if exists(legacy) else adjacent
    intent,unlink,done=(state/n for n in ('retire-intent.json','unlink-intent.json','retired.json'))
    for record in (intent,unlink,done):
        if exists(record):op.need(contents(record)['operation']==key,'record belongs to another source or decision')
    a,b,i,u,d=map(exists,(src,q,intent,unlink,done))
    op.need((a,b,i,u,d) in [(1,0,0,0,0),(1,0,1,0,0),(0,1,1,0,0),(0,1,1,1,0),(0,0,1,1,0),(0,0,1,1,1)],
            'unrecognized source/quarantine/receipt combination')
    if d:return contents(done)
    closure()
    if a:
        validate(src,True,False)
        if not i:
            c.save(intent,dict(operation=key,physical_ceiling=src.lstat().st_blocks*512))
            checkpoint('intent')
        closure();validate(src,True,False);rename(src,q)
        sync_dir(src.parent);sync_dir(state);checkpoint('quarantine')
    if exists(q):
        # A rename changes ctime. Revalidate dev/inode/size/mtime/mode/link and content in quarantine.
        validate(q,False,True);closure();validate(q,False,False)
        if not u:
            c.save(unlink,dict(operation=key,before_available=free(),
                               physical_ceiling=contents(intent)['physical_ceiling']))
            checkpoint('unlink-intent')
        closure();validate(q,False,False)
        q.unlink();sync_dir(q.parent);checkpoint('unlink')
    sync_dir(state);sync_dir(src.parent)
    prior=contents(unlink);after=free()
    result=dict(operation=key,physical_ceiling=prior['physical_ceiling'],
                before_available=prior['before_available'],after_available=after,
                concurrent_filesystem_delta=after-prior['before_available'],
                source_name_absent=True,quarantine_name_absent=True,capacity_credit=0)
    op.need(not any(exists(p) for p in (src,legacy,adjacent)),'local name reappeared')
    c.save(done,result)
    return result

def run(booking_ref):
    book=op.binding(booking_ref)
    op.need(book['operation']=='retire' and os.geteuid()==0,'booked local retirement required')
    fit=op.booked_kernel(book)
    if fit['physical_peak']<4*op.M:
        pool=op.binding(book['prepaid_control_space'])
        allocation=op.binding(pool['original_allocation'])
        for field in pool['byte_cap_field']:
            allocation=allocation[field]
        op.need(type(allocation) is int and allocation>=pool['remaining_bytes'] and
                pool['controller']==op.MAIN and pool['complete_basis']==book['complete_basis'] and
                pool['phase']=='retire' and pool['remaining_bytes']>=4*op.M and
                pool['covers_durable_metadata'] and pool['already_charged']==True,
                'unfunded durable metadata')
    review=book['comparison_closure'];anchor=book['durable_custody'];grant=op.binding(book['local_release'])
    op.need(grant['controller']==op.MAIN and grant['release_authorized'] and grant['source']==str(op.SRC)
            and grant['source_identity']==list(op.STAMP) and grant['custody']==anchor
            and grant['postcomparison']==op.binding(review)['postcomparison'] and not grant['remote_mutations'],
            'wrong exact local release')
    proof=op.binding(anchor)
    op.need(Path(anchor['path'])==c.STATE/'custody.json' and c.pair(proof['park'],proof['verify'])==proof,'durable custody mismatch')
    for p in (op.SRC.parent,c.STATE):
        m=p.lstat()
        op.need(p.resolve()==p and stat.S_ISDIR(m.st_mode) and m.st_dev==op.DEV and m.st_uid==m.st_gid==0 and
                stat.S_IMODE(m.st_mode)==0o700,'wrong exact local directory')
    def closure():
        c.compare_close(review)
        op.need(not op.census(op.DEV,op.INO),'held source/quarantine referenced')
    def validate(p,original,full):
        s=op.stamp(p)
        op.need((s==op.STAMP if original else s[:4]==op.STAMP[:4]),'not original body incarnation')
        if full:op.need(op.digest(p)==op.SHA and op.stamp(p)==s,'quarantine full SHA or incarnation changed')
    def free():
        v=os.statvfs(c.STATE);return v.f_bavail*v.f_frsize
    key=dict(source=str(op.SRC),identity=list(op.STAMP),sha256=op.SHA,custody=anchor,
             postcomparison=grant['postcomparison'],release=book['local_release'])
    return transition(op.SRC,c.STATE,key,validate,closure,free)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--epoch',type=int,choices=(267,268),default=268);p.add_argument('booking',type=Path);p.add_argument('sha256')
    a=p.parse_args()
    if a.epoch==267:
        c.select_epoch267()
    print(json.dumps(run(dict(path=str(a.booking),sha256=a.sha256)),sort_keys=True))
