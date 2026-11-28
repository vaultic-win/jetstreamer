"""Bind the sole running normal status publisher and 136 bridge at the native cutover."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

if __name__ == "__main__":
    sys.path.insert(0,"/var/lib/jetstreamer/horizon_runtime_data/epoch166-post168-cadence-20261121-v1/publisher-v1")
import status168

DIR = status168.ROOT / 'epoch166-post168-cadence-20261121-v1'
UNIT = 'horizon-archive-status-cadence-after172-20261120-v1.service'
LOCK = status168.ROOT / 'stable-cadence-controller-20261120-v1/consumer.lock'
SEALER = 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
MARKER = DIR / 'METERED168_STATUS_REGISTERED.json'
FILES = dict(intent='START_INTENT.json',gated='NATIVE_GATED.json',admission='ACTUAL_ADMISSION_AND_PROTECTION.json',
             first_worker='FIRST_PROTECTED_WORKER.json')

def image(path):
    meta=path.stat()
    status168.need(path.resolve(strict=True)==path and stat.S_ISREG(meta.st_mode) and meta.st_uid==0
                   and stat.S_IMODE(meta.st_mode) in (0o444,0o555) and meta.st_nlink==1,
                   'unsealed member '+str(path))
    with path.open('rb') as fd:
        digest=hashlib.file_digest(fd,'sha256').hexdigest()
        after=os.fstat(fd.fileno())
    status168.need(os.path.samestat(meta,after) and meta.st_ctime_ns==after.st_ctime_ns and os.path.samestat(after,path.stat()),
                   'member changed '+str(path))
    return status168.ref(path,digest)

def deployment(folder,digest):
    receipt,ref=status168.read(folder/'deployment-seal-receipt.json',digest)
    status168.need(receipt['destination']==str(folder) and receipt['sealer_sha256']==SEALER
                   and receipt['schema']=='jetstreamer-sealed-deployment-receipt-v1'
                   and not receipt['remote_mutations'],'foreign status deployment')
    members={}
    for item in receipt['members']:
        name=item['name']
        status168.need(name==Path(name).name and name not in members,'foreign or duplicated member')
        member=image(folder/name)
        status168.need(item['sha256']==member['sha256'] and (folder/name).stat().st_mode&0o777==int(item['mode'],8),
                       'image differs from deployment')
        members[name]=member
    return ref,members

def binding(pub,bridge,verification):
    publisher=DIR/'publisher-v1'
    parent=DIR/'parent-package'
    seal,members=deployment(publisher,pub)
    pst,helper=deployment(parent,bridge)
    proof,qref=status168.read(DIR/'JOINT_REGISTRATION_QUALIFICATION.json',verification)
    status168.need(proof['publisher_seal']==seal and proof['parent_seal']==pst
                   and proof['verified_status_readbacks']==19 and proof['five_normal_stages_verified'] is True
                   and proof['original_trace_retained'] is True and proof['historical_166_local_transition_qualified'] is True
                   and proof['bounded_136_registration_qualified'] is True and proof['production_writes']==0,
                   'joint status and parent qualifications do not match')
    status168.need('parent136' in helper,'missing 136 parent')
    for name in ('consume','race166.py','closed166.py','status168.py','cadence168.py','closed168.py','private136.py'):
        status168.need(name in members,'combined publisher lacks '+name)
    u=status168.show(UNIT); pid=int(u['MainPID']); root=Path('/proc')/str(pid)
    _,ticks,group=status168.process(pid)
    status168.need(u['ActiveState']=='active' and u['SubState']=='running' and u['NRestarts']=='0'
                   and not u['Job'] and status168.iid(u['InvocationID'])
                   and u['ControlGroup']=='/system.slice/'+UNIT and group=='0::'+u['ControlGroup']
                   and (root/'fd/255').readlink()==publisher/'consume' and status168.same_file(root/'fd/255',publisher/'consume')
                   and (root/'fd/9').readlink()==LOCK and status168.same_file(root/'fd/9',LOCK)
                   and any(s.startswith('lock:') and 'FLOCK' in s and 'WRITE' in s for s in (root/'fdinfo/9').read_text().splitlines()),
                   'missing incumbent consumer image, cgroup or kernel lock')
    info=LOCK.stat()
    current=dict(unit=UNIT,invocation_id=u['InvocationID'],pid=pid,start_ticks=ticks,cgroup=u['ControlGroup'],
                 consumer=members['consume'],lock=dict(path=str(LOCK),device=info.st_dev,inode=info.st_ino))
    # inspect-status independently proves the parent accepts the actual publisher's current head.
    args=(root/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    status168.need(len(args)==4 and args[1]==str(publisher/'consume'),'wrong publisher seed')
    reply=json.loads(subprocess.check_output([parent/'parent136','inspect-status',args[2],args[3]],timeout=45))
    status168.need(reply['fleet']['path'] and reply['fleet']['sha256'] and status168.show(UNIT)==u
                   and status168.process(pid)[1]==ticks,'publisher changed during 136 registration')
    _,trace=status168.read(status168.TRACE,status168.CLOSED)
    _,prepared=status168.read(status168.D/'PREPARED.json',status168.PREPARED)
    _,controller=status168.read(status168.D/'controller/deployment-seal-receipt.json',status168.CONTROLLER)
    return dict(schema='horizon-metered168-status-registered-v1',epoch=168,prior_trace_terminal=trace,prepared=prepared,
                controller=controller,producer_unit=status168.U,timer_unit=status168.T,publisher_seal=seal,
                qualification=qref,parent_seal=pst,publisher=current,resource_credit_bytes=0,
                evidence_paths={key:str(status168.D/name) for key,name in FILES.items()})

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=('inspect','record'))
    for key in ('publisher_seal','parent_seal','qualification'):parser.add_argument(key)
    a=parser.parse_args()
    record=binding(a.publisher_seal,a.parent_seal,a.qualification)
    if a.mode=='record':
        # The existing root-owned status package provides atomic durable no-replace publication.
        sys.path.insert(0,str(DIR/'publisher-v1'))
        from evidence import durable
        durable(MARKER,record)
    print(json.dumps(record,sort_keys=True))
