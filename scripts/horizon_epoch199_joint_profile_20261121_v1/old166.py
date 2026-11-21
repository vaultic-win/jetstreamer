"""Measure exact canonical names and size-compatible candidates in three stopped AccountsDb trees."""
import collections
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
B = R/'epoch199-delivery-recovery-20261121-v1'
V11 = R/'incident-replay-fit-20261121-v1/tools-v11'
INPUT = Path('/usr/local/lib/jetstreamer/horizon-standard-local-input166-20261110-v1')
NAME = 'snapshot-71711708-73JLv83cyRgHUNxtajhwXimfDSH4GUmu6R8LHKPbxu76.tar.zst'
SHA = '1e8fa388737b80a9e2218cd09f2fee43b064e19a65e26e466abda25d5e3688f4'
OLD = Path('/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1')
SITES = [(6,104863603,(104864342,104864398,104864699,104865024)),(7,104529955,(104529958,104529959,104529960,104529975)),(8,108068870,(108068886,108068887,108068888,108068889))]
def need(test, reason):
    if not test:
        raise ValueError(reason)
def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()
def pinned(path,sha):
    need(path.resolve(strict=True)==path and path.stat().st_uid==0 and digest(path)==sha,'changed '+str(path))
    return path
def main(fleet,sha):
    need(os.geteuid()==0 and sys.flags.isolated and __debug__,'isolated root required')
    pkg=B/'terminal-accounts-members-v1'
    pinned(pkg/'measure.py','d1bbf6b3cc218545db32d97e756a73fa75de3b7fe1a003839e44c6e703a129d6')
    helpers=runpy.run_path(str(pinned(pkg/'archive.py','a1ec16aaf9efb1a8a97788ea2f009f098e0dcea8243e5c908453c08425d62e50')))
    pub=runpy.run_path(str(pinned(V11/'publication-fit','7c7cd5c883f768b0f374f63952eefa1efb5f0e08fe74269d939f8d1e98eca1b4')))
    provider=pinned(V11/'post-stop-fit','f6583caf06127010d2a3209f1a173df78264766f70bc869067bed10adf3b0349')
    out=B/('old166-census-'+os.environ['INVOCATION_ID'])
    out.mkdir(mode=0o700)
    fit=json.loads(pub['capture_provider'](provider,fleet,sha))
    need(fit['fits'] and fit['fleet']==dict(path=fleet,sha256=sha) and 0<=time.time()-fit['recorded_unix_seconds']<90 and fit['available_HOME_bytes']>=fit['complete_required_HOME_bytes']+(16<<20) and fit['available_memory_bytes']>=fit['required_available_memory_bytes']+(512<<20),'unfunded metadata census')
    helpers['write_json'](out/'FIT.json',fit)
    seal=json.loads(pinned(INPUT/'deployment-seal-receipt.json','154cb890a47e91e6ae465340e8c9b7616e58b4cbf3b9447800bf8cfd3b3206ee').read_bytes())
    lin=json.loads(pinned(INPUT/'source-lineage.json','cce598547c133f51429c6e98029abc6aab30e001a90662428f27bbf4fab77833').read_bytes())
    need(seal['destination']==str(INPUT) and any(m['name']==NAME and m['sha256']==SHA for m in seal['members']) and lin['bootstrap_sha256']==SHA,'different original boot')
    canon={}
    by_slot={}
    canon_keys=hashlib.sha256()
    canonical=INPUT/NAME
    with helpers['opened'](canonical) as sf:
        original=helpers['stamp'](sf)
        fcntl.fcntl(sf,fcntl.F_SETLEASE,fcntl.F_RDLCK)
        with os.fdopen(os.dup(sf),'rb') as source:
            need(hashlib.file_digest(source,'sha256').hexdigest()==SHA,'canonical bytes differ')
        os.lseek(sf,0,0)
        a=helpers['Archive'](sf)
        try:
            for name,ent in a.entries():
                name=name.removeprefix(b'./')
                match=helpers['NAME'].fullmatch(name)
                if not match:
                    need(not name.startswith(b'accounts/') or name==b'accounts/','invalid member')
                    continue
                slot,idx=map(int,match.groups()); length=a.lib.archive_entry_size(ent)
                need(0<length<=4<<30 and a.lib.archive_entry_filetype(ent)==stat.S_IFREG and not a.lib.archive_entry_hardlink(ent) and not a.lib.archive_entry_symlink(ent),'foreign entry')
                need(name==f'accounts/{slot}.{idx}'.encode() and (slot,idx) not in canon,'duplicate member')
                canon[slot,idx]=length
                sizes=by_slot.setdefault(slot,[])
                sizes.append(length)
                canon_keys.update(name+b'\0'+str(length).encode()+b'\n')
        finally:
            a.close()
        need(original==helpers['stamp'](sf) and fcntl.fcntl(sf,fcntl.F_GETLEASE)==fcntl.F_RDLCK,'source changed')
    rows=[]
    for retry,inode,shards in SITES:
        old=OLD/f'replacement-local3retry{retry}-20261110-v1'
        matches=list(old.glob('private/*/work/root-cohort-166-166/run-*/scratch/.historical-runtime/*/*/accounts-state'))
        need(len(matches)==1,'different accounts roots')
        site=matches[0]
        need(site.resolve(strict=True)==site and site.stat().st_dev==64512 and site.stat().st_ino==inode and set(os.listdir(site))==set('0123'),'foreign old tree')
        counters=collections.defaultdict(lambda:[0,0,0])
        for number,ino in enumerate(shards):
            with helpers['opened'](site/str(number),True) as fd:
                before=helpers['stamp'](fd)
                need(before[0:2]==[64512,ino],'foreign shard')
                with os.scandir(fd) as items:
                    for item in items:
                        need(re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)',item.name),'non-AppendVec entry')
                        slot,idx=map(int,item.name.split('.')); m=item.stat(follow_symlinks=False)
                        need(m.st_dev==64512 and stat.S_ISREG(m.st_mode) and m.st_nlink==1,'foreign shard entry')
                        size=m.st_size; exact=canon.get((slot,idx)); same_slot=by_slot.get(slot,[])
                        if exact==size:kind='name_and_length'
                        elif exact is not None:kind='name_different_length'
                        elif size in same_slot:kind='other_id_same_slot_and_length'
                        elif same_slot:kind='other_id_same_slot_different_length'
                        else:kind='local_only_slot'
                        row=counters[kind];row[0]+=1;row[1]+=size;row[2]+=m.st_blocks*512
                need(before==helpers['stamp'](fd),'shard changed')
        rows.append(dict(retry=retry,site=str(site),root_inode=inode,shard_inodes=shards,classes=counters))
    helpers['write_json'](out/'METADATA.json',dict(schema='horizon-old166-canonical-accounts-census-v1',sha256=SHA,canonical_path=str(canonical),canonical_stat=original,canonical_members=len(canon),canonical_slots=len(by_slot),canonical_name_length_order_sha256=canon_keys.hexdigest(),rows=rows,fields=['files','logical_bytes','allocated_bytes'],capacity_credit_bytes=0,removed_bytes=0))
if __name__=='__main__':
    main(*sys.argv[1:])
