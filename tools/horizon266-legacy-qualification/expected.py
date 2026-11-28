"""Read only the compact-index rows needed for known finalized epoch 266 blocks."""
from pathlib import Path
import base64, ctypes, hashlib, json, os, stat, struct

ROOT='bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu'
PRIOR='bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu'
PREFIX=f'epoch-266-{ROOT}-mainnet-'
SIZE=396186095544
# getBlocks included the complete epoch opening 114912000..114912015.
SLOTS=((114912004,None),(115128002,115128001),(115343448,115343447))
V=Path('/var/lib/jetstreamer')
CACHE=V/'horizon266-index-acquire-v1/cache/sealed'
D=Path('/home/ubuntu/.codex/diagnostics/horizon266-index-acquire-v1')
MASK=(1<<64)-1
xx=ctypes.CDLL('libxxhash.so.0').XXH64
xx.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_uint64]
xx.restype=ctypes.c_uint64
def require(ok,why):
    if not ok:raise ValueError(why)
def ref(p):
    return dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
def lookup(path,key,width):
    with path.open('rb') as f:
        fd=f.fileno()
        def read(offset,length):
            b=os.pread(fd,length,offset)
            require(len(b)==length,'compact index truncated')
            return b
        head=read(0,25);hdr,size,count=struct.unpack_from('<IQI',head,8)
        require(head[:8]==b'compiszd' and head[24]==1 and size==width and count>0,'wrong compact header')
        h=xx(key,len(key),0);u=h%count
        if (h-u)//count<u:
            u=((u^(u>>33))*0xff51afd7ed558ccd)&MASK
            u=((u^(u>>33))*0xc4ceb9fe1a85ec53)&MASK
            u^=u>>33
        b=read(12+hdr+16*(u%count),16);domain,n,hlen=struct.unpack_from('<IIB',b)
        require(1<=hlen<=8,'compact hash width')
        off=int.from_bytes(b[10:16],'little')
        raw=domain.to_bytes(4,'little')+bytes(28)+key
        target=xx(raw,len(raw),0)&((1<<(8*hlen))-1)
        i=0
        while i<n:
            row=read(off+i*(hlen+width),hlen+width)
            got=int.from_bytes(row[:hlen],'little')
            if got==target:return row[hlen:]
            i=2*i+1+int(got<target)
        raise ValueError('known key missing '+key.hex())
def expected(slot_path,cid_path):
    def section(slot):
        cid=lookup(slot_path,slot.to_bytes(8,'little'),36)
        require(cid[:4]==bytes.fromhex('01711220'),'noncanonical Block CID')
        val=lookup(cid_path,cid,9)
        off=int.from_bytes(val[:6],'little');length=int.from_bytes(val[6:],'little')
        require(59<=off<off+length<=SIZE,'invalid Block section')
        return off,off+length,'b'+base64.b32encode(cid).decode().lower().rstrip('=')
    out=[]
    for slot,parent in SLOTS:
        block,end,cid=section(slot)
        start=section(parent)[1] if parent else 59
        require(start<=block<end and 0<end-start<=20*1024*1024,'invalid bounded complete slot')
        out.append(dict(slot=slot,previous_local_slot=parent,offset=start,length=end-start,block_offset=block,cid=cid))
    return out
def main():
    for name in ('completion.json','launch.json','booking.json'):
        path=D/name
        require(path.resolve()==path and path.stat().st_uid==0 and stat.S_IMODE(path.stat().st_mode)==0o400,name)
    completed=json.loads((D/'completion.json').read_bytes())
    launch=json.loads((D/'launch.json').read_bytes())
    require(completed['unit']=='horizon266-index-acquire-v1.service' and completed['invocation']==launch['unit']['InvocationID']=='b1a89d8deda341c5a19510f55a9e6202' and
            completed['success'] and completed['cgroup_drained'] and completed['local_cache_accepted'] and completed['launch']==ref(D/'launch.json') and
            launch['booking']==ref(D/'booking.json') and completed['native']['MESSAGE_ID']=='7ad2d189f7e94e70a38c781354912448' and
            completed['native']['INVOCATION_ID']==completed['invocation'],'original accepted acquisition required')
    transfer=CACHE.parent.parent/'transfer'
    canonical={'acquisition':transfer/'acquisition.json','worker':transfer/'worker-result.json','seal':CACHE/'deployment-seal-receipt.json'}
    require(completed['native']['_PID']=='1' and completed['native']['UNIT']==completed['unit'],'wrong manager')
    for k,p in canonical.items():
        require(completed[k]['path']==str(p),'wrong '+k)
    for k in ('acquisition','seal','worker'):
        p=Path(completed[k]['path']);require(p.stat().st_uid==0 and p.resolve()==p and ref(p)==completed[k],k)
    seal=json.loads((CACHE/'deployment-seal-receipt.json').read_bytes());acq=json.loads(Path(completed['acquisition']['path']).read_bytes())
    require(completed['seal']==ref(CACHE/'deployment-seal-receipt.json') and seal['destination']==str(CACHE) and acq['invocation']==completed['invocation'],'wrong seal')
    worker=json.loads(canonical['worker'].read_bytes())
    require(worker['success'] is True and worker['invocation']==completed['invocation'] and
            worker['seal_sha256']==completed['seal']['sha256'] and worker['acquisition_sha256']==completed['acquisition']['sha256'],'acquisition worker binding')
    for key in ('before','after'):
        require(acq[key]['root']==ROOT and acq[key]['http']==206 and acq[key]['bytes']==4096 and acq[key]['url']=='https://files.old-faithful.net/266/epoch-266.car' and acq[key]['sha256']=='f6b4974df3daa2b7181395c5380479a7a2b38d6c4554991a59502211295acd66','CAR bracket differs')
    names=[f'epoch-265-{PRIOR}-mainnet-slot-to-cid.index',PREFIX+'slot-to-cid.index',PREFIX+'cid-to-offset-and-size.index']
    sums=['b7728d6947e43869b78118fe46109f8d5670af6d58ad3f0a1e2bc3261bc25f06','9be621a54768e2d22aafd0d639bbf7ae546e7e4eb6610c3dbf2723cf06c8a0b6',acq['index']['full_sha256']]
    rows={e['name']:e for e in seal['members']}
    require(set(rows)==set(names) and len(rows)==len(seal['members'])==3,'wrong seal members')
    for name,digest,n in zip(names,sums,[15484110,14576860,9348706694]):
        p=CACHE/name;st=p.lstat();member=rows[name]
        require(p.resolve()==p and st.st_uid==st.st_gid==0 and st.st_mode==(stat.S_IFREG|0o444) and st.st_nlink==1 and
                member['bytes']==st.st_size==n and member['sha256']==digest,'changed '+name)
    print(json.dumps(dict(acquisition=ref(D/'completion.json'),seal=completed['seal'],members=[rows[n] for n in names],slots=expected(CACHE/names[1],CACHE/names[2]),car_root=ROOT),indent=2))
if __name__=='__main__':main()
