"""Finite payload only. Main admits, isolates, arms and supervises the original unit first."""
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

SRC=Path(__file__).resolve().parent
BASE=Path('/var/lib/jetstreamer/horizon267-slot-input-v1')
CURL=Path('/usr/bin/curl')
SEALER=Path('/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer')
RUSTC=BASE/'toolchain/bin/rustc'
RUSTC_SHA='3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2'
SEALER_SHA='faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a'
CURL_SHA='d90fe31761b6ac228a75507b62186b3ed00ccf1f0fc5c7ce704bbe3936e31343'
PINS={'toolchain.py':'4dd32fac995c3af2f8a848683fd7f76daea317239bb26eb2ab329d58da3a0f82','toolchain.json':'de5155665ce8d8975bf8aad79e24909f05942b4c235125a33cf98d123da2067f','indexes.json':'e78d9f9fcd94552f289b36af51fe5d72b639ac17a8db4c76c94b98fd9077c75b',
      '267-slot-to-cid.bin':'add8388b9cc822c6fcadeffe06885c37cd8d8172ba8f0049ac2ac9cb846127c7',
      '267-car.bin':'6de6caf41e8c666071c32e01ca73efd28f214097bfd940f7fb7552a137654221',
      'slot267.rs':'d2f00493ffa20a4946bee64b4dcbbfa7a500d6b26f8c0fbb047953c8d86400ff'}
SIZE=15166712

def need(value, reason):
    if not value: raise ValueError(reason)
def sha(p):
    with p.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def syncdir(p):
    fd=os.open(p,os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def record(path,data):
    with path.open('x') as f:
        json.dump(data,f,indent=2); f.write('\n'); f.flush(); os.fchmod(f.fileno(),0o400); os.fsync(f.fileno())
    syncdir(path.parent)
def stamp(p):
    m=p.lstat()
    need(p.resolve()==p and stat.S_ISREG(m.st_mode) and m.st_nlink==1, 'invalid regular file')
    return [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns]
def rootdir(p,mode):
    m=p.lstat()
    need(p.resolve()==p and stat.S_ISDIR(m.st_mode) and m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==mode,'unexpected private directory '+str(p))
def hdr(path):
    lines=path.read_bytes().decode('latin1').strip().split('\r\n\r\n')[-1].splitlines()
    fields={}
    for line in lines[1:]:
        k,v=line.split(':',1);k=k.lower()
        need(k not in fields or k not in ('content-length','content-range','content-encoding'), 'duplicate header')
        fields[k]=v.strip()
    return int(lines[0].split()[1]),fields

def get(out,name,r,prefix_only):
    n=4096 if prefix_only else SIZE
    headers=out/(name+'.headers')
    body=out/(name+'.body')
    args=[CURL,'--disable','--silent','--show-error','--retry','0','--proto','=https','--max-redirs','0','--connect-timeout','8','--max-time','25' if prefix_only else '120','--header','Accept-Encoding: identity','--max-filesize',str(n),'--dump-header',headers]
    if prefix_only:args+=['--range','0-4095']
    # Send the body to our exclusive fd; curl never reopens a caller-chosen destination.
    with body.open('xb') as f:
        subprocess.run([*args,r['url']],stdout=f,check=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        f.flush();os.fchmod(f.fileno(),0o444 if not prefix_only else 0o400);os.fsync(f.fileno())
    status,h=hdr(headers)
    need(status==(206 if prefix_only else 200) and int(h['content-length'])==n==body.stat().st_size and h.get('content-encoding','identity')=='identity','unexpected body')
    need(h.get('content-range')==(f'bytes 0-4095/{r["bytes"]}' if prefix_only else None),'unexpected range')
    with headers.open('rb') as f: os.fsync(f.fileno())
    with body.open('rb') as f:need(hashlib.sha256(f.read(4096)).hexdigest()==r['prefix_sha256'],'prefix changed')
    return {'url':r['url'],'http':status,'bytes':n,'headers_sha256':sha(headers),'sha256':sha(body),'identity':stamp(body)}
def transfer(out,rows):
    need(sha(CURL)==CURL_SHA,'curl changed')
    car,slot=rows
    before=get(out,'car-before',car,True)
    body=get(out,'slot',slot,False)
    after=get(out,'car-after',car,True)
    need(before['sha256']==after['sha256']==car['prefix_sha256'],'CAR root bracket changed')
    return dict(car_before=before,body=body,car_after=after,source_prefixes=PINS,full_validation_pending=True)
def child(argv,cwd):
    # Only the isolated compiler and checker run as the unprivileged uid.
    completed=subprocess.run(argv,cwd=cwd,user=1000,group=1000,extra_groups=[],umask=0o077,
        env={'PATH':'/usr/bin:/bin','TMPDIR':str(cwd),'LANG':'C','RUST_BACKTRACE':'0'},
        check=False,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
    need(completed.returncode==0,'unprivileged process failed: '+completed.stdout[-8192:])
    return completed.stdout
def verify(out,rows):
    rootdir(BASE/'transfer',0o711)
    transfer_path=BASE/'transfer'/'result.json'
    tr=json.loads(transfer_path.read_bytes());body=BASE/'transfer'/'slot.body'
    need(tr['phase']=='transfer' and tr['inputs']==PINS and tr['body']['url']==rows[1]['url'] and tr['body']['identity']==stamp(body) and tr['body']['bytes']==SIZE and tr['body']['sha256']==sha(body),'transfer receipt or source drift')
    tc=runpy.run_path(str(SRC/'toolchain.py'))
    revision=tc['manifest']()
    before_inputs=tc['check_view'](revision,True)
    need(sha(RUSTC)==RUSTC_SHA and sha(SEALER)==SEALER_SHA,'compiler/sealer changed')
    work=out/'compile';work.mkdir(mode=0o700);os.chown(work,1000,1000)
    access=child(['/usr/bin/python3.14','-I','-B','-c',
        "import os,pathlib,sys; p=pathlib.Path.cwd()/'access.fixture'; assert os.getuid()==os.getgid()==1000 and not os.getgroups(); p.write_bytes(b'probe'); assert p.read_bytes()==b'probe';p.unlink(); assert pathlib.Path(sys.argv[1]).open('rb').read(1); assert pathlib.Path(sys.argv[2]).open('rb').read(1); assert os.access(sys.argv[3],os.X_OK) and not os.access(sys.argv[4],os.W_OK) and not os.access(sys.argv[5],os.R_OK); print('uid1000 verified')",
        SRC/'slot267.rs',body,RUSTC,out,BASE/'verify-control/booking.json'],work)
    need(access.strip()=='uid1000 verified','compiler UID path access probe')
    args=[str(RUSTC),'--sysroot',str(tc['VIEW']),'--edition=2021','-Dwarnings','-Copt-level=0','-Cdebuginfo=0','-Ccodegen-units=1','-Clinker=/usr/bin/gcc-15','-Clink-arg=-fuse-ld=bfd','-Clink-arg=-Wl,--no-keep-memory',str(SRC/'slot267.rs')]
    compiler=child([RUSTC,'--version','--verbose'],work)
    need(child([RUSTC,'--print','sysroot','--sysroot',str(tc['VIEW'])],work).strip()==str(tc['VIEW']),'compiler sysroot')
    child([*args,'--test','-o',work/'tests'],work)
    tests=child([work/'tests','--test-threads=1'],work)
    need('2 passed; 0 failed;' in tests,'native fixture tests')
    child([*args,'-o',work/'checker'],work)
    # Keep the verifier in root custody and run that exact copy unprivileged.
    chk=out/'checker'; source=work/'checker'
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    m=os.fstat(fd)
    try:
        need(stat.S_ISREG(m.st_mode) and m.st_uid==1000 and m.st_nlink==1 and 0<m.st_size<=16<<20 and os.path.samestat(m,source.lstat()),'unprivileged compiler output')
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd,'rb') as src,chk.open('xb') as dst:
        piece=src.read(m.st_size+1)
        need(len(piece)==m.st_size and os.fstat(fd).st_ctime_ns==m.st_ctime_ns and os.path.samestat(m,source.lstat()),'compiler output changed')
        dst.write(piece);dst.flush();os.fchmod(dst.fileno(),0o555);os.fsync(dst.fileno())
    before=stamp(chk);native=json.loads(child([chk,body],work))
    need(native=={'epoch':267,'kind':'slot-to-cid','bytes':SIZE,'entries':388871,'buckets':39,'all_cid_types_checked':True,'all_search_trees_checked':True,'car_lookups_verified':False,'admission_authorized':False} and stamp(chk)==before and stamp(body)==tr['body']['identity'],'native result/source identity')
    after_inputs=tc['check_view'](revision,True)
    need(after_inputs==before_inputs,'compiler input envelope changed')
    name=rows[1]['url'].rsplit('/',1)[1]
    dst=out/'sealed'
    plan=dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(dst),members=[dict(name=name,source=str(body),mode=0o444,sha256=tr['body']['sha256'])])
    record(out/'seal-plan.json',plan)
    subprocess.run([SEALER,out/'seal-plan.json','--plan-sha256',sha(out/'seal-plan.json'),'--self-sha256',SEALER_SHA],check=True,umask=0o022,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    receipt=dst/'deployment-seal-receipt.json';seal=json.loads(receipt.read_bytes())
    m,=seal['members'];sealed=dst/name
    need(seal['destination']==str(dst) and seal['plan_sha256']==sha(out/'seal-plan.json') and seal['sealer_sha256']==SEALER_SHA and m['name']==name and m['sha256']==tr['body']['sha256'] and m['bytes']==SIZE and m['mode']=='0444','seal binding')
    st=sealed.lstat()
    need(st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o444 and stamp(sealed)[2]==SIZE and sha(sealed)==tr['body']['sha256'] and stamp(body)==tr['body']['identity'],'sealed body')
    return dict(compiler_inputs_before=before_inputs,compiler_inputs_after=after_inputs,compiler_uid_probe=access.strip(),transfer_receipt_sha256=sha(transfer_path),transfer_invocation=tr['invocation'],checker_sha256=sha(chk),compiler=compiler,compiler_sha256=RUSTC_SHA,fixture_result=tests,structure=native,full_sha256=m['sha256'],cache_path=str(sealed),seal_sha256=sha(receipt))
def watch(phase,iid):
    ctl=BASE/(phase+'-control')
    book=ctl/'booking.json'
    digest=sha(book);token=ctl/'tokens'/iid/'guard-admission.json'
    t=json.loads(token.read_bytes())
    need(t['invocation']==iid and t['phase']==phase and t['booking']['sha256']==digest and sha(ctl/'first.json')==t['first_guard']['sha256'] and sha(ctl/'first-PID1.json')==t['guard_pid1']['sha256'],'first guard token')
    def checked():
        latest=json.loads((ctl/'latest.json').read_bytes())
        need(not (ctl/'trip.json').exists() and latest['invocation']==iid and latest['booking']['sha256']==digest and latest['trip'] is False and 0<=time.monotonic()-latest['monotonic']<15,'guard trip or stale timer')
    checked()
    def monitor():
        while True:
            time.sleep(1)
            try:checked()
            except BaseException:os._exit(78)
    threading.Thread(target=monitor,daemon=True).start()
def main():
    phase,=sys.argv[1:]
    need(phase in ('transfer','verify') and os.geteuid()==0,'invalid phase or UID')
    rootdir(BASE,0o711)
    need(Path(sys.executable).resolve()==Path('/usr/bin/python3.14') and sys.version_info[:2]==(3,14) and sha(Path('/usr/bin/python3.14'))=='be9a2a5eada8c89c1c399fdfb8397179e877c20d8db0739c802f726d4d0e69fd','original Python base')
    iid=os.environ['INVOCATION_ID']
    unit='horizon267-slot-'+phase+'-v1.service'
    need(re.fullmatch('[a-f0-9]{32}',iid) and Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/'+unit,'wrong cgroup or invocation')
    cg=Path('/sys/fs/cgroup/system.slice')/unit
    mem=134217728 if phase=='transfer' else 536870912
    need((cg/'memory.max').read_text().strip()==str(mem) and (cg/'memory.swap.max').read_text().strip()=='0' and (cg/'cpu.max').read_text().strip()=='100000 100000','wrong resource limits')
    # Main's service wrapper must hold its actual booked guard and release this process only after protection is live.
    need(SRC.resolve()==SRC and SRC.stat().st_uid==0 and not SRC.stat().st_mode&0o222 and all((SRC/k).lstat().st_uid==0 and not (SRC/k).lstat().st_mode&0o222 and sha(SRC/k)==v for k,v in PINS.items()),'source package custody')
    rows=[v for v in json.loads((SRC/'indexes.json').read_bytes()) if v['epoch']==267 and v['kind'] in ('car','slot-to-cid')]
    need([v['kind'] for v in rows]==['car','slot-to-cid'],'unexpected source order')
    watch(phase,iid)
    out=BASE/phase;rootdir(out,0o711);need(not list(out.iterdir()),'used phase stage')
    result=(transfer if phase=='transfer' else verify)(out,rows)
    record(out/'result.json',dict(phase=phase,invocation=iid,inputs=PINS,**result,replay_authorized=False,r2_mutations=False))
if __name__=='__main__':main()
