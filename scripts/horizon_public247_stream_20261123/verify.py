"""Run the current slot-range verifier against the pinned staged object. Archive staging is zero."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

sys.path.insert(0, '/var/lib/jetstreamer/horizon248-delivery-v213-tools')
import delivery248 as prior
from retry_fit import partition, price
from funds import put

D, V, CG = prior.D, prior.V, prior.CG
ref, bound, props = prior.ref, prior.bound, prior.props
NAME = 'horizon-r2-public247-current-reader-v214'
FIRST_UNIT = NAME + '.service'
UNIT = NAME + '-a2.service'
ROOT = D / NAME
REPORTS = ROOT / 'reports'
BOOK = ROOT / 'assignment.json'
LAUNCH = ROOT / 'launch.json'
END = ROOT / 'terminal.json'
ACCEPT = ROOT / 'verified.json'
PLAN = V / 'horizon247-public-reader-58709604-v1/epoch-247-plan.json'
OLD = Path('/home/ubuntu/.jetstreamer-private/current-reader-delivery-247-20261119-v2/playback/epoch-247-2774321-1795300264597561103')
ORIGIN = 'https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev'
LIMIT = 22 << 30
GROSS = LIMIT + (512 << 20)
METADATA = 32 << 20
CPUS = set(range(20,32))
SIZE = 180370916960
ETAG = '"c1be2474b6c9ba8d0ac11405a97ebee3-2688"'
SHA = '0533b69ef3377b59c485893fa1386cc632dd7489da6ec721eeb7dcfeaacd2116'
def remote():
    archive = prior.aws('head-object','--key','epoch-247.jet','--if-match',ETAG)
    assert archive['ETag']==ETAG and archive['ContentLength']==SIZE and archive['Metadata']['sha256']==SHA
    return dict(key='epoch-247.jet', bytes=SIZE, etag=ETAG, epoch=247)

def source():
    plan = bound(ref(PLAN))
    qual = bound(plan['qualification'])
    image = plan['pipeline']
    path = Path(image['path'])
    assert qual['pipeline']==image and path.resolve()==path and path.stat().st_uid==0 and not path.stat().st_mode & 0o222
    with path.open('rb') as file: assert hashlib.file_digest(file,'sha256').hexdigest()==image['sha256']
    assert image['sha256']=='f82ea2b2834cdca5732ff472188315868e780b6e02d39e2baa186daa77e91851'
    prior.git('fetch','origin','refs/heads/account-updates:refs/remotes/origin/account-updates')
    head=prior.git('rev-parse','origin/account-updates')
    scope=bound(prior.pin(D/'horizon247-reader-scope-v211-a1/comparison.json','8c7cfde8e5d7d82ce0a33e9f5c7c66f8d47f4bee944268e9edab67e2e38cc9b7'))['compared']
    for name in ('reader','compiled reader'):
        assert scope[name]['base']==plan['reader_commit'] and not prior.git('diff','--name-only',plan['reader_commit'],head,'--',*scope[name]['paths'])
    assert Path(__file__).read_text().strip()==prior.git('show',head+':scripts/horizon_public247_stream_20261123/verify.py')
    return dict(head=head, plan=ref(PLAN), image=image, reader=plan['reader_commit'], stack=qual['minimum_thread_stack_bytes'])

def active(book):
    fields=['Id','LoadState','ActiveState','SubState','MainPID','InvocationID','AllowedCPUs','MemoryMax','MemorySwapMax','Restart','NRestarts']
    state=props(UNIT,fields)
    assert state['Id']==UNIT and state['LoadState']=='loaded' and state['ActiveState']=='active' and state['SubState']=='running' and state['NRestarts']=='0'
    assert state['AllowedCPUs']=='20-31' and state['MemoryMax']==str(LIMIT) and state['MemorySwapMax']=='0' and state['Restart']=='no'
    pid=int(state['MainPID'])
    assert os.sched_getaffinity(pid)==CPUS and os.path.samefile(f'/proc/{pid}/exe',book['source']['image']['path'])
    assert Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')==[*map(os.fsencode,book['argv']),b'']
    assert str(pid) in (CG/UNIT/'cgroup.procs').read_text().split() and int((CG/UNIT/'memory.max').read_text())==LIMIT
    return state

def charge():
    if not BOOK.exists(): return 0,0
    book=bound(ref(BOOK))
    assert book['gross']==GROSS and book['metadata']==METADATA and book['archive_staging']==0 and book['donor']==ref(prior.BOOK)
    if END.exists():
        assert bound(ref(END))['assignment']==ref(BOOK) and bound(ref(END))['drained'] and not (CG/UNIT).exists()
        return METADATA,METADATA
    return GROSS,METADATA

def witness():
    if not BOOK.exists() or END.exists(): return {}
    if not LAUNCH.exists() and not (CG/UNIT).exists():
        assert props(FIRST_UNIT,['ActiveState','MainPID','ExecMainStatus']) == dict(ActiveState='failed',MainPID='0',ExecMainStatus='2')
        assert not (CG/FIRST_UNIT).exists()
        return {}
    state=active(bound(ref(BOOK)))
    assert state==bound(ref(LAUNCH))['unit']
    return {UNIT:(state['InvocationID'],int(state['MainPID']),LIMIT,CPUS)}

def install_price():
    target=Path('/run/horizon266-bounded-tools-v208/retry_fit.py')
    s=target.read_text()
    assert hashlib.sha256(s.encode()).hexdigest()=='0c29fa9984e56568d507270f05ea7b6631483d9b3884f521a036205b0c2e7321'
    for old,new in [
        (' import delivery248 as delivery',' import delivery248 as delivery\n sys.path.insert(0,"/var/lib/jetstreamer/horizon-public247-stream-v214")\n import verify as audit247'),
        ('  fixed.update(delivery.finite_owner())','  fixed.update(delivery.finite_owner())\n  fixed.update(audit247.witness())'),
        (" assert q['hard']<=total"," audit_growth,audit_disk=audit247.charge();growth+=audit_growth;floor+=audit_disk\n assert q['hard']<=total"),
        ('return dict(reserved_211_delivery=', 'return dict(public247_charge=audit_growth,public247_metadata=audit_disk,reserved_211_delivery=')]:
        assert s.count(old)==1
        s=s.replace(old,new)
    compile(s,str(target),'exec')
    tmp=target.with_suffix('.audit247');tmp.write_text(s);tmp.chmod(0o400);os.replace(tmp,target)

def issue():
    with partition.take():
        assert not BOOK.exists() and not (CG/UNIT).exists()
        assert props(UNIT,['LoadState','ActiveState','Job'])==dict(LoadState='not-found',ActiveState='inactive',Job='')
        q=price(0,0,0)
        _,_,parent,_=prior.registered()
        assert q['reserved_211_delivery']==ref(prior.BOOK) and parent['reserve_after']-GROSS>=prior.GROSS
        assert parent['donor_manager']['CPUAffinity']=='16-31' and not (CG/parent['donor']['unit']).exists()
        assert q['growth_margin']>=GROSS and q['disk_margin']>=METADATA
        assert all(CPUS.isdisjoint(os.sched_getaffinity(int(props(u,['MainPID'])['MainPID']))) for u in q['before'])
        f=bound(q['fleet']);assert {item['epoch'] for item in f['active']}=={247,248,266}
        observed=bound(dict(path=f['observer_receipt'],sha256=f['observer_sha256']))
        old,=[r for r in observed['delivery_resources'] if r['range']=='247-247']
        assert old['status']=='observed'
        local=ref(OLD/'local-plugin.json');historical=bound(local)
        assert historical['full_epoch_verified'] and historical['report']['worker_count']==2
        current=source()
        assert current['image']['path']!=historical['invocation'][0]
        # Two-worker measured RSS bounds the fast run's 16 simultaneous decoders. The process has a separate hard cap.
        measured=old['observation']['producer_after']['rss']['aggregate_rss_bytes']
        assert measured>0 and 8*measured<LIMIT
        row,=[e for e in f['inventory']['entries'] if e['epoch']==247]
        assert row['state']=='archive-only' and row['archive_metadata_sha256']==SHA
        obj=remote()
        assert row['archive_length']==SIZE and row['archive_etag']==ETAG.strip('"')
        assert bound(ref(OLD/'public-archive-inventory.json'))['objects']==[obj]
        ROOT.mkdir(mode=0o700,exist_ok=True);REPORTS.mkdir(mode=0o700)
        inv=put(ROOT/'inventory.json',dict(objects=[obj],public_origin=ORIGIN))
        argv=[current['image']['path'],'247:247',ORIGIN,'--verify-only','--slot-ranges','--threads','256','--max-active-partitions','16','--archive-inventory',inv['path'],'--verification-report-dir',str(REPORTS)]
        properties=['Type=exec','Restart=no','KillMode=control-group','AllowedCPUs=20-31','CPUAffinity=20-31','CPUQuota=1200%',
                    f'MemoryMax={LIMIT}','MemorySwapMax=0','TasksMax=512','LimitFSIZE=33554432','NoNewPrivileges=yes','ProtectSystem=strict','ProtectHome=read-only',
                    'CapabilityBoundingSet=','SupplementaryGroups=ubuntu','UMask=0077','PrivateDevices=yes','ReadWritePaths='+str(REPORTS),'StandardOutput=append:'+str(ROOT/'operation.log'),'StandardError=inherit']
        install_price()
        book=put(BOOK,dict(gross=GROSS,metadata=METADATA,archive_staging=0,source=current,argv=argv,properties=properties,pin=inv,control=prior.MAIN if hasattr(prior,'MAIN') else os.environ['CODEX_THREAD_ID'],
                          boot=q['boot'],fit=q,donor=ref(prior.BOOK),donor_after=parent['reserve_after']-GROSS,observed_two_worker_rss=measured,old_local=local,
                          memory_margin=q['growth_margin']-GROSS,disk_margin=q['disk_margin']-METADATA,sidecar_authority=False))
        subprocess.run(['systemd-run','--quiet','--unit='+UNIT,*['--property='+p for p in properties],
                        '--property=UnsetEnvironment=HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_S3_ENDPOINT AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK',
                        '--setenv=RUST_LOG=info','--setenv=RUST_MIN_STACK='+str(current['stack']),'--setenv=TOKIO_WORKER_THREADS=12',*argv],check=True)
        state=active(bound(book))
        put(LAUNCH,dict(assignment=book,unit=state,at=time.time()))
        print(LAUNCH,flush=True)
    finish()

def retry_unreadable_directory():
    with partition.take():
        book=bound(ref(BOOK))
        assert not LAUNCH.exists() and not END.exists() and not list(REPORTS.iterdir())
        old=props(FIRST_UNIT,['ActiveState','MainPID','ExecMainStatus','InvocationID','Result','NRestarts'])
        assert old==dict(ActiveState='failed',MainPID='0',ExecMainStatus='2',InvocationID='5e11e873f7c64b2283ebf1eb6f78a655',Result='exit-code',NRestarts='0')
        assert not (CG/FIRST_UNIT).exists() and not (CG/UNIT).exists()
        assert props(UNIT,['ActiveState','LoadState','Job'])==dict(ActiveState='inactive',LoadState='not-found',Job='')
        perms=['setpriv','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all']
        assert subprocess.run([*perms,'--clear-groups','test','-d',REPORTS]).returncode==1
        assert subprocess.run([*perms,'--groups','1000','test','-d',REPORTS]).returncode==0
        q=price(0,0,0)
        assert q['public247_charge']==GROSS and q['public247_metadata']==METADATA
        assert all(CPUS.isdisjoint(os.sched_getaffinity(int(props(u,['MainPID'])['MainPID']))) for u in q['before'])
        assert remote()==bound(book['pin'])['objects'][0]
        checked=source();assert checked['image']==book['source']['image']
        properties=['StandardOutput=append:'+str(ROOT/'public-replay.log') if p.startswith('StandardOutput=') else p for p in book['properties']]
        properties.append('SupplementaryGroups=ubuntu')
        retry=put(ROOT/'retry.json',dict(prior_manager=old,assignment=ref(BOOK),source=checked,fit=q,properties=properties,original_log=ref(ROOT/'operation.log'),unit=UNIT,extra_memory=0))
        subprocess.run(['systemd-run','--quiet','--unit='+UNIT,*['--property='+p for p in properties],
                        '--property=UnsetEnvironment=HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_S3_ENDPOINT AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK',
                        '--setenv=RUST_LOG=info','--setenv=RUST_MIN_STACK='+str(checked['stack']),'--setenv=TOKIO_WORKER_THREADS=12',*book['argv']],check=True)
        state=active(book)
        put(LAUNCH,dict(assignment=ref(BOOK),retry=retry,unit=state,at=time.time()))
        print(LAUNCH,flush=True)
    finish()

def finish():
    b=bound(ref(BOOK));l=bound(ref(LAUNCH));assert l['assignment']==ref(BOOK)
    with (ROOT/'finish.lock').open('ab') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if not END.exists():
            pid=int(l['unit']['MainPID'])
            if Path(f'/proc/{pid}').exists():
                fd=os.pidfd_open(pid); assert l['unit']==active(b)
                poll=select.poll();poll.register(fd,select.POLLIN);poll.poll();os.close(fd)
            deadline=time.monotonic()+30
            while True:
                state=props(UNIT,['MainPID','ActiveState','Job'])
                raw=subprocess.check_output(['journalctl','-o','json','--no-pager','_PID=1','_UID=0','UNIT='+UNIT,'INVOCATION_ID='+l['unit']['InvocationID']])
                life=[json.loads(line) for line in raw.splitlines()]
                success=any(e.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' for e in life)
                if not (CG/UNIT).exists() and state['MainPID']=='0' and not state['Job'] and state['ActiveState'] in ('failed','inactive') and (success or any(e.get('UNIT_RESULT') for e in life)):break
                assert time.monotonic()<deadline;time.sleep(.5)
            assert all(e['_BOOT_ID']==b['boot'].replace('-','') for e in life)
            success=success and all(e.get('UNIT_RESULT','success')=='success' for e in life)
            put(END,dict(assignment=ref(BOOK),launch=ref(LAUNCH),drained=True,manager=state,events=life,success=success))
        assert bound(ref(END))['success']
        native=ref(REPORTS/'epoch-247.json');result=bound(native)
        assert result['full_epoch_verified'] and result['schema']=='jetstreamer-horizon-plugin-playback-v1' and result['source']==ORIGIN and result['invocation']==b['argv']
        r=result['report'];old=bound(b['old_local'])['report']
        assert r['epoch']==247 and r['slots']==432000 and r['first_slot']==result['expected_first_slot']==106704000 and r['last_slot']==result['expected_last_slot']==107135999
        assert r['worker_count']==256 and len(r['stream_digest'])==32
        for key in ('slots','blocks','skipped','entries','transactions','transaction_updates','orphan_updates','epoch_updates','account_data_bytes'):assert old[key]==r[key],key
        assert [remote()]==bound(b['pin'])['objects'];branch=source()
        print(put(ACCEPT,dict(terminal=ref(END),report=native,source_after=branch,authenticated_object=remote(),counters_match=True,publication_performed=False,archive_staging=0)),flush=True)

if __name__=='__main__':
    action,=sys.argv[1:]
    {'issue':issue,'retry-unreadable-directory':retry_unreadable_directory,'finish':finish}[action]()
