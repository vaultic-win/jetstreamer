from pathlib import Path
import ast,fcntl,hashlib,importlib.util,json,os,re,subprocess,sys,tempfile,time

V=Path('/var/lib/jetstreamer')
BASE=V/'horizon230-program-demotion-ram-v328'
CONTROL=V/'horizon-seven-publication-controller-v222'
TOKEN_ROOT=V/'horizon230-program-demotion-tokens-v328'
CURRENT=V/'horizon292-full-v322'
SOURCE=Path('/home/ubuntu/workspace/jetstreamer')
SOURCE_PATH=Path('scripts/horizon_foundation_delivery247_20261124')
ADAPTER='diagnostic230_program_demotion_ram'
PROFILE_SHA=sys.argv[1]
assert re.fullmatch('[0-9a-f]{64}',PROFILE_SHA)
spec=importlib.util.spec_from_file_location('accepted_standalone_launch',CURRENT/'admit.py')
kit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)
ops,runner,starter=kit.ops,kit.replay,kit.startup
THREAD=runner.THREAD

def store(path, data):
    with path.open('x') as out:
        os.fchmod(out.fileno(),0o400)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    return ops.ref(path)

def git(*args):
    return subprocess.check_output(['runuser','-u','ubuntu','--','git','-C',str(SOURCE),*args],timeout=20)

def source_provenance(profile):
    remote=git('rev-parse','origin/account-updates').decode().strip()
    qualification=ops.bound(profile['worker_qualification'])
    commit=qualification['source_commit']
    assert re.fullmatch(r'[0-9a-f]{40}',commit)
    git('merge-base','--is-ancestor',commit,remote)
    deployment={
        'epoch230_program_demotion_inputs.py': BASE/'finalize-inputs-v2.py',
        'epoch230_program_demotion_launch.py': Path(__file__).resolve(),
        'epoch230_program_demotion.service.template': BASE/'producer.service.template',
    }
    for name,path in deployment.items():
        assert git('show',f'{remote}:{SOURCE_PATH/name}')==path.read_bytes(),name
    return dict(remote=remote,repair_commit=commit)

def cadence_changes(profile):
    source=CONTROL/'diagnostic230_bank_trace.py'
    adapter=source.read_text()
    for before,after in (
        ('horizon-qualify-230-bank-trace-v316.service',profile['unit']),
        ('horizon230-bank-trace-ram-v316',BASE.name),
        ('/home/ubuntu/.jetstreamer-private/epoch230-trace-tmpfs-v316/run',profile['run_root']),
        ('bank hash diagnostic','program account demotion diagnostic'),
        ('europe-rooted-slot-hash-comparison','europe-rooted-program-demotion-comparison'),
        ('Compare the captured bank hash inputs, dirty account hashes and rewards at slots 99368200 and 99368201 with the finalized history.',
         'Verify the signed epoch 230 bank hash through the program-account demotion and independent terminal checkpoint.')):
        assert before in adapter,before
        adapter=adapter.replace(before,after)
    anchor='    assert re.fullmatch("[0-9a-f]{32}", row["invocation_id"]) and row["main_pid"] > 0'
    assert adapter.count(anchor)==1
    adapter=adapter.replace(anchor,anchor+"""
    assert row["first_divergent_slot"] == 99368201
    assert bound(row["admission"])["profile"]["sha256"] == '"""+PROFILE_SHA+"""'
    active_guard = bound(row["active_guard"])
    assert active_guard["producer_invocation_id"] == row["invocation_id"] and active_guard["trip_reason"] is None
    assert active_guard["plan_sha256"] == row["guard_plan"]["sha256"] and active_guard["producer"]["pid"] == row["main_pid"]""")
    modifications={
      'cycle.py':[
        ('import diagnostic230_bank_trace\n','import diagnostic230_bank_trace\nimport '+ADAPTER+'\n'),
        ("cfg['diagnostic_replays'] += diagnostic230_bank_trace.configuration()",
         "cfg['diagnostic_replays'] += diagnostic230_bank_trace.configuration()\ncfg['diagnostic_replays'] += "+ADAPTER+".configuration()"),
        ('    diagnostic230_bank_trace.gate(plan)','    diagnostic230_bank_trace.gate(plan)\n    '+ADAPTER+'.gate(plan)'),
        ('and not diagnostic229_slot_hash_ram.owns(r)]','and not diagnostic229_slot_hash_ram.owns(r) and not '+ADAPTER+'.owns(r)]')],
      'native_binding_replays.py':[
        ('import diagnostic230_bank_trace\n','import diagnostic230_bank_trace\nimport '+ADAPTER+'\n'),
        ('diagnostic230_bank_trace, diagnostic229_slot_hash_ram)','diagnostic230_bank_trace, diagnostic229_slot_hash_ram, '+ADAPTER+')')]}
    path=CONTROL/(ADAPTER+'.py')
    assert not path.exists()
    ast.parse(adapter)
    changes=[]
    for filename,updates in modifications.items():
        original=CONTROL/filename
        previous=original.read_text()
        contents=previous
        for marker,edit in updates:
            assert contents.count(marker)==1, marker
            contents=contents.replace(marker,edit)
        ast.parse(contents,filename=filename)
        changes.append((original,previous,contents))
    return path, adapter, changes

def install(changeset):
    path, adapter, changes = changeset
    saved=[store(BASE/(file.name+'.previous'),data) for file,data,_ in changes]
    def deploy(dest,blob):
        with tempfile.NamedTemporaryFile(dir=CONTROL,delete=False,mode='w') as out:
            tmp=out.name
            os.fchmod(out.fileno(),0o400)
            out.write(blob);out.flush();os.fsync(out.fileno())
        os.replace(tmp,dest)
        return ops.ref(dest)
    installed=[deploy(path,adapter)]
    for file,_,contents in changes:
        installed.append(deploy(file,contents))
    fd=os.open(CONTROL,os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return ops.funds.put(BASE/'cadence-deployment.json',dict(previous=saved,installed=installed,publication_authorized=False))

def fresh_fit(profile):
    _,fleet_ref,fleet=kit.measure.source.latest()
    assert next(r for r in fleet['inventory']['entries'] if r['epoch']==230)['state']=='missing'
    owners={}
    reconciled_terminals={}
    for row in fleet['active']:
        epoch=row['epoch']
        assert epoch not in owners
        live=row['producer']
        if epoch==229:
            terminal=V/'horizon229-trace-ram-v325/terminal.json'
            if terminal.is_file():
                terminal_ref=ops.ref(terminal)
                record=ops.bound(terminal_ref)
                correction_ref=ops.ref(terminal.with_name('terminal-timer-correction.json'))
                correction=ops.bound(correction_ref)
                assert record['epoch']==correction['epoch']==229 and correction['original_terminal']==terminal_ref
                observed=record['producer']
                assert observed['Id']==live['Id'] and observed['InvocationID']==live['InvocationID']
                assert correction['invocation_id']==observed['InvocationID']
                assert observed['MainPID']=='0' and not observed['ControlGroup']
                assert ops.props(observed['Id'],list(observed))==observed
                timer=correction['guard_timer_before']
                for unit,state in ((timer['Id'],correction['guard_timer_drained']),
                                   (timer['Unit'],correction['guard_service_drained'])):
                    assert state['ActiveState']=='inactive' and state['Job']==''
                    assert ops.props(unit,list(state))==state
                reconciled_terminals[epoch]=dict(terminal=terminal_ref,guard_correction=correction_ref)
                continue
        owners[epoch]=kit.measure.source.helper.active_props(live['Id'],live['InvocationID'])
    assert set(owners)-{229}=={226,252,257,261,292}
    last=ops.bound(ops.ref(CURRENT/'admission.json'))['fit']
    for epoch,folder,lane in [(288,'horizon288-full-v303',last['live_units']['288']),
                              (230,'horizon230-bank-trace-ram-v316',last['diagnostic_ram_owner'])]:
        record=ops.bound(ops.ref(V/folder/'terminal.json'))
        assert record['epoch']==epoch and record['timer_drained']=={'ActiveState':'inactive','Job':''}
        assert ops.bound(record['registration'])['invocation_id']==lane['InvocationID']
        owner=record['producer']
        assert owner['Id']==lane['Id'] and owner['MainPID']=='0' and not owner['ControlGroup']
        assert ops.props(owner['Id'],list(owner))==owner
    broker=last['broker']
    hold=kit.measure.source.helper.active_props(broker['Id'],broker['InvocationID'])
    live=[*owners.values(),hold]
    observed=subprocess.check_output(['systemctl','list-units','--type=service','--state=running,activating','--no-pager',
        '--no-legend','--plain','horizon-qualify-*','horizon-perf-*','horizon-upload-*','horizon-restore-*',
        'foundation-*-broker-*'],text=True,timeout=10)
    assert {p['Id'] for p in live}=={line.split()[0] for line in observed.splitlines() if line.strip()}
    pool=set(profile['cpu'])
    assert all(p['AllowedCPUs'] and not pool & kit.measure.source.helper.cpus(p['AllowedCPUs']) for p in live)
    mem={key:int(val.split()[0])*1024 for key,val in
        (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()) if key in ('MemAvailable','MemTotal')}
    reserve=sum(max(0,int(r['MemoryMax'])-int(r['MemoryCurrent'])) for r in live)
    headroom=mem['MemAvailable']-mem['MemTotal']//10-reserve
    st=os.statvfs(profile['filesystem'])
    tmpfs_bytes=st.f_frsize*st.f_bavail
    assert os.stat('/').st_dev!=os.stat(profile['filesystem']).st_dev
    assert tmpfs_bytes >= profile['ram_scratch_cap_bytes']+(2 << 30)
    assert headroom>=profile['memory_max_bytes'],headroom
    return dict(fleet=fleet_ref,live=owners,reconciled_terminals=reconciled_terminals,broker=hold,headroom=headroom,
                tmpfs_available_bytes=tmpfs_bytes,sampled_unix_seconds=int(time.time()))

def inventory():
    binary=ops.checked_image(ops.R2)
    cmd=['systemd-run','--quiet','--wait','--pipe','--collect','--unit=foundation-230-focused-inventory-v328',
         '--property=Type=exec','--property=EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env',
         '--setenv=TOKIO_WORKER_THREADS=2','--',binary,'inventory','/home/ubuntu/horizon',
         '--epochs','230-230','--receipt-directory','/home/ubuntu/.jetstreamer-private/r2-receipts']
    doc=json.loads(subprocess.check_output(cmd,timeout=40))
    assert doc['schema']=='jetstreamer-horizon-r2-inventory-v1' and doc['anomalies']==0
    row,=doc['entries']
    assert row['epoch']==230 and row['state']=='missing'
    return row

def launch(profile,profile_ref,observed,deployment,provenance):
    fit=fresh_fit(profile)
    assert int(time.time())-fit['sampled_unix_seconds'] <= 20
    unit,guard=profile['unit'],profile['guard_unit']
    timer=guard.replace('.service','.timer')
    receipts=BASE/'guard-receipts'
    proposal=ops.bound(profile['focused'])
    static=ops.bound(profile['guard_plan'])
    claim=ops.funds.put(BASE/'admission.json',dict(epoch=230,controller=THREAD,profile=profile_ref,fit=fit,
        source_provenance=provenance,
        schema='foundation-epoch230-program-demotion-admission-v328', exact_inventory=observed,deployment=deployment,
        admitted=True,canonical_epoch_publication_authorized=False))
    for name in (unit,guard,timer):
        state=ops.props(name,['LoadState','ActiveState','Job'])
        assert state==dict(LoadState='not-found',ActiveState='inactive',Job=''),state
    properties,argv=starter.start_props(unit,Path(profile['producer']['path']))
    assert argv==profile['argv']
    properties.append(f'--property=ExecStartPre=/usr/bin/bash {TOKEN_ROOT / "pre-start.sh"} 60 {TOKEN_ROOT}')
    starter.systemd_run(unit,properties,argv,'--slice=system.slice')
    def prestart():
        status=ops.props(unit,['InvocationID','ActiveState','SubState','ControlPID','MainPID'])
        if (status['ActiveState'],status['SubState'],status['MainPID'])==('activating','start-pre','0') and int(status['ControlPID'])>0:
            return status
        return None
    iid=starter.until(prestart,12)['InvocationID']
    assert re.fullmatch('[0-9a-f]{32}',iid)
    plan=ops.funds.put(BASE/'guard-plan.json',dict(static,invocation_id=iid))
    gprops=['--property=Type=oneshot','--property=User=root','--property=UMask=0077',
        '--property=Restart=no','--property=MemoryMax=1G','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=TasksMax=256','--property=TimeoutStartSec=90','--property=ProtectSystem=strict',
        '--property=ProtectHome=read-only','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes',
        '--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE',
        '--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE',f'--property=ReadWritePaths={receipts}']
    runner.PRODUCER,runner.GUARD_UNIT,runner.TIMER,runner.RECEIPTS=unit,guard,timer,receipts
    runner.GUARD_SHA=profile['guard']['sha256']
    starter.systemd_run(guard,gprops,[profile['guard']['path'],plan['path'],'--plan-sha256',plan['sha256'],
        '--self-sha256',runner.GUARD_SHA],'--on-active=1s','--on-unit-inactive=60s',
        '--timer-property=AccuracySec=1s','--timer-property=RandomizedDelaySec=0')
    first,sample=starter.until(lambda:runner.first_guard(iid,plan),35)
    clock,next_observation=starter.until(runner.timer_ready,15)
    assert prestart()['InvocationID']==iid and sample['root_physical_observation_error'] is None
    stamp=TOKEN_ROOT/iid
    stamp.mkdir(mode=0o755);stamp.chmod(0o755)
    token=ops.funds.put(stamp/'guard-admission.json',dict(epoch=230,unit=unit,invocation_id=iid,
        guard_invocation_id=sample['guard_invocation_id'], sample=first,admission=claim,guard_plan=plan,
        guard_timer_invocation=clock['InvocationID'],next_guard_monotonic_usec=next_observation,
        canonical_epoch_publication_authorized=False))
    def running():
        status=ops.props(unit,['InvocationID','ActiveState','SubState','MainPID','NRestarts','ControlGroup','Result','LoadState'])
        if (status['ActiveState'],status['SubState'])!=('active','running'):
            return None
        pid=int(status['MainPID'])
        assert status['InvocationID']==iid and status['NRestarts']=='0' and pid>0
        binary=Path('/proc')/str(pid)/'exe'
        if not binary.samefile(argv[0]):
            return None
        for path in sorted(receipts.glob('sample-*.json'),key=lambda p:p.stat().st_mtime_ns,reverse=True):
            sample_ref=ops.ref(path)
            reading=ops.bound(sample_ref)
            if reading['producer']['active']!='active' or not reading['workers']:
                continue
            assert reading['producer_invocation_id']==iid and reading['producer']['pid']==pid and reading['plan_sha256']==plan['sha256']
            assert reading['trip_reason'] is None and reading['worker_observation_error'] is None
            return status,pid,sample_ref
        return None
    status,pid,qualified=starter.until(running,220)
    identity=dict(unit=unit,active_state='active',sub_state='running',main_pid=pid,invocation_id=iid,
        restarts=0,result=status['Result'],load_state=status['LoadState'],guarded_binding_verified=True)
    registration=ops.funds.put(BASE/'cadence-registration.json',dict(
        schema='jetstreamer-historical-performance-launch-receipt-v1',kind='europe-rooted-program-demotion-comparison',
        epoch=230,unit=unit,invocation_id=iid,main_pid=pid,node_path=argv[0],run_root=profile['run_root'],
        bootstrap_slot=proposal['bootstrap_slot'],first_divergent_slot=proposal['first_divergent_slot'],
        target_slot=proposal['following_vote_slot'],terminal_slot=proposal['checkpoint_slot'],
        launched=True,entry_replay_requested=True,canonical_epoch_publication_authorized=False,remote_mutations=False,r2_mutations=False,
        admission=claim,guard_plan=plan,launch_token=token,active_guard=qualified,evidence=dict(units=[identity])))
    print(json.dumps(registration),flush=True)

assert os.geteuid()==0 and __debug__ and os.environ['CODEX_THREAD_ID']==THREAD
os.umask(0o077)
with kit.partition.take(), (CONTROL/'cycle.lock').open('a+b') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert kit.partition.locked(kit.partition.LOCK,os.getpid())
    assert ops.props('foundation-publication-cadence-v222.service',['ActiveState','Job'])=={'ActiveState':'inactive','Job':''}
    binding=dict(path=str(BASE/'profile.json'),sha256=PROFILE_SHA)
    profile=ops.bound(binding)
    assert profile['epoch']==230 and not profile['canonical_epoch_publication_authorized']
    assert not (BASE/'admission.json').exists()
    provenance=source_provenance(profile)
    for role in ('guard','worker','node'):
        assert ops.checked_image(profile[role])==profile[role]['path']
    for role in ('producer','guard_plan','token','namespace','focused'):
        assert ops.ref(Path(profile[role]['path']))==profile[role]
    assert ops.bound(profile['namespace'])['result']['namespace_verified']
    assert list(TOKEN_ROOT.iterdir())==[TOKEN_ROOT/'pre-start.sh']
    checked=inventory()
    preview=fresh_fit(profile)
    changeset=cadence_changes(profile)
    print(json.dumps(dict(epoch=230,available_after_commitments=preview['headroom'],tmpfs_bytes=preview['tmpfs_available_bytes'])),flush=True)
    if '--check-only' not in sys.argv:
        deployment=install(changeset)
        launch(profile,binding,checked,deployment,provenance)
