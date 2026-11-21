"""Read the actual restarted archive producers and their native standalone guard evidence."""
from pathlib import Path
import time
import subprocess
import json
import stat

from evidence import BASE, bound, checked, need
from guard_stops import EVENT

HOME = Path('/home/sol/.jetstreamer-private')
ROUTES = {
    166: ('166-independent-recovery-20261121-v1', 'epoch166-independent-cold-recovery-20261121-v1',
          HOME/'epoch166-independent-cold-20261120-v1/replacement-local3retry10-20261121-v1', 93782017, 288),
    167: ('167-source-index-v1-20261121', 'epoch167-source-index-recovery-20261121-v1',
          HOME/'epoch167-standard-lane-20261109-v1/replacement-source-index-v1-20261121', 107675649, 512),
    170: ('170-replacement-local3retry10-20261121-v1', 'epoch170-retry10-recovery-20261121-v1',
          HOME/'epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1', 113710084, 288),
}
GUARD_SHA = '07f6924ee1cf8d8311aa7bed6620dcf1af580a5546e948206af628c57aa3443b'
QUAL = {'path':str(BASE/'incident-replay-guard-20261121-v1/GUARD_QUALIFIED.json'),
        'sha256':'d1db864cb4e9fab729238d03ec2bb291ff9985ed59c93b9370f4b1ac1b9053f1'}
FIELD = 'original_disk_guard_recovery_workers'
ACTOR = ('Id','MainPID','InvocationID','ControlGroup','ActiveState','SubState','Job','NRestarts',
         'MemoryMax','CPUQuotaPerSecUSec','MemorySwapMax','ExecMainStartTimestamp')


def node(epoch):
    return 'horizon-qualify-' + ROUTES[epoch][0] + '.service'


def timer(epoch):
    return 'horizon-guard-' + ROUTES[epoch][0] + '.timer'


def native(epoch):
    from owners import show, ticks

    unit = node(epoch)
    row = show(unit, ACTOR)
    if row['ActiveState'] in ('inactive', 'failed') and row['MainPID'] == '0' and not row['Job']:
        return None
    name, subdir, run, inode, _ = ROUTES[epoch]
    root = BASE / subdir
    intent = checked(bound(root/'START_INTENT.json'))
    need(intent['epoch'] == epoch and intent['producer_unit'] == unit and intent['timer_unit'] == timer(epoch)
         and (run.stat().st_dev, run.stat().st_ino) == (HOME.stat().st_dev, inode), 'unregistered replacement intent')
    need(row['ActiveState'] == 'active' and row['SubState'] == 'running' and row['NRestarts'] == '0'
         and row['MemoryMax'] == str(68<<30) and row['CPUQuotaPerSecUSec'] == '9s' and row['MemorySwapMax'] == '0'
         and not row['Job'] and row['ControlGroup'] == '/system.slice/' + unit, 'wrong replacement node or booking')
    pid = int(row['MainPID'])
    proc = Path('/proc') / str(pid)
    need((proc/'exe').readlink().name == 'jetstreamer-node' and
         (proc/'cgroup').read_text().strip() == '0::'+row['ControlGroup'], 'foreign replacement node image')
    identity = dict(producer_pid=pid, producer_unit=unit, producer_invocation_id=row['InvocationID'], start_ticks=ticks(pid))
    if (root/'ACTUAL_PRODUCER_NATIVE.json').exists():
        observed=checked(bound(root/'ACTUAL_PRODUCER_NATIVE.json'))
        image=(proc/'exe').stat()
        need(all(observed[k] == v for k,v in identity.items()) and
             (observed['exe_device'],observed['exe_inode'])==(image.st_dev,image.st_ino),
             'changed replacement actor')
    return row, identity


def guard(epoch, admission, actor):
    from owners import show

    _, subdir, _, _, cap = ROUTES[epoch]
    root = BASE / subdir
    planref = bound(root/'ACTUAL_GUARD_PLAN.json')
    plan = checked(planref)
    directory = root/'guard-receipts'
    t = show(timer(epoch), ('Id','InvocationID','ActiveState','SubState','Triggers','Job'))
    service = timer(epoch).removesuffix('.timer')+'.service'
    required = dict(unit=node(epoch), invocation_id=actor['producer_invocation_id'], filesystem='/home/sol',
                    maximum_root_physical_bytes=cap<<30, receipt_directory=str(directory))
    qualified = checked(QUAL)
    need(qualified['guard']['sha256'] == GUARD_SHA and plan["data_fulfillment"] == qualified["contract"],
         "unqualified guard contract or image")
    need(admission['actual_guard_plan'] == planref and all(plan[k] == v for k,v in required.items())
         and t['InvocationID'] == admission['timer_invocation_id'] and t['ActiveState'] == 'active'
         and not t['Job'] and t['Triggers'] == service, 'changed actual guard configuration')
    need(admission['first_guard']==bound(root/'FIRST_GUARD.json') and
         admission['post_guard_capacity']==bound(root/'POST_GUARD_CAPACITY.json') and
         checked(admission['post_guard_capacity'])['fits'] is True, 'foreign first guard or post-guard fit')
    candidates=sorted(directory.glob('sample-*.json'), key=lambda p:p.stat().st_mtime_ns, reverse=True)
    for p in candidates[:3]:
        ref=bound(p);sample=checked(ref);gid=sample['guard_invocation_id']
        need(sample['guard_sha256']==GUARD_SHA and sample['plan_sha256']==planref['sha256'] and
             p.name=='sample-'+gid+'.json' and sample['producer_invocation_id']==actor['producer_invocation_id']
             and sample['producer']['pid']==actor['producer_pid'] and sample['producer']['active']=='active'
             and sample['producer_stop_enabled'] and sample['trip_reason'] is None
             and sample['DATA_fulfillment_observation_error'] is None and sample['DATA_fulfillment']
             and sample['worker_observation_error'] is None and sample['root_physical_observation_error'] is None
             and not sample['root_physical_observation']['exceeds_budget'] and
             0 <= time.time()-sample['recorded_unix_seconds'] <= 120, 'stale or tripped replacement guard')
        events = subprocess.check_output(['journalctl','--no-pager','-ojson','--output-fields=UNIT,INVOCATION_ID,JOB_RESULT',
                        '_PID=1','UNIT='+service,'INVOCATION_ID='+gid,'-n12'],timeout=15,text=True)
        if any(json.loads(line).get('JOB_RESULT') == 'done' for line in events.splitlines()):
            return dict(receipt=ref,timer=t,guard_invocation=gid),sample
    raise ValueError('pending completed native guard for '+str(epoch))


def observe_worker(epoch, actor, first, sample):
    from owners import ticks

    unit = node(epoch)
    _, _, run, _, _ = ROUTES[epoch]
    pid = first['worker_pid']
    need(all(first[k] == v for k,v in actor.items()) and first['epoch']==epoch and len(sample['workers'])==1
         and sample['workers'][0][0]==pid and ticks(pid)==first['worker_start_ticks'], 'changed protected worker')
    proc=Path('/proc')/str(pid);image=(proc/'exe').readlink()
    need((proc/'cgroup').read_text().strip()=='0::/system.slice/'+unit and
         int((proc/'stat').read_text().rsplit(')',1)[1].split()[1])==actor['producer_pid'] and
         (proc/'exe').samefile(image) and image.is_relative_to(run/'private'), 'worker cgroup, parent or image changed')
    cfg=first['observer_row'];log=run/'producer.log';st=log.lstat()
    need(cfg['range']==str(epoch) and cfg['expected_producer_invocation_id']==cfg['expected_controller_invocation_id']==actor['producer_invocation_id']
         and cfg['controller_unit']==cfg['producer_unit']==unit and image.name==cfg['worker_executable_basename']
         and image.is_relative_to(cfg['scratch_path']) and Path(cfg['scratch_path']).is_relative_to(run/'private')
         and cfg['append_log']==dict(path=str(log),device=st.st_dev,inode=st.st_ino)
         and st.st_uid==0 and stat.S_ISREG(st.st_mode) and not st.st_mode&0o077 and st.st_nlink==1
         and (Path('/proc')/str(actor['producer_pid'])/'fd/1').samefile(log), 'foreign worker journal or observation path')
    return cfg


def ownership(fleet):
    """Stable identity for every new unit, including a pre-admission actor."""
    view={}
    old=fleet.get(FIELD,{})
    events = checked(EVENT)['reports']
    for epoch, (_, subdir, _, _, _) in ROUTES.items():
        root=BASE/subdir
        state=native(epoch)
        if state is None:
            need(str(epoch) not in old and not (root/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists(),
                 'replacement stopped; reconcile the actual terminal')
            continue
        unit,actor=state
        record=dict(unit=unit,actor=actor,admission=None,first_worker=None)
        if (root/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists():
            ar=bound(root/'ACTUAL_ADMISSION_AND_PROTECTION.json'); ad=checked(ar)
            intent=checked(bound(root/'START_INTENT.json'))
            need(ad['intent']==bound(root/'START_INTENT.json') and ad['fleet']==intent['fleet']
                 and ad['stable_root']==intent['stable_root'] and ad['predecessor_stop']==intent['predecessor_stop']
                 and ad['resource_credit_bytes']==0, 'unbound replacement intent or booking')
            need(ad['epoch']==epoch and all(ad[k]==v for k,v in actor.items()) and
                 ad['predecessor_stop']==checked(events[str(epoch)])['guard_stop_completion']
                 and ad['timer_unit']==timer(epoch) and ad['bootstrap_only'] and not ad['transaction_replay_claimed']
                 and ad['first_guard']==bound(root/'FIRST_GUARD.json') and ad['actual_guard_plan']==bound(root/'ACTUAL_GUARD_PLAN.json'),
                 'admission belongs to another generation')
            record['admission']=ar
            if (root/'FIRST_PROTECTED_WORKER.json').exists():
                fr=bound(root/'FIRST_PROTECTED_WORKER.json')
                need(checked(fr)['admission']==ar,'protected worker belongs to another generation')
                record['first_worker']=fr
        prev=old.get(str(epoch))
        if prev:
            need(prev['actor']==actor and all(not prev[k] or prev[k]==record[k] for k in ('admission','first_worker')),
                 'prior admitted replacement or worker changed')
        view[str(epoch)]=record
    return view


def freeze(c):
    from evidence import durable,ensure_dir

    live=ownership(c.fleet)
    path=c.paths['out']/'RECOVERED_WORKERS.json'
    ensure_dir(path.parent)
    if not path.exists():
        sampled={}
        for key, entry in live.items():
            epoch=int(key);ad=entry['admission']
            if not ad:continue
            proof,sample=guard(epoch,checked(ad),entry['actor'])
            cfg=None
            if entry['first_worker']:
                cfg=observe_worker(epoch,entry['actor'],checked(entry['first_worker']),sample)
            sampled[key]=dict(protection=proof,config=cfg)
        durable(path,dict(fleet=c.fleet_ref,sample=c.sample_ref,owners=live,measured=sampled))
    ref=bound(path);v=checked(ref)
    need(v['fleet']==c.fleet_ref and v['sample']==c.sample_ref and v['owners']==live,
         'replacement changed during observation')
    return ref,v


def sample_rows(c, observed_lane):
    reference,capture=freeze(c)
    c.recovered_ref=reference
    c.recovered_owners=capture['owners']
    c.new_rows={}
    for key,measured in capture['measured'].items():
        epoch=int(key);captured=c.recovered_owners[key]
        actor=captured['actor'];cfg=measured['config'];ar=captured['admission'];ad=checked(ar)
        configured=[r for r in c.cfg['replays'] if r['range']==key]
        sampled=[r for r in c.sample['replays'] if r['range']==key]
        need(len(configured)==len(sampled)<=1 and (not configured or configured==[cfg]),
             'scheduled successor worker configuration changed')
        previous=next((r for r in c.fleet['actual_executing_replays']+c.fleet['actual_active_bootstraps']
                       if r['epoch']==epoch and r['admission']==ar),{})
        advancing=False
        work=None
        if sampled:
            s=sampled[0]
            advancing=observed_lane(s,cfg,actor['producer_invocation_id'],actor['producer_pid'])
            first=checked(captured['first_worker'])
            need(all(s[k]['pid']==first['worker_pid'] and s[k]['matching_workers']==1 and s[k]['executable_beneath_bound_scratch']
                 for k in ('worker_before','worker_after')), 'different successor worker in coordinated sample')
            work=s['useful_work']
            if advancing:
                last=work['last'];prior=previous.get('last_progress')
                need(epoch*432000<=work['first']['slot']<=last['slot']<=(epoch+1)*432000-1 and
                     last['terminal_slot']==(epoch+1)*432000-1, 'replacement progressed outside assigned epoch')
                advancing=work['counter_resets']==0 and (not prior or (last['slot']>=prior['slot'] and
                          last['transactions']>=prior['transactions'] and last['realtime_microseconds']>prior['realtime_microseconds']))
            c.lanes[epoch]=s
        phase='replay' if advancing or previous.get('phase')=='replay' else 'verification'
        c.advancing[epoch]=advancing
        c.new_rows[epoch]=dict(epoch=epoch,unit=captured['unit'],start_ticks=actor['start_ticks'],admission=ar,
            first_guard=ad['first_guard'],guard_timer=measured['protection']['timer'],guard_protection=measured['protection']['receipt'],
            post_guard_capacity=ad['post_guard_capacity'],phase=phase,stage='bootstrap' if phase=='verification' else 'replay',
            observer=c.sample_ref,observer_config=cfg,measured_progress=advancing,in_current_observer=bool(configured),
            scratch_path=cfg['scratch_path'] if cfg else None,progress=work,
            last_progress=work['last'] if advancing else previous.get('last_progress'),recovery_observation=reference)
        if cfg:
            c.next_cfg['replays'].append(cfg)
    c.next_cfg['replays'].sort(key=lambda x:int(x['range']))


def install(fleet,c):
    fleet[FIELD]=c.recovered_owners
    fleet['recovered_workers_observation']=c.recovered_ref
    for e,row in c.new_rows.items():
        boot=row['phase']!='replay'
        owner_key='actual_active_bootstraps' if boot else 'actual_executing_replays'
        fleet[owner_key].append(row)
        item=next(r for r in fleet['epochs'] if r['epoch']==e)
        item.update(current_repair_owner=None,no_live_producer_claimed=False,repair_open=False,state='bootstrap' if boot else 'executing',
                    current_status_scope='Guarded recovery on the matching native producer and timer.')
        item.pop('current_replay',None);item.pop('current_bootstrap',None)
        item['current_bootstrap' if boot else 'current_replay']=row
        fleet['canonical_producer_count']+=1;fleet['active_producer_count']+=1
        fleet['live_replay_count']+=int(not boot);fleet['bootstrap_count']+=int(boot);fleet['guarded_bootstrap_owner_count']+=int(boot)


def forecast(c,epoch,old,prior):
    from status import observed_archive
    from evidence import utc
    from delivery_eta import prepare
    import datetime as dt

    row=c.new_rows[epoch]
    archive=observed_archive(c,epoch) if row['scratch_path'] else None
    elapsed=round((c.now-dt.datetime.strptime(row['unit']['ExecMainStartTimestamp'],'%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=dt.timezone.utc)).total_seconds()*1000)
    same=prior and prior.get('producer_invocation_id')==row['unit']['InvocationID']
    need(elapsed>=0 and (not same or elapsed>=old['elapsed_execution_millis']), 'replacement clock regressed')
    size=archive['size'] if archive else 0
    need(not same or size>=old['jet_size_bytes'], 'replacement output shrank')
    quote=prepare(c,epoch,size)
    stop=checked(checked(EVENT)['reports'][str(epoch)])
    model=stop['model']
    if same:
        age=round((c.now-utc(old['sampled_at_utc'])).total_seconds()*1000)
        remaining=old['estimated_remaining_millis']-age
    else:
        # The actual node start replaces the earlier six-hour repair estimate.
        remaining=model['full_replay_with_10pct_ms']+quote['total_millis']-elapsed
    if c.advancing[epoch] and row['progress']['elapsed_seconds']>=60:
        w=row['progress'];remaining=round((w['last']['terminal_slot']-w['last']['slot'])*w['elapsed_seconds']/w['slot_delta']*1100)+quote['total_millis']
    need(remaining>0,'replacement forecast expired; reconcile actual replay')
    return dict(old,sampled_at_utc=c.stamp,elapsed_execution_millis=elapsed,estimated_remaining_millis=remaining,
                phase=row['phase'],jet_size_bytes=size),archive
