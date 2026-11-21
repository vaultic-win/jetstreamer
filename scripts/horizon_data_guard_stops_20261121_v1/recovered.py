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


def check_170_payload(root, intent, proc, actor):
    """Follow the same systemd MainPID from its guarded hold through the authorized exec."""
    import os

    prepared = bound(root / 'PREPARED.json')
    need(intent['prepared'] == prepared and
         prepared['sha256'] == '82f8d1992252e0c376aa773a27ba6d38e041638daa51e2376c0be54bcc114d83',
         'different prepared epoch 170 inputs')
    profile = checked(checked(prepared)['profile'])
    args = profile['normal_argv']
    image = proc / 'exe'
    argv = [os.fsdecode(x) for x in (proc / 'cmdline').read_bytes().split(b'\0') if x]
    if image.samefile('/usr/bin/python3'):
        gate = root / 'controller/gate.py'
        alias = Path('run/horizon-recovered170')
        need(bound(gate)['sha256'] == '8e5f7c0d3a3118d2deaa2fc88a77e12044d8c7d93c3690644f4df7a45afdf1f9' and
             (proc / 'root' / alias / 'gate.py').samefile(gate) and
             (proc / 'root' / alias / 'profile.json').samefile(root / 'profile.json') and
             argv == ['/usr/bin/python3', '-IB', '/' + str(alias / 'gate.py'), *args] and
             (Path('/sys/fs/cgroup/system.slice') / node(170) / 'cgroup.procs').read_text().split() ==
             [str(actor['producer_pid'])] and not (root / 'ACTUAL_PRODUCER_NATIVE.json').exists(),
             'foreign process in the epoch 170 startup gate')
        return
    permit = checked(bound(root / 'AUTHORIZED_GATED_PAYLOAD.json'))
    need(argv == args and image.samefile(profile['node']['path']) and
         all(permit[k] == v for k, v in actor.items()) and
         permit['intent'] == bound(root / 'START_INTENT.json') and
         permit['first_guard'] == bound(root / 'FIRST_GUARD.json') and
         permit['capacity'] == bound(root / 'POST_GUARD_CAPACITY.json') and
         checked(permit['capacity'])['fits'] and
         (root / 'barrier/allow').read_bytes() == actor['producer_invocation_id'].encode(),
         'epoch 170 payload lacks its matching guard release')


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
    identity = dict(producer_pid=pid, producer_unit=unit, producer_invocation_id=row['InvocationID'], start_ticks=ticks(pid))
    need((proc/'cgroup').read_text().strip() == '0::'+row['ControlGroup'], 'foreign replacement cgroup')
    if epoch == 170:
        check_170_payload(root, intent, proc, identity)
    else:
        need((proc/'exe').readlink().name == 'jetstreamer-node', 'foreign replacement node image')
    if (root/'ACTUAL_PRODUCER_NATIVE.json').exists():
        observed=checked(bound(root/'ACTUAL_PRODUCER_NATIVE.json'))
        image=(proc/'exe').stat()
        need(all(observed[k] == v for k,v in identity.items()) and
             (observed['exe_device'],observed['exe_inode'])==(image.st_dev,image.st_ino),
             'changed replacement actor')
    return row, identity


EXTENDED_170 = {
    'path':str(BASE/'epoch170-retry10-guard384-20261121-v1/GUARD_QUALIFIED.json'),
    'sha256':'6bd212f907ffa68a34dbc967f61ebba84cd3034b19643a4a0d1013b1fe6ba43d',
}
CLOSED_170 = {
    'path':str(BASE/'epoch170-ancestor-accounts-20261121-v1/CLOSED_6_7_RETIRED.json'),
    'sha256':'c246bb365dd59d234fd389d7dfcaed30910cbab36dfeeacff62cd2e9d64196dc',
}


def guard_budget(epoch, root, plan, admission):
    original = ROUTES[epoch][4]
    if epoch != 170 or plan['maximum_root_physical_bytes'] == original<<30:
        return original, GUARD_SHA, checked(QUAL)
    cap=384<<30
    booking=bound(root/'ACCEPTED_384_BOOKING.json')
    booked=checked(booking)
    cost=checked(admission['post_guard_capacity'])
    intent=checked(admission['intent'])
    paid=checked(CLOSED_170)
    retired={n:v['completion'] for n,v in paid['completions'].items()}
    extension=cost['epoch170_extension']
    need(plan['maximum_root_physical_bytes']==cap and intent['booking']==booking
         and booked['epoch']==epoch and booked['cap_bytes']==cap and booked['extra_bytes']==96<<30
         and booked['retired']==retired and booked['guard']==EXTENDED_170 and booked['prestart']==intent['prestart']
         and booked['prestart']['fits'] and cost['fits'] and cost['epoch']==epoch
         and cost['bookings']['170']['cap_bytes']==cap and extension['accepted']==booking
         and extension['guard']==EXTENDED_170 and extension['retired']==retired
         and extension['retirement']==CLOSED_170 and extension['extra_bytes']==96<<30
         and cost['candidate']['producer_invocation_id']==admission['producer_invocation_id'],
         'unfunded or foreign epoch 170 guard extension')
    proof=checked(EXTENDED_170)
    need(bound(Path(proof['guard']['path']))==proof['guard'], 'extended guard executable changed')
    return 384,proof['guard']['sha256'],proof


def guard(epoch, admission, actor):
    from owners import show

    _, subdir, _, _, _ = ROUTES[epoch]
    root = BASE / subdir
    planref = bound(root/'ACTUAL_GUARD_PLAN.json')
    plan = checked(planref)
    cap, guard_sha, qualified = guard_budget(epoch,root,plan,admission)
    directory = root/'guard-receipts'
    t = show(timer(epoch), ('Id','InvocationID','ActiveState','SubState','Triggers','Job'))
    service = timer(epoch).removesuffix('.timer')+'.service'
    required = dict(unit=node(epoch), invocation_id=actor['producer_invocation_id'], filesystem='/home/sol',
                    maximum_root_physical_bytes=cap<<30, receipt_directory=str(directory))
    need(qualified['guard']['sha256'] == guard_sha and plan["data_fulfillment"] == qualified["contract"],
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
        need(sample['guard_sha256']==guard_sha and sample['plan_sha256']==planref['sha256'] and
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


def startup_progress(work):
    """Recover the native window after both counters reset at the first target slot."""
    import datetime as dt
    import hashlib
    import re

    if work['counter_resets'] != 2 or not work['sufficient_for_rates']:
        return work
    log = work['append_log_evidence']
    offset, length = log['read_offset_bytes'], log['read_bytes']
    need(0 <= offset and 0 < length <= 8 << 20 and offset+length == log['snapshot_length_bytes'],
         'invalid frozen append interval')
    path = Path(log['path'])
    with path.open('rb') as f:
        import os
        m = os.fstat(f.fileno())
        need(path.resolve() == path and (m.st_dev,m.st_ino) == (log['device'],log['inode'])
             and stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and m.st_uid == 0 and not m.st_mode & 0o077,
             'changed frozen append identity')
        f.seek(offset)
        data = f.read(length)
    need(len(data)==length and hashlib.sha256(data).hexdigest()==log['read_sha256'], 'frozen append bytes changed')
    markers = []
    for line in data.splitlines(keepends=True)[int(offset>0):]:
        if not line.endswith(b'\n') or b'progress slot ' not in line:
            continue
        stamp = line[1:].split(b' ',1)[0].decode('ascii')
        date = dt.datetime.fromisoformat(stamp.replace('Z','+00:00'))
        seconds = int(date.timestamp())
        if not work['since_unix_seconds'] <= seconds < work['until_unix_seconds']:
            continue
        match = re.search(rb'progress slot (\d+)/(\d+).*? txs=(\d+) accounts=(\d+)',line)
        need(match is not None, 'invalid frozen progress marker')
        slot, terminal, tx, accounts = map(int,match.groups())
        markers.append(dict(realtime_microseconds=seconds*1000000+date.microsecond, slot=slot,
                            terminal_slot=terminal, transactions=tx, account_updates=accounts))
        if len(markers)==2:
            break
    if len(markers) != 2:
        return work
    first, start = markers
    end = work['last']
    if (first != work['first'] or start['slot'] < first['slot']
        or start['transactions'] >= first['transactions'] or start['account_updates'] >= first['account_updates']
        or first['terminal_slot']!=start['terminal_slot'] or end['terminal_slot']!=start['terminal_slot']):
        return work
    # These two decreases consume the native reset count for the entire sample.
    elapsed = (end['realtime_microseconds']-start['realtime_microseconds'])/1e6
    if elapsed < 60 or end['slot']<=start['slot'] or end['transactions']<=start['transactions']:
        return work
    clean = dict(work, first=start, counter_resets=0, matching_markers=work['matching_markers']-1,
                 elapsed_seconds=elapsed, startup_counter_reset=first)
    for field, delta, rate in [('slot','slot_delta','slots_per_second'),
                               ('transactions','transaction_delta','transactions_per_second'),
                               ('account_updates','account_update_delta','account_updates_per_second')]:
        clean[delta] = end[field]-start[field]
        clean[rate] = clean[delta]/elapsed
    return clean


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
            work=startup_progress(s['useful_work']) if not previous.get('last_progress') else s['useful_work']
            if work is not s['useful_work']:
                advancing=observed_lane(dict(s,useful_work=work),cfg,actor['producer_invocation_id'],actor['producer_pid'])
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


def admission_status_path(epoch, iid):
    from evidence import STATUS_ROOT
    import re

    need((epoch in ROUTES or epoch==168) and re.fullmatch('[0-9a-f]{32}', iid), 'unexpected recovery identity')
    return STATUS_ROOT / f'event-{epoch}-guarded-admission-{iid}' / 'RECEIPT.json'


def admission_status(epoch, predecessor, tag, raw):
    """Adopt the single authenticated repair-to-producer status from the actual admission."""
    from evidence import digest
    from status import body, key, FIELDS

    if epoch == 168:
        from status168 import D, inspect
        normal = inspect()
        if not normal or not normal['ordinary_canonical'] or not normal['first_worker']:
            return None
        actor = normal['actor']
        root = D
    else:
        current = native(epoch)
        if current is None:
            return None
        _, actor = current
        root = BASE / ROUTES[epoch][1]
    iid = actor['producer_invocation_id']
    path = admission_status_path(epoch, iid)
    # A measured startup transition follows the completed bootstrap status from the same worker.
    progress = path.parent / ('progress-' + predecessor['sha256'] + '.json')
    measured = progress.exists()
    if measured:
        path = progress
    if not path.exists():
        return None
    ref = bound(path)
    event = checked(ref)
    prior = checked(predecessor)
    admitted = bound(root/'ACTUAL_ADMISSION_AND_PROTECTION.json')
    first = bound(root/'FIRST_PROTECTED_WORKER.json')
    admitted_actor = checked(admitted)
    need(event['schema']==('horizon-measured-startup-status-v1' if measured else 'horizon-guarded-admission-status-v1') and event['epoch']==epoch
         and event['key']==key(epoch) and not event['archive_or_sidecar_mutations']
         and event['authenticated_readback'] and event['conditional_header']=='If-Match'
         and event['previous_receipt']==predecessor and event['before_status']==prior['after_status']
         and event['before_sha256']==prior['after_sha256'] and event['before_etag']==prior['after_etag']
         and event['actor']==actor and event['producer_invocation_id']==iid and event['admission']==admitted
         and event['first_worker']==first and checked(first)['admission']==admitted
         and all(admitted_actor[k]==v for k,v in actor.items())
         and event['after_etag']==tag and set(event['after_status'])==FIELDS
         and event['after_status']['epoch']==epoch and event['after_status']['phase']==('replay' if measured else 'verification')
         and event['after_sha256']==digest(raw) and raw==body(event['after_status']),
         'unbound recovery admission status for '+str(epoch))
    if measured:
        need(prior['producer_invocation_id']==iid and prior['observer']==event['observer'], 'foreign bootstrap predecessor')
        source=checked(prior['observer'])
        lane=next(x for x in source['replays'] if x['range']==str(epoch))
        window=startup_progress(lane['useful_work'])
        need('startup_counter_reset' in window and window==event['measured_progress'], 'different startup evidence')
    return ref,event


def before_sample_path(fleet_ref):
    return BASE / 'epoch168-witness-incident-20261121-v1' / ('before-' + fleet_ref['sha256']) / 'sealed-next' / 'observer.json'


def registered_config(cfg, fleet_ref, fleet):
    """Include newly admitted workers in the next scheduled sample of this exact fleet."""
    from evidence import sealed

    original = Path(fleet['sole_next_observer']['path'])
    selected = before_sample_path(fleet_ref)
    if not selected.exists():
        return cfg, original
    extra = sealed(bound(selected))
    rows = extra['replays']
    keys = [int(r['range']) for r in rows]
    need(keys == sorted(set(keys)) and extra == dict(cfg, replays=rows), 'recovery changed the scheduled sample')
    old = {r['range']:r for r in cfg['replays']}
    need(all(r in rows for r in old.values()) and len(rows)>len(old), 'scheduled workers changed')
    current = ownership(fleet)
    for row in rows:
        if row['range'] in old:
            continue
        epoch = int(row['range'])
        if epoch == 168:
            from status168 import inspect
            normal = inspect()
            need(normal and normal['ordinary_canonical'] and normal['first_worker']
                 and row == normal['observer_row'], 'foreign normal 168 worker')
            continue
        need(epoch in ROUTES, 'unknown added worker')
        candidate = current[row['range']]
        actor = candidate['actor']
        first = checked(candidate['first_worker'])
        need(first['admission'] == candidate['admission'], 'unadmitted observation row')
        _, sample = guard(epoch, checked(candidate['admission']), actor)
        need(row == observe_worker(epoch, actor, first, sample), 'added worker identity changed')
    return extra, selected
