"""Attach the half-core full-epoch producer to the existing coordinated fleet and status writer."""
import datetime as dt
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

if __name__ == '__main__':
    sys.path.insert(0,str(Path(__file__).resolve().parent))

from evidence import BASE, bound, checked, content, durable, ensure_dir, need, utc

ROOT = BASE / 'epoch172-full-half-core-20261120-v1'
ADMISSION = ROOT / 'ACTUAL_ADMISSION_AND_PROTECTION.json'
PACKAGE = ROOT / 'controller'
SEAL = 'ca1546165ade05d8d0bd75ea8c0760cc868552a513e551aa9f7b3003e05f4e2e'
UNIT = 'horizon-qualify-172-full-half-core-20261120-v1.service'
TIMER = 'horizon-guard-172-full-half-core-20261120-v1.timer'
LOG = Path('/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1/full-metered-20261120-v1/producer.log')
CAP = 288 << 30
FIRST, LAST = 74304000, 74735999


def owned(fleet):
    rows = [row for row in fleet['actual_executing_replays'] + fleet['actual_active_bootstraps'] if row['epoch'] == 172]
    need(len(rows) <= 1, 'multiple canonical epoch 172 owners')
    if rows:
        row, = rows
        need(row['unit']['Id'] == UNIT and row['admission']['path'] == str(ADMISSION), 'foreign epoch 172 owner')
        return row


def actor(ad):
    from owners import show, ticks
    n = show(UNIT, ('Id','ActiveState','SubState','InvocationID','MainPID','NRestarts','Job','ControlGroup','CPUQuotaPerSecUSec','MemoryMax','MemorySwapMax','ExecMainStartTimestamp'))
    pid = ad['producer_pid']
    need(ad['epoch'] == 172 and ad['producer_unit'] == UNIT and n['Id'] == UNIT
         and ad['producer_invocation_id'] == n['InvocationID'] and n['MainPID'] == str(pid)
         and int(pid) > 1 and ticks(pid) == ad['start_ticks'] and n['NRestarts'] == '0'
         and n['ActiveState'] == 'active' and n['SubState'] == 'running' and not n['Job']
         and n['ControlGroup'] == '/system.slice/' + UNIT and Path(f'/proc/{pid}/cgroup').read_text().strip() == '0::' + n['ControlGroup']
         and n['CPUQuotaPerSecUSec'] == '500ms' and int(n['MemoryMax']) == 68 << 30 and n['MemorySwapMax'] == '0', 'full 172 native owner or limits changed')
    return n


def admitted(fleet):
    prior = owned(fleet)
    if not ADMISSION.exists():
        need(prior is None, 'adopted epoch 172 admission missing')
        return None
    ref = bound(ADMISSION)
    ad = checked(ref)
    need(prior is None or prior['admission'] == ref, 'adopted admission changed')
    need(ad['branch']['seal'] == SEAL and ad['bootstrap_only'] and not ad['transaction_replay_claimed']
         and not ad['archive_publication_authorized'] and not ad['r2_mutations'], 'unexpected 172 launch authority')
    need(content(ROOT/'AUTHORIZED_GATED_PAYLOAD.json') == ad and (ROOT/'barrier/allow').read_text() == ad['producer_invocation_id'], 'unreleased epoch 172')
    first = checked(ad['first_guard'])
    sample = checked(first['receipt'])
    need(first['genuine_first_timer_driven_success'] and sample['producer_invocation_id'] == ad['producer_invocation_id']
         and first['timer']['Id'] == TIMER and sample['producer_stop_enabled'] and sample['trip_reason'] is None, '172 first guard mismatch')
    fit = checked(ad['post_guard_capacity'])
    need(fit['candidate_cap_bytes'] == CAP and fit['complete_cpu_quota_micros'] == 64_000_000
         and fit['resource_credit_bytes'] == fit['resource_promise_ending_bytes'] == 0, '172 post-guard reservations changed')
    return ref, ad


def identity(fleet):
    result = admitted(fleet)
    if result is None:
        return None
    ref, ad = result
    from owners import show
    timer = show(TIMER, ('Id','InvocationID','ActiveState','Job','Triggers'))
    first = checked(ad['first_guard'])
    need(timer['InvocationID'] == first['timer']['InvocationID'] and timer['ActiveState'] == 'active' and not timer['Job']
         and timer['Triggers'] == TIMER.replace('.timer','.service'), '172 guard ownership changed')
    return {'admission':ref, 'unit':actor(ad), 'timer':timer}


def guard_view(ref):
    # Isolate the deployed controller's capacity/profile imports from the cadence modules.
    args = ['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()), 'guard', ref['sha256']]
    return json.loads(subprocess.check_output(args,timeout=100,text=True))


def guard_main(sha):
    import hashlib
    def hash_file(p):
        with p.open('rb') as f:
            return hashlib.file_digest(f, 'sha256').hexdigest()
    seal = PACKAGE / 'deployment-seal-receipt.json'
    need(hash_file(seal) == SEAL, '172 controller seal changed')
    for m in content(seal)['members']:
        path = PACKAGE / m['name']
        need(path.is_relative_to(PACKAGE) and path.resolve() == path and path.stat().st_uid == 0
             and not path.stat().st_mode & 0o222 and hash_file(path) == m['sha256'], '172 controller member changed')
    sys.path.insert(0,str(PACKAGE))
    import session
    ad = checked({'path':str(ADMISSION),'sha256':sha})
    plan = checked(ad['actual_guard_plan'])
    return current_guard(session, ad, plan)


def current_guard(session, ad, plan):
    # A full disk scan can finish after the preceding guard has aged out.
    # Keep the original freshness and PID 1 completion checks on every attempt.
    deadline = time.monotonic() + 75
    while True:
        n = session.native(UNIT)
        need(n['InvocationID'] == ad['producer_invocation_id'], '172 invocation changed')
        samples = sorted(Path(plan['receipt_directory']).glob('sample-*.json'), key=lambda p:p.stat().st_mtime_ns,reverse=True)
        need(samples, 'missing protective guard evidence')
        if content(samples[0])['workers']:
            try:
                w = session.observer_row(ad)
            except ValueError as error:
                if str(error) != 'waiting for first protected historical worker':
                    raise
            else:
                m = LOG.lstat()
                need(m.st_uid == 0 and m.st_nlink == 1 and not m.st_mode & 0o077 and stat.S_ISREG(m.st_mode), '172 log not observable by native sampler')
                return {'proof':w['worker_guard'], 'observer_config':w['observer_row'], 'worker_pid':w['worker_pid'], 'worker_start_ticks':w['worker_start_ticks']}
        else:
            proof = session.latest_guard(n, plan, ad['actual_guard_plan']['sha256'])
            if proof is not None:
                return {'proof':proof[0],'observer_config':None}
        need(time.monotonic() < deadline, 'timed out waiting for a completed fresh 172 guard')
        time.sleep(1)


def freeze(c):
    ident = identity(c.fleet)
    r = c.paths['out']/'FULL172_OBSERVATION.json'
    if ident is None:
        need(not r.exists(), 'epoch 172 disappeared during coordinated cycle')
        return None
    ad = checked(ident['admission'])
    if owned(c.fleet) is None:
        cursor = c.fleet_ref
        while cursor != ad['fleet']:
            predecessor = checked(cursor)
            need(utc(predecessor['sampled_at_utc']) > utc(checked(ad['fleet'])['sampled_at_utc']), '172 admitted against a different fleet')
            cursor = predecessor['previous_Root_operational_review']
    ensure_dir(c.paths['out'])
    if not r.exists():
        durable(r, dict(identity=ident, observer=c.sample_ref, fleet=c.fleet_ref, guard=guard_view(ident['admission'])))
    v = content(r)
    need(v['identity'] == ident and v['observer'] == c.sample_ref and v['fleet'] == c.fleet_ref,'172 cycle ownership changed')
    return v


def reconcile_sample(c, observed_lane):
    v = c.full172
    configured = [r for r in c.cfg['replays'] if r['range'] == '172']
    samples = [r for r in c.sample['replays'] if r['range'] == '172']
    need(len(configured) == len(samples) <= 1, 'unexpected epoch 172 sample membership')
    if not v:
        need(not configured, '172 sampled without admission')
        return
    old = owned(c.fleet)
    i = v['identity']; n = i['unit']; guard = v['guard']; cfg = guard['observer_config']
    measured = False
    if configured:
        need(configured == [cfg], '172 worker or stdout differs from coordinated config')
        sample, = samples
        measured = observed_lane(sample,cfg,n['InvocationID'],int(n['MainPID']))
        for k in ('worker_before','worker_after'):
            worker=sample[k]
            need(worker['pid'] == guard['worker_pid'] and worker['matching_workers'] == 1 and worker['executable_beneath_bound_scratch'], '172 sampled a different worker')
        work = sample['useful_work']
        last = work.get('last'); previous = (old or {}).get('last_progress')
        if measured:
            need(FIRST <= work['first']['slot'] <= last['slot'] <= LAST and last['terminal_slot'] == LAST, '172 sample outside epoch')
            measured = work['counter_resets'] == 0 and (previous is None or (last['realtime_microseconds'] > previous['realtime_microseconds'] and last['slot'] >= previous['slot'] and last['transactions'] >= previous['transactions']))
    was_replay = bool(old and old['phase'] == 'replay')
    phase = 'replay' if measured or was_replay else 'verification'
    ad = checked(i['admission'])
    row = dict(epoch=172, admission=i['admission'], first_guard=ad['first_guard'], post_guard_capacity=ad['post_guard_capacity'],
               guard_protection=guard['proof']['receipt'], guard_timer=i['timer'], unit=n, start_ticks=ad['start_ticks'],
               phase=phase, stage='replay' if phase=='replay' else 'bootstrap', observer=c.sample_ref, observer_config=cfg,
               measured_progress=measured, in_current_observer=bool(configured), scratch_path=cfg['scratch_path'] if cfg else None,
               progress=samples[0]['useful_work'] if samples else None,
               last_progress=samples[0]['useful_work']['last'] if measured else (old or {}).get('last_progress'))
    c.full172_row = row
    if configured:
        c.lanes[172] = samples[0]
        c.advancing[172] = measured
    c.next_cfg['replays'] = [r for r in c.next_cfg['replays'] if r['range'] != '172'] + ([cfg] if cfg else [])


def forecast(c, old, archive):
    row = c.full172_row
    started = dt.datetime.strptime(row['unit']['ExecMainStartTimestamp'],'%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=dt.timezone.utc)
    elapsed = round((c.now-started).total_seconds()*1000)
    need(elapsed >= 0, 'epoch 172 started after this sample')
    previous = owned(c.fleet)
    if previous:
        need(elapsed >= old['elapsed_execution_millis'], 'epoch 172 owner elapsed regressed')
    remain = max(0,old['estimated_remaining_millis'] - round((c.now-utc(old['sampled_at_utc'])).total_seconds()*1000))
    if not previous:
        # Two full172 prefixes gave 0.711–0.715 slots/s at 50% CPU; allow the normal 10% + 12h to sidecar.
        remain = round((LAST-FIRST+1)/0.711*1100) + 12*3600000 - elapsed
    if row['measured_progress']:
        w = row['progress']
        if w['elapsed_seconds'] >= 60:
            remain = round((LAST-w['last']['slot'])*w['elapsed_seconds']/w['slot_delta']*1100)+12*3600000
    need(remain > 0, 'epoch 172 forecast expired')
    size = archive['size'] if archive else old['jet_size_bytes'] if previous else 0
    if previous:
        need(size >= old['jet_size_bytes'], 'epoch 172 archive shrank')
    return dict(old,phase=row['phase'],jet_size_bytes=size,sampled_at_utc=c.stamp,elapsed_execution_millis=elapsed,estimated_remaining_millis=remain)


def install_fleet(c, f):
    if not c.full172:
        return
    row = c.full172_row
    boot = row['phase'] != 'replay'
    f['actual_active_bootstraps'] = [row] if boot else []
    if not boot:
        f['actual_executing_replays'].append(row)
    f.update(bootstrap_count=int(boot),guarded_bootstrap_owner_count=int(boot),live_replay_count=4-int(boot),
             canonical_producer_count=4,active_producer_count=6,current_full172_admission=row['admission'],
             current_full172_post_guard_fit=row['post_guard_capacity'])
    item = next(r for r in f['epochs'] if r['epoch']==172)
    item.update(current_repair_owner=None,no_live_producer_claimed=False,repair_open=False,
                state='bootstrap' if boot else 'executing',current_status_scope='Guarded full epoch 172 under its actual producer and timer.')
    item.pop('current_bootstrap',None); item.pop('current_replay',None)
    item['current_bootstrap' if boot else 'current_replay'] = row


if __name__ == '__main__':
    need(sys.argv[1:2] == ['guard'] and len(sys.argv) == 3, 'expected guard ADMISSION_SHA256')
    print(json.dumps(guard_main(sys.argv[2])))
