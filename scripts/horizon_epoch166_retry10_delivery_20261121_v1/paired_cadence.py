"""Reconcile the original recovered 166 and metered 168 independently in one native cadence."""
import os
from pathlib import Path
import select
import runpy
from types import SimpleNamespace
import subprocess
import sys
import time

import cadence168
import closure
import recovered166
from evidence import SEALER, bound, checked, durable, ensure_dir, lock, need, sealed, utc

def metered_authority():
    root = closure.R/'epoch168-current-delivery-20261121-v1/closure-tools'
    p = root/'deployment-seal-receipt.json'
    expected = '073d0da33d8c4187aa25c7e8bccd0d5c1b41e0252170ece14df1d4e6941d11f1'
    receipt = checked(dict(path=str(p),sha256=expected))
    members = {m['name']:m['sha256'] for m in receipt['members']}
    pins = {'closure168.py':'56b81259d2149bd28c2f36e8e75cb51fb6d9fcc0d754ee2d774b08fc4a7139d9',
            'closure.py':'bb2f740e675ff7b1d651ce6301a3fa6e5e35a138d7950dcc5f7c3ae81a22324f'}
    need(receipt['destination']==str(root) and all(members.get(n)==h==bound(root/n)['sha256'] for n,h in pins.items()),
         'foreign metered guard closure package')
    authority = runpy.run_path(str(root/'closure168.py'))
    return SimpleNamespace(**{k:authority[k] for k in ('T','DONE','FIELD','UNIT','IID','committed','inspect','retire','guard')})


ROUTES = {166: closure, 168: metered_authority()}
FIELDS = {epoch: route.FIELD for epoch, route in ROUTES.items()}
LABELS = {166: 'recovered166', 168: 'metered168'}
REGISTRY = recovered166.REGISTRY


def preceding(fleet, epoch):
    if epoch == 166:
        return fleet.get(REGISTRY, {}).get('166')
    return cadence168.previous(fleet)


def transition(fleet, epoch):
    route = ROUTES[epoch]
    existing = fleet.get(route.FIELD)
    if not (route.T / 'TERMINAL_SUCCESS.json').exists():
        need(existing is None and not route.DONE.exists(), 'registered terminal disappeared')
        return None
    already_drained = route.DONE.exists()
    proof = route.inspect() if already_drained else route.committed()
    old = preceding(fleet,epoch)
    if existing is not None:
        need(existing == proof['terminal'] and old is None and
             already_drained and fleet[LABELS[epoch]+'_guard_retirement'] == proof['guard_retirement'],
             'conflicting terminal, retained guard or live owner')
    else:
        need(old and old['admission'] == proof['admission'] and old['first_worker'] == proof['first_worker'],
             'foreign predecessor admission or worker')
        actor = old['actor'] if epoch == 166 else checked(fleet[cadence168.FIELD])['state']['actor']
        need(actor['producer_unit'] == route.UNIT and actor['producer_invocation_id'] == route.IID,
             'foreign predecessor native generation')
    if not already_drained:
        retired = route.retire()
        need(all(retired.get(k)==v for k,v in proof.items()), 'terminal changed during guard retirement')
        proof = retired
    return proof


def proofs(fleet):
    return {e:p for e in ROUTES if (p := transition(fleet,e))}


def original(proof):
    return checked(proof['first_worker'])['observer_row']


def remove(cfg, epoch, proof):
    row = original(proof)
    route = ROUTES[epoch]
    need([r for r in cfg['replays'] if r['range'] == str(epoch)] == [row] and
         row['producer_unit'] == route.UNIT and row['expected_producer_invocation_id'] == route.IID,
         'changed scheduled terminal row')
    return dict(cfg, replays=[r for r in cfg['replays'] if r['range'] != str(epoch)])


def projected(cfg,path,fleet,closures):
    out = cfg
    for epoch, proof in closures.items():
        scheduled = any(r['range']==str(epoch) for r in cfg['replays'])
        accepted = fleet.get(FIELDS[epoch])
        if not scheduled:
            need(accepted == proof['terminal'], 'original live predecessor omitted its worker')
            continue
        if accepted:
            need(fleet.get(LABELS[epoch]+'_preselected_config') == bound(path),
                 'unregistered historical observer row')
        out = remove(out, epoch, proof)
    return out


def select_config(cfg,path,ref,fleet,closures):
    effective = projected(cfg,path,fleet,closures)
    if effective == cfg:
        return cfg,path
    suffix = '-'.join(str(e) for e in closures if original(closures[e]) in cfg['replays'])
    folder = Path(ref['path']).parent / ('after-local-' + suffix)
    ensure_dir(folder)
    fd = lock(folder/'selection.lock')
    try:
        p = folder/'observer.json'
        dest = folder/'sealed-next'
        durable(p,effective)
        removed = {str(e):dict(row=original(proof),terminal=proof['terminal'],guard=proof['guard_retirement'])
                   for e,proof in closures.items() if original(proof) in cfg['replays']}
        durable(folder/'selection.json',dict(fleet=ref,previous_sample=fleet['observer'],upstream=bound(path),
                                             removed=removed,projected=bound(p)))
        plan = folder/'seal-plan.json'
        durable(plan,dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(dest),
                          members=[dict(name=p.name,source=str(p),sha256=bound(p)['sha256'],mode=0o444)]))
        if not dest.exists():
            subprocess.run([recovered166.SEAL,plan,'--plan-sha256',bound(plan)['sha256'],'--self-sha256',SEALER],
                           check=True,stdout=subprocess.DEVNULL)
        selected = dest/p.name
        need(sealed(bound(selected)) == effective, 'wrong deployed survivor set')
        return effective,selected
    finally:
        os.close(fd)


def historical(c,cfg,epoch,proof):
    from race166 import successful_sample
    live = checked(proof['live'])
    route = ROUTES[epoch]
    original_row = original(proof)
    rows = [r for r in c.sample['replays'] if r['range'] == str(epoch)]
    need(len(rows)==1 and original_row in cfg['replays'] and checked(c.sample_ref)==c.sample and
         c.sample_ref['path']==cfg['output'] and c.sample['cadence']['previous_sample_sha256']==c.fleet['observer']['sha256']
         and c.sample['cadence']['previous_sample']==c.fleet['observer']['path']
         and rows[0]['scratch_path']==original_row['scratch_path']==live['private_scratch']['path']
         and rows[0]['invocation_binding_stable'] and original_row['append_log']==live['producer_log'],
         'foreign scheduled historical observation')
    row = rows[0]
    for edge in ('before','after'):
        p,w = row['producer_'+edge],row['worker_'+edge]
        need(p['unit']==route.UNIT and p['invocation_id']==route.IID and p['main_pid']==live['native']['parent']['pid']
             and p['restarts']==0 and p['active_state']=='active' and p['sub_state']=='running'
             and w['matching_workers']==1 and w['pid']==live['native']['worker']['pid']
             and w['executable']==live['native']['worker']['exe'] and w['executable_beneath_bound_scratch'],
             'foreign original producer or worker in completed sample')
    end = int(checked(proof['terminal'])['manager_terminal']['__REALTIME_TIMESTAMP'])
    need(utc(c.sample['recorded_at_utc']).timestamp()*1_000_000 <= end, 'terminal predates live sample')
    return dict(sample=c.sample_ref,sampler=successful_sample(c),terminal=proof['terminal'],
                **{'original_'+str(epoch)+'_row':row})


def select_cycle(c,cfg,path):
    c.commits = proofs(c.fleet)
    c.histories = {}
    projected(cfg,path,c.fleet,c.commits)
    expected = list(cfg['replays'])
    sampled = [r['range'] for r in c.sample['replays']]
    for e,proof in c.commits.items():
        if str(e) in sampled:
            need(not c.fleet.get(FIELDS[e]), 'already retired producer in later sample')
            c.histories[e] = historical(c,cfg,e,proof)
        else:
            expected = [r for r in expected if r['range'] != str(e)]
    need([r['range'] for r in expected]==sampled, 'incomplete or unexpected native survivor set')
    c.recovered166 = c.commits.get(166)
    c.recovered166_history = c.histories.get(166)
    c.metered168_commit = c.commits.get(168)
    if c.histories:
        c.original_status_dir = c.paths['statuses']
        suffix = '166-168' if len(c.histories)==2 else LABELS[next(iter(c.histories))]
        c.paths['statuses'] = c.original_status_dir / ('after-'+suffix)
    # Leave the sample intact. Suppress live interpretations only for proven ended rows.
    return dict(cfg,replays=expected)


def next_config(c,previous):
    projected = previous
    for e in c.histories:
        if any(r['range']==str(e) for r in projected['replays']):
            projected = remove(projected,e,c.commits[e])
    need(projected == c.next_cfg, 'different preselected next observation')
    return previous


def unchanged(c):
    need(proofs(c.fleet)==c.commits, 'local commit changed during scheduled cycle')


def worker_gone(first):
    p = Path('/proc')/str(first['worker_pid'])/'stat'
    try:
        return int(p.read_text().rsplit(')',1)[1].split()[19]) != first['worker_start_ticks']
    except FileNotFoundError:
        return True


def wait_terminal(epoch,first,deadline):
    from terminal_event import Changes
    changes = Changes()
    route = ROUTES[epoch]
    try:
        changes.watch(route.T)
        while not (route.T/'TERMINAL_SUCCESS.json').exists():
            need(worker_gone(first), 'failed observation still has its original worker')
            left = deadline - time.monotonic()
            need(left>0 and select.select([changes.fd],[],[],left)[0], 'original terminal was not recorded')
            os.read(changes.fd,65536)
    finally:
        changes.close()


def dispatch(cfg,path,ref,fleet,native):
    deadline = time.monotonic()+1800
    for attempt in range(len(ROUTES)+1):
        closed = proofs(fleet)
        effective,selected = select_config(cfg,path,ref,fleet,closed)
        candidates = {e:checked(previous['first_worker']) for e in ROUTES if e not in closed and
                      (previous := preceding(fleet,e)) and previous.get('first_worker') and
                      original(previous) in effective['replays']}
        if not candidates:
            os.execv(native,[native,selected])
        result = subprocess.run([native,selected],stderr=subprocess.PIPE)
        if result.returncode==0:
            return
        error = result.stderr.decode(errors='replace')
        matched = [e for e,w in candidates.items() if any(s in error for s in
                   (ROUTES[e].UNIT,w['observer_row']['scratch_path'],str(w['worker_pid'])))]
        if len(matched)!=1 or len(result.stderr)>65536 or Path(cfg['output']).exists() or attempt==len(ROUTES):
            sys.stderr.write(error)
            raise ValueError('failed native sample outside an identified terminal')
        e, = matched
        wait_terminal(e,candidates[e],deadline)
        need(transition(fleet,e) and not Path(cfg['output']).exists(), 'failed or superseded native observation')


def forecast(c,e,old,prior):
    from delivery_eta import prepare
    from race166 import status_clock
    proof = c.commits[e]
    terminal = checked(proof['terminal'])
    archive = terminal['local_archive']
    end = int(terminal['manager_terminal']['__REALTIME_TIMESTAMP'])
    clock = status_clock(c.now,end)
    age = round((clock-utc(old['sampled_at_utc'])).total_seconds()*1000)
    need(age>=0, 'newer committed status already exists')
    quote = prepare(c,e,archive['size'],committed=True)
    if prior.get(FIELDS[e])==proof['terminal']:
        remaining = old['estimated_remaining_millis']-age
    else:
        need(prior.get('producer_invocation_id')==ROUTES[e].IID and old['phase'] in ('replay','verification'),
             'foreign pre-close status')
        remaining = end//1000+quote['total_millis']-round(clock.timestamp()*1000)
    need(remaining>0, 'fresh committed delivery estimate required')
    return dict(old,sampled_at_utc=clock.strftime('%Y-%m-%dT%H:%M:%SZ'),phase='verification',
                jet_size_bytes=archive['size'],estimated_remaining_millis=remaining,
                elapsed_execution_millis=old['elapsed_execution_millis']+age),archive


def install168(c,fleet):
    p = c.metered168_commit
    if not p:
        return
    old = fleet.pop(cadence168.FIELD,None)
    if old:
        fleet['historical_metered168_worker'] = old
    need(not any(r['epoch']==168 for key in ('actual_executing_replays','actual_active_bootstraps') for r in fleet[key]),
         'closed metered worker still owns a lane')
    fleet[FIELDS[168]] = p['terminal']
    fleet['metered168_guard_retirement'] = p['guard_retirement']
    frozen = c.paths['out']/'METERED168_OBSERVATION.json'
    if frozen.exists():
        reference = bound(frozen)
        value = checked(reference)
        need(value['fleet']==c.fleet_ref and value['sample']==c.sample_ref and
             value['state']['admission']==p['admission'] and value['state']['first_worker']==p['first_worker'],
             'foreign metered worker capture under the committed sample')
        fleet['historical_metered168_frozen_capture']=reference
    if 168 in c.histories:
        fleet['historical_metered168_observation'] = c.histories[168]
    if any(r['range']=='168' for r in c.next_cfg['replays']):
        need(168 in c.histories and sealed(fleet['sole_next_observer'])==c.next_cfg,'foreign preselected 168 observer')
        fleet['metered168_preselected_config'] = fleet['sole_next_observer']
    else:
        fleet.pop('metered168_preselected_config',None)
    row = next(r for r in fleet['epochs'] if r['epoch']==168)
    row.pop('current_replay',None)
    row.pop('current_bootstrap',None)
    row.update(current_repair_owner='/root',no_live_producer_claimed=True,state='verification',repair_open=True,
               metered168_local_commit=p['terminal'],next_action='Verify and publish the committed metered archive.',
               current_status_scope='Metered epoch 168 committed locally and awaits verification and public delivery.')


def capacity(c):
    result = {}
    for e,proof in c.commits.items():
        ad = checked(proof['admission'])
        post = ad['post_guard_capacity']
        fit = checked(post)
        if e==166:
            booking = fit['bookings']['166']
            need(booking['cap_bytes']==288<<30, 'recovered 166 retained cap changed')
        else:
            booking = fit['native_incident_fit']['bookings']['168']
            need(booking['cap_bytes']==288<<30 and booking['root']==checked(ad['actual_guard_plan'])['worker_root'],
                 'metered 168 retained cap changed')
        result[str(e)] = dict(terminal=proof['terminal'],guard_retirement=proof['guard_retirement'],
                              admission=proof['admission'],post_guard_capacity=post,retained_cap_bytes=288<<30,
                              resource_credit_bytes=0,reservation_ending_bytes=0)
    return result


def observation(c,out,probe):
    # A closure can arrive after the ordinary capacity pass has already committed.
    # Retain the same witness, native sample and audit interval.
    candidates = [out/'CYCLE_OBSERVATION.json']
    if len(c.commits)==2:
        singles = [out/('POST_LOCAL_'+str(e)+'_CYCLE_OBSERVATION.json') for e in c.commits]
        available = [p for p in singles if p.exists()]
        need(len(available)<=1,'incomparable capacity snapshots for the same native sample')
        candidates += available
    for path in reversed(candidates):
        if not path.exists():
            continue
        ref = bound(path)
        record = checked(ref)
        need(record['observer']==c.sample_ref and record['fleet_predecessor']==c.fleet_ref,
             'foreign prior capacity observation')
        retained = capacity(c)
        old = record['capacity']
        need(all(retained.get(k)==v for k,v in old.get('retained_local_commit_bookings',{}).items()),
             'retained source booking changed')
        cap = dict(old,retained_local_commit_bookings=retained,prior_same_sample_capacity_observation=ref)
        if 168 in c.commits:
            cap.pop(cadence168.FIELD,None)
        return dict(record,capacity=cap)
    return probe(c)


def partial_status(c,e,ip,rp):
    """Keep applied ancestor intents across either order of the two terminal events."""
    from evidence import content
    from status import receipt_identity
    parents = [c.original_status_dir]
    if len(c.histories)==2:
        singles = [parents[0]/('after-'+LABELS[k]) for k in c.histories]
        occupied = [p for p in singles if p.is_dir()]
        need(len(occupied)<=1, 'incomparable single-terminal status branches')
        parents += occupied
    for d in reversed(parents):
        a,b = d/ip.name,d/rp.name
        need(not b.exists() or a.exists(),'receipt without original intent')
        if a.exists():
            entry = content(a)
            receipt_identity(entry,c,e)
            if e not in c.histories or entry.get(FIELDS[e])==c.commits[e]['terminal']:
                return a,b,None
            return ip,rp,(a,b)
    return ip,rp,None


def inherited(c,e,pair,etag,data):
    from evidence import content,digest
    from status import body,receipt_identity
    from datetime import datetime,timezone
    if pair is None:
        return None
    ip,rp = pair
    entry = content(ip)
    receipt_identity(entry,c,e)
    if rp.exists():
        proof = content(rp)
        need(proof['authenticated_readback'] and all(proof[k]==v for k,v in entry.items()) and
             proof['after_etag']==etag and proof['after_sha256']==digest(data),'changed pre-terminal readback')
        return bound(rp)
    if data==body(entry['after_status']) and digest(data)==entry['after_sha256']:
        durable(rp,dict(entry,authenticated_readback=True,after_etag=etag,
                        verified_at_utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        already_published_intent_read_back=True))
        return bound(rp)
    prior = checked(entry['previous_receipt'])
    need(prior['after_etag']==etag and prior['after_sha256']==digest(data) and body(prior['after_status'])==data,
         'unapplied historical intent has a foreign predecessor')
    return entry['previous_receipt']


def retry_cycle(path,sha,sample_sha):
    from cycle import load_fleet
    from evidence import names
    from guard_stops import select
    from race166 import properties
    from types import SimpleNamespace
    ref = dict(path=str(path),sha256=sha)
    fleet,cfg,_ = load_fleet(ref)
    cfg,selected = select(cfg,ref,fleet)
    paths = names(cfg['not_before_utc'])
    sample = dict(path=str(paths['sample']),sha256=sample_sha)
    need(not (paths['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json').exists(),'already accepted cycle')
    pid = properties('horizon-archive-status-cadence-after172-20261120-v1.service','MainPID')['MainPID']
    proc = Path('/proc')/pid
    need((proc/'fd/255').samefile(Path(__file__).with_name('consume')) and
         (proc/'fd/9').samefile(closure.R/'stable-cadence-controller-20261120-v1/consumer.lock') and
         ' FLOCK ' in (proc/'fdinfo/9').read_text() and (proc/'cgroup').read_bytes()==Path('/proc/self/cgroup').read_bytes(),
         'retry requires the original sole cadence consumer')
    c = SimpleNamespace(fleet=fleet,fleet_ref=ref,paths=paths,sample_ref=sample,sample=checked(sample))
    deadline = time.monotonic()+1800
    sampled = {r['range'] for r in c.sample['replays']}
    for epoch,route in ROUTES.items():
        previous = preceding(fleet,epoch)
        if not previous or not previous.get('first_worker') or str(epoch) not in sampled:
            continue
        first = checked(previous['first_worker'])
        if not (route.T/'TERMINAL_SUCCESS.json').exists() and worker_gone(first):
            wait_terminal(epoch,first,deadline)
    select_cycle(c,cfg,selected)
    need(c.histories,'no authenticated terminal transition in successful native sample')
    # Every retry must add at least one new authenticated transition.
    retry = paths['out']/('POST_LOCAL_RETRY_'+'_'.join(str(e) for e in sorted(c.histories))+'.json')
    ensure_dir(paths['out'])
    need(not retry.exists(),'this terminal subset already retried')
    durable(retry,dict(fleet=ref,sample=sample,terminals={str(e):c.commits[e]['terminal'] for e in c.histories}))


if __name__=='__main__':
    need(os.geteuid()==0 and __debug__ and len(sys.argv)==5 and sys.argv[1]=='retry-cycle','invalid cycle retry')
    retry_cycle(Path(sys.argv[2]),sys.argv[3],sys.argv[4])
