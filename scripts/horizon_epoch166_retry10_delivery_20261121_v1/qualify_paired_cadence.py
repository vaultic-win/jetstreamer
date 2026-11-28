"""Offline terminal combinations and partial conditional writes against one accepted native sample."""
from contextlib import ExitStack
import copy
import json
from itertools import combinations
from pathlib import Path
import shutil
from types import SimpleNamespace
from unittest.mock import patch

import cadence168
import paired_cadence as pair
import race166
import reconcile
import status
from evidence import BASE,EPOCHS,bound,checked,digest,durable,ensure_dir,need,sealed,utc

HEAD = BASE/'root134959-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'
AUTH = {166:'epoch166-retry10-delivery-20261121-v1/qa-f575041147e641a7804574723b890172',
        168:'epoch168-current-delivery-20261121-v1/qa-7c6af9f813ed4f9bb1263e9da87454ca'}


def save(path,value):
    durable(path,value)
    return bound(path)


class Storage:
    def __init__(self,previous):
        self.values = {}
        self.writes = []
        for e in EPOCHS:
            row = checked(previous['receipts'][str(e)])
            self.values[e] = row['after_etag'],status.body(row['after_status'])

    def get(self,e):
        return self.values[e]

    def put(self,e,tag,data):
        need(self.values[e][0]==tag,'fixture conditional tag changed')
        etag = '"'+digest(data)[:32]+'"'
        self.values[e] = etag,data
        self.writes.append(e)
        return etag


def run(work, check_private=None):
    need(bound(HEAD)['sha256']=='adc16f718a5d6780c93d60713978416c3f1272eb4f19731557e35f7ac309a771','wrong native fleet fixture')
    head = checked(bound(HEAD))
    prev = head['previous_Root_operational_review']
    f = checked(prev)
    cfg = sealed(f['sole_next_observer'])
    sp = head['observer']
    sample = checked(sp)
    report = checked(head['authenticated_status_audit'])
    previous = checked(f['authenticated_status_audit'])
    cp = checked(head['current_home_cycle_capacity'])
    audit = bound(HEAD.parent/'AUDIT.json')
    rows = {r['epoch']:r for r in head['actual_executing_replays']}
    actual = {e:checked(report['receipts'][str(e)]) for e in EPOCHS}
    records = {}
    simulator = {}
    sources={e:BASE/subdir for e,subdir in AUTH.items()}
    for e,digest_value in {167:'57c6ff2ccaee8fa8207c2f78fb9c7bb42c7de524d60c983e855376d7eba59582',
                           170:'2322cb695d658f79acd50aa9a2b6d60b4e16e6b7cba5d5037268bbad7c3876c1',
                           172:'99e74c3c8b7ce841426098a0c630539b32647eee7b2d697cb7a80c4837a1ca9e'}.items():
        reference=dict(path=str(pair.ROUTES[e].T/'HELD_PUBLICATION_QUALIFIED.json'),sha256=digest_value)
        package=checked(reference)
        qualified=checked(package['qualification'])
        need(package['epoch']==e and package['r2_writes']==0 and qualified,'foreign held archive qualification')
        sources[e]=Path(package['qualification']['path']).parent
    for e,source in sorted(sources.items()):
        route = pair.ROUTES[e]
        directory = source/'test-publisher/authority'
        tr = bound(directory/'TERMINAL_SUCCESS.json')
        term = checked(tr)
        lr = bound(directory/'LIVE.json')
        live = checked(lr)
        ad,w = live['admission'],live['first_protected_worker']
        g = route.ORIGINAL if e==166 else route.guard
        g.validate_terminal(term,live,lr,ad,w)
        records[e] = tr
        # The genuine singleton has a zero-work manager fixture. Supply the local clock on a separate test envelope.
        term['manager_terminal']['__REALTIME_TIMESTAMP'] = str(int(utc(sample['completed_at_utc']).timestamp()*1e6)+2_000_000)
        terminal = save(work/('terminal-clock-'+str(e)+'.json'),term)
        drained = save(work/('drained-'+str(e)+'.json'),dict(fixture=tr,timer=g.guard_timer))
        simulator[e] = dict(terminal=terminal,first_worker=w,admission=ad,live=lr,guard_retirement=drained)
    all_epochs=tuple(sorted(simulator))
    rejections = {}
    def reject(key,call):
        try:call()
        except (ValueError,KeyError,AssertionError,FileNotFoundError) as exc:rejections[key]=str(exc)
        else:raise AssertionError('unexpected acceptance '+key)
    for e,p in simulator.items():
        bad = copy.deepcopy(cfg)
        next(r for r in bad['replays'] if r['range']==str(e))['producer_unit']='foreign.service'
        reject('foreign-registered-'+str(e),lambda:pair.remove(bad,e,p))
        reject('other-generation-'+str(e),lambda:pair.remove(cfg,e,simulator[next(other for other in all_epochs if other!=e)]))
        need(pair.preceding(f,e)['first_worker']==p['first_worker'],'wrong actual lineage')
    def bind_context(active,folder):
        c = SimpleNamespace(fleet=f,fleet_ref=prev,cfg=cfg,sample=sample,sample_ref=sp,
                            paths=dict(out=HEAD.parent,statuses=folder),now=utc(head['sampled_at_utc']),stamp=head['sampled_at_utc'],
                            prior=previous,public_fresh=lambda:None,unchanged=lambda:None,rows={},private136=None,
                            retired168=True,full172=172 not in active,full172_row=rows[172] if 172 not in active else None,terminal166=None,terminal_sample=None,
                            historical166=None,diagnostic=cp['retained_private_diagnostic_168'],
                            diagnostic169=cp['retained_private_diagnostic_169'],native={},closures=actual[166]['historical_epoch170_closures'],
                            next={'timer':head['sole_next_timer']},lanes={})
        current = {e:simulator[e] for e in active}
        with patch.object(pair,'proofs',return_value=current):
            selected=pair.select_cycle(c,cfg,Path(f['sole_next_observer']['path']))
        need(selected==cfg and c.histories.keys()==current.keys(),'lost pre-terminal native sample')
        c.next_cfg=copy.deepcopy(sealed(head['sole_next_observer']))
        for e,p in current.items():
            c.next_cfg=pair.remove(c.next_cfg,e,p)
        c.advancing={e:True for e in rows if e not in current}
        c.new_rows={e:rows[e] for e in (166,167,170) if e not in current}
        c.recovered_owners={k:v for k,v in head[pair.REGISTRY].items() if int(k) not in current}
        c.recovered_ref=head['recovered_workers_observation']
        c.metered168_row=rows[168] if 168 not in current else None
        c.metered168=dict(reference=head[cadence168.FIELD]) if c.metered168_row else None
        return c

    # Before the sample, seal and reuse exactly one survivor config for every nonempty set.
    projections={}
    for active in (g for size in range(1, len(all_epochs)+1) for g in combinations(all_epochs,size)):
        folder=work/('pre-'+'-'.join(map(str,active)))
        ensure_dir(folder)
        ref=save(folder/'fixture_fleet.json',dict(source=prev))
        cs={e:simulator[e] for e in active}
        prepared,path=pair.select_config(cfg,Path(f['sole_next_observer']['path']),ref,f,cs)
        need(pair.select_config(cfg,Path(f['sole_next_observer']['path']),ref,f,cs)==(prepared,path),'duplicate successor config')
        need(prepared==dict(cfg,replays=[r for r in cfg['replays'] if int(r['range']) not in active]) and sealed(bound(path))==prepared,
             'surviving timers or config changed')
        fixed=copy.deepcopy(sample)
        fixed['replays']=[r for r in fixed['replays'] if int(r['range']) not in active]
        c=SimpleNamespace(fleet=f,sample=fixed,sample_ref=sp,fleet_ref=ref,paths={'statuses':folder})
        with patch.object(pair,'proofs',return_value=cs):
            need(pair.select_cycle(c,cfg,Path(f['sole_next_observer']['path']))==prepared and not c.histories,'bad surviving native sample')
        projections[str(active)]=bound(path)
    for e in simulator:
        c=bind_context((e,),work)
        bad=copy.deepcopy(sample)
        row=next(r for r in bad['replays'] if int(r['range'])==e)
        row['worker_after']['pid']+=1
        c.sample=bad
        reject('wrong-frozen-sample-'+str(e),lambda:pair.historical(c,cfg,e,simulator[e]))
        wrong=copy.deepcopy(cfg)
        wrong['replays'].pop()
        reject('unrelated-next-clock-'+str(e),lambda:pair.next_config(c,wrong))

    def forbid(*args,**kwargs):
        raise AssertionError('unexpected native, remote or guard mutation in offline fixture')
    dispatches=[]
    for order in ((166,168),(167,170),all_epochs,tuple(reversed(all_epochs))):
        outer=work/('dispatch-'+'-'.join(map(str,order)))
        ensure_dir(outer)
        ph=outer/'unwritten-sample.json'
        arr=dict(cfg,output=str(ph))
        up=save(outer/'observer.json',arr)
        frozen=save(outer/'fixture-fleet.json',dict(source=prev))
        closed={}
        calls=[]
        def invoke(cmd,stderr=None):
            actual_config=sealed(bound(Path(cmd[1]))) if Path(cmd[1]).parent.name=='sealed-next' else checked(up)
            keys=[int(r['range']) for r in actual_config['replays']]
            calls.append(keys)
            if len(closed)==len(order):
                return SimpleNamespace(returncode=0,stderr=b'')
            pending=order[len(closed)]
            return SimpleNamespace(returncode=1,stderr=pair.ROUTES[pending].UNIT.encode())
        def observe_exit(e,w,deadline):
            need(e==order[len(closed)] and w==checked(simulator[e]['first_worker']),'retried wrong sampler')
            closed[e]=simulator[e]
        orig_sub=pair.subprocess.run
        def wrapped(cmd,**kwargs):
            return invoke(cmd,**kwargs) if cmd[0]=='/fixture/native' else orig_sub(cmd,**kwargs)
        class Exec(Exception): pass
        def finish(native,args):
            need(native=='/fixture/native','unexpected native command')
            calls.append([int(r['range']) for r in sealed(bound(Path(args[1])))['replays']])
            raise Exec()
        with patch.object(pair,'proofs',side_effect=lambda f:dict(closed)),patch.object(pair,'transition',side_effect=lambda f,e:closed[e]),patch.object(pair,'wait_terminal',side_effect=observe_exit),patch.object(pair.subprocess,'run',side_effect=wrapped),patch.object(pair.os,'execv',side_effect=finish):
            try:pair.dispatch(arr,Path(up['path']),frozen,f,'/fixture/native')
            except Exec:pass
        need(calls==[[e for e in sorted(rows) if e not in order[:count]] for count in range(len(order)+1)],'duplicate or omitted native retry')
        dispatches.append(calls)
        mixed=copy.deepcopy(sample)
        mixed['replays']=[r for r in mixed['replays'] if int(r['range'])!=order[0]]
        mr=save(outer/'mixed-sample.json',mixed)
        mcfg=dict(cfg,output=mr['path'])
        c=SimpleNamespace(fleet=f,fleet_ref=prev,sample=mixed,sample_ref=mr,paths={'statuses':outer})
        with patch.object(pair,'proofs',return_value={e:simulator[e] for e in order}):
            selected=pair.select_cycle(c,mcfg,Path(up['path']))
        need(set(c.histories)==set(order[1:]) and [r['range'] for r in selected['replays']]==[r['range'] for r in mixed['replays']],
             'closure on either side of native sample lost lineage')
    for e,p in simulator.items():
        dr=work/('guard-'+str(e))
        ensure_dir(dr)
        save(dr/'TERMINAL_SUCCESS.json',checked(p['terminal']))
        route=SimpleNamespace(T=dr,DONE=dr/'drained',FIELD=pair.FIELDS[e],UNIT=pair.ROUTES[e].UNIT,IID=pair.ROUTES[e].IID,
                              committed=lambda:{k:v for k,v in p.items() if k!='guard_retirement'},retire=lambda:p,inspect=lambda:p)
        with patch.dict(pair.ROUTES,{e:route}):
            need(pair.transition(f,e)==p,'qualified terminal did not join registered fleet')
            wrong=copy.deepcopy(f)
            if e == 172:
                next(r for r in wrong['actual_executing_replays'] if r['epoch']==172)['unit']['InvocationID']='0'*32
            elif e == 168:
                next(r for r in wrong['actual_executing_replays'] if r['epoch']==168)['first_worker']={}
            else:
                wrong[pair.REGISTRY][str(e)]['actor']['producer_invocation_id']='0'*32
            with patch.object(route,'retire',side_effect=forbid) as unused:
                reject('wrong-lineage-before-guard-'+str(e),lambda:pair.transition(wrong,e));need(not unused.called,'drained a foreign guard')
    captures=[]
    frozen=checked(head['recovered_workers_observation'])
    for order in ((166,167,170),(170,166,167)):
        folder=work/('capture-'+'-'.join(map(str,order)))
        ensure_dir(folder)
        predecessor=save(folder/'RECOVERED_WORKERS.json',frozen)
        for stop in range(1,len(order)+1):
            active=order[:stop]
            c=bind_context(active,folder)
            c.paths['out']=folder
            live={k:v for k,v in frozen['owners'].items() if int(k) not in active}
            path=pair.recover_capture(c,live)
            projected=checked(bound(path))
            need(projected['owners']==live and projected['prior_same_sample_capture']==predecessor and
                 projected['measured']=={k:v for k,v in frozen['measured'].items() if int(k) not in active},
                 'frozen replays changed outside the original completions')
            captures.append(bound(path))
            predecessor=bound(path)
        # A second sibling history cannot be an ancestor of the same sample.
        save(pair.recovered_capture_path(folder,(order[1],)),frozen)
        reject('crossed-captures-'+str(order[0]),lambda:pair.prior_paths(order,lambda group:pair.recovered_capture_path(folder,group)))
    passes=[]
    episodes=[((166,168),None),((168,166),None),((167,170),'landed'),((170,167),'unsent'),
              (all_epochs,'landed'),(tuple(reversed(all_epochs)),'unsent'),((168,170,167,166),None), ((172,166,170),'landed'), ((167,172,168),'unsent')]
    for order,partial in episodes:
        base=work/('post-'+'-'.join(map(str,order))+'-'+str(partial))
        ensure_dir(base)
        store=Storage(previous)
        # Retain the actual same-window If-Match intents, some of which predate closure.
        for e,row in actual.items():
            source=Path(report['receipts'][str(e)]['path'])
            ip=source.with_name('epoch-'+str(e)+'.intent.json')
            need(ip.exists(),'fixture intent unavailable')
            shutil.copyfile(ip,base/ip.name)
            if partial and e==order[0]:
                if partial=='landed':
                    store.values[e]=row['after_etag'],status.body(row['after_status'])
                continue
            shutil.copyfile(source,base/source.name)
            store.values[e]=row['after_etag'],status.body(row['after_status'])
        for count in range(1,len(order)+1):
            active=order[:count]
            c=bind_context(active,base)
            out=c.paths['statuses'];ensure_dir(out)
            sr=status._publish(c,store,out,report['ready_epochs'])
            writes=len(store.writes)
            need(status._publish(c,store,out,report['ready_epochs'])==sr and len(store.writes)==writes,'repeat wrote twice')
            audit_status=checked(sr)
            reconcile.validate_status(c,audit_status)
            need(len(audit_status['receipts'])==19,'missing statuses')
            for e in active:
                entry=checked(audit_status['receipts'][str(e)])
                need(entry['archive_sample']==checked(simulator[e]['terminal'])['local_archive'] and entry[pair.FIELDS[e]]==simulator[e]['terminal']
                     and entry['producer_invocation_id'] is None and store.get(e)==(entry['after_etag'],status.body(entry['after_status'])),
                     'wrong local archive or conditional readback')
            for e in set(EPOCHS)-set(active):
                need(checked(audit_status['receipts'][str(e)])['after_status']==actual[e]['after_status'],'changed unrelated receipt')
            caps=dict(cp,retained_local_commit_bookings=pair.capacity(c))
            captured=dict(observer=sp,fleet_predecessor=prev,audit=checked(audit),capacity=cp)
            save(base/'CYCLE_OBSERVATION.json',captured)
            recovered_capacity=pair.observation(c,base,forbid)
            need(recovered_capacity['capacity']['retained_local_commit_bookings']==caps['retained_local_commit_bookings']
                 and recovered_capacity['audit']==captured['audit'] and
                 recovered_capacity['capacity']['prior_same_sample_capacity_observation']==bound(base/'CYCLE_OBSERVATION.json'),
                 'resumed cycle did not preserve earlier audit or bookings')
            hr=save(out/'home.json',caps)
            # assemble with the previously frozen successor to cover the mid-finish case.
            survivor=copy.deepcopy(c.next_cfg)
            preselected=sealed(head['sole_next_observer'])
            c.next_cfg=pair.next_config(c,preselected)
            accepted=reconcile.assemble(c,sr,audit,hr,head['sole_next_observer'])
            need(accepted['authenticated_status_count']==19 and accepted['canonical_producer_count']==5-len(active)
                 and {r['epoch'] for r in accepted['actual_executing_replays']}==rows.keys()-set(active)
                 and accepted['actual_active_private_diagnostics']==head['actual_active_private_diagnostics']
                 and accepted['sole_next_timer']==head['sole_next_timer'],'peer owner or clock lost')
            need(pair.projected(preselected,Path(head['sole_next_observer']['path']),accepted,{e:simulator[e] for e in active})==survivor,
                 'accepted successor cannot project historical workers')
            import guard_stops
            need(guard_stops.project(preselected,bound(HEAD),accepted)==preselected,
                 'original projected next worker rejected by scheduled guard')
            for e in active:
                need(accepted[pair.FIELDS[e]]==simulator[e]['terminal'] and pair.preceding(accepted,e) is None
                     and caps['retained_local_commit_bookings'][str(e)]['retained_cap_bytes']=={166:288,167:512,168:288,170:384,172:288}[e]<<30,
                     'registered a retired owner or lost its booking')
            if check_private is not None:
                check_private(c,sr,audit,hr,head['sole_next_observer'],preselected,accepted,out)
            passes.append(dict(order=list(order),closed=list(active),report=sr,survivors=sorted(rows.keys()-set(active)),
                               conditional_puts=list(store.writes),retained=hr))
        need(store.writes==list(order),'duplicate or unrelated conditional put')
    base=work/'fresh-both'
    ensure_dir(base)
    c=bind_context(all_epochs,base)
    c.histories={}
    c.recovered166_history=None
    c.paths['statuses']=base
    del c.original_status_dir
    store=Storage(previous)
    for e in set(EPOCHS)-set(simulator):
        src=Path(report['receipts'][str(e)]['path'])
        ip=src.with_name('epoch-'+str(e)+'.intent.json')
        shutil.copyfile(ip,base/ip.name)
        shutil.copyfile(src,base/src.name)
        store.values[e]=actual[e]['after_etag'],status.body(actual[e]['after_status'])
    fresh=status._publish(c,store,base,report['ready_epochs'])
    reconcile.validate_status(c,checked(fresh))
    need(store.writes==list(all_epochs) and all(checked(checked(fresh)['receipts'][str(e)])['previous_receipt']==previous['receipts'][str(e)]
         for e in simulator),'fresh projection did not use original authenticated predecessors')
    return dict(base_fleet=bound(HEAD),native_sample=sp,singleton_fixtures=records,projections=projections,frozen_captures=captures,fresh_all=fresh,
                fixture_status_and_fleet_passes=passes,failed_native_observer_retries=dispatches,refusals=rejections,real_archive_or_status_writes=0)
