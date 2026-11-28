"""Exercise the private diagnostic settlement alongside each archive settlement sequence."""
import copy
from pathlib import Path
from types import SimpleNamespace

import focused169_completion as fc
import qualify_paired_cadence as q
import reconcile
from evidence import bound, checked, durable, need, sealed


def run(work):
    route=fc.authority()
    live,lr=route['live']()
    original=live['original']
    results=[]
    refusals=[]
    labels=sorted(fc.DISPOSITIONS)

    def check(c,sr,audit,hr,nextref,cfg,accepted,out):
        report=checked(sr)
        cap=checked(hr)
        disposition=labels[len(results)%len(labels)]
        terminal,guard=out/'private-terminal.json',out/'private-drained.json'
        durable(terminal,dict(schema='private-cadence-fixture',disposition=disposition,original=lr))
        durable(guard,dict(terminal=bound(terminal),timer=route['TIMER_IID']))
        proof={k:original[k] for k in ('first_guard','admission','actual_guard_plan')}
        proof.update(live=lr,terminal=bound(terminal),guard_retirement=bound(guard),producer_invocation_id=route['IID'],
                     timer_unit=route['TIMER'],timer_invocation_id=route['TIMER_IID'],guard_unit=route['GUARD'],
                     disposition=disposition,resource_credit_bytes=0)
        child=SimpleNamespace(**vars(c))
        child.focused_terminal=proof
        child.diagnostic169=fc.observation(child,proof)
        need(child.diagnostic169['historical_capture']==bound(c.paths['out']/'FOCUSED169_OBSERVATION.json'),
             'lost the previous registered private capture')
        cap['retained_private_diagnostic_169']=child.diagnostic169
        saved=out/'private-capacity.json'
        durable(saved,cap)
        fleet=reconcile.assemble(child,sr,audit,bound(saved),nextref)
        need(fleet['actual_executing_replays']==accepted['actual_executing_replays'] and
             fleet['actual_active_private_diagnostics']==[r for r in accepted['actual_active_private_diagnostics'] if r['epoch']!=169] and
             fleet['active_producer_count']==accepted['active_producer_count']-1 and
             fleet['authenticated_status_audit']==sr and fleet['effective_status_receipts']==report['receipts'] and
             fleet['sole_next_timer']==accepted['sole_next_timer'] and fleet['sole_next_observer']==nextref and
             fc.retained(fleet,proof)==child.diagnostic169['retained_booking'] and fleet['all_reservation_ending_bytes']==0,
             'private exit changed an independent worker, booking or status')
        row=next(r for r in fleet['epochs'] if r['epoch']==169)
        need(row['current_repair_owner']=='/root' and row['no_live_producer_claimed'] is True and
             'current_private_diagnostic' not in row and row['current_status']['phase']=='verification' and
             row[fc.GUARD]==proof['guard_retirement'] and fleet[fc.FIELD]==row[fc.FIELD]==proof['terminal'],
             'private epoch recorded as public delivery')
        nextcfg=fc.remove_preselected(child,cfg)
        need([r for r in nextcfg['diagnostic_replays'] if r['range']=='169']==[] and nextcfg['replays']==cfg['replays'],
             'archive slot range changed')
        now=copy.deepcopy(report)
        now['coordinated_private_diagnostic_169']=child.diagnostic169
        now['active_producer_count']-=1
        now['active_private_diagnostic_count']-=1
        reconcile.validate_status(child,now)
        for kind in ('wrong-timer','wrong-admission','credited','missing-guard'):
            forged=dict(proof)
            if kind=='wrong-timer':forged['timer_invocation_id']='f'*32
            if kind=='wrong-admission':forged['admission']=proof['first_guard']
            if kind=='credited':forged['resource_credit_bytes']=1
            if kind=='missing-guard':forged['guard_retirement']=None
            try:fc.original(fleet,forged)
            except (KeyError,ValueError):refusals.append(kind)
            else:raise AssertionError('accepted '+kind)
        results.append(dict(preceding_status=sr,closed_archives=sorted(c.commits),disposition=disposition))

    suite=q.run(work,check)
    need(len(results)==28 and len(refusals)==112,'incomplete private transition coverage')
    suite['private_transitions']=results
    suite['private_refusals']=len(refusals)
    return suite
