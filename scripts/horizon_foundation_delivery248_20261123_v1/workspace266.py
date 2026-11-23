"""Price a new full 266 workspace after the bounded replay stopped, retaining existing obligations."""
import hashlib
import json
import os
from pathlib import Path
import sys
from . import delivery249 as lane
from .closed266 import T, TERMINAL

def check_drained(unit,watch,guard):
    term=lane.bound(lane.shared.pin(TERMINAL,'94958f52d3f1265519325c5b5bbccacf68b119cf441a8939ea678eb8946f5667'))
    h=lane.bound(term['handoff'])
    closed=lane.bound(lane.shared.pin(TERMINAL.parent/'protective-timer-drained.json','b21867e1756b0b3a71584ec541e0866f2154e9c7e71504c45f3f7a0c75b967b1'))
    assert closed['terminal']==lane.ref(TERMINAL) and closed['before']['InvocationID']==h['timer']
    assert term['bounded_target_met'] and term['producer_drained'] and not term['resources_released']
    assert term['unit']==h['unit']==unit and term['iid']==h['iid'] and term['original_reservation']==lane.ref(lane.V/'horizon266-capped-bounded-v207-control/reservation.json')
    assert lane.shared.props(unit,['ActiveState','MainPID','Job'])==dict(ActiveState='inactive',MainPID='0',Job='')
    for service in (unit,watch['Id'],guard):
        assert not (lane.CG/service).exists()
    timer=closed['before']['Id']
    assert lane.shared.props(timer,['ActiveState','Job'])==closed['after']
    assert not Path('/proc',str(h['pid'])).exists()

def install():
    target=T/'retry_fit.py'
    s=target.read_text()
    assert hashlib.sha256(s.encode()).hexdigest()=='0bfb3b23b963f9b0aba0a7d0796cfaea7208a7145365a8aa41ad3dc7e7027441'
    def sub(old,new):
        nonlocal s
        assert s.count(old)==1,old
        s=s.replace(old,new)
    sub('def price(serial,retained,disk):','def price(serial,retained,disk,*,assessment_only=False):')
    sub("  assert os.path.samefile('/proc/3483521/exe',spec['argv'][0]);samples={}", """  from ordinary249.workspace266 import check_drained
  check_drained(u,watch,guard)
  del fixed[u]
  samples={u:0}""")
    sub("  assert props(guard[:-8]+'.timer',['ActiveState','Unit','InvocationID'])==dict(ActiveState='active',Unit=guard,InvocationID=h['timer'])\n  active=assess.manager_services();allowed=set(fixed)|{guard}","  active=assess.manager_services();allowed=set(fixed)")
    sub("  for unit in (delivery.UNIT,audit247.UNIT):","  for unit in (delivery.UNIT,audit247.UNIT,lane249.UNIT):")
    sub("for unit in (delivery.UNIT,audit247.UNIT)}","for unit in (delivery.UNIT,audit247.UNIT,lane249.UNIT)}")
    sub(" and credit[audit247.UNIT]<=audit_growth"," and credit[audit247.UNIT]<=audit_growth and credit[lane249.UNIT]<=delivery.LIMIT")
    sub(" assert q['hard']<=total and growth<=avail and p['free']>=floor+disk,"," assert not assessment_only or (serial,retained,disk)==(0,0,0)\n assert q['hard']<=total and (assessment_only or (growth<=avail and p['free']>=floor+disk)),")
    sub("return dict(reserved_211_delivery249=", "return dict(assessment_only=assessment_only,closed266=ref(D/'horizon266-bounded-terminal-event-v211-a1/completion.json'),reserved_211_delivery249=")
    compile(s,str(target),'exec')
    temp=target.with_suffix('.closed')
    with lane.shared.partition.take():
        with temp.open('x') as f:
            f.write(s);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
        os.replace(temp,target)

def assess():
    from retry_fit import price
    with lane.shared.partition.take():
        fit=price(0,0,0,assessment_only=True)
        term=lane.bound(fit['closed266'])
        assert sorted(r['epoch'] for r in lane.bound(fit['fleet'])['active'])==[247,248,249]
        guard=lane.bound(lane.bound(term['handoff'])['guard'])
        received=Path('/var/lib/jetstreamer/horizon266-capped-bounded-v210-control/pilot/receipts')
        peak=0;observed=0;peak_ref=None
        for path in received.glob('sample-*.json'):
            q=json.loads(path.read_bytes())
            sample=q.get('root_physical_observation')
            if q['producer_invocation_id']!=term['iid'] or not sample:continue
            assert q['maximum_root_physical_bytes']==guard['maximum_root_physical_bytes']
            observed+=1
            if sample['conservative_physical_bytes']>peak:
                peak=sample['conservative_physical_bytes'];peak_ref=lane.ref(path)
        assert observed>0 and peak>=term['archive']['size']
        # Use the established full-epoch planning allowances. Only early recording was observed.
        assessment=lane.bound(lane.shared.pin(lane.D/'horizon296-300-live-workspace-v210-a1/assessment.json',
            '616fe04772d8d2f85dfb4a8c1d973fe07ce9e7ce7cf1b22e21c5555da8fdbd11'))
        source=assessment['prior_model']
        data=Path(source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==source['sha256']=='97d81ed3bb3616e32b01dd3332757385ec9a47e7cd8c392fc5c5de86cbe571ab'
        basis=json.loads(data)['physical']['phases']['267']['terms']
        terms={k:basis[k] for k in ('scratch_if_capped_shrink','all_outputs_through_epoch','host_control_logs_and_metadata')}
        assert terms['scratch_if_capped_shrink']>=peak
        # Existing snapshot and indexes stay bound at their original paths.
        spec=lane.bound(lane.bound(term['handoff'])['spec'])
        total=sum(terms.values())
        gross=fit['extent']['identity']['cap']
        parking={}
        for epoch in (250,251):
            hand=lane.ref(lane.V/f'horizon-singleton-delivery{epoch}-20261119-v1/terminal-handoff.json')
            parking[epoch]=dict(handoff=hand,length=lane.bound(hand)['source']['archive']['identity']['length'],credited_bytes=0)
        info=dict(fit=fit,terminal=fit['closed266'],guard_sample_count=observed,measured_bounded_peak=peak,peak_sample=peak_ref,
            partial_archive=term['archive'],plan_source=source,terms=terms,cost_before_filesystem_overhead=total,existing_inputs=spec['argv'],
            fresh_workspace_deficit=max(0,total-fit['disk_margin']),previous_workspace_nominal_cap=gross,
            minimum_deficit_even_if_entire_previous_cap_reused=max(0,total-gross-fit['disk_margin']),
            possible_holding_relief=parking,capacity_released=False,full_replay_admitted=False)
        out=lane.D/'horizon266-full-workspace-after-target-v214'
        out.mkdir(mode=0o700,exist_ok=True)
        print(lane.shared.funds.put(out/'assessment.json',info))
        print({k:info[k] for k in ('measured_bounded_peak','fresh_workspace_deficit','minimum_deficit_even_if_entire_previous_cap_reused')})

if __name__=='__main__':
    action,=sys.argv[1:]
    {'install':install,'assess':assess}[action]()
