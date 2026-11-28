"""Simulate cold bootstrap and advancing 172 using the installed writer and native sample schema."""
import copy
import datetime as dt
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch

package = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(package))
import cycle
import evidence
import full172
import status
from fixture_test import SimulatedStorage, defaults


def rejected(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError('invalid sample accepted')


def scenario(root, replay):
    c, *_ = defaults(root)
    c.full172_row = None
    c.rolling167 = {"fixture":"incumbent"}
    c.public_fresh = c.unchanged = lambda: None
    c.next_cfg = copy.deepcopy(c.cfg)
    c.now = evidence.utc(c.sample['recorded_at_utc'])
    c.stamp = c.sample['recorded_at_utc']
    c.advancing = {e:True for e in (166,167,170)}
    c.lanes = {int(r['range']):r for r in c.sample['replays']}
    old_lane = c.sample['replays'][0]
    row = copy.deepcopy(c.cfg['replays'][0]); row.update(range='172',producer_unit=full172.UNIT,controller_unit=full172.UNIT,
        expected_controller_invocation_id='a'*32,expected_producer_invocation_id='a'*32)
    unit = dict(Id=full172.UNIT,MainPID='123',InvocationID='a'*32,ExecMainStartTimestamp=(c.now-dt.timedelta(minutes=70)).strftime('%a %Y-%m-%d %H:%M:%S UTC'))
    adpath=root/'ad.json'; evidence.durable(adpath,dict(first_guard={},post_guard_capacity={},start_ticks=12)); ad=evidence.bound(adpath)
    v=dict(identity=dict(admission=ad,unit=unit,timer={}),guard=dict(proof=dict(receipt={}),observer_config=row if replay else None,worker_pid=471))
    c.full172=v
    evidence.durable(c.paths['out']/'FULL172_OBSERVATION.json',v)
    if replay:
        c.cfg['replays'].append(row)
        sample=copy.deepcopy(old_lane);sample.update(range='172',scratch_path=row['scratch_path'])
        for key in ('producer_before','producer_after'):
            sample[key].update(unit=full172.UNIT,main_pid=123,invocation_id='a'*32)
        for key in ('worker_before','worker_after'):
            sample[key]['pid']=471
        w=sample['useful_work'];w['journal_invocation_id']='a'*32;w['append_log_evidence']['producer_main_pid']=123
        start=w['first']['slot']
        for key in ('first','last'):
            w[key]['slot']=full172.FIRST+w[key]['slot']-start;w[key]['terminal_slot']=full172.LAST
        c.sample['replays'].append(sample)
        sample['worker_before']['pid']+=1
        rejected(lambda:full172.reconcile_sample(c,cycle.observed_lane))
        sample['worker_before']['pid']-=1
    full172.reconcile_sample(c,cycle.observed_lane)
    assert c.full172_row['stage']==('replay' if replay else 'bootstrap')
    old=evidence.checked(c.prior['receipts']['172'])['after_status']
    after,_=status.forecast(c,172,old) if not replay else (full172.forecast(c,old,{'size':451}),None)
    assert after['phase']==('replay' if replay else 'verification') and after['elapsed_execution_millis']==70*60000
    assert after['estimated_remaining_millis'] > 0 and (not replay or after['jet_size_bytes']==451)
    store=SimulatedStorage(c);c.paths['statuses']=root/'statuses'
    original_status=status.forecast
    def forecast(c,e,old):
        if e==172: return original_status(c,e,old)
        # Accepted previous fixtures cover incumbents including 167's separate rolling model.
        return dict(old,sampled_at_utc=c.stamp),None
    with patch.object(status,'forecast',side_effect=forecast), patch.object(status,'observed_archive',return_value={'size':451}):
        store.interrupt_after=5
        try:status.publish(c,store)
        except ConnectionError:pass
        else:raise AssertionError('missing interrupted cycle')
        store.interrupt_after=None
        ref=status.publish(c,store); assert status.publish(c,store)==ref
        proof=evidence.checked(ref)
        assert len(store.puts)==19 and len(set(store.puts))==19 and proof['authenticated_status_count']==19
        assert proof['canonical_producer_count']==4 and proof['active_producer_count']==6 and proof['active_bootstraps']==int(not replay)
        r=evidence.checked(proof['receipts']['172']);assert r['after_status']==after and r['producer_invocation_id']=='a'*32
        assert r['authenticated_readback'] and r['current_repair_owner'] is None
        assert evidence.checked(proof['receipts']['166'])['producer_invocation_id']!='a'*32
    f=copy.deepcopy(c.fleet);closed=f['terminal172_closure']; full172.install_fleet(c,f)
    assert full172.owned(f)==c.full172_row and f['terminal172_closure']==closed and f['guarded_bootstrap_owner_count']==int(not replay)
    assert len(f['actual_executing_replays'])==3+int(replay) and len(f['actual_active_bootstraps'])==int(not replay)
    if replay:
        assert c.next_cfg['replays'][-1]==row
        f['actual_active_bootstraps'].append(c.full172_row)
        rejected(lambda:full172.owned(f))


def guard_completion_race(root):
    session = Mock()
    session.native.return_value = {'InvocationID': 'worker'}
    plan = {'receipt_directory': str(root)}
    ad = {'producer_invocation_id': 'worker', 'actual_guard_plan': {'sha256': 'plan'}}
    evidence.durable(root/'sample-one.json', {'workers': [[123, 10]]})
    result = {'worker_guard': 'guard', 'observer_row': 'row', 'worker_pid': 123, 'worker_start_ticks': 3}
    missing = ValueError('waiting for first protected historical worker')
    session.observer_row.side_effect = [missing, result]
    with patch.object(full172, 'LOG', root/'sample-one.json'), patch.object(full172.time, 'sleep') as wait:
        assert full172.current_guard(session, ad, plan)['proof'] == 'guard'
        wait.assert_called_once_with(1)
        wait.reset_mock()
        session.observer_row.side_effect = ValueError('guard incomplete or tripped')
        rejected(lambda: full172.current_guard(session, ad, plan))
        wait.assert_not_called()
        session.observer_row.side_effect = missing
        with patch.object(full172.time, 'monotonic', side_effect=[0, 76]):
            rejected(lambda: full172.current_guard(session, ad, plan))
        wait.assert_not_called()


if __name__=='__main__':
    with tempfile.TemporaryDirectory(dir=evidence.BASE) as tmp:
        guard_completion_race(Path(tmp))
    for replay in (False,True):
        with tempfile.TemporaryDirectory(dir=evidence.BASE) as tmp:
            with patch.object(full172,"ADMISSION",Path(tmp)/"ad.json"):
                scenario(Path(tmp),replay)
    print('Passed bootstrap, replay, cadence membership, archive status, historical closure, foreign worker, duplicate owner and interrupted 19-key writer fixtures.')
