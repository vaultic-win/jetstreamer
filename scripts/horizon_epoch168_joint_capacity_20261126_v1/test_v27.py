import ast
import copy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from unittest import TestCase, main
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE/'source'
sys.path.insert(0,str(SOURCE))


def need(test, msg):
    if not test:
        raise ValueError(msg)


sys.modules['evidence'] = NS(bound=Mock(), checked=Mock(), need=need)
sys.modules['owners'] = NS(ticks=Mock(), show=Mock())
import joint168_status as status
lane = status.lane

A = dict(invocation_id='1'*32,pid=300,start_ticks=201,ready_at=312,boot_id='0'*32)
W = dict(pid=301,start_ticks=202,path=str(lane.WORKER_SCRATCH/'jetstreamer-historical-parent-test/bound-worker/historical-worker'))
LOG = dict(path=str(lane.RUN/'producer.log'),device=1,inode=2)
E = dict(actor=A,prestart_quote={'ref':'quote'},append_log=LOG)
REF = {'ref':'enrolled'}
SEAL = {'ref':'V26'}
U = {'Id':lane.UNIT,'ActiveState':'active','InvocationID':A['invocation_id']}
OWN146 = {'range':'146','producer_unit':'producer146','controller_unit':'producer146'}
PROC = [[A['pid'],A['start_ticks'],20,21]]
JOINT_CFG = status.observer_row(E,W)


def context():
    return NS(fleet={},sample_ref={'ref':'observer'},cfg={'diagnostic_replays':[OWN146]},
              sample={'diagnostic_replays':[]},next_cfg={'diagnostic_replays':[OWN146]})


class Joint168Status(TestCase):
    def test_absent_keeps_incumbent_schedule_and_checks_idle(self):
        with TemporaryDirectory() as d, patch.object(lane,'ENROLLMENT',Path(d)/'none'), patch.object(status,'TERMINAL',Path(d)/'terminal'), patch.object(lane,'require_idle') as idle:
            c = context()
            self.assertIsNone(status.observe(c,SEAL,None))
            status.project(c,None)
            self.assertEqual(c.next_cfg['diagnostic_replays'],[OWN146])
            idle.assert_called_once()
            c.cfg['diagnostic_replays'].append(JOINT_CFG)
            with self.assertRaisesRegex(ValueError,'lost its confirmed'):
                status.observe(c,SEAL,None)

    def test_exact_held_and_same_pid_native_lifecycle(self):
        c = context()
        with TemporaryDirectory() as d, patch.object(lane,'ENROLLMENT',Path(d)/'intent'), patch.object(status,'TERMINAL',Path(d)/'terminal'), patch.object(status,'enrollment',return_value=(REF,{'enrollment':REF},E,{'joint':True})), patch.object(lane,'props',return_value=U), patch.object(lane,'load_payload',return_value={'payload':True}), patch.object(lane,'native',return_value=(U,PROC,None)) as native, patch.object(Path,'samefile',return_value=True) as image:
            lane.ENROLLMENT.touch()
            hold = status.observe(c,SEAL,None)
            self.assertEqual(hold['phase'],'held')
            self.assertIsNone(hold['observer_config'])
            c.fleet[status.FIELD] = hold
            image.return_value = False
            with patch.object(status,'latest_guard',return_value=({'guard':True},False)) as guard, patch.object(lane,'validate_release',return_value={'release':True}):
                boot = status.observe(c,SEAL,None)
                self.assertEqual(boot['phase'],'bootstrap')
                self.assertEqual(boot['actor'],hold['actor'])
                self.assertIsNone(boot['observer_config'])
                native.return_value = (U,PROC+[[W['pid'],W['start_ticks'],22,23]],W)
                guard.return_value = ({'guard':True},True)
                worker = status.observe(c,SEAL,None)
                self.assertEqual(worker['phase'],'worker')
                self.assertFalse(worker['transaction_replay_claimed'])
                status.project(c,worker)
                self.assertEqual(c.next_cfg['diagnostic_replays'],[OWN146,JOINT_CFG])
                c.fleet[status.FIELD] = worker
                image.return_value = True
                with self.assertRaisesRegex(ValueError,'reverted to the held'):
                    status.observe(c,SEAL,None)

    def test_scheduled_worker_progress_pins_both_endpoints(self):
        c = context()
        c.cfg['diagnostic_replays'].append(JOINT_CFG)
        point = {'pid':W['pid'],'executable':W['path']}
        result = dict(range='168',producer_unit=lane.UNIT,expected_producer_invocation_id=A['invocation_id'],
                      scratch_path=JOINT_CFG['scratch_path'],ordinary_replay_claim=False,
                      publication_authorized=False,r2_mutations=False,status='observed',
                      observation=dict(worker_before=point,worker_after=dict(point)))
        c.sample['diagnostic_replays'] = [result]
        prior = {'observer_config':JOINT_CFG}
        self.assertEqual(status.sample_row(c,A,'worker',JOINT_CFG,W,prior,lambda *_:True),(result,True))
        self.assertEqual(status.sample_row(c,A,'terminal',None,None,prior,None),(result,False))
        point['pid'] += 1
        with self.assertRaisesRegex(ValueError,'crossed its protected child'):
            status.sample_row(c,A,'worker',JOINT_CFG,W,prior,lambda *_:True)

    def test_unavailable_worker_observation_has_no_replay_claim(self):
        c = context()
        c.cfg['diagnostic_replays'].append(JOINT_CFG)
        result = dict(range='168',producer_unit=lane.UNIT,expected_producer_invocation_id=A['invocation_id'],
                      scratch_path=JOINT_CFG['scratch_path'],ordinary_replay_claim=False,
                      publication_authorized=False,r2_mutations=False,status='unavailable',observation=None,
                      error=f"expected exactly one historical-worker beneath {JOINT_CFG['scratch_path']}, found 0")
        c.sample['diagnostic_replays'] = [result]
        self.assertEqual(status.sample_row(c,A,'bootstrap',None,None,{'observer_config':JOINT_CFG},None),(result,False))
        result['error'] = 'different device'
        with self.assertRaisesRegex(ValueError,'observation failed'):
            status.sample_row(c,A,'bootstrap',None,None,{'observer_config':JOINT_CFG},None)

    def test_terminal_clean_exit_or_native_process_failure_requires_drain(self):
        event = dict(_PID='1',_UID='0',UNIT=lane.UNIT,_BOOT_ID=A['boot_id'],INVOCATION_ID=A['invocation_id'],
                     MESSAGE_ID='7ad2d189f7e94e70a38c781354912448',__REALTIME_TIMESTAMP=str(A['ready_at']*1_000_000))
        receipt = dict(schema='horizon-epoch168-joint-reduced-terminal-v1',enrollment=REF,
                       producer_invocation_id=A['invocation_id'],producer_pid=A['pid'],
                       producer_start_ticks=A['start_ticks'],disposition='checkpoint-complete',
                       resource_credit_bytes=0,archive_publication_authorized=False,remote_mutations=False,
                       private_output_preserved=True,pid1_terminal_event=event,independent_archive_scan_pending=True)
        bound_terminal = {'ref':'terminal'}
        with patch.object(status,'read',return_value=(receipt,bound_terminal)), patch.object(lane,'require_idle') as idle, patch.object(status,'ticks',side_effect=FileNotFoundError):
            self.assertEqual(status.terminal(REF,E,None),bound_terminal)
            idle.assert_called_once()
            receipt['disposition'] = 'held-expired'
            with self.assertRaisesRegex(ValueError,'failed process event'):
                status.terminal(REF,E,None)
            event.update(MESSAGE_ID='98e322203f7a4ed290d09fe03c09fe15',COMMAND='ExecStart',EXIT_STATUS='1')
            self.assertEqual(status.terminal(REF,E,None),bound_terminal)
            idle.side_effect = ValueError('guard remains active')
            with self.assertRaisesRegex(ValueError,'guard remains active'):
                status.terminal(REF,E,None)

    def test_terminal_clears_only_its_private_projection_and_never_publishes(self):
        c = context()
        c.next_cfg['diagnostic_replays'].append(JOINT_CFG)
        terminal = dict(phase='terminal',observer_config=None,archive_publication_authorized=False)
        status.project(c,terminal)
        self.assertEqual(c.next_cfg['diagnostic_replays'],[OWN146])
        f = dict(actual_active_private_diagnostics=[],active_private_diagnostic_count=0,
                 active_producer_count=4,canonical_producer_count=4)
        original = copy.deepcopy(f)
        status.install(f,terminal)
        self.assertEqual({k:f[k] for k in original},original)
        status.install(f,dict(terminal,phase='worker',observer_config=JOINT_CFG,epoch=168))
        self.assertEqual(f['active_private_diagnostic_count'],1)
        self.assertEqual(f['active_producer_count'],5)
        self.assertEqual(f['canonical_producer_count'],4)
        self.assertFalse(f[status.FIELD]['archive_publication_authorized'])

    def test_filters_only_exact_joint_unit_and_rejects_range_collision(self):
        c = context()
        c.next_cfg['diagnostic_replays'].append(dict(range='168',producer_unit='different168'))
        with self.assertRaisesRegex(ValueError,'duplicate private'):
            status.project(c,{'observer_config':JOINT_CFG})

    def test_make_context_preserves_146_and_joins_only_released_joint_native(self):
        tree = ast.parse((SOURCE/'status_cycle.py').read_bytes())
        fn, = (v for v in tree.body if isinstance(v,ast.FunctionDef) and v.name=='make_context')
        obs = {'sample':True}
        all_calls = []
        cold = NS(reconcile=lambda *_:None, cold168=NS(census=lambda _owners,_ident,pop,**_kwargs:all_calls.append(pop)))
        f146 = dict(phase='worker',unit={'Id':'146'},actor={'producer_pid':146})
        joined = dict(phase='held',unit={'Id':lane.UNIT},actor={'producer_pid':A['pid']},observer_config=None)
        mocked = NS(observe=lambda *_:joined,project=status.project,recheck=Mock())
        ns = dict(checked=lambda v:v,check_sample=lambda *_:'2026-11-26T20:18:08Z',utc=lambda v:v,
                  SimpleNamespace=NS,Path=Path,copy=copy,PRIVATE136=False,full172=NS(
                      owned=lambda _:True,identity=lambda _:42,guard_view=lambda _:43,reconcile_sample=lambda *_:None),
                  read_ref=lambda _:dict(observer={'path':'/sample'},fleet={},identity=42),
                  FULL146=True,FAILED166_VERSION=26,METERED_FULL170=False,HOURLY170=False,
                  cold_workers=cold,cycle=NS(observed_lane=None),epoch146_entry=lambda _:None,
                  epoch143_entry=lambda _:None,owners=NS(),focused168_status=NS(FIELD='focused',observe=lambda _:None),
                  bound=lambda p:{'path':str(p)},CURRENT=SOURCE/'status_cycle.py',
                  full146_status=NS(observe=lambda *_:f146,observer=lambda c:None,recheck=Mock()),
                  joint168_status=mocked,need=need)
        # Existing reconciliation populates recovered owners before adding either new lane.
        def recover(c,_):
            c.recovered_owners = {'167':{'previous':True}}
        cold.reconcile = recover
        ns['full172'].identity = lambda _: {'admission':42}
        ns['read_ref'] = lambda _:dict(observer={'path':'/sample'},fleet={},identity={'admission':42})
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'<sole-cadence make_context>','exec'),ns)
        with TemporaryDirectory() as d:
            path=Path(d)
            (path/'FULL172_OBSERVATION.json').touch()
            args=({}, {'authenticated_status_audit':{}}, {'path':'/sample'}, {'diagnostic_replays':[]},path)
            ns['make_context'](*args)
            self.assertEqual(set(all_calls[-1]),{'146','167'})
            joined['phase']='bootstrap'
            ns['make_context'](*args)
            self.assertEqual(set(all_calls[-1]),{'146','167','joint168'})
            self.assertIs(all_calls[-1]['146'],f146)
            joined['phase']='terminal'
            ns['make_context'](*args)
            self.assertEqual(set(all_calls[-1]),{'146','167'})


if __name__ == '__main__':
    main()
