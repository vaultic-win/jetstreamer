import copy
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main, mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'source'))
import joint168_capacity as lane

G = 1 << 30


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


class Joint168(TestCase):
    def setUp(self):
        self.s = SimpleNamespace(need=need)
        self.base = json.loads((HERE/'TEST_V19_ACTIVE_146.json').read_bytes())
        self.old = copy.deepcopy(self.base)
        self.proposal = dict(growth_bytes=64*G,stop_allowance_bytes=8*G)
        self.candidate = dict(mode='prestart',physical=250*G,retirement={'sha256':'a'*64},
                              processes=[],available_home=9_500_000_000_000,available_ram=750*G)

    def test_dynamic_cap_cpu_ram_and_full_incumbent_unchanged(self):
        q = lane.project(self.s,self.base,self.candidate,self.proposal)
        self.assertEqual(q['joint168']['whole_tree_cap_bytes'],314*G)
        self.assertEqual(q['joint168']['remaining_home_bytes'],64*G)
        self.assertEqual(q['fit']['extra_cpu_quota_micros'],0)
        self.assertEqual(q['fit']['extra_memory_bytes'],52*G)
        self.assertEqual(q['fit']['required_home_bytes'],
                         self.base['fit']['projected_home_floor_bytes']+72*G)
        self.assertEqual(q['full146'],self.old)
        self.assertEqual(self.base,self.old)
        self.assertEqual(q['full146']['retained_185_restore_overlap_bytes'],123_350_028_052)

    def test_hard_disk_and_memory_limits_use_lower_available(self):
        q = lane.project(self.s,self.base,self.candidate,self.proposal)
        self.assertFalse(q['fit']['fits'])
        self.assertEqual(q['fit']['available_home_bytes'],self.base['fit']['available_home_bytes'])
        self.assertEqual(q['fit']['available_memory_bytes'],self.base['fit']['available_memory_bytes'])
        self.assertEqual(q['fit']['memory_shortfall_bytes'],0)

    def test_held_to_active_same_cap_and_single_advance_charge(self):
        first = lane.project(self.s,self.base,self.candidate,self.proposal)
        guard = dict(available=self.candidate['available_home'])
        h = dict(self.candidate,mode='held',first_fit=first['joint168'],guard=guard,processes=[[14,20,23,24]])
        a = dict(h,mode='active',physical=258*G,processes=[[14,20,25,27],[15,21,26,28]])
        held = lane.project(self.s,self.base,h,self.proposal)
        active = lane.project(self.s,self.base,a,self.proposal)
        self.assertEqual(active['joint168']['whole_tree_cap_bytes'],held['joint168']['whole_tree_cap_bytes'])
        self.assertEqual(active['fit']['required_home_bytes'],held['fit']['required_home_bytes']-8*G)
        self.assertEqual(active['fit']['required_available_memory_bytes'],held['fit']['required_available_memory_bytes'])

    def test_over_cap_and_floor_reprice_fail(self):
        first = lane.project(self.s,self.base,self.candidate,self.proposal)
        a = dict(self.candidate,mode='active',physical=315*G,first_fit=first['joint168'])
        q = lane.project(self.s,self.base,a,self.proposal)
        self.assertEqual(q['fit']['whole_tree_over_cap_bytes'],G)
        self.assertFalse(q['fit']['fits'])
        a['first_fit']['guard_floor_bytes'] -= 123
        self.assertEqual(lane.project(self.s,self.base,a,self.proposal)['fit']['guard_floor_shortfall_bytes'],123)

    def test_changed_allowance_or_incumbent_rejected(self):
        self.base['pending_epoch168_followup']['cpu_quota_micros'] -= 1
        with self.assertRaisesRegex(ValueError,'reserved promises'):
            lane.project(self.s,self.base,self.candidate,self.proposal)
        self.base = self.old
        self.base['active_full146']['actor']['producer_invocation_id'] = '4'*32
        with self.assertRaisesRegex(ValueError,'existing 146 owner'):
            lane.project(self.s,self.base,self.candidate,self.proposal)

    def test_joined_census_checks_identity_and_minimum_available(self):
        a = dict(self.candidate,actor={'pid':45,'start_ticks':964})
        b = dict(a,available_home=a['available_home']-1,available_ram=a['available_ram']+1)
        self.assertEqual(lane.pair(self.s,a,b)['available_home'],b['available_home'])
        self.assertEqual(lane.pair(self.s,a,b)['available_ram'],a['available_ram'])
        b['actor'] = {'pid':45,'start_ticks':965}
        with self.assertRaisesRegex(ValueError,'during full census'):
            lane.pair(self.s,a,b)

    def test_tight_native_cgroup_limits(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            for name,value in {'cpu.max':'175000 100000','memory.max':str(59*G),'memory.swap.max':'0'}.items():
                (d/name).write_text(value)
            self.assertTrue(lane.cgroup_limits(d,1_750_000,59*G))
            self.assertFalse(lane.cgroup_limits(d,2_000_000,59*G))
            (d/'memory.swap.max').write_text('max')
            self.assertFalse(lane.cgroup_limits(d,1_750_000,59*G))

    def test_unloaded_pid1_timer_omits_service_pid_fields(self):
        def show(name, fields):
            row = dict(Id=name, ActiveState='inactive', Job='')
            if name == lane.SERVICE:
                row.update(MainPID='0', ControlPID='0')
            elif name == lane.UNIT:
                row.update(MainPID='0')
            return row

        with mock.patch.object(lane, 'props', side_effect=show), mock.patch.object(
            lane, 'process_members', return_value=set()
        ):
            with self.assertRaisesRegex(ValueError, 'already occupied'):
                lane.require_idle(self.s)

        def drained(name, fields):
            row = show(name, fields)
            if name == lane.UNIT:
                row['ControlPID'] = '0'
            return row

        with mock.patch.object(lane, 'props', side_effect=drained), mock.patch.object(
            lane, 'process_members', return_value=set()
        ):
            lane.require_idle(self.s)

    def test_donor_filters_only_the_enrolled_canonical_146(self):
        from runpy import run_path
        legacy = run_path(str(HERE/'source/build_159_price.py'))['incumbent_146_roster']
        first = {'epoch': 167}
        unit = 'horizon-qualify-146-full-local-20261126-v1.service'
        actor = {'producer_unit': unit, 'producer_invocation_id': 'a' * 32}
        enrollment = {'path': '/fixture/full146', 'sha256': 'b' * 64}
        row = dict(epoch=146, phase='worker', actor=actor, enrollment=enrollment,
                   unit={'Id': unit, 'InvocationID': actor['producer_invocation_id']})
        owner = dict(mode='active', unit=unit, actor=actor, enrollment=enrollment)
        native = {'full146_census': owner}
        fleet = dict(actual_executing_replays=[first, copy.deepcopy(row)],
                     actual_active_bootstraps=[], actual_active_private_diagnostics=[],
                     current_full146=row, canonical_producer_count=2)
        self.assertEqual(legacy(fleet,native,None), ([first,row],2))
        self.assertEqual(legacy(fleet,native,owner), ([first],1))
        fleet['actual_executing_replays'][1]['unit']['InvocationID'] = 'c' * 32
        with self.assertRaisesRegex(ValueError, 'different epoch 146'):
            legacy(fleet,native,owner)

    def test_only_unobserved_checked_retirement_advances_coordinated_disk_bound(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            check = root/'CHECK.json'
            done = root/'COMPLETE.json'
            check.touch()
            done.touch()
            ref = {'path': str(done), 'sha256': 'a' * 64}
            record = {'retired_tree_before_bytes': 88971591680,
                      'scope_root_remaining_bytes': 4096,
                      'check_sha256': 'b' * 64}
            verified = {'schema': 'horizon168-retry4-stopped-accounts-check-v1',
                        'allocated_bytes': 88971591680}
            fleet = {'complete_cycle_conservative_available_DATA_bytes': 10**12,
                     'recorded_unix_seconds': int(check.stat().st_mtime)-1}
            with mock.patch.object(lane, 'retirement', return_value=ref), mock.patch.object(
                lane, 'read', side_effect=lambda _, item: record if item == ref else verified
            ):
                fresh = lane.fleet_storage_bound(self.s, fleet, ref)
                self.assertEqual(fresh['post_fleet_retirement_bytes'], 88971587584)
                fleet['recorded_unix_seconds'] += 1
                later = lane.fleet_storage_bound(self.s, fleet, ref)
                self.assertEqual(later['fleet_available_upper_bound'], 10**12)

    def test_only_exact_private_roster_is_accepted(self):
        prior = {'epoch':172}
        row = {'epoch':168,'unit':{'Id':lane.UNIT},'phase':'worker','archive_publication_authorized':False}
        with self.assertRaisesRegex(ValueError,'without an active roster'):
            lane.fleet_roster(self.s,{},[prior,row])
        fleet = {lane.FIELD:row,'actual_active_private_diagnostics':[row]}
        self.assertEqual(lane.fleet_roster(self.s,fleet,[prior,row]),[prior])
        with self.assertRaisesRegex(ValueError,'changed joint 168'):
            lane.fleet_roster(self.s,fleet,[prior,row,row])

    def test_dynamic_payload_gate_keeps_exact_scope(self):
        from runpy import run_path
        gate = run_path(str(HERE/'scope/gate.py'))
        p = json.loads((HERE/'source/joint168-scope-template.json').read_bytes())
        p['accounting_basis'] = dict(prestart_quote_sha256='a'*64, retired_scope_sha256='b'*64,
                                     baseline_physical_bytes=250*G, incremental_growth_bytes=64*G,
                                     stop_allowance_bytes=8*G)
        p['caps']['whole_tree_bytes'] = 314*G
        gate['verify_joint_payload'](p,lane.ALIAS,lane.RUN)
        p['caps']['whole_tree_bytes'] = 448*G
        with self.assertRaisesRegex(RuntimeError,'scope'):
            gate['verify_joint_payload'](p,lane.ALIAS,lane.RUN)


if __name__ == '__main__':
    main()
