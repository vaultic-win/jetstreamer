import json
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import TestCase, main

import sys
sys.path.insert(0, str(Path(sys.argv.pop(1)).resolve(strict=True)))
V17_QUOTE = Path(sys.argv.pop(1)).resolve(strict=True)
import full146_capacity as lane


def need(ok, why):
    if not ok:
        raise ValueError(why)


class Full146Capacity(TestCase):
    def setUp(self):
        q = json.loads(V17_QUOTE.read_bytes())
        self.native = q['native_v17_quote']
        self.native['bounded_qualification'] = None
        self.s = NS(need=need)
        self.request = {'proposal': q['proposal']}
        self.p = dict(epoch168_followup_cpu_quota_micros=2_000_000,
                      epoch168_followup_memory_bytes=8<<30,
                      epoch168_followup_additive_home_bytes=0)
        self.pre = dict(mode='prestart', proposal=self.p, processes=[], footprint=0)

    def test_firing_timer_retains_its_invocation_across_accounting(self):
        timer = dict(Id='horizon-guard-146.timer', InvocationID='a'*32, ActiveState='active',
                     Triggers='horizon-guard-146.service', Job='', SubState='waiting')
        before = dict(actor='fixed', footprint=1234, timers=timer)
        running = dict(before, timers=dict(timer, SubState='running'))
        lane.check_same(self.s, before, running)
        with self.assertRaisesRegex(ValueError, 'timers'):
            lane.check_same(self.s, before, dict(running, timers=dict(timer, InvocationID='b'*32)))
        with self.assertRaisesRegex(ValueError, 'footprint'):
            lane.check_same(self.s, before, dict(running, footprint=1235))
        with self.assertRaisesRegex(ValueError, 'timer is inactive'):
            lane.check_same(self.s, before, dict(before, timers=dict(timer, SubState='dead')))

    def test_prestart_preserves_v17_charges_and_exact_donor(self):
        result = lane.project(self.s, self.native, self.pre, self.request)
        self.assertTrue(result['fit']['fits'])
        self.assertEqual(result['fit']['projected_cpu_quota_micros'], 64_000_000)
        self.assertEqual(result['fit']['projected_required_memory_bytes'],
                         self.native['required_available_memory_bytes'] + (8<<30))
        self.assertEqual(result['fit']['projected_home_floor_bytes'],
                         self.native['complete_required_HOME_bytes'] + lane.CAP)
        self.assertEqual(result['bookings']['168'], self.native['bookings']['168'])
        self.assertEqual(result['retained_185_restore_overlap_bytes'], 123_350_028_052)

    def test_same_pid_exec_preserves_exact_single_booking(self):
        actor = dict(mode='held', armed_floor=self.native['complete_required_HOME_bytes'],
                     proposal=self.p, processes=[[500, 20, 1, 1]], footprint=0)
        self.native['population'][lane.UNIT] = [[500, 20]]
        held = lane.project(self.s, self.native, actor, self.request)
        boot = dict(actor, mode='active', processes=[[500, 20, 2, 2]], footprint=16384)
        released = lane.project(self.s, self.native, boot, self.request)
        self.assertEqual(released['fit']['projected_cpu_quota_micros'],
                         held['fit']['projected_cpu_quota_micros'])
        self.assertEqual(released['fit']['projected_required_memory_bytes'],
                         held['fit']['projected_required_memory_bytes'])
        self.assertEqual(released['bookings']['146']['remaining_bytes'], lane.CAP-16384)
        self.assertEqual(released['fit']['projected_home_floor_bytes'],
                         held['fit']['projected_home_floor_bytes']-16384)
        boot['processes'].append([501, 21, 3, 3])
        self.native['population'][lane.UNIT].append([501, 21])
        self.assertEqual(lane.project(self.s,self.native,boot,self.request)['bookings']['146'],
                         released['bookings']['146'])

    def test_unknown_or_crossed_actor_fails(self):
        self.native['population']['foreign.service'] = [[500, 20]]
        with self.assertRaisesRegex(ValueError, 'incumbent population'):
            lane.project(self.s, self.native, self.pre, self.request)
        with self.assertRaisesRegex(ValueError, 'changed during quote'):
            lane.check_same(self.s, {'pid': 30, 'timers': None}, {'pid': 31, 'timers': None})

    def test_rejects_lost_holding_or_duplicate_booking(self):
        self.native['bookings']['146'] = dict(cap_bytes=lane.CAP)
        with self.assertRaisesRegex(ValueError, 'custody changed'):
            lane.project(self.s, self.native, self.pre, self.request)
        del self.native['bookings']['146']
        self.native['epoch185_lanel_holding']['holding_reservation']['restore_overlap_bytes'] -= 1
        with self.assertRaisesRegex(ValueError, 'custody changed'):
            lane.project(self.s, self.native, self.pre, self.request)

    def test_cpu_shortfall_keeps_placement_out(self):
        self.p['epoch168_followup_cpu_quota_micros'] += 1
        q = lane.project(self.s,self.native,self.pre,self.request)
        self.assertFalse(q['fit']['fits'])
        self.assertEqual(q['fit']['cpu_shortfall_micros'], 1)

    def test_live_roster_only_removes_exact_registered_actor(self):
        row = dict(epoch=146, phase='held', actor={'producer_unit': lane.UNIT}, unit={'Id': lane.UNIT})
        peer = {'epoch': 172}
        self.assertEqual(lane.fleet_roster(self.s, {lane.FIELD: row}, [peer, row]), [peer])
        with self.assertRaisesRegex(ValueError, 'unregistered'):
            lane.fleet_roster(self.s, {}, [peer, row])
        with self.assertRaisesRegex(ValueError, 'roster overlaps'):
            lane.fleet_roster(self.s, {lane.FIELD: row}, [peer, row, row])


if __name__ == '__main__':
    main()
