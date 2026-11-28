"""Fixture the boundaries that allow a held worker to become a replay owner."""
import unittest
from unittest.mock import patch

import capacity
import profile
import session


class FitTests(unittest.TestCase):
    def inputs(self):
        gib=profile.GIB
        fleet={"complete_projected_memory_bytes":761131708416,"all_reservation_ending_bytes":0}
        obligation={"additional_cpu_quota_micros":4000000,"additional_memory_bytes":24*gib,
                    "configured_free_floor_bytes":6796908511026,
                    "current_storage":{"remaining_archive_growth_bytes":0,"remaining_DATA_growth_bytes":18*gib}}
        previous={"simultaneous_cpu_upper_bound_micros":63250000,"complete_memory_plus_reserve_bytes":810658050048,
                  "protected_raw_floor_bytes":8499707994704}
        guard={"maximum_root_physical_bytes":96*gib,"minimum_free_bytes":8515329790544}
        data={"temporary_cpu_micros":0,"temporary_memory":0,"historical_floor_bytes":6829053656882,
              "independent166_whole_cap_bytes":288*gib,"roots":{"peer_remaining_growth_bytes":100*gib,
              "remaining_standard_root_bytes":10*gib},"auxiliary":{"remaining_growth_bytes":70*gib,
              "memory_bytes":6576668672,"cpu_quota_micros":3250000}}
        return [fleet,obligation,previous,guard,data,24*gib,31*gib,700*gib,810902843392,9_300_000_000_000,235*gib,64]

    def test_explicitly_funds_every_remaining_focused_byte(self):
        args=self.inputs()
        fit=capacity.calculate(*args)
        self.assertEqual(fit["complete_cpu_quota_micros"],64000000)
        self.assertEqual(fit["focused169_remaining_bytes"],65*profile.GIB)
        self.assertGreaterEqual(fit["base_protected_floor_bytes"],8515329790544+65*profile.GIB)
        self.assertEqual(fit["remaining_standard_root_bytes"],264*profile.GIB)
        armed=capacity.select(fit)
        fit["available_HOME_bytes"]=armed+fit["remaining_standard_root_bytes"]-1
        with self.assertRaisesRegex(ValueError,"HOME requires"):
            capacity.select(fit, armed)

    def test_no_retired_cpu_or_future_audit_credit(self):
        for mutate in [lambda a:a[4].update(temporary_cpu_micros=1),
                       lambda a:a[2].update(simultaneous_cpu_upper_bound_micros=63000000),
                       lambda a:a[1].update(additional_cpu_quota_micros=6000000),
                       lambda a:a[0].update(all_reservation_ending_bytes=1),
                       lambda a:a[1]["current_storage"].update(remaining_archive_growth_bytes=1)]:
            args=self.inputs()
            mutate(args)
            with self.assertRaises(ValueError): capacity.calculate(*args)

    def test_armed_floor_and_memory_survive_second_fit(self):
        fit=capacity.calculate(*self.inputs())
        armed=capacity.select(fit)
        fit["base_protected_floor_bytes"]=armed+1
        with self.assertRaisesRegex(ValueError,"moved"): capacity.select(fit,armed)
        fit=capacity.calculate(*self.inputs())
        fit["available_memory_bytes"]=fit["required_available_memory_bytes"]-1
        with self.assertRaisesRegex(ValueError,"memory"): capacity.select(fit)


class GuardTests(unittest.TestCase):
    iid="1234567890abcdef1234567890abcdef"
    def sample(self):
        plan=profile.guard_plan(self.iid,8515329790544)
        actor={"InvocationID":self.iid,"MainPID":"123"}
        s={"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan_sha256":"a"*64,
           "guard_sha256":profile.GUARD_SHA,"guard_invocation_id":"b"*32,"producer_invocation_id":self.iid,
           "producer":{"pid":123,"invocation_id":self.iid,"cgroup":"/system.slice/"+profile.UNIT,
                       "restarts":0,"active":"active","sub":"running"},"producer_stop_enabled":True,
           "trip_reason":None,"worker_observation_error":None,"root_physical_observation_error":None,
           "bounded_measurement":False,"r2_mutations":False,"remote_mutations":False,"native_main":None,
           "maximum_worker_vmas":profile.VMA,"minimum_free_bytes":plan["minimum_free_bytes"],
           "available_bytes":plan["minimum_free_bytes"]+100,"maximum_root_physical_bytes":profile.CAP,
           "root_physical_observation":{"maximum_physical_bytes":profile.CAP,
                                      "conservative_physical_bytes":200,"exceeds_budget":False},"workers":[]}
        return actor,plan,s

    def test_held_and_real_worker_are_separate(self):
        actor,plan,s=self.sample()
        session.verify_sample(s,actor,plan,"a"*64)
        with self.assertRaises(ValueError): session.verify_sample(s,actor,plan,"a"*64,True)
        s["workers"]=[[456,40]]
        session.verify_sample(s,actor,plan,"a"*64,True)
        with self.assertRaises(ValueError): session.verify_sample(s,actor,plan,"a"*64)

    def test_foreign_oversize_or_nonprotective_guard_rejected(self):
        for change in [dict(producer_stop_enabled=False),dict(plan_sha256="b"*64),
                       dict(producer_invocation_id="0"*32),dict(trip_reason="worker-vma-ceiling"),
                       dict(minimum_free_bytes=1),dict(maximum_root_physical_bytes=profile.CAP+1),
                       dict(worker_observation_error="no worker custody")]:
            actor,plan,s=self.sample()
            s.update(change)
            with self.assertRaises(ValueError): session.verify_sample(s,actor,plan,"a"*64)

    def test_next_observer_cannot_claim_a_different_producer(self):
        ref={"path":"/fixture/admission","sha256":"2"*64}
        fleet_ref={"path":"/fixture/fleet","sha256":"3"*64}
        status={"path":"/fixture/status","sha256":"4"*64}
        actor={"InvocationID":self.iid,"MainPID":"123","ActiveState":"active"}
        ad={"producer_invocation_id":self.iid,"producer_pid":123,"start_ticks":99}
        body={"epoch":172,"phase":"bootstrap"}
        f={"recorded_unix_seconds":100,"actual_executing_replays":[],"actual_active_bootstraps":[
            {"epoch":172,"admission":ref,"unit":{"Id":profile.UNIT,"InvocationID":self.iid},"phase":"bootstrap"}],
           "epochs":[{"epoch":172,"current_authenticated_status_receipt":status,"current_status":body}]}
        receipt={"epoch":172,"authenticated_readback":True,"after_status":body,"producer_invocation_id":self.iid}
        def fixture(r):
            return {ref["path"]:ad,fleet_ref["path"]:f,status["path"]:receipt}[r["path"]]
        with patch.object(session,"native",return_value=actor),patch.object(session,"ticks",return_value=99),\
             patch.object(session,"bound",side_effect=fixture),patch.object(session.time,"time",return_value=125):
            self.assertEqual(session.confirm_adoption(ref,fleet_ref)["phase"],"bootstrap")
            receipt["producer_invocation_id"]="a"*32
            with self.assertRaisesRegex(ValueError,"status differs"):session.confirm_adoption(ref,fleet_ref)


if __name__=="__main__":
    unittest.main()
