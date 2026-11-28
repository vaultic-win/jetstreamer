"""Exercise the ordinary writer paths using retained Anza evidence and disposable modules."""
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))
import after_ram170_scope as preparation
import after_ram170_drain as drain
import derive_after_ram170_writer as derive

RT = preparation.prep.ROOT
WRITER = RT / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v62-entry146"
EVIDENCE = RT / "prefix140-status-cadence-20261122-v1/cadence-tools"
FLEET = {"path":str(RT / "root071808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
         "sha256":"a6036483b6409ebeed6323920f6f0ef24c5fcdaa716937639d7d198b0b09379d"}
scratch_root = Path("/home/sol/.jetstreamer-private")


@unittest.skipUnless(os.access(FLEET["path"],os.R_OK), "requires the retained private Anza fixture")
class Successor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = preparation.document()
        digest = sha256((json.dumps(cls.scope, indent=2)+"\n").encode()).hexdigest()
        scope_ref = dict(path=str(preparation.SCOPE_PATH), sha256=digest)
        cls.stage = TemporaryDirectory(dir=scratch_root, prefix="after170-source-fixture-")
        cls.addClassCleanup(cls.stage.cleanup)
        path = Path(cls.stage.name)
        for name, data in derive.members(WRITER, scope_ref).items():
            (path / name).write_bytes(data)
        original_path = sys.path[:]
        sys.path[:0] = [str(path),str(WRITER),str(EVIDENCE)]
        cls.addClassCleanup(lambda: sys.path.__setitem__(slice(None),original_path))
        import after_ram170_status
        import after_ram170_history
        cls.status, cls.history = after_ram170_status, after_ram170_history
        cls.contract = cls.status.contract
        cls.fleet = preparation.prep.read(FLEET)
        cls.config = preparation.prep.read(cls.fleet["sole_next_observer"])
        initial = cls.contract.checked
        delegate = patch.object(cls.contract, "checked", side_effect=lambda ref, **kw:
                                cls.scope if ref == scope_ref else initial(ref, **kw))
        delegate.start()
        cls.addClassCleanup(delegate.stop)

    def test_staged_inputs_and_actual_previous_owner(self):
        self.assertEqual(self.contract.interface(), self.scope)
        actual = self.contract.previous_owner(self.fleet)
        self.assertEqual(actual["phase"],"worker")
        self.assertEqual(actual["actor"]["producer_invocation_id"],self.contract.IID)
        fleet = deepcopy(self.fleet)
        fleet["current_private170_third_ram_gap"]["release"] = self.status.old.interface()["old_release"]
        with self.assertRaisesRegex(ValueError,"different preceding RAM producer"):
            self.contract.previous_owner(fleet)

    def test_normal_population_preserves_running_ram_assignment(self):
        self.assertIsNone(self.status.retained_population(self.fleet,self.config))
        self.assertIs(self.status.history_config(self.fleet,self.config),self.config)
        invalid = deepcopy(self.config)
        invalid["diagnostic_replays"].append(dict(self.config["diagnostic_replays"][-1],range="170",
                                                   producer_unit="foreign.service"))
        with self.assertRaisesRegex(ValueError,"foreign private"):
            self.status.retained_population(self.fleet,invalid)

    def test_an_unreleased_or_failed_predecessor_cannot_issue(self):
        actor = Path(self.stage.name) / "after_ram170_native.py"
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.status.following,"ACTOR",actor))
            attempt = stack.enter_context(patch.object(self.status.following,"observe"))
            for state, event in (("worker",self.status.following.SUCCESS),("terminal",self.status.following.FAILURE)):
                owner = dict(phase=state, native_terminal=dict(INVOCATION_ID=self.contract.IID,MESSAGE_ID=event))
                ctx = type("Context",(),dict(fleet=self.fleet,third_ram_gap170=owner))()
                with self.assertRaisesRegex(ValueError,"active or failed"):
                    self.status.observe(ctx,None,None)
            attempt.assert_not_called()

    def test_registration_requires_actual_checkpoint_and_drained_guard(self):
        missing = Path(self.stage.name) / "no-clean-comparison"
        with self.assertRaises(FileNotFoundError):
            self.contract.closed_comparison(dict(self.scope,closed_comparison=str(missing)))
        with patch.object(self.status.following,"ACTOR",missing), patch.object(self.status.old.native,"idle") as idle:
            self.status.legacy_idle()
            idle.assert_called_once_with(self.status.UNIT)
        with patch.object(self.status.old,"ACTOR",Path(self.stage.name)/"after_ram170_contract.py"), \
             patch.object(self.status.following,"ACTOR",Path(self.stage.name)/"after_ram170_native.py"):
            with self.assertRaisesRegex(ValueError,"old fourth-window contract"):
                self.status.legacy_idle()

    def test_new_config_only_removes_the_exact_successor(self):
        row = {"observer_config": {"range":"170","producer_unit":self.status.UNIT}}
        other = {"range":"162","producer_unit":"peer.service"}
        cfg = {"diagnostic_replays":[other,row["observer_config"]]}
        with patch.object(self.status,"retained_population", return_value=row):
            self.assertEqual(self.status.history_config({},cfg),{"diagnostic_replays":[other]})
            self.assertEqual(len(cfg["diagnostic_replays"]),2)

    def test_enrollment_uses_the_actual_ram_comparison_before_release(self):
        native = self.status.following
        head, writer = {"test":"head"}, {"test":"writer"}
        actor_ref, actor = {"test":"actor"}, {"producer_invocation_id":"1"*32}
        comparison = {"test":"closed"}
        plan_ref = {"test":"plan"}
        docs = {"head":self.fleet, "writer":{"ready":{"test":"ready"}},
                "ready":{"after_ram170_interface":self.status.INTERFACE,
                         "third_ram_gap170_interface":self.scope["prior_ram_interface"]},
                "plan":{"invocation_id":actor["producer_invocation_id"],"unit":self.status.UNIT,
                        "receipt_directory":self.scope["guard_receipts"]}}
        isolated = Path(self.stage.name)/"absent"
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.status,"checked",side_effect=lambda r:docs[r["test"]]))
            stack.enter_context(patch.object(self.status,"bound",return_value=plan_ref))
            stack.enter_context(patch.object(self.contract,"closed_comparison",return_value=comparison))
            stack.enter_context(patch.object(self.contract,"interface",return_value=dict(self.scope,barrier=str(isolated))))
            stack.enter_context(patch.object(native.native,"idle"))
            stack.enter_context(patch.object(native,"read_actor",return_value=(actor_ref,actor)))
            stack.enter_context(patch.object(native.native,"props",return_value=dict(
                Id=native.GUARD_TIMER, ActiveState="active",InvocationID="2"*32)))
            for module, names in ((self.status.old,("ACTOR","RELEASE","ENROLLMENT")), (native,("RELEASE","ENROLLMENT"))):
                for name in names: stack.enter_context(patch.object(module,name,isolated))
            guard = stack.enter_context(patch.object(native,"guard",return_value=({},False)))
            enroll = stack.enter_context(patch.object(native,"enroll",return_value={"test":"enrolled"}))
            self.assertEqual(self.status.enroll({},head,writer),{"test":"enrolled"})
            enroll.assert_called_once_with({},head,writer)
            guard.return_value = ({},True)
            with self.assertRaisesRegex(ValueError,"already released"):
                self.status.enroll({},head,writer)
            self.assertEqual(enroll.call_count,1)

    def test_cycle_keeps_the_old_and_new_enrollment_routes(self):
        source = (WRITER / "status_cycle.py").read_text()
        result = derive.cycle(source,63)
        self.assertIn("after_ram170_history as successor170_status",result)
        self.assertEqual(result.count(derive.ENROLL_OPTION),1)
        self.assertEqual(result.count("ram170_third_status.enroll("),source.count("ram170_third_status.enroll("))
        self.assertIn("ram170_third_status.install(fleet,c.third_ram_gap170)",result)
        self.assertIn("after_ram170_status.install(fleet,c.after_ram170)",result)

    def test_guard_drain_rejects_a_reused_timer_before_stop(self):
        ref = self.scope["old_release"]
        grant = preparation.prep.read(ref)
        scope = preparation.prep.read(grant["interface"])
        fixture = dict(Id=drain.TIMER, Job="", ActiveState="active",SubState="waiting",
                       InvocationID="f"*32, Triggers=drain.GUARD)
        guard = dict(Id=drain.GUARD, Job="", TriggeredBy=drain.TIMER, ExecStart="", Restart="no",
                     MemoryMax=str(1 << 30), MemorySwapMax="0",CPUQuotaPerSecUSec="1s")
        with patch.object(drain,"idle_service"), patch.object(drain,"properties",side_effect=[fixture,guard]):
            with self.assertRaisesRegex(ValueError,"different RAM guard"):
                drain.timer(scope,grant)


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        scratch_root = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
