from copy import deepcopy
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import second162_peer as s


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


class Second162Tests(TestCase):
    def setUp(self):
        self.peer = {"need": need}
        self.iid = "1234567890abcdef"*2
        self.unit = {"Id":s.UNIT, "InvocationID":self.iid}
        self.actor = {"producer_unit":s.UNIT, "producer_invocation_id":self.iid}
        self.current = dict(epoch=162, phase="worker", unit=self.unit, actor=self.actor,
                            producer_invocation_id=self.iid, held_owner={"sha256":"held"},
                            archive_publication_authorized=False, canonical_replay_claimed=False, resource_credit_bytes=0)
        self.other = {"epoch":167}
        self.fleet = {s.FIELD:self.current, "actual_active_private_diagnostics":[self.other,self.current],
                     "actual_active_bootstraps":[], "actual_executing_replays":[]}
        self.peer["read"] = lambda path: (self.actor, self.current["held_owner"])

    def test_only_hides_exact_successor_in_first_read(self):
        saved = deepcopy(self.fleet)
        first = s.predecessor_view(self.peer, self.fleet)
        self.assertEqual(first["actual_active_private_diagnostics"], [self.other])
        self.assertEqual(self.fleet, saved)
        self.assertEqual(first[s.FIELD], self.current)
        for key, value in [("phase","terminal"), ("held_owner",{"sha256":"other"}),
                           ("unit", {"Id":"wrong","InvocationID":self.iid}),
                           ("archive_publication_authorized",True)]:
            bad = deepcopy(self.fleet)
            bad[s.FIELD][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.predecessor_view(self.peer, bad)
        duplicate = dict(self.fleet, actual_active_private_diagnostics=[self.current,self.current])
        with self.assertRaises(ValueError):
            s.predecessor_view(self.peer, duplicate)

    def test_registration_before_guard_and_through_terminal(self):
        others = dict(self.fleet, actual_active_private_diagnostics=[self.other])
        self.assertIs(s.predecessor_view(self.peer, others), others)
        package = {"operator":"signed"}
        root = Path("/run/test")
        reader = dict(path=str(root/"second162_status.py"), sha256=s.READER["sha256"])
        ready = dict(second162_reader=reader, second162_provider=s.PROVIDER,
                     package={"path":str(root/"deployment-seal-receipt.json")})
        self.peer["bound"] = lambda ref: {"ready":"ready","new":{"program":str(root/"writer.py")}} if ref == package else ready
        self.peer["read"] = lambda path: (s.PROVIDER,{})
        self.peer["frozen"] = lambda path, ref: need(ref == reader and path == reader["path"], "foreign reader")
        self.assertTrue(s.registered_writer(self.peer, package))
        ready["second162_reader"] = dict(reader, sha256="wrong")
        with self.assertRaises(ValueError):
            s.registered_writer(self.peer, package)

    def quote(self):
        base = dict(available_home=90*s.G, ram_margin=-s.G, home_margin=14*s.G, fits=False)
        final = dict(required_home=80*s.G, guard_floor=65*s.G, home_margin=10*s.G,
                     ram_margin=-s.G, fits=False, realized_162_ram=0,
                     frozen_first_162_image=dict(prospective_materialization_bytes=1854349312),
                     prospective_162_interval_two=dict(additional_output=s.OUTPUT, additional_control=s.CONTROL,
                         additional_home=s.OUTPUT+s.CONTROL, additional_compute=0, retained_first_image_allowance=0))
        return base, final

    def observed(self, phase, resident=0, remaining=s.OUTPUT, floor=0):
        owner = None if phase == "precharged" else dict(phase=phase, unit=self.unit, invocation_id=self.iid,
                                                        actor={"sha256":"held"}, release=None)
        return dict(enrolled=True, phase=phase, owner=owner, floor=floor, resident=resident, remaining=remaining)

    def test_precharged_held_and_terminal_use_one_reservation(self):
        for phase in ("precharged","held","terminal"):
            with self.subTest(phase=phase):
                base, final = self.quote()
                remaining = s.OUTPUT - 128*1024**2 if phase=="held" else s.OUTPUT
                sample = self.observed(phase, remaining=remaining)
                s.apply(need,base,final,sample,sample)
                self.assertEqual(final["required_home"],80*s.G-s.OUTPUT+remaining)
                self.assertEqual(final["ram_margin"],-s.G)
                self.assertFalse(final["fits"])
                self.assertEqual(final["prospective_162_interval_two"]["additional_home"],s.OUTPUT+s.CONTROL)
                if phase == "precharged":
                    self.assertIsNone(final["second_162_actor"])
                else:
                    self.assertEqual(final["second_162_actor"],dict(phase=phase,unit=self.unit,
                                     held_owner={"sha256":"held"},producer_invocation_id=self.iid))

    def test_caps_residency_at_both_samples_and_preserves_higher_floor(self):
        base, final = self.quote()
        left = self.observed("worker", resident=3*s.G, remaining=2*s.G, floor=82*s.G)
        right = dict(left,resident=2*s.G,remaining=s.G)
        s.apply(need,base,final,left,right)
        self.assertTrue(final["fits"])
        self.assertEqual(final["required_home"],84*s.G)
        self.assertEqual(final["guard_floor"],82*s.G)
        self.assertEqual(final["ram_margin"],s.G)
        self.assertEqual(final["second_162_accounting"]["resident_lower_bytes"],2*s.G)
        with self.assertRaisesRegex(ValueError,"owner or writer"):
            s.apply(need,base,final,left,right)

    def test_rejects_unprotected_credit_changed_actor_floor_or_output(self):
        base, original = self.quote()
        worker = self.observed("worker",resident=s.G)
        for left,right in [(self.observed("held",resident=s.G),self.observed("held",resident=s.G)),
                           (worker,dict(worker,owner={})),(worker,dict(worker,floor=s.G)),
                           (worker,dict(worker,enrolled=False)),
                           (self.observed("terminal", remaining=0),self.observed("terminal", remaining=0))]:
            with self.subTest(left=left,right=right), self.assertRaises(ValueError):
                s.apply(need,base,deepcopy(original),left,right)

    def test_an_unrelated_home_shortfall_still_refuses(self):
        base, final = self.quote()
        base["home_margin"] = -1
        sample = self.observed("worker",resident=2*s.G)
        s.apply(need,base,final,sample,sample)
        self.assertFalse(final["fits"])

    def test_capture_pins_lease_and_native_guard_for_each_phase(self):
        from types import SimpleNamespace

        plan = dict(producer_memory_max=62*s.G, guard_memory_max=s.G, combined_ram=63*s.G,
                    home_image=s.OUTPUT, control=s.CONTROL, swap_bytes=0)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        donor = {"sha256":"donor"}
        enrolled = {"sha256":"enroll"}
        lease_ref = {"sha256":"lease"}
        pre_ref = {"sha256":"pre"}
        intent_ref = {"sha256":"intent"}
        guard_ref = {"sha256":"guard"}
        tree = s.ROOT/"split-v1"
        self.peer["DONOR"] = donor
        operator = {"operator":s.PROVIDER,"donor":donor,"whole_roster":{"sha256":"v12"}}
        original = dict(unit=s.UNIT,profile=plan,prestart=pre_ref,lease=lease_ref,canonical_publication_authorized=False)
        lease = dict(unit=s.UNIT,profile=plan,prestart=pre_ref,owner_enrollment=enrolled,donor=donor,boot_id=boot)
        previous = dict(unit=s.UNIT,profile=plan,enrollment=enrolled,donor=donor,boot_id=boot,
                        exclusive_166_lease=True,fits=True,phase="prestart",held_invocation=None,
                        whole_roster={"package":operator["whole_roster"]})
        guard = dict(unit=s.UNIT,invocation_id=self.iid,minimum_free_bytes=80*s.G)
        refs = {s.INTERFACE["sha256"]:dict(field=s.FIELD,producer_unit=s.UNIT,operator=s.PROVIDER,second162_reader=s.READER,
                                         first_slot=69991077,last_slot=69998119),
                s.PROVIDER["sha256"]:dict(destination=str(s.PKG),members=[dict(name="status162.py",sha256=s.READER["sha256"])]),
                "intent":original, "pre":previous, "guard":guard}
        actor = dict(self.actor,intent=intent_ref,guard_plan=guard_ref,boot_id=boot)
        row = dict(self.current,actor=actor,profile=plan,donor=donor,terminal=None,
                   held_owner=dict(path=str(tree/"HELD_OWNER.json")),release=None,worker=None,
                   guard={"sha256":"sample"},mounts={"image":[1,2,3]},disk=dict(floor=80*s.G,maximum=s.OUTPUT,
                   fixed_control=s.CONTROL,remaining=s.OUTPUT-4096))
        layout = SimpleNamespace(profile=lambda g: plan if g==36 else None,BOOT=Path("/proc/sys/kernel/random/boot_id"),DATA=tree)
        api = {"current": lambda fleet:row,"api":lambda:layout,"PKG":s.PKG,"FIELD":s.FIELD}
        self.peer.update(bound=lambda ref:refs[ref["sha256"]], read=lambda path:{
            tree/"LEASE.json":(lease,lease_ref),s.ROOT/"SPLIT162_ENROLLMENT.json":(operator,enrolled)}[path],
            frozen=lambda path, ref:need(ref==s.READER,"different native source"), resident=lambda *_:8*s.G)
        with patch.object(s.runpy,"run_path",return_value=api), patch.object(s,"registered_writer",return_value=True):
            for phase in ("held","bootstrap","worker","terminal"):
                row["phase"] = phase
                row["unit"]["ControlGroup"] = "" if phase=="terminal" else "/system.slice/"+s.UNIT
                row["release"] = None if phase=="held" else {"sha256":"grant"}
                row["worker"] = {"pid":123} if phase=="worker" else None
                row["terminal"] = {"MESSAGE_ID":"exit"} if phase=="terminal" else None
                with self.subTest(phase=phase):
                    snap=s.sample(self.peer,self.fleet,{})
                    self.assertEqual(snap["owner"]["invocation_id"],self.iid)
                    self.assertEqual(snap["owner"]["actor"],row["held_owner"])
                    self.assertEqual(snap["resident"],8*s.G if phase=="worker" else 0)
                    self.assertEqual(snap["remaining"],s.OUTPUT if phase=="terminal" else s.OUTPUT-4096)
            previous["fits"] = False
            with self.assertRaisesRegex(ValueError,"existing loan"):
                s.sample(self.peer,self.fleet,{})
