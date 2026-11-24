"""Exercise the 145 self-probe, six original leases and successor registration offline."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
from unittest import TestCase, main
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("incident-phase.py")
UNIT = "horizon-holding-export145-20261121-v1.service"
GROUP = "0::/system.slice/" + UNIT
V5O_IID = "f3474dfad55f4a05a64431421881db29"
V5O_TERMINAL = "epoch145-semantic-continuity-20261121-v1/f3474dfa-stopped-status-owner-20261123/TERMINAL.json"


class Status:
    @staticmethod
    def need(valid, reason):
        if not valid:
            raise ValueError(reason)

    @staticmethod
    def read(path, expected=None):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        Status.need(expected is None or expected == digest, "different fixture digest")
        return json.loads(raw), dict(path=str(path), sha256=digest)

    @staticmethod
    def process(pid):
        return (0 if pid == 10 else 10, pid + 100, GROUP)

    @staticmethod
    def iid(value):
        return len(value) == 32 and int(value, 16) != 0

    same_file = staticmethod(os.path.samefile)


class StatusOwnerFixture(Status):
    @staticmethod
    def read(path, expected=None):
        # The synthetic state directory links to the real read-only stopped record.
        return Status.read(path.resolve() if path.parent.name == V5O_IID else path, expected)


class HomefloorPhase(TestCase):
    version = "tools-v5g"
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR", "/home/sol/.jetstreamer-private"))
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        pkg = root / self.version
        pkg.mkdir()
        (pkg / SCRIPT.name).write_bytes(SCRIPT.read_bytes())
        self.reader = runpy.run_path(str(pkg / SCRIPT.name))["inspect"]
        self.status = StatusOwnerFixture if self.version == "tools-v5p" else Status
        g = self.reader.__globals__
        self.assertTrue(g["HOMEFLOOR_REJOIN"])
        self.generation = "1" * 32
        image = pkg / "export145"
        image.write_bytes(b"offline fixture")
        self.sha = hashlib.sha256(image.read_bytes()).hexdigest()
        self.provider = g["BASE"] / "incident-replay-fit-20261121-v1" / g["HOMEFLOOR_PROVIDER"] / "post-stop-fit"
        self.fleet = g["BASE"] / "root214757-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"

        def record(p, value):
            p.write_text(json.dumps(value))
            return Status.read(p)[1]

        meta = dict(verifier_sha256=self.sha)
        if g["LEASE_START"]:
            iid = "f2afc696a63a4e6aa6812451cf3559e5"
            state = root / "state"
            state.mkdir()
            (state / iid).symlink_to(g["STATE"] / iid, target_is_directory=True)
            meta["startup_failure"] = Status.read(state / iid / "failed.json")[1]
            meta["child_lease_readiness_protocol"] = "self-stop-after-three-leases"
            if g["MISSED_CLOCK"]:
                prior = "ff597d64ad37400ea5c6836336fb6706"
                (state / prior).symlink_to(g["STATE"] / prior, target_is_directory=True)
                meta["missed_clock_failure"] = Status.read(state / prior / "failed.json")[1]
                meta["previous_recovery"] = Status.read(state / prior / "recovery-started.json")[1]
                if g["GUARD_WALK"]:
                    meta["previous_missed_recovery"] = meta["previous_recovery"]
                    prior = "dba04d40f1b046b4875d7e27e0ff224a"
                    (state / prior).symlink_to(g["STATE"] / prior, target_is_directory=True)
                    meta["guard_walk_failure"] = Status.read(state / prior / "failed.json")[1]
                    meta["previous_recovery"] = Status.read(state / prior / "recovery-started.json")[1]
                    meta["rejected_guard"] = {"sha256":"6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"}
                    meta["registered_guard_clock"] = {"sha256":"119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"}
                    if g["DONOR_PRESSURE"]:
                        prior = "f86e7e61f4b34dc7aedc4e08a128e713"
                        (state / prior).symlink_to(g["STATE"] / prior, target_is_directory=True)
                        meta["donor_pressure_failure"] = Status.read(state / prior / "failed.json")[1]
                        meta["donor_pressure_recovery"] = Status.read(state / prior / "recovery-started.json")[1]
        if g["STATUS_OWNER_RECOVERY"]:
            (state / V5O_IID).symlink_to(g["STATE"] / V5O_IID, target_is_directory=True)
            terminal, meta["status_owner_terminal"] = Status.read(g["BASE"] / V5O_TERMINAL)
            meta.update(status_owner_failure=terminal["failure"], status_owner_recovery=terminal["startup"],
                        resumed_status=dict(invocation_id="d6d40746a4974ca186acd7f2d5a5cac4"))
        build = record(pkg / "build-proof.json", meta)
        seal = record(pkg / "deployment-seal-receipt.json",
                      dict(destination=str(pkg), members=[dict(name="export145", sha256=self.sha),
                           dict(name="build-proof.json", sha256=build["sha256"])]))
        self.profile = dict(seal_sha256=seal["sha256"], build_sha256=build["sha256"], image_sha256=self.sha)
        state = root / "state"
        self.session = state / self.generation
        self.session.mkdir(parents=True)
        prior = g["STATE"] / g["OLD"]
        (state / g["OLD"]).symlink_to(prior, target_is_directory=True)
        self.old = Status.read(state / g["OLD"] / "failed.json", g["OLD_FAILURE"])[1]
        self.proc = root / "proc"
        self.parent = self.proc / "10"
        self.worker = self.proc / "20"
        for proc in (self.parent, self.worker):
            proc.mkdir(parents=True)
            (proc / "exe").symlink_to(image)
            (proc / "environ").write_bytes(b"INVOCATION_ID=" + self.generation.encode() + b"\0")
        for sub in ("fd", "fdinfo"):
            (self.parent / sub).mkdir()
        (self.parent / "fd/7").symlink_to(g["LOCK"])
        (self.parent / "fdinfo/7").write_text("lock: 1: FLOCK ADVISORY WRITE 10 fc:00:95818311 0 EOF\n")
        def proc_path(*parts):
            path = Path(*parts)
            return self.proc / path.relative_to("/proc") if path.is_relative_to("/proc") else path

        self.argv = {10: [str(image),"recover-full-output",str(self.fleet),Status.read(self.fleet)[1]["sha256"],self.sha],
                     20: [str(image),"recover-worker","10",self.sha]}
        g.update(PKG=pkg, IMAGE=image, STATE=state, Path=proc_path, argv=self.argv.__getitem__)
        self.manager = dict(MainPID="10", InvocationID=self.generation, Id=UNIT, ControlGroup=GROUP[3:],
                            ActiveState="active", SubState="running", Job="", NRestarts="0", ControlPID="0",
                            CPUQuotaPerSecUSec="1s", MemoryMax=str(2 << 30), MemorySwapMax="0")
        self.started = dict(iid=self.generation, image=self.sha, file=str(g["OUTPUT"]), r2_mutations=False,
                            fresh_fit=dict(schema="horizon-incident-replay-fit-v1", epoch=145, fits=True,
                                phase145=dict(invocation_id=self.generation, stage="controller",
                                   window=dict(native_parent=dict(pid=10,start_ticks=110),failed_predecessor=self.old)),
                                provider_seal=dict(path=str(self.provider.with_name("deployment-seal-receipt.json")))),
                            prior_frozen_recovery=dict(failed_retry1=dict(current_boot_failure=dict(failure=self.old))))
        if g["STATUS_OWNER_RECOVERY"]:
            self.started["fresh_fit"]["phase145"]["window"].update(
                {key:value for key,value in meta.items() if key.startswith("status_owner_")})
            self.started["fresh_fit"]["status_registration"] = meta["resumed_status"]
        self.write = lambda: record(self.session / "recovery-started.json", self.started)

    def inspect(self, members):
        # Only the kernel self-probe is replaced. All phase and original inode checks use production code.
        return self.reader(self.status, lambda pid, obj: {str(k[1]):pid for k in obj}, self.manager,
                           members, 145, self.provider, self.profile)

    def test_bootstrap_and_leased_worker(self):
        with patch.dict(self.reader.__globals__, own_probe=lambda *args:(10,)):
            with patch("os.getpid", return_value=30):
                boot = self.inspect((10,30))
                self.assertEqual(boot["stage"], "controller")
        self.write()
        active = self.inspect((10,20))
        self.assertEqual(active["stage"], "leased-worker")
        for k in ("leases_parent","leases_worker"):
            self.assertEqual(set(active["window"][k]), {"100214429","100214450","103237059"})

    def test_does_not_admit_another_predecessor_probe_or_topology(self):
        self.write()
        with self.assertRaises(ValueError):
            self.inspect((10,))
        with self.assertRaises(ValueError):
            self.inspect((10,20,30))
        seal = self.started["fresh_fit"]["provider_seal"]
        old_path = seal["path"]
        seal["path"] = str(self.provider.parent.parent / "tools-v20/deployment-seal-receipt.json")
        self.write()
        with self.assertRaisesRegex(ValueError, "foreign 145 pre-worker"):
            self.inspect((10,20))
        seal["path"] = old_path
        self.started["fresh_fit"]["phase145"]["invocation_id"] = "2" * 32
        self.write()
        with self.assertRaisesRegex(ValueError,"foreign 145 pre-worker"):
            self.inspect((10,20))
        self.started["fresh_fit"]["phase145"]["invocation_id"] = self.generation
        self.started["prior_frozen_recovery"]["failed_retry1"]["current_boot_failure"]["failure"] = {}
        self.write()
        with self.assertRaisesRegex(ValueError,"left its native frozen"):
            self.inspect((10,20))


class FiveLanePhase(HomefloorPhase):
    version = "tools-v5h"

    def test_new_provider_is_required(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-rejoin-v2")


class Retry3Phase(HomefloorPhase):
    version = "tools-v5i"

    def test_retry3_provider_is_required(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-rejoin-v3")


class Retry4Phase(HomefloorPhase):
    version = "tools-v5j"

    def test_retry4_provider_is_required(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-rejoin-v4")


class LeaseReadyPhase(HomefloorPhase):
    version = "tools-v5k"

    def test_current_lease_failure_is_required(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-lease-rejoin-v1")
        self.write()
        v = self.inspect((10,20))
        self.assertEqual(v["window"]["startup_failure"]["sha256"],
                         "eff2c5c0da6cb103890f6ced5cb11920959f637234567d7fd2382a2fca2fbcc7")


class MissedClockPhase(HomefloorPhase):
    version = "tools-v5m"

    def test_separate_provider_and_both_failures(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-missed-rejoin-v1")
        self.write()
        v = self.inspect((10,20))
        self.assertEqual(v["window"]["startup_failure"]["sha256"],
                         "eff2c5c0da6cb103890f6ced5cb11920959f637234567d7fd2382a2fca2fbcc7")
        self.assertEqual(v["window"]["missed_clock_failure"]["sha256"],
                         "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6")
        original_read = Status.read
        def wrong_history(path, expected=None):
            data, ref = original_read(path, expected)
            if path.name == "build-proof.json":
                data["missed_clock_failure"] = data["startup_failure"]
            return data, ref
        with patch.object(Status, "read", side_effect=wrong_history):
            with self.assertRaisesRegex(ValueError,"unqualified retry of the missed fleet census"):
                self.inspect((10,20))


class GuardWalkPhase(HomefloorPhase):
    version = "tools-v5n"

    def test_guard_evidence_is_bound_to_original_failure_and_registered_clock(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-guard-walk-rejoin-v1")
        self.write()
        self.assertEqual(self.inspect((10,20))["window"]["guard_walk_failure"]["sha256"],
                         "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010")
        original = Status.read
        for key in ("registered_guard_clock","rejected_guard","guard_walk_failure","previous_recovery"):
            def wrong(path, expected=None):
                data, ref = original(path, expected)
                if path.name == "build-proof.json":
                    data[key] = {"sha256":"0"*64}
                return data, ref
            with self.subTest(field=key), patch.object(Status,"read",side_effect=wrong), self.assertRaises(ValueError):
                self.inspect((10,20))


class DonorPressurePhase(HomefloorPhase):
    version = "tools-v5o"

    def test_binds_the_v5n_failure_and_recovery(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-donor-pressure-rejoin-v1")
        self.write()
        window = self.inspect((10, 20))["window"]
        self.assertEqual(window["donor_pressure_failure"]["sha256"],
                         "553c2d9be55bf4688dd1c8b42bc497ba2f6ea985305e42b7fb7db951f400bd36")
        self.assertEqual(window["donor_pressure_recovery"]["sha256"],
                         "dad6a11f67b7717668c0189c607142ac89a64fc7fde8971b28b4e3c8622619ed")
        original = Status.read
        for key in ("donor_pressure_failure", "donor_pressure_recovery"):
            def wrong(path, expected=None):
                data, ref = original(path, expected)
                if path.name == "build-proof.json":
                    data[key] = {"sha256": "0" * 64}
                return data, ref

            with self.subTest(field=key), patch.object(Status, "read", side_effect=wrong):
                with self.assertRaisesRegex(ValueError, "unqualified retry of the V5n donor pressure failure"):
                    self.inspect((10, 20))


class StatusOwnerPhase(HomefloorPhase):
    version = "tools-v5p"

    def test_binds_v5o_stop_and_preworker_admission(self):
        self.assertEqual(self.provider.parent.name, "tools-homefloor-145-status-owner-rejoin-v1")
        self.write()
        window = self.inspect((10,20))["window"]
        self.assertEqual(window["status_owner_terminal"]["sha256"],
                         "95fc24c89db925ca86fa1f918a6f61e665d3c124a7e4687ecf8ee44816b01f6f")
        for key in ("status_owner_failure", "status_owner_recovery", "status_owner_terminal"):
            original = Status.read
            def wrong(path, expected=None):
                data, ref = original(path, expected)
                if path.name == "build-proof.json":
                    data[key] = {}
                return data, ref
            with self.subTest(key=key), patch.object(Status, "read", side_effect=wrong):
                with self.assertRaisesRegex(ValueError, "unqualified retry of the V5o status-owner failure"):
                    self.inspect((10,20))

    def test_rejects_preworker_price_from_the_predecessor_status_writer(self):
        self.started["fresh_fit"]["status_registration"] = dict(
            invocation_id="e83c7741fbb843029b110f1369e973a4")
        self.write()
        with self.assertRaisesRegex(ValueError, "foreign status-owner pre-worker admission"):
            self.inspect((10,20))


class EncodedPrefixStop(TestCase):
    def test_provider_binds_the_original_stop_to_the_current_native_successor(self):
        with tempfile.TemporaryDirectory(dir="/home/sol/.jetstreamer-private") as directory:
            base = Path(directory)
            package = base / "tools-v5r"
            package.mkdir()
            adapter = package / SCRIPT.name
            adapter.write_bytes(SCRIPT.read_bytes())
            validate = runpy.run_path(str(adapter))["encoded_prefix_stop"]
            validate.__globals__.update(BASE=base, PKG=package)
            handoff = base / "v5r-name-handoff"
            handoff.mkdir()
            receipt = handoff / "PREDECESSOR_STOP.json"
            original = "cbacb5a17e6347509640846eccb95cb0"
            successor = "a" * 32
            records = dict(stop_started={"cursor": "one"}, deactivated={"cursor": "two"},
                           stop_finished={"cursor": "three"})
            stopped = dict(schema="horizon-manager-explicit-stop-witness-v1", unit=UNIT,
                           invocation_id=original, boot_id="b" * 32,
                           not_before_monotonic_usec=100, records=records,
                           worker_launch_authorized=False)
            receipt.write_text(json.dumps(stopped))
            inspector = base / "epoch145-explicit-stop-inspector-20261124-v2/tools/follow145"
            inspector.parent.mkdir(parents=True)
            inspector.write_bytes(b"stop inspector test fixture")
            inspector.chmod(0o555)
            seal = inspector.with_name("deployment-seal-receipt.json")
            seal.write_text(json.dumps(dict(destination=str(inspector.parent), remote_mutations=False,
                members=[dict(name="follow145", mode="0555",
                              sha256=hashlib.sha256(inspector.read_bytes()).hexdigest())])))
            build = dict(stop_inspector_seal_sha256=Status.read(seal)[1]["sha256"])
            witness = dict(stopped, schema="horizon-manager-explicit-successor-witness-v1",
                           successor_invocation_id=successor)
            with patch("subprocess.check_output", return_value=json.dumps(witness)) as observe:
                self.assertEqual(validate(Status, build, successor), Status.read(receipt)[1])
                observe.assert_called_once_with(
                    [str(inspector), "inspect-native-stop", original, "100", successor], timeout=15)
            crossed = dict(witness, successor_invocation_id="c" * 32)
            with patch("subprocess.check_output", return_value=json.dumps(crossed)):
                with self.assertRaisesRegex(ValueError, "does not follow the recorded native stop"):
                    validate(Status, build, successor)
            receipt.write_text(json.dumps(dict(stopped, records={})))
            with patch("subprocess.check_output") as observe:
                with self.assertRaisesRegex(ValueError, "different encoded-prefix predecessor stop"):
                    validate(Status, build, successor)
                observe.assert_not_called()


if __name__ == "__main__":
    main()
