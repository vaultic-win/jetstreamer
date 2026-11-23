"""Tagged v5j semantic and ordinary local/public qualification fixtures."""
import importlib.util
import hashlib
import json
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

spec = importlib.util.spec_from_file_location("post_inputs", Path(__file__).with_name("post_inputs.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
IID = "f" * 32
UNIT = "horizon-holding-export145-20261121-v1.service"


def fixture():
    leaf = p.ARCHIVE.with_name(".tmp36MvkN")
    view = leaf.parent.parent / "epoch145-prefix-extract-materialized-view-20261121-v1/epoch-145.jet"
    candidate = dict(bytes=105610995833, inode=103237059)
    review = dict(old_manager=dict(Id=UNIT, InvocationID="afcf6cdd1ec0400ea2757f81472987b3"),
                  failed_phase=dict(candidate=candidate), reader=dict(sha256="f" * 64),
                  retained_inputs=[{"path": "/original"}, {}, {"path": str(leaf)}],
                  retained_manifest={"sha256": "a" * 64})
    argv = ["systemd-run", "--", "/v5j", "recover-full-output", "/fleet", "1" * 64, "f" * 64]
    links = [{"path": "166", "sha256": "a" * 64}, {"path": "168", "sha256": "b" * 64}]
    intent = {"original": {"_BOOT_ID": "boot"}, "preflight": {"serial_handback": links}, "argv": argv}
    result = {"invocation_id": IID, "argv": argv, "manager_start_cursor": "original-start"}
    event = dict(UNIT=UNIT, INVOCATION_ID=IID, _PID="1", _BOOT_ID="boot")
    rows = [dict(event, MESSAGE_ID="39f53479d3a045ac8e11786248231fbf", __CURSOR="original-start",
                 __MONOTONIC_TIMESTAMP="1", MESSAGE="Started " + UNIT + " - " + " ".join(argv[2:]) + "."),
            dict(event, MESSAGE_ID=p.SUCCESS, __CURSOR="original-success", __MONOTONIC_TIMESTAMP="2")]
    extraction = dict(schema="jetstreamer-private-epoch145-canonical-prefix-extraction-v1", archive=str(p.ARCHIVE),
                      epoch=145, archive_bytes=105610995833, output_slot_start=62640000, output_slot_count=432000,
                      source_archive="/original", source_archive_sha256="cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353",
                      source_manifest_sha256="a" * 64, worker_sha256="2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
                      source_canonical_checkpoint_slot=63072070, source_canonical_accounts_hash="DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p",
                      retained_verification_tail_slots=71, source_must_be_retained=True, independent_output_reread_passed=True,
                      current_plugin_verification_passed=False, canonical_sidecar_authorized=False, publication_authorized=False,
                      retirement_authorized=False, r2_mutations=False, archive_sha256="3" * 64, output_semantic_sha256="4" * 64,
                      expected_output_provenance_sha256="5" * 64)
    refs = [{"path": tag, "sha256": str(i) * 64} for i, tag in enumerate(["start", "verified", "extract", "complete"], 1)]
    phase = {"invocation_id": IID, "stage": "controller", "window": {"native_parent": {"pid": 123}}}
    start = dict(iid=IID, file=str(leaf), image=review["reader"]["sha256"], r2_mutations=False,
                 fresh_fit=dict(phase145=phase, serial_145_holding_handback=links))
    verified = dict(iid=IID, parent=123, before=candidate, private_projection=str(view), paid_source=str(leaf),
                    original_export=p.ORIGINAL, extraction=dict(extraction, archive=str(view)), r2_mutations=False)
    extract = dict(schema="horizon-epoch145-guarded-private-prefix-completion-v1", actor_iid=IID,
                   verified_frozen=refs[1], recovery_evidence=refs[0], archive_publication_authorized=False,
                   original_export=p.ORIGINAL, extraction=extraction, r2_mutations=False)
    done = dict(iid=IID, receipt=refs[2], recovered_from=p.ORIGINAL, r2_mutations=False)
    return [IID, intent, result, review, rows, list(zip((start, verified, extract, done), refs))]


class PublicationInputs(unittest.TestCase):
    def test_tagged_v5j_semantic_success(self):
        f = fixture()
        accepted = p.validate_terminal(*f)
        self.assertEqual(accepted["invocation_id"], IID)
        self.assertEqual(accepted["completion"], f[-1][-1][1])
        self.assertEqual(accepted["pid1_success"], "original-success")

    def test_reject_v5f_failure_stale_generation(self):
        f = fixture()
        f[0] = f[3]["old_manager"]["InvocationID"]
        with self.assertRaisesRegex(ValueError, "foreign semantic generation"):
            p.validate_terminal(*f)

    def test_reject_interchanged_terminal_boot_cursor_or_failed_pid1(self):
        for index, key, value in ((0, "__CURSOR", "other"), (1, "_BOOT_ID", "other"),
                                  (1, "MESSAGE_ID", "failed"), (1, "_PID", "123")):
            f = fixture()
            f[4][index][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.validate_terminal(*f)

    def test_promoted_archive_requires_exact_links_and_all_slots(self):
        for key, value in (("epoch", 144), ("output_slot_count", 431999), ("source_must_be_retained", False),
                           ("publication_authorized", True), ("source_canonical_checkpoint_slot", 63071999)):
            f = fixture()
            f[5][2][0]["extraction"][key] = value
            f[5][1][0]["extraction"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.validate_terminal(*f)
        f = fixture()
        f[5][3][0]["receipt"] = {"path": "different"}
        with self.assertRaises(ValueError):
            p.validate_terminal(*f)

    def test_reject_replaced_frozen_candidate_or_different_serial_handback(self):
        f = fixture()
        f[5][1][0]["before"] = dict(f[3]["failed_phase"]["candidate"], inode=1)
        with self.assertRaises(ValueError):
            p.validate_terminal(*f)
        f = fixture()
        f[5][0][0]["fresh_fit"]["serial_145_holding_handback"] = []
        with self.assertRaises(ValueError):
            p.validate_terminal(*f)

    def test_deployed_post_adapter_accepts_only_the_selected_v5j(self):
        for version in ("tools-v13d", "tools-v13e", "tools-v13f", "tools-v13g", "tools-v13h", "tools-v13i"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as td:
                self.exercise_adapter(Path(td), version)

    def exercise_adapter(self, root, version):
        guard = version in ("tools-v13h", "tools-v13i")
        missed = guard or version == "tools-v13g"
        lease = missed or version == "tools-v13f"
        retry = lease or version == "tools-v13e"
        pkg = root / "family" / version
        pkg.mkdir(parents=True)
        src = Path(__file__).with_name("incident-post-phase.py")
        deployed = pkg / src.name
        deployed.write_bytes(src.read_bytes())
        complete = runpy.run_path(str(deployed))["completion"]
        state = root / "state"
        name = pkg.parent / ("v5n-name-handoff" if guard else "v5m-name-handoff" if missed else "v5k-name-handoff" if lease else "v5j-name-handoff-retry1" if retry else "v5j-name-handoff")
        name.mkdir()
        original = state / IID
        original.mkdir(parents=True)
        output = root / "output"
        output.mkdir()

        class Status:
            need = staticmethod(p.need)
            iid = staticmethod(lambda v: isinstance(v, str) and len(v) == 32 and all(c in "0123456789abcdef" for c in v))
            @staticmethod
            def read(path, sha=None):
                raw = path.read_bytes()
                actual = hashlib.sha256(raw).hexdigest()
                p.need(sha is None or sha == actual, "foreign receipt")
                return json.loads(raw), {"path": str(path), "sha256": actual}
            @staticmethod
            def bound(ref, path):
                p.need(ref["path"] == str(path), "different path")
                return Status.read(path, ref["sha256"])[0]
        def write(path, val):
            path.write_text(json.dumps(val))
            return Status.read(path)[1]
        f = fixture()
        start, verified, extract, done = [v[0] for v in f[-1]]
        archive = output / "epoch-145.jet"
        extract["extraction"]["archive"] = str(archive)
        fleet = {"path":"/fleet", "sha256":"1"*64}
        image_sha = "f"*64
        if missed:
            image_sha = "9068d5ac9ccd4d35481cbf2882faf67a97b0926133663a2e4885917e714bdc21"
            start["image"] = image_sha
            native = start["fresh_fit"]
            native.update(fits=True, fleet=fleet, epoch159_donor_cover=dict(fleet=fleet, credited_retirement_bytes=0))
            native["phase145"]["window"].update(
                continuity_seal={"sha256":"db422be5b246aa3aef2457fd9325f6b8cca739e3e4c63d2e4794ae30c527f6c4"},
                missed_clock_failure={"sha256":"04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"})
        if guard:
            image_sha = "a"*64
            start["image"] = image_sha
            native["phase145"]["window"].update(continuity_seal={"sha256":"7"*64},
                guard_walk_failure={"sha256":"8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"},
                registered_guard_clock={"sha256":"119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"},
                rejected_guard={"sha256":"6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"})
        sr = write(original / "recovery-started.json", start)
        vr = write(original / "verified-frozen.json", verified)
        extract.update(verified_frozen=vr, recovery_evidence=sr)
        er = write(original / "extraction-complete.json", extract)
        dr = write(original / "complete.json", dict(done, receipt=er))
        proof = {"schema": "horizon-145-v5j-semantic-completion-v1", "start": sr, "completion": dr, "invocation_id": IID}
        receipt = name / "semantic-completion.json"
        write(receipt, proof)
        args = [str(pkg.parent / ("tools-v5n/export145" if guard else "tools-v5m/export145" if missed else "tools-v5k/export145" if lease else "tools-v5j/export145")), "recover-full-output", "/fleet", "1"*64, image_sha]
        write(name / "submission-result.json", dict(invocation_id=IID, argv=args))
        dispatch = {"path": "/sealed-dispatch", "sha256": "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea" if missed else "f69f462cecb76fc586799d36f358e61b1880f99d0c024b0c76dd27d3a2f9637e" if lease else "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee"}
        intent = dict(fleet=fleet, argv=args, original={"INVOCATION_ID": "ff597d64ad37400ea5c6836336fb6706" if missed else "f2afc696a63a4e6aa6812451cf3559e5" if lease else "48ad7b2234d74e74b0498e7110e0aee3"},
                      review_sha256="28540e178ace196165ea892f924001a72b59396708b8269fb3a057a2627b132f" if missed else "1a7f7bce208d97831963c66c462bbac28b7f9b84e990d09fa5da7e5efa56d150" if lease else "38774819c4dbbe1246851585afb57ba65df4919cbf457fb6a04b75ef2e77fc07",
                      preflight={"quote_provider":dispatch})
        if guard:
            dispatch["sha256"]="8"*64
            intent.update(review_sha256="9"*64,original={"INVOCATION_ID":"dba04d40f1b046b4875d7e27e0ff224a"})
        write(name / "submission-intent.json", intent)
        build = {"semantic_image": {"sha256": image_sha}, "semantic_dispatch": dispatch}
        if guard:
            build["guard_walk_binding"] = write(pkg.parent/"V5N_RUNTIME_BINDINGS.json",
                dict(review={"sha256":intent["review_sha256"]},dispatcher=dispatch,reader=build["semantic_image"],
                     worker=native["phase145"]["window"]["continuity_seal"]))
        with patch.dict(complete.__globals__, STATE=state, OUTPUT=output, ARCHIVE=archive, PKG=pkg):
            self.assertEqual(complete(Status(), build), (dr, extract["extraction"]))
            if retry:
                for change in (dict(review_sha256="0"*64), dict(original={"INVOCATION_ID": "afcf6cdd1ec0400ea2757f81472987b3"}),
                               dict(preflight={"quote_provider":dict(dispatch, sha256="0"*64)})):
                    write(name / "submission-intent.json", dict(intent, **change))
                    with self.assertRaisesRegex(ValueError, "foreign (retry|lease-ready) handoff"):
                        complete(Status(), build)
                write(name / "submission-intent.json", intent)
            if missed:
                state_album = original / "recovery-started.json"
                for key in (("guard_walk_failure","registered_guard_clock","rejected_guard","continuity_seal","missed_clock_failure") if guard else ("continuity_seal", "missed_clock_failure")):
                    window = start["fresh_fit"]["phase145"]["window"]
                    keep = window[key]
                    window[key] = {"sha256":"0"*64}
                    broken = write(state_album, start)
                    write(receipt, dict(proof, start=broken))
                    with self.assertRaisesRegex(ValueError, "unbound (guard walk|missed-clock) recovery"):
                        complete(Status(), build)
                    window[key] = keep
                self.assertEqual(write(state_album,start), sr)
                write(receipt,proof)
            write(receipt, dict(proof, invocation_id="afcf6cdd1ec0400ea2757f81472987b3"))
            with self.assertRaisesRegex(ValueError, "different bound v5j"):
                complete(Status(), build)

    def test_post_build_price_selects_only_current_leased_retry(self):
        parent = {"pid": 123, "start_ticks": 45}
        old = "48ad7b2234d74e74b0498e7110e0aee3"
        state, handoff = Path("/state"), Path("/handoff")
        result = {"invocation_id": IID}
        refs = [{"path":"166"}, {"path":"168"}]
        intent = {"original":{"INVOCATION_ID":old}, "preflight":{"serial_handback":refs}}
        host = Mock()
        host.state.return_value = ({"InvocationID":IID}, [])
        host.accepted.return_value = result
        receipts = {p.DISPATCH / "admission-review.json":{}, handoff / "submission-intent.json":intent,
                    handoff / "submission-result.json":result}
        started = dict(iid=IID, image="f"*64, r2_mutations=False,
                       fresh_fit={"phase145":{"window":{"native_parent":parent}}, "serial_145_holding_handback":refs})
        d = {"Host":lambda *args:host, "HANDOFF":handoff, "STATE":state, "OLD":old, "IMAGE_SHA":"f"*64,
             "read":lambda path,*args:(json.dumps(receipts[path]).encode(),{}), "REVIEW_SHA":"b"*64,
             "bound":lambda ref:started, "retained":Mock(), "retry_handback":Mock()}
        window = {"native_parent":parent, "recovery":{"path":str(state / IID / "recovery-started.json")}}
        phase = {"stage":"leased-worker", "invocation_id":IID, "window":window}
        p.verify_build_price(d, {"phase145":phase})
        for change in (dict(invocation_id=old), dict(stage="controller"),
                       dict(window=dict(window, native_parent=dict(parent, start_ticks=44))),
                       dict(window=dict(window, recovery={"path":"/other"}))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.verify_build_price(d, {"phase145":dict(phase, **change)})


if __name__ == "__main__":
    unittest.main()
