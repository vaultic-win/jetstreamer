"""Verify that ordinary epoch 145 checks consume only authenticated V5w completion."""
import hashlib
import json
from pathlib import Path
import runpy
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

phase = runpy.run_path(str(Path(__file__).with_name("incident-post-phase.py")))
route = phase["v5w_completion"]
scope = route.__globals__
iid = "97bd2045ebe449e3ae77330c7e4ec7b4"
expected_hash = "42118f1624e540ed5973d37e358ad4a9f0ba68e3c8c2100c9f777e01c0f2a9bf"


class V5wPostPhase(unittest.TestCase):
    def test_reopen_captured_receipts_only_after_matching_sealed_checker(self):
        parent = Path("/private/epoch145")
        pkg = parent / "tools-v13o"
        original = parent / "tools-v5w"
        helper = original / "v5v_semantic_completion.py"
        handoff = parent / "v5w-name-handoff"
        state = parent / "state"
        completed = {"path":str(state/iid/"complete.json"),"sha256":"5"*64}
        extracted = {"path":str(state/iid/"extraction-complete.json"),"sha256":"6"*64}
        invocation = {"schema":"horizon-epoch145-v5v-custody-successor-semantic-completion-v1",
                      "invocation_id":iid,"completion":completed,"extraction":extracted,
                      "publication_authorized":False,"r2_mutations":False}
        primary = {"archive_bytes":105_610_995_833}
        records = {
            original/"deployment-seal-receipt.json":
                {"destination":str(original),"members":[{"name":helper.name,"mode":"0444","sha256":expected_hash}]},
            handoff/"SEMANTIC_COMPLETION.json":invocation,
            state/iid/"complete.json":{"receipt":extracted},
            state/iid/"extraction-complete.json":{"extraction":primary},
        }

        def need(ok,message):
            if not ok:
                raise ValueError(message)

        def read(path,*_digest):
            return records[path],{}

        def bound(receipt,path):
            self.assertEqual(receipt["path"],str(path))
            return records[path]

        status = SimpleNamespace(read=read,need=need,bound=bound)
        md = SimpleNamespace(st_uid=0,st_gid=0,st_nlink=1,st_mode=stat.S_IFREG|0o444)
        with patch.dict(scope, PKG=pkg, STATE=state), patch.object(Path,"lstat",return_value=md), \
             patch.object(Path,"resolve",autospec=True,side_effect=lambda p,**_:p), \
             patch.object(Path,"read_bytes",return_value=b"sealed tool"), \
             patch.object(hashlib,"sha256",return_value=SimpleNamespace(hexdigest=lambda:expected_hash)), \
             patch.object(scope["subprocess"],"check_output",return_value=json.dumps(invocation)) as checked:
            self.assertEqual(route(status),(completed,primary))
            command=checked.call_args.args[0]
            self.assertEqual(command[:4],["/usr/bin/python3","-IB",helper,handoff/"START_RESULT.json"])
            changed = dict(invocation,invocation_id="f"*32)
            checked.return_value=json.dumps(changed)
            with self.assertRaisesRegex(ValueError,"foreign V5w semantic"):
                route(status)
            records[handoff/"SEMANTIC_COMPLETION.json"]=changed
            with self.assertRaisesRegex(ValueError,"foreign V5w semantic"):
                route(status)
            records[handoff/"SEMANTIC_COMPLETION.json"]=invocation
            checked.return_value=json.dumps(invocation)
            records[original/"deployment-seal-receipt.json"]["members"][0]["sha256"]="0"*64
            with self.assertRaisesRegex(ValueError,"different sealed V5w"):
                route(status)

    def test_v5x_post_uses_the_successor_receipt_schema_and_start(self):
        self.check_successor(
            "v5x", "horizon-epoch145-v5x-donor-successor-semantic-completion-v1",
            "v5w-name-handoff/V5W_TERMINAL_FAILURE_DONOR.json",
        )

    def test_v5z_post_uses_the_custody_successor_start(self):
        self.check_successor(
            "v5z", "horizon-epoch145-v5z-custody-successor-semantic-completion-v1",
            "v5y-name-handoff/V5Y_TERMINAL_FAILURE_RECEIPT_MODE.json",
        )

    def test_v6_post_binds_the_exact_guard_walk_successor(self):
        self.check_successor(
            "v6-guard-walk", "horizon-epoch145-v5z-custody-successor-semantic-completion-v1",
            "v5z-name-handoff/V5Z_TERMINAL_FAILURE_GUARD_WALK.json",
        )

    def test_v7_post_rejects_crossed_custody_for_the_same_receipt_schema(self):
        self.check_successor(
            "v7-168-stop", "horizon-epoch145-v5z-custody-successor-semantic-completion-v1",
            "v6-guard-walk-name-handoff/V6_TERMINAL_FAILURE_168_STOP.json",
        )

    def check_successor(self, generation, schema, predecessor_path):
        root = Path("/private/runtime")
        family = root / "epoch145-semantic-continuity-20261121-v1"
        v7 = generation == "v7-168-stop"
        authority = family / (f"tools-{generation}-v2" if v7 else f"tools-{generation}")
        handoff = family / f"{generation}-name-handoff"
        actor = "a" * 32
        state = root / "state"
        helper = authority / "v5v_semantic_completion.py"
        start = handoff / "START_RESULT.json"
        sealed = authority / "deployment-seal-receipt.json"
        build = authority / "build-proof.json"
        done = state / actor / "complete.json"
        extraction = state / actor / "extraction-complete.json"

        def ref(path):
            return {"path": str(path), "sha256": expected_hash}

        predecessor = ref(family / predecessor_path)
        result = {"schema":schema,
                  "invocation_id":actor, "completion":ref(done), "extraction":ref(extraction),
                  "start":ref(start),
                  "startup_evidence":{"invocation_id":actor,"submission_result":ref(start),
                                      "worker_build":ref(build),"worker_seal":ref(sealed),
                                      "predecessor_terminal":predecessor},
                  "r2_mutations":False, "publication_authorized":False}
        captured = handoff / "SEMANTIC_COMPLETION.json"
        extracted = {"archive_bytes":105_610_995_833}
        records = {
            sealed:{"schema":"jetstreamer-sealed-deployment-receipt-v1","destination":str(authority),
                    "members":[{"name":name,"mode":mode,"sha256":expected_hash}
                               for name,mode in ((helper.name,"0444"),(build.name,"0444"),("export145","0555"))]},
            build:{"verifier_sha256":expected_hash,"semantic_checker":ref(helper),"guard_terminal":predecessor},
            start:{}, captured:result, done:{"receipt":ref(extraction)}, extraction:{"extraction":extracted},
        }

        def need(ok, message):
            if not ok:
                raise ValueError(message)

        def bound(binding, path):
            self.assertEqual(binding, ref(path))
            return records[path]

        status = SimpleNamespace(read=lambda path:(records[path],ref(path)), need=need, bound=bound,
                                 iid=lambda value:value == actor)
        md = SimpleNamespace(st_uid=0,st_gid=0,st_nlink=1,st_mode=stat.S_IFREG|0o444,st_size=1)
        v6 = generation == "v6-guard-walk"
        with patch.dict(scope, ROOT=root, STATE=state, V5Z_POST=generation != "v5x", V6_POST=v6,
                        V6_INVOCATION=actor, V6_START_SHA=expected_hash, V6_SEAL_SHA=expected_hash,
                        V7_POST=v7, V7_INVOCATION=actor, V7_START_SHA=expected_hash, V7_SEAL_SHA=expected_hash), \
             patch.object(Path,"lstat",return_value=md), \
             patch.object(Path,"resolve",autospec=True,side_effect=lambda p,**_:p), \
             patch.object(Path,"read_bytes",return_value=b"sealed tool"), \
             patch.object(hashlib,"sha256",return_value=SimpleNamespace(hexdigest=lambda:expected_hash)), \
             patch.object(scope["subprocess"],"check_output",return_value=json.dumps(result)) as checked:
            self.assertEqual(phase["v5x_completion"](status),(ref(done),extracted))
            self.assertEqual(checked.call_args.args[0][-2:], [str(start),expected_hash])
            if v6:
                with patch.dict(scope, V6_START_SHA="0" * 64):
                    with self.assertRaisesRegex(ValueError, "different authenticated V6"):
                        phase["v5x_completion"](status)
            if v7:
                with patch.dict(scope, V7_SEAL_SHA="0" * 64):
                    with self.assertRaisesRegex(ValueError, "different authenticated V7"):
                        phase["v5x_completion"](status)
                crossed = dict(result, start=ref(family / "v6-guard-walk-name-handoff/START_RESULT.json"))
                records[captured] = crossed
                checked.return_value = json.dumps(crossed)
                with self.assertRaisesRegex(ValueError, "foreign V5x semantic completion"):
                    phase["v5x_completion"](status)
            wrong = dict(result,schema="horizon-epoch145-v5w-donor-successor-semantic-completion-v1")
            records[captured] = wrong
            checked.return_value = json.dumps(wrong)
            with self.assertRaisesRegex(ValueError,"foreign V5x semantic completion"):
                phase["v5x_completion"](status)


if __name__=="__main__":
    unittest.main()
