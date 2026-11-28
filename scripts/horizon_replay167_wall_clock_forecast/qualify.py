"""Read-only replay of the captured model and the real publisher against private test storage."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import replay167_event as event
import replay167_rate as rate
import status
from evidence import BASE, EPOCHS, bound, checked, digest, utc

class ConditionalStatusRetryTests(unittest.TestCase):
    def make_storage(self, status_code=503):
        from botocore.exceptions import ClientError

        error = ClientError({"ResponseMetadata": {"HTTPStatusCode": status_code}}, "PutObject")
        storage = status.Storage.__new__(status.Storage)
        storage.pending = None
        storage.s3 = SimpleNamespace(put_object=Mock(side_effect=error))
        storage.get = Mock(return_value=('"before"', b'before'))
        return storage, error

    def test_unchanged_etag_retries_only_the_same_conditional_write(self):
        storage, error = self.make_storage()
        attempts = []

        def put(**request):
            attempts.append((storage.pending, request))
            if len(attempts) == 1:
                raise error
            return {"ETag": '"after"'}

        storage.s3.put_object.side_effect = put
        with patch.object(status.time, "sleep") as backoff:
            self.assertEqual(storage.put(172, '"before"', b'after'), '"after"')
        backoff.assert_called_once_with(0.5)
        storage.get.assert_called_once_with(172)
        self.assertEqual(attempts, [attempts[0], attempts[0]])
        self.assertEqual(attempts[0][0], ('epoch-172.epoch-status.json', '"before"'))
        self.assertIsNone(storage.pending)

    def test_changed_etag_requires_exact_intended_readback(self):
        for body in (b'after', b'foreign'):
            with self.subTest(body=body), patch.object(status.time, "sleep"):
                storage, _ = self.make_storage()
                storage.get.return_value = ('"after"', body)
                if body == b'after':
                    self.assertEqual(storage.put(172, '"before"', b'after'), '"after"')
                else:
                    with self.assertRaisesRegex(ValueError, "status changed"):
                        storage.put(172, '"before"', b'after')
                self.assertEqual(storage.s3.put_object.call_count, 1)
                self.assertIsNone(storage.pending)

    def test_retry_is_bounded_and_precondition_failure_still_propagates(self):
        for status_code, attempts in ((503, 4), (412, 1)):
            with self.subTest(status_code=status_code), patch.object(status.time, "sleep"):
                storage, error = self.make_storage(status_code)
                with self.assertRaises(type(error)):
                    storage.put(172, '"before"', b'after')
                self.assertEqual(storage.s3.put_object.call_count, attempts)
                self.assertEqual(storage.get.call_count, attempts if status_code == 503 else 0)
                self.assertIsNone(storage.pending)


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.oldsample = {"path":str(BASE/"sample-root194959-live166167170-20261120-v1.json"),
                          "sha256":"c4c41fe73dab59b2345f1243fe59c83fceb5a4534812cee6af01d2b20b6fb25e"}
        self.s = checked(self.oldsample)
        self.w = next(r["useful_work"] for r in self.s["replays"] if r["range"] == "167")
        self.prev = checked(event.PREVIOUS)
        self.model = event.expected()

    def test_recorded_downtime_and_recovery(self):
        m = rate.forecast(self.oldsample,662810859)
        self.assertEqual((m["slot_delta"],m["wall_microseconds"],m["estimated_remaining_millis"]), (20284,10741571652,228422792))
        self.assertEqual(m["state"], "advancing")
        self.assertLess(m["latest_transport_error_us"],m["last"]["realtime_microseconds"])
        self.assertEqual(len(m["samples"]),6)
        new = self.model["after_status"]
        self.assertEqual(new, dict(self.prev["after_status"],estimated_remaining_millis=217881025))

    def test_provenance(self):
        for k in ("journal_invocation_id","counter_resets","inode","main_pid","sha256","time","slot"):
            with self.subTest(k=k):
                changed = copy.deepcopy(self.s)
                row = next(r for r in changed["replays"] if r["range"] == "167")
                work = row["useful_work"]
                if k == "inode": work["append_log_evidence"][k] += 1
                elif k == "main_pid": row["producer_before"][k] += 1
                elif k == "sha256": changed["cadence"]["previous_sample_sha256"] = "a"*64
                elif k == "time": changed["cadence"]["previous_sample_recorded_at_utc"] = changed["recorded_at_utc"]
                elif k == "slot": work["first"]["slot"] = 0
                elif k == "counter_resets": work[k] = 1
                else: work[k] = "foreign"
                with patch.object(rate,"checked",side_effect=lambda ref: changed if ref == self.oldsample else checked(ref)):
                    with self.assertRaises(ValueError):
                        rate.forecast(self.oldsample,10)
        with self.assertRaises(ValueError):
            rate.captured_bytes(dict(self.w["append_log_evidence"],read_sha256="0"*64))

    def test_unrecovered_and_flat(self):
        data = rate.captured_bytes(self.w["append_log_evidence"])
        late = b"\n[2026-11-20T19:49:59.000000001Z WARN  jetstreamer::firehose] HTTP 429 Too Many Requests fetching epoch 167\n"
        self.assertFalse(rate.recovery(self.w,data+late)[0])
        with patch.object(rate,"captured_bytes",return_value=data+late):
            m=rate.forecast(self.oldsample,662810859)
        self.assertEqual((m["state"],m["estimated_remaining_millis"]),("stalled-or-recovery-unproven",662810859))
        with patch.object(rate, "chain", return_value=[(event.SAMPLE,self.s["recorded_at_utc"],dict(self.w,first=None,last=None))]*6):
            m=rate.forecast(self.oldsample,662810859)
        self.assertEqual((m["slot_delta"],m["estimated_remaining_millis"]), (0,662810859))

    def test_follow_exact_event(self):
        old = self.prev
        after = status.body(self.model["after_status"])
        r = dict(self.model,authenticated_readback=True,after_etag='"fixture"',verified_at_utc="2026-11-20T20:00:00Z")
        ref = {"path":str(event.EVENT/"RECEIPT.json"),"sha256":"a"*64}
        reader = lambda f: r if f == ref else checked(f)
        with patch.object(event,"bound",return_value=ref),patch.object(event,"checked",side_effect=reader):
            self.assertEqual(status.follow_event(167,event.PREVIOUS,'"fixture"',after), (ref,r))
            for k,v in (("producer_invocation_id","x"),("after_etag",'"wrong"'),("before_sha256","wrong"),("archive_sample",{}),("authenticated_readback",False),("after_status",{}),("rolling_rate_evidence",{}),("conditional_header","none")):
                with self.subTest(k=k),patch.object(event,"checked",side_effect=lambda f: dict(r,**{k:v}) if f == ref else checked(f)):
                    with self.assertRaises(ValueError): status.follow_event(167,event.PREVIOUS,'"fixture"',after)
            with self.assertRaises(ValueError): status.follow_event(167,old["previous_receipt"],'"fixture"',after)
            with self.assertRaises(ValueError): status.follow_event(166,event.PREVIOUS,'"fixture"',after)
            self.assertEqual(status.follow_event(167,event.PREVIOUS,old["after_etag"],status.body(old["after_status"])),(event.PREVIOUS,old))

    def test_entire_scheduled_writer(self):
        self.s = checked(event.SAMPLE)
        fleet = checked(event.FLEET)
        results = checked(fleet["authenticated_status_audit"])
        prior = {e:checked(results["receipts"][str(e)]) for e in EPOCHS}
        c = SimpleNamespace(now=utc(self.s["recorded_at_utc"]),stamp=self.s["recorded_at_utc"],sample_ref=event.SAMPLE,
                lanes={int(r["range"]):r for r in self.s["replays"]},native={},rows={},
                advancing={e:prior[e]["measured_canonical_progress"] for e in (166,167,170)},fleet_ref=prior[167]["fleet_predecessor"],
                fleet=fleet,closures=prior[167]["historical_epoch170_closures"],diagnostic=prior[168]["coordinated_private_diagnostic_168"],
                diagnostic169=prior[169]["coordinated_private_diagnostic_169"],public_fresh=lambda:None,unchanged=lambda:None)
        c.prior=dict(receipts={str(e):prior[e]["previous_receipt"] for e in EPOCHS},inventory=results["inventory"])
        native={}
        for e in c.lanes:
            row=prior[e]["native_identity"]
            n=dict(row[0]);n["ExecMainStartTimestamp"]=(c.now-dt.timedelta(milliseconds=prior[e]["after_status"]["elapsed_execution_millis"])).strftime("%a %Y-%m-%d %H:%M:%S UTC")
            c.native[str(e)]=row;c.rows[e]={"unit":{"Id":n["Id"]}};native[n["Id"]]=n
        db={e:(prior[e]["before_etag"],status.body(prior[e]["before_status"])) for e in EPOCHS}
        def put(e,etag,data):
            self.assertEqual(db[e][0],etag)
            tag='"fixture-'+str(e)+'"';db[e]=(tag,data);return tag
        storage=SimpleNamespace(get=lambda e:db[e],put=put)
        with tempfile.TemporaryDirectory(dir=str(BASE)) as tmp,patch.object(status,"show",side_effect=lambda name,props:native[name]),patch.object(status,"observed_archive",side_effect=lambda cyc,e:prior[e]["archive_sample"]):
            out=Path(tmp)
            receipt=checked(status._publish(c,storage,out,results["ready_epochs"]))
            self.assertEqual(len(receipt["receipts"]),19)
            for e in EPOCHS:
                got=checked(receipt["receipts"][str(e)])
                expected=self.model["after_status"] if e==167 else prior[e]["after_status"]
                self.assertEqual(got["after_status"],expected)
                self.assertEqual(got["after_sha256"],digest(db[e][1]))
                self.assertEqual(got["conditional_header"],"If-Match")

if __name__=="__main__":
    unittest.main()
