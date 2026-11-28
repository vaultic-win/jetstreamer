"""Run the production V73 epoch 167 publisher against in-memory R2 and same-cadence native evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import derive_assembly_cadence as setup

RT = setup.RT
OLD_FLEET = RT / "root111808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
CHECK_FLEET = RT / "root114808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
NATIVE = setup.EVIDENCE / "COORDINATED_114808_QUALIFICATION.json"
NATIVE_SHA = "f1251bfa3dc93f91a0e6dc9efa6bebe0d60489d2300b906a2e1cc502cee6a350"


class MemoryStore:
    def __init__(self, previous, api):
        self.api = api
        self.raw = api.status.body(previous["after_status"])
        self.etag = previous["after_etag"]
        self.writes = 0

    def get(self, epoch):
        assert epoch == 167
        return self.etag, self.raw

    def put(self, epoch, expected, body):
        assert epoch == 167 and expected == self.etag
        self.raw = body
        self.etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
        self.writes += 1
        return self.etag


def main():
    os.umask(0o077)
    sys.path.insert(0, str(setup.NEW))
    import status_cycle as api
    import assembly_cadence as route
    import assembly_forecast as model
    from evidence import bound, checked, durable
    package = api.entry()
    assert api.FAILED166_VERSION == 73 and package == bound(setup.NEW / "deployment-seal-receipt.json")
    historical = checked(model.ref(NATIVE, NATIVE_SHA))
    coordinated = checked(bound(CHECK_FLEET))
    head = coordinated["previous_Root_operational_review"]
    assert head == bound(OLD_FLEET)
    stamp = historical["after"]["sampled_at_utc"]
    assert checked(coordinated["observer"])["recorded_at_utc"] == stamp
    sample = checked(historical["observation"])
    previous = model.status_receipt(model.FIRST_OUTPUT)
    failed = previous[api.cold167_status.TERMINAL_FIELD]
    assert route.owns(previous) and route.owns(checked(coordinated["complete_active_status_receipts"]["167"]))
    c = SimpleNamespace(fleet_ref=head, fleet=checked(head), sample_ref=coordinated["observer"],stamp=stamp,
                        now=api.utc(stamp), failed167=failed, new_rows={}, advancing={}, split162=None, split169=None)
    # Use the genuine measurement taken during this original observation. This invocation only writes local fixtures.
    with patch.object(route, "observation", return_value=sample):
        c.assembly167 = route.freeze(c)
    with patch.object(route, "observation", side_effect=AssertionError("must replay the original frozen observation")):
        assert route.freeze(c) == c.assembly167
    assert checked(c.assembly167)["observed_at_utc"] == sample["observed_at_utc"]
    outputs = {}
    with tempfile.TemporaryDirectory(dir=setup.EVIDENCE) as tmp:
        out = Path(tmp)
        ref = {"167":model.FIRST_OUTPUT}
        store = MemoryStore(previous, api)
        api.publish(c,store,ref,out,167)
        first_receipt = checked(ref["167"])
        assert first_receipt["after_status"] == historical["after"] and first_receipt["archive_sample"] == sample["archive_sample"]
        assert first_receipt["authenticated_readback"] and first_receipt[api.cold167_status.TERMINAL_FIELD] == failed
        assert first_receipt["current_repair_owner"] is None and not first_receipt["archive_publication_authorized"]
        assert first_receipt["assembly_invocation_id"] == model.INVOCATION and first_receipt["observer"] == c.sample_ref
        api.publish(c,store,{"167":model.FIRST_OUTPUT},out,167)
        assert store.writes == 1
        view = copy.deepcopy(c.fleet)
        route.install(view, ref["167"])
        epoch, = (r for r in view["epochs"] if r["epoch"] == 167)
        assert view[route.FIELD] == c.assembly167 and not epoch["no_live_producer_claimed"]
        assert view["actual_executing_replays"] == c.fleet["actual_executing_replays"]
        assert [r for r in view["epochs"] if r["epoch"] != 167] == [r for r in c.fleet["epochs"] if r["epoch"] != 167]
        outputs["running"] = first_receipt["after_status"]
        for phase in ("upload", "readback"):
            separate = copy.deepcopy(previous)
            separate["after_status"]["phase"] = phase
            fake = MemoryStore(separate, api)
            separate["after_sha256"] = hashlib.sha256(fake.raw).hexdigest()
            receipt = out / (phase+"-prior.json")
            durable(receipt, separate)
            folder = out / phase
            folder.mkdir()
            api.publish(c,fake,{"167":bound(receipt)},folder,167)
            assert fake.writes == 0 and not list(folder.iterdir())
        failing_at = str(int(c.now.timestamp())*1_000_000-5_000_000)
        failed_sample = dict(sample, state="failed", failure={"__REALTIME_TIMESTAMP":failing_at}, archive_sample=None)
        failed_after, failed_private = route.failed(c,failed_sample,c.assembly167)
        later = SimpleNamespace(now=c.now+model.timedelta(minutes=30),stamp=model.wire_time(c.now+model.timedelta(minutes=30)))
        failed_later, _ = route.failed(later,failed_sample,c.assembly167)
        assert failed_after["jet_size_bytes"] == 0 and failed_after["estimated_remaining_millis"]-failed_later["estimated_remaining_millis"] == 1_800_000
        assert failed_private["producer_invocation_id"] is None and failed_private["current_repair_owner"] == "/root"
        outputs["failure_planning"] = dict(no_replay=failed_private["terminal_delivery_estimate"]["full_replay_ms"] == 0,
                                           elapsed_ms=failed_after["elapsed_execution_millis"])
    print(json.dumps(dict(package=package, historical_sample=c.assembly167, historical_previous=model.FIRST_OUTPUT,
                          results=outputs, full_publish_and_retry=True, preserved_upload_and_readback=True,
                          unaffected_epoch_rows=True, public_writes=0, external_reads=0),sort_keys=True))


if __name__ == "__main__":
    main()
