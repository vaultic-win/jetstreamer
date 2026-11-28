"""The single admitted, captured replay estimate correction for retry8."""
from pathlib import Path
from evidence import BASE, STATUS_ROOT, bound, checked, digest, need
from replay167_rate import EPOCH, IID, PID, UNIT, forecast

FLEET = {"path": str(BASE/"root204959-live166167170-20261120-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
         "sha256": "d0d537f25764799ed48242ed6a33a487712f77c5af7f9d5cd3043caf891db98d"}
PREVIOUS = {"path": str(STATUS_ROOT/"cycle204959-live166167170-19-20261120-v1/epoch-167.receipt.json"),
            "sha256": "be74152ca1f757ee1eee5820042c8931e8b611632787563dbb78d49f544db3f2"}
EVENT = STATUS_ROOT/"event-167-rolling-after204959-20261120-v1"
SAMPLE = {"path": str(BASE/"sample-root204959-live166167170-20261120-v1.json"),
          "sha256": "a8312e934ed6201ab8e0c5257da44ff19529c07c68adb83b885e4ef828a2c682"}

def expected():
    from status import body, key
    fleet = checked(FLEET)
    cohort = checked(fleet["authenticated_status_audit"])
    prior = checked(PREVIOUS)
    old = prior["after_status"]
    need(fleet["observer"] == prior["observer"] == SAMPLE and cohort["receipts"]["167"] == PREVIOUS and
         cohort["authenticated_status_count"] == len(cohort["receipts"]) == 19 and
         cohort["authenticated_readback"] and prior["authenticated_readback"] and
         prior["conditional_header"] == "If-Match" and prior["after_sha256"] == digest(body(old)),
         "unqualified 167 source receipts")
    native, guard = prior["native_identity"]
    archive = prior["archive_sample"]
    need(old["phase"] == "replay" and old["epoch"] == EPOCH and prior["producer_invocation_id"] == IID and
         native["Id"] == UNIT and native["MainPID"] == str(PID) and native["InvocationID"] == IID and
         guard["InvocationID"] == "54788f2e334641e68aa8487931c849f5" and
         archive["device"] == 64512 and archive["inode"] == 107692764 and archive["size"] == old["jet_size_bytes"] and
         archive["bound_producer_fds"] == [f"/proc/{PID}/fd/12"], "unqualified 167 source producer or archive")
    model = forecast(SAMPLE, old["estimated_remaining_millis"])
    need(model["state"] == "advancing" and model["estimated_remaining_millis"] == 217881025, "captured 167 forecast differs")
    after = dict(old, estimated_remaining_millis=model["estimated_remaining_millis"])
    return dict(schema="horizon-167-rolling-replay-estimate-event-v1", epoch=EPOCH, key=key(EPOCH), owner="/root",
                previous_receipt=PREVIOUS, before_status=old, before_etag=prior["after_etag"],before_sha256=prior["after_sha256"],
                after_status=after, after_sha256=digest(body(after)), sampled_at_utc=old["sampled_at_utc"],
                owner_fleet=FLEET,observer=SAMPLE,current_repair_owner=None,producer_invocation_id=IID,
                native_identity=prior["native_identity"], archive_sample=archive, rolling_rate_evidence=model,
                conditional_header="If-Match", archive_or_sidecar_mutations=False)

def verify_event(v, wanted, etag, data):
    from status import body
    need(set(v) == set(wanted) | {"authenticated_readback","after_etag","verified_at_utc"} and
         all(v[k] == value for k,value in wanted.items()) and v["authenticated_readback"] is True and
         v["after_etag"] == etag and data == body(v["after_status"]) and digest(data) == v["after_sha256"],
         "unbound 167 metadata correction")

def follow(ref, etag, data):
    need(ref == PREVIOUS, "unexpected predecessor for the 167 correction")
    receipt = bound(EVENT/"RECEIPT.json")
    v = checked(receipt)
    verify_event(v, expected(), etag, data)
    return receipt, v
