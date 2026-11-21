"""Adopt the guarded epoch 168 event between two ordinary coordination cycles."""
import json

import status168
from evidence import STATUS_ROOT, bound, checked, digest, need


def follow(predecessor, etag, raw):
    from status import FIELDS, body, key

    live = status168.inspect()
    if live is None or live["stage"] != "protected-worker":
        return None
    actor = live["actor"]
    iid = actor["producer_invocation_id"]
    receipt = STATUS_ROOT / f"event-168-guarded-admission-{iid}" / "RECEIPT.json"
    if not receipt.exists():
        return None
    ref = bound(receipt)
    event = checked(ref)
    old = checked(predecessor)
    admission = checked(live["admission"])
    worker = checked(live["first_worker"])
    need(event["schema"] == "horizon-guarded-admission-status-v1" and event["epoch"] == 168
         and event["key"] == key(168) and event["owner"] == "/root" and event["current_repair_owner"] is None
         and event["authenticated_readback"] is True and event["conditional_header"] == "If-Match"
         and event["archive_or_sidecar_mutations"] is False and event["measured_canonical_progress"] is False
         and event["previous_receipt"] == predecessor and event["before_status"] == old["after_status"]
         and event["before_etag"] == old["after_etag"] and event["before_sha256"] == old["after_sha256"]
         and event["producer_invocation_id"] == iid and event["actor"] == actor
         and event["admission"] == live["admission"] == worker["admission"]
         and event["first_worker"] == live["first_worker"] and event["fleet"] == admission["fleet"]
         and all(admission[k] == v for k, v in actor.items()) and event["guard"]["timer"]["InvocationID"] == admission["timer_invocation_id"]
         and event["after_etag"] == etag and digest(raw) == event["after_sha256"]
         and set(event["after_status"]) == FIELDS and event["after_status"]["epoch"] == 168
         and event["after_status"]["phase"] == "verification" and event["after_status"] == json.loads(raw)
         and body(event["after_status"]) == raw, "unbound normal 168 admission event")
    return ref, event
