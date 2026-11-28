"""Pair the retained hourly history and its replacement on the same 30-minute observer."""
from copy import copy
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as c
import observe


def observe_retry(context, observed_lane):
    row=observe.current(context.fleet)
    prior=context.fleet.get(observe.FIELD)
    configured=[a for a in context.cfg["diagnostic_replays"] if a["range"]=="169" and a["producer_unit"]==c.UNIT]
    sampled=[a for a in context.sample["diagnostic_replays"] if a["range"]=="169" and a["producer_unit"]==c.UNIT]
    c.need(len(configured)==len(sampled)<=1,"duplicate or missing private retry sample")
    if row is None:
        c.need(not prior and not configured,"169 retry assignment lost its owner")
        return None
    if prior:
        c.need(prior["invocation_id"]==row["invocation_id"] and
               (prior["phase"]!="terminal" or row["phase"]=="terminal" and prior["terminal"]==row["terminal"]),
               "169 retry invocation changed")
    row.update(observer=context.sample_ref,transaction_replay_claimed=False,native_diagnostic=None)
    if configured:
        cfg,actual=configured[0],sampled[0]
        c.need(prior and prior.get("observer_config")==cfg and cfg["producer_unit"]==cfg["controller_unit"]==c.UNIT
               and cfg["expected_producer_invocation_id"]==cfg["expected_controller_invocation_id"]==row["invocation_id"]
               and cfg["append_log"]["path"]==str(observe.LOG) and cfg["scratch_path"]==str(c.OLD/"v158/scratch")
               and actual["expected_producer_invocation_id"]==row["invocation_id"] and actual["scratch_path"]==cfg["scratch_path"]
               and actual["ordinary_replay_claim"] is actual["publication_authorized"] is actual["r2_mutations"] is False
               and actual["status"] in ("observed","unavailable"),"foreign private retry measurement")
        row["native_diagnostic"]=actual
        if row["phase"]=="worker" and actual["status"]=="observed":
            detail=actual["observation"]
            c.need(row["observer_config"]==cfg and all(detail[k]["pid"]==row["worker"]["pid"]
                   and detail[k]["executable"]==row["worker"]["path"] for k in ("worker_before","worker_after")),
                   "169 worker changed during cadence")
            row["transaction_replay_claimed"]=observed_lane(detail,cfg,row["invocation_id"],row["actor"]["producer_pid"])
    return row


def install(fleet, row):
    if row is None:
        return
    registered=fleet.get("current_private169_hourly")
    c.need(registered and registered["phase"]=="terminal" and registered["invocation_id"]==c.OLD_IID
           and not any(r["epoch"]==169 for key in ("actual_active_private_diagnostics","actual_executing_replays",
                       "actual_active_bootstraps") for r in fleet[key]), "competing epoch 169 or lost hourly closure")
    fleet[observe.FIELD]=row
    if row["phase"]!="terminal":
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"]+=1
        fleet["active_producer_count"]+=1
    entry,=(r for r in fleet["epochs"] if r["epoch"]==169)
    entry.update(current_private_diagnostic=row,current_status_scope=f"Private hourly retry {row['phase']}. Canonical repair remains open.")


def project(context, row):
    configured=[a for a in context.next_cfg["diagnostic_replays"] if a["range"]!="169"]
    if row and row.get("observer_config"):
        configured.append(row["observer_config"])
    context.next_cfg["diagnostic_replays"]=configured


def predecessor_context(context, retry):
    """Let the original callback validate its own terminal and the pre-retry diagnostic sample."""
    adapted=copy(context)
    adapted.fleet=observe.predecessor_view(context.fleet)
    def original(values):
        for row in values:
            if row["range"]=="169" and row["producer_unit"]==c.UNIT:
                c.need(retry and row["expected_producer_invocation_id"]==retry["invocation_id"]
                       and retry["native_diagnostic"],"unvalidated 169 retry assignment")
        return [r for r in values if r["range"]!="169" or r["producer_unit"]!=c.UNIT]
    adapted.cfg=dict(context.cfg,diagnostic_replays=original(context.cfg["diagnostic_replays"]))
    adapted.sample=dict(context.sample,diagnostic_replays=original(context.sample["diagnostic_replays"]))
    return adapted


def status_fields(row):
    return dict(private169_retry_phase=row["phase"],private169_retry_invocation=row["invocation_id"],
                private169_retry_guard=row.get("guard"),private169_retry_terminal=row.get("terminal"),
                private169_retry_transaction_progress=row["transaction_replay_claimed"])
