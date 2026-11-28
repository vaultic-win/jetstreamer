"""Bind the separately admitted RAM-backed retry to both retained interrupted recordings."""
from pathlib import Path

from evidence import BASE, checked, need
import gap170_contract as first

ROOT = BASE/"epoch170-from-73760367-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73760367-ram-20261128-v1.service"
INTERFACE = dict(path=str(ROOT/"RAM_GAP170_WRITER_INTERFACE.json"),
                 sha256="cf7836a48efd71f886924a07657101691d27d24f6ccf05cbe7938b4be1daedaf")
STOP = dict(path=str(ROOT/"PREDECESSOR_FLOOR_STOP.json"),
            sha256="2eb844de0deb0717268b07b9cc0bdd746a92880075fbb14ca515638305f2721c")
CHECKPOINT = first.CHECKPOINT
PREVIOUS = "d8ea1fcfbd6646839b9593752f4afdef"


def interface():
    scope=checked(INTERFACE)
    prior=first.interface()
    end=checked(STOP)
    entry=checked(scope["source_preflight"])
    ns=checked(scope["namespace"])
    profile=scope["profile"]
    need(scope["schema"]=="horizon-170-ram-gap-writer-interface-v1" and scope["prior_gap"]==first.INTERFACE
         and scope["ram_retry_predecessor"]==STOP and end["invocation_id"]==PREVIOUS and not end["closed_segment"]
         and scope["expected_producer_unit"]==profile["host_unit"]==UNIT
         and scope["expected_guard_unit"]==UNIT.replace("-qualify-","-guard-")
         and scope["expected_guard_timer"]==scope["expected_guard_unit"].replace(".service",".timer")
         and profile["producer_memory_bytes"]==56<<30 and profile["scratch_noswap_tmpfs_bytes"]==40<<30
         and profile["new_home_total_bytes"]==8<<30 and profile["new_control_bytes"]==64<<20
         and profile["sealed_package"]==scope["guard_seal"] and scope["guard_seal"]["sha256"]==
             "8e75d3793628da23d999b07c857b9bebfa0bdf0ab8e2f945ffc389345244b69c"
         and all(profile[k]==prior["profile"][k] for k in ("bootstrap","first","last","positions","checkpoints",
                 "node","worker","producer_cpu_quota_micros","guard_cpu_quota_micros","guard_memory_bytes"))
         and all(scope[k]==prior[k] for k in ("source_packet","independent_checkpoint","handoff","old_release","old_actor"))
         and scope["source_preflight"]["sha256"]=="d89c7f89bbf646ae36a20397e140a02c000d2bfc81faa712808f626135487beb"
         and scope["namespace"]==entry["namespace"]==profile["namespace"] and entry["route_accepted"]
         and entry["scope"]==[73760368,73766969] and ns["report"]["limits"]["memory.max"]==str(56<<30)
         and ns["report"]["scratch"]["bytes"]==40<<30 and ns["wrong_tmpfs_size_refused"]
         and ns["no_host_scratch_payload"] and not entry["worker_executed"]
         and not scope["admission_or_release"] and not scope["publication_authorized"],
         "different RAM-backed checkpoint scope, namespace or input")
    return scope


def checkpoint(scope):
    return first.checkpoint(scope)


def stopped_owner(fleet):
    first.stopped_owner(fleet)
    scope=interface()
    row=fleet["current_private170_checkpoint_gap"]
    end=checked(scope["ram_retry_predecessor"])
    need(row["phase"]=="terminal" and row["unit"]["Id"]==end["unit"] and row["actor_ref"]==end["actor"]
         and row["release"]==end["release"] and row["interface"]==scope["prior_gap"]
         and row["native_terminal"]["INVOCATION_ID"]==end["invocation_id"]==PREVIOUS
         and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"],
         "first gap outcome changed")
    return row
