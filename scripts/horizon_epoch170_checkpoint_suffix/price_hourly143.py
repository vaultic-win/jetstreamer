#!/usr/bin/python3 -IB
"""Price 143 before booking and with its actual held guard; projection never admits a worker."""
import argparse
import json
from pathlib import Path
import sys
import time

PACKAGE = Path(__file__).resolve().parent
sys.path.insert(0,str(PACKAGE))
import continuation_price as second
import rollover143 as roll

core = second.prior
G, M = roll.G, roll.M
TREE, EVIDENCE, RAM = 64*G,64*M,41*G


def owner170():
    old = core.state(core.UNIT)
    new = core.state(second.UNIT)
    interface, _ = second.scope()
    if old["ActiveState"] == "active":
        core.inactive(second.UNIT)
        a = core.bound(interface["old_actor"])
        core.need(old["InvocationID"]==a["producer_invocation_id"] and old["MainPID"]==str(a["producer_pid"]),
                  "current bounded 170 actor changed")
        live = roll.guard(core, second.OLD, core.UNIT, core.DEP/"guard-receipts",old["InvocationID"],"live")
        return "predecessor",live
    second.predecessor_exit()
    if new["ActiveState"] == "active":
        a, _ = core.read(second.DEP/"SUCCESSOR_ACTOR.json")
        core.need(a["producer_invocation_id"]==new["InvocationID"] and a["producer_pid"]==int(new["MainPID"]),
                  "second 170 owner changed")
        mode = "live" if (second.DEP/"SUCCESSOR_RELEASE.json").exists() else "held170"
        live = roll.guard(core, second.DEP, second.UNIT, second.DEP/"guard-receipts",new["InvocationID"],mode)
        return "successor",live
    core.inactive(second.UNIT)
    if Path(interface["closed_comparison"]).exists():
        second.compare_predecessor()
        return "between", None
    return "readback", None


def arithmetic(j, aux, peer, phase, tail_resident, peer_resident, available, candidate_floor=0):
    # The incumbent 170 calculation carries 44 GiB HOME/30 GiB RAM for the first
    # 141. Its on-disk finished tree is already absent from current statvfs.
    raw = j["required_home"]-j["candidate_growth"]-(44*G+64*M)
    floors=[core.bound(r)["minimum_free_bytes"] for r in j["guard_samples"].values()]
    old_remaining=0 if peer is None else max(0,peer["cap"]-peer["low"])
    # Until the exact predecessor archive closes, its scoped unallocated growth
    # still belongs to the readback, even after PID1 has reaped the producer.
    upper = j["terminal_tree_bounds"][1]
    if phase == "readback":
        interface, _ = second.scope()
        old_plan = core.bound(core.bound(interface["old_release"])["guard_plan"])
        upper = old_plan["maximum_root_physical_bytes"]
        core.need(j["terminal_tree_bounds"][1] <= upper, "ended 170 tree exceeds its admitted cap")
        old_remaining = upper - j["terminal_tree_bounds"][0]
    elif peer:
        upper = peer["cap"]
    next_growth=36*G if phase != "successor" else 0
    future=old_remaining+next_growth
    cap = 384*G
    guard_ok = upper + next_growth <= cap
    peer_floor=0 if peer is None else peer["floor"]
    # Guard floors apply to current free space. Do not feed this candidate's own
    # floor back into its retained requirement on the second guarded screen.
    base=max(raw,*floors,peer_floor)
    retained=base+future+aux["evidence_home"]+aux["controller_home"]
    historical=j["historical_home_limit"]+aux["incremental_185_m_after_fleet"]-(raw+future+aux["evidence_home"]+aux["controller_home"]+TREE+EVIDENCE)
    live=available[0]-(retained+TREE+EVIDENCE)
    margin=min(live,historical)
    ram=j["required_ram"]-31*G-tail_resident-peer_resident+aux["fourth_ram"]+aux["parallel_controls_ram"]+aux["controller_ram"]+aux["watcher_ram"]
    h=retained+TREE+EVIDENCE+margin
    return dict(retained_required_home_bytes=retained,retained_required_ram_bytes=ram,available_home_bytes=h,
                available_ram_bytes=available[1],home_margin_bytes=margin,ram_margin_bytes=available[1]-ram-RAM,
                disk_fits=margin>=0 and guard_ok and (not candidate_floor or (candidate_floor>=retained and h>=candidate_floor+TREE+EVIDENCE)),
                memory_fits=available[1]>=ram+RAM,live_home_margin=live,historical_home_margin=historical,live_available_home_bytes=available[0],
                original_scoped_home=raw,peer_remaining=old_remaining,next_170_reserved=next_growth,
                peer_tree_cap_fits=guard_ok,peer_raw_floor=peer_floor)


def price(fleet,sha,held=None,projection=False):
    _, profile=core.read(roll.ROOT/"contract-v1/LAUNCH_PROFILE.json",roll.SHA)
    closed=None
    if not projection or roll.ACCEPT.exists():
        closed=roll.first_closed(core)
    else:
        owner,_=core.read(roll.OLD/"HELD_OWNER.json","f746b5dbe75d5c33749f7fc66f199431a726494e5a82934bfadc76b27ef6d3ac")
        core.need(core.state(roll.FIRST)["InvocationID"]==owner["producer_invocation_id"],"141 transition in progress")
    if held:
        core.need(not projection and closed,"cannot hold 143 on an occupied envelope")
        own=roll.guard(core,roll.ROOT,roll.UNIT,roll.ROOT/"guard-receipts",held,"gate")
    else:
        core.inactive(roll.UNIT)
        own=None
    before=core.availability()
    phase,peer=owner170()
    j=core.price("start" if peer is None else "held",attempt=second.OLD,
                 live_tree_bounds=(peer["low"],peer["high"]) if peer else None,
                 held_replacement=second.UNIT if phase=="successor" else None,hourly_replacement=held)
    core.need(j["fleet"]==dict(path=fleet,sha256=sha) and j["extra"]["reserved_141"]["sha256"]=="73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131"
              and j["candidate_growth"]==36*G,"wrong shared 170 budget/fleet")
    tail=core.bound(j["charged_167"])
    core.need(core.bound(tail["actor"]["intent"])["quote"]["exact_native_fit"]["reserved_new_selector_RAM_bytes"]==4*G,
              "original selector no longer priced")
    t_res=second.anonymous(tail["actor"]["unit"],tail["actor"]["producer_invocation_id"],[p[:2] for p in tail["processes"]],42*G)
    peer_res=second.anonymous(peer["unit"],peer["iid"],peer["roster"],48*G) if peer else 0
    aux=roll.auxiliary(core,j["fleet"])
    after=core.availability()
    now=(min(before[0],after[0]),min(before[1],after[1],j["available_ram"]))
    quote=arithmetic(j,aux,peer,phase,t_res,peer_res,now,own["floor"] if own else 0)
    core.need(core.current_fleet()[1]==j["fleet"] and (not peer or core.state(peer["unit"])==peer["manager"])
              and (not own or core.state(roll.UNIT)==own["manager"]),"owner changed during 143 price")
    if projection:
        # No hypothetical release can be consumed by the launcher or booking writer.
        quote["projected_disk_fits"]=quote["disk_fits"]
        quote["projected_memory_fits"]=quote["memory_fits"]
        quote["disk_fits"]=quote["memory_fits"]=False
    return dict(schema="horizon-epoch143-first-hourly-replacement-fit-v1",recorded_unix_seconds=int(time.time()),
                fleet=j["fleet"],contract=profile,closed141=closed,projection_only=projection,held_invocation=held,
                candidate_guard_sample=own and own["sample"],candidate_home_bytes=TREE+EVIDENCE,candidate_ram_bytes=RAM,
                candidate_cpu_quota_micros=3_000_000,joint_funding=j,phase170=phase,protected170=peer,
                tail_anonymous_resident=t_res,peer_anonymous_resident=peer_res,auxiliary=aux,
                resource_credit_bytes=0,archive_publication_authorized=False,**quote)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("fleet");parser.add_argument("sha");parser.add_argument("held",nargs="?")
    parser.add_argument("--project",action="store_true")
    args=parser.parse_args()
    print(json.dumps(price(args.fleet,args.sha,args.held,args.project)))
