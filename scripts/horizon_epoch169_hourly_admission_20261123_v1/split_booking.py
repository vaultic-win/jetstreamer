"""Read-only lineage for the booked private focused 169 worker."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
B=Path("/var/lib/jetstreamer/horizon_runtime_data")
G=1<<30
TMPFS_SHA="a32df85b252f81e3cb82836dc89e9d76603e85df5a1180ad270885a9fd7b24bf"
SIX="e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb"
CLOSE="218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5"
DRAIN="113c410f773cfb565bbed3de95d1c9b7fc17b278010fcae14fa92728a90e1448"
LOCK=Path("/run/horizon-epoch171-to136-g1.operation.lock")
U="horizon-qualify-169-focused-hourly-20261123-v1.service"
def pin(p,h,refs):
    p=Path(p);st=p.lstat()
    assert p.resolve(strict=True)==p and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022,p
    raw=p.read_bytes(); assert hashlib.sha256(raw).hexdigest()==h,p
    refs.append(dict(path=str(p),sha256=h))
    return json.loads(raw)
def read(ref,refs): return pin(ref["path"],ref["sha256"],refs)
def check_idle(unit, exited=None):
    command=["/usr/bin/systemctl","show","--property=Id,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Job,InvocationID,NRestarts,ExecMainStatus,RemainAfterExit",unit]
    out=subprocess.run(command,check=False,capture_output=True,text=True)
    props=dict(l.split("=",1) for l in out.stdout.splitlines())
    drained = props["ActiveState"] in ("inactive","failed") or (exited is not None and props["ActiveState"]=="active" and props["SubState"]=="exited" and props["InvocationID"]==exited and props["ExecMainStatus"]=="0" and props["RemainAfterExit"]=="yes" and props["NRestarts"]=="0")
    assert out.returncode in (0,4) and props["Id"]==unit and drained and not props["Job"] and not props["ControlGroup"] and props["MainPID"]==props["ControlPID"]=="0",unit
    group=Path("/sys/fs/cgroup/system.slice")/unit/"cgroup.procs"
    assert not group.exists() or not group.read_text().strip(),unit
    return props
def prove(raw,books,owner169=None,owner162=None):
    if not __debug__:
        raise RuntimeError("native booking checks require Python assertions")
    ref=[]
    focus=pin(B/"epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json","803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc",ref)
    old=pin(B/"epoch172-full-half-core-20261120-v1/POST_GUARD_CAPACITY.json",SIX,ref)
    owner="0dfa0d36fbc246c28443a1c90a82c9cb"
    assert old["owners"]["169"]["iid"]==owner and focus["candidate_additive_memory_bytes"]==0
    assert old["complete_cpu_quota_micros"]==64_000_000 and old["complete_memory_plus_reserve_bytes"]==810_658_050_048
    assert focus["simultaneous_cpu_upper_bound_micros"]==63_250_000
    full=pin(B/"epoch146-full-local-admission-20261126-v1/FULL146_POST_GUARD_CAPACITY.json","2d8ac8beef9fb4c35ca5a5da18979fcb5789ccabe0a80ae9c8feff32862ea056",ref)
    native=full["native_successor_quote"];terminal=native["closed_focused169"]; loan=native["epoch159_donor_cover"]; correction=native["corrected_159_donor"]
    assert terminal["producer_invocation_id"]==owner and terminal["terminal"]["sha256"]==CLOSE and terminal["guard_retirement"]["sha256"]==DRAIN
    read(terminal["terminal"],ref);read(terminal["guard_retirement"],ref)
    assert native["registered_host_equation"]["source"]["sha256"]==SIX
    assert native["complete_memory_plus_reserve_bytes"]==old["complete_memory_plus_reserve_bytes"]
    assert native["candidate136"]["occupied"] is False and native["candidate136"]["loan_micros"]==0
    assert read(full["proposal"],ref)["reuse_ended_epoch168_compute"] is True
    assert full["fit"]["donor_memory_bytes_used"]==69*G and full["fit"]["donor_cpu_quota_micros_used"]==9_250_000
    assert loan["original_donor_price_sha256"]=="0341586ebc5fd04e0f354fc3081774fdc1d952558dc456542cb79599f4ff6b62"
    orig=pin(B/"epoch159-bounded-reference-20261123-v1/HEAD131757-132005-donor.json",loan["original_donor_price_sha256"],ref)
    h=orig["reserved_hourly"]
    assert [h[k] for k in ("producer_cpu_micros","guard_cpu_micros","producer_memory","guard_memory","added_memory_bytes","added_cpu_micros","private_workspace")]==[3000000,1000000,68*G,G,0,0,68117473606]
    assert orig["charged_reference"]["memory_bytes"]==48*G and orig["charged_reference"]["cpu_cores"]==2
    a=B/"epoch159-bounded-reference-20261123-v1/attempt-v1"; c=B/"epoch159-vote-feature-reference-20261123-v1/attempt-v1"
    pin(a/"driver-exit.json",loan["diagnostic"]["driver_exit"],ref);pin(a/"scratch-retired.json",loan["diagnostic"]["scratch"]["retired"],ref)
    pin(c/"driver-exit.json",correction["terminal"],ref)
    assert correction["stage"]=="drained" and loan["credited_retirement_bytes"]==0
    assert native["phase145"]["stage"]=="independent-semantic-complete-v10-drained"
    src=pin(B/"epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1/BRIDGE_RELEASED_167_FLEET0548_REQUEST.json","6154762ac10677fad75372e012a29032aa8f5ae2efe3048b68e7ff86e272e3bb",ref)
    bridge=read(src["native_reference"],ref); compute=bridge["replacement167_fit"]["compute"]
    assert bridge["full146"]["native_successor_quote"]["closed_focused169"]["producer_invocation_id"]==owner
    assert compute["pre_replacement_memory_plus_reserve_bytes"]==old["complete_memory_plus_reserve_bytes"] and (compute["replaced_167_producer_bytes"],compute["charged_167_producer_bytes"],compute["charged_167_guard_bytes"])==(68*G,42*G,G)
    assert compute["post_replacement_memory_plus_reserve_bytes"]==782740762624 and compute["complete_cpu_quota_micros"]==64000000
    settlement=bridge["terminal168_compute_settlement"]
    assert settlement["source_scope_epoch"]==167 and settlement["terminal"]["path"]==str(B/"epoch168-joint-checkpoint-reduced-run-20261126-v1/TERMINAL.json") and settlement["replaced_168_memory_bytes"]==60*G and settlement["released_memory_bytes"]==54*G
    intent=pin(B/"epoch167-checkpoint-tail-20261127-v1/START_INTENT.json","976b1beb6c24ecb2aa0eb50ffc4fd451f971c94c6698e54fbee6005a2c8ba560",ref)
    compute167=intent["quote"]["exact_native_fit"]
    assert compute167["prior_fit"]["sha256"]=="691f6fbdb859597b760ebc29067d5db903298c0e38411591285d0ec61a79277d"
    total_full = compute167["required_available_memory_bytes"]+compute167["resident_lower_bound_bytes"]
    assert total_full == 782740762624+6*G+4*G+(192+8)*(1<<20)
    post=pin(B/"epoch167-checkpoint-tail-20261127-v1/POST_GUARD_CAPACITY.json","3a834858ca1b1fb7a485fc7fcf6cfe9d01dad9dd980137699b5454d4a26fbdbe",ref)
    assert post["intent"]["sha256"]==ref[-2]["sha256"] and post["required_ram_bytes"]==compute167["required_available_memory_bytes"]
    q=raw["raw"]; j=q["joint"]
    ret=read(j["return140"],ref); assert ret["producer_and_guard_drained"]
    b140=read(j["booking140"],ref)["cpu_donor"]
    assert b140["unit"]=="horizon-qualify-170-full-metered-20261124-v1.service" and b140["bridge_invocation_id"]==read(j["loan140"],ref)["live_bridge_invocation"]
    assert j["producer_allowance"]==48*G and j["guard_sibling_allowance"]==G and q["guarded_hourly_remaining"]==64*G and q["concurrent_143_growth_bytes"]==0 and not q["replacement143"]
    assert q["assembly168"]["incremental_ram"]==2*G and not q["resource_credit_bytes"] and not raw["resource_credit_bytes"]
    assert j["required_ram"]+j["resident_lower_bytes"]>=total_full and books["rooms"]["holding_ram_available_from_serial"]==2*G
    fleet=read(q["fleet"],ref)
    assert fleet["current_private_169_observer_result"]["terminal"]==terminal["terminal"]
    assert not fleet["terminal169_resource_promise_ending_bytes"] and not fleet["terminal169_resource_credit_bytes"] and not fleet["all_reservation_ending_bytes"]
    rows=fleet["actual_executing_replays"]+fleet["actual_active_private_diagnostics"]
    own = [r for r in rows if r["epoch"] == 169]
    registered162 = [r for r in rows if r["epoch"] == 162]
    if registered162:
        assert len(registered162) == 1 and owner162 and owner162["phase"] in ("held","bootstrap","worker")
        assert registered162[0]["held_owner"] == owner162["held_owner"] and registered162[0]["unit"]["Id"] == owner162["unit"]["Id"]
        assert registered162[0]["unit"]["InvocationID"] == owner162["invocation_id"]
    assert sorted(r["epoch"] for r in rows if r["epoch"] not in (169,162)) == [146, 167, 170, 172]
    if own:
        assert owner169 and len(own) == 1 and own[0]["hourly169_start_intent"] == owner169["hourly169_start_intent"]
    if owner169:
        assert owner169["phase"] in ("held", "bootstrap", "worker") and owner169["unit"]["Id"] == U
        assert owner169["binding"]["unit"] == U and owner169["binding"]["producer_iid"] == owner169["unit"]["InvocationID"]
        assert owner169["binding"]["private_scratch_mount"]["ram_limit_bytes"] == 44 * G
    users=[U,old["owners"]["169"]["unit"],"horizon-epoch159-bounded-vote-trace-20261123-v1.service",correction["unit"],native["phase145"]["Id"],native["phase145"]["verifier_unit"],"horizon-admit-136-actual-20261120-g1.service","horizon-qualify-136-actual-20261120-g1.service"]
    idle={u:check_idle(u, native["phase145"]["completed_invocation_id"] if u==native["phase145"]["verifier_unit"] else None) for u in users if u != U or owner169 is None}
    return dict(same_169_compute=True,fleet=q["fleet"],previous_focus=owner,references=ref,bounded_167_base=total_full,original_146_donor_epoch=168,retained_146_donor_memory=full["fit"]["donor_memory_bytes_used"],temporary159_loan_memory=48*G,static_169_memory=69*G,static_169_cpu=4000000,actual_idle_units=idle)
