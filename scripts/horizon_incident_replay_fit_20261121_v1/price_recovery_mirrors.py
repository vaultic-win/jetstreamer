#!/usr/bin/python3 -IB
"""Price the failed V5e bootstrap and the two original 136 mirror inputs on one accepted audit generation."""
import json
import os
from pathlib import Path
import runpy
import sys
import time

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = R / "incident-replay-fit-20261121-v1"
NATIVE = BASE / "tools-v20-prestart"
SEAL = "952f6e40c056d57d4541728a56a31b3058c2b55337dc96ed88d76903af86631a"
V6 = R / "epoch136-joint-writer-20261122-v6/preflight-tools"
V6_SEAL = "404c245db5060e54e24295cb54de1d60d5549f657fc288c2185c4c72612a8ee8"
CADENCE = R / "prefix140-status-cadence-20261122-v1/cadence-tools"
CADENCE_SEAL = "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e"
ADAPTER = R / "epoch166-retry10-delivery-20261121-v1/capacity-tools-bounded/publication-fit"
CLOSED = R / "ready-range-audit-20261121-v1/accepted/144-144.json"
CLOSED_SHA = "4565e2da06301ac2cc738eaa060af1decb1a50949c9738bbaba02d29c8bccac2"


def capture(path, digest, active_seal=None, *, successor=None, capture_native=None):
    # Start with the same root-owned sealed loader and the V6 mirror, prefix and host budget routines.
    import hashlib
    def pinned(p,sha):
        if p.resolve(strict=True)!=p or p.stat().st_uid!=0 or p.stat().st_mode & 0o222 or hashlib.sha256(p.read_bytes()).hexdigest()!=sha:
            raise ValueError("changed price input " + str(p))
    pinned(V6/"incident_prestart.py","ccb02a582afaadaefdebf824a1105ca6b0eb434c782fefd9fd70d0b39278fdf1")
    v6=runpy.run_path(str(V6/"incident_prestart.py"))
    require=v6["require"]
    require(os.geteuid()==0 and sys.flags.isolated and __debug__ and path.parent.parent==R and
            path.name=="ROOT_COMPLETE_OPERATIONAL_FLEET.json","foreign caller or fleet")
    native_package = NATIVE if active_seal is None else BASE / "tools-v20"
    native_seal = SEAL if active_seal is None else active_seal
    guard_terminal = Path(__file__).resolve().parent == BASE / "tools-v22-prestart"
    if guard_terminal:
        require(isinstance(active_seal,str) and len(active_seal)==64, "V22 bootstrap requires its sealed package")
        native_package = Path(__file__).resolve().parent
    elif successor is not None:
        require(Path(__file__).resolve().parent == BASE / "tools-v22-active-mirrors" and
                active_seal == "87dae932c9b4b0773db56fcd04a1b882ac2b2db2c2b63428b7cb09bf306f546d" and
                callable(capture_native), "unbound successor mirror price")
    elif active_seal is not None:
        require(Path(__file__).resolve().parent == native_package and len(active_seal) == 64,
                "active mirror price requires the original V20 package and seal")
    for package,sha in ((V6,V6_SEAL),(CADENCE,CADENCE_SEAL),(native_package,native_seal)):
        v6["check_package"](package,sha)
    v6["pin"](ADAPTER,v6["ADAPTER_SHA"])
    mirrors=runpy.run_path(str(V6/"price-mirrors"))
    sys.path.insert(0,str(CADENCE))
    from evidence import checked
    from retired_public_audit import observe_public
    from prefix140_storage import storage
    ref=dict(path=str(path),sha256=digest)
    fleet=checked(ref)
    ready=fleet["active_ready_range_audit_obligation"]
    historical=fleet["continuing_audit_obligation"]
    recorded=checked(fleet["current_home_cycle_capacity"])
    observation=checked(fleet["current_audit_progress"]["observation"])
    terminal=dict(path=str(CLOSED),sha256=CLOSED_SHA)
    receipt=checked(terminal)
    require(ready["current_observation"]==fleet["current_audit_progress"]["observation"] and
            ready["current_storage"]==recorded["audit_storage"] and historical["current_storage"]["pricing_basis_only"] and
            historical["current_storage"]["included_in_current_aggregate"] is False and
            historical["current_storage"]["remaining_DATA_growth_bytes"]==18<<30 and
            receipt["schema"]=="horizon-ready-range-verified-v1" and receipt["range"]==[144,144] and
            receipt["exit"]["success"] is True and terminal in observation["summary"]["accepted_ranges"],"fleet lacks the original 144 terminal")
    def audit():
        seen,paid,witness=observe_public(Path("/home/sol").stat().st_dev,historical)
        workers=seen["active_ready_workers"]
        require(witness==recorded["audit_owner_witness"] and witness["native"]["ActiveState"]=="active" and
                workers==observation["active_ready_workers"] and all(x["range"]!=[144,144] for x in workers) and
                terminal in seen["summary"]["accepted_ranges"] and paid["output_budget"]==ready["current_storage"]["output_budget"] and
                paid["maximum_host_allocation_bytes"]==ready["maximum_output_allocation_bytes"]==256<<20,
                "public audit owner, accepted ranges, workers or budget changed")
        return witness,workers,paid
    witness,workers,ready_before=audit()
    prefix_before=storage()
    adapter=runpy.run_path(str(ADAPTER))
    observe = capture_native if successor is not None else adapter["capture_provider"]
    native=json.loads(observe(native_package/"post-stop-fit",str(path),digest))
    phase = native["phase145"]
    if guard_terminal:
        require(phase["InvocationID"] == "50af3d8ab5da47e8bdc2828feab53908" and
                phase["source_checkpoint_exists"] is False and phase["failure"]["sha256"] ==
                "38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd" and
                phase["qualification_census_incident"]["sha256"] ==
                "f4a13a58292296c22dd870d5ecdf4ab4c056f3e06562bb5bb121a899c89f3bb7",
                "foreign V5f guard-fixture terminal")
        semantic_worker = None
    elif active_seal is None:
        require(phase["InvocationID"]=="a99ed8b51e8a482b805b8a36a11b2700" and
                phase["source_checkpoint_exists"] is False,"foreign terminal 145 price")
        semantic_worker = None
    else:
        from evidence import bound
        progress = R / "epoch145-semantic-continuity-20261121-v1/V5F_ACTUAL_ADVANCING_WORKER.json"
        semantic_worker = successor if successor is not None else bound(progress)
        worker = checked(semantic_worker)
        generation = phase["invocation_id"]
        start = checked(worker["start"])
        failed = start["prior_frozen_recovery"]["failed_qualification_census"]["current_boot_failure"]["failure"]
        require(phase["stage"]=="leased-worker" and generation==worker["invocation_id"]==start["iid"]
                and len(worker["observations"])==2 and worker["start"]["path"]==str(
                    R / "epoch145-guarded-export-20261121-v1/state" / generation / "recovery-started.json")
                and failed==dict(path=str(R / "epoch145-guarded-export-20261121-v1/state/a99ed8b51e8a482b805b8a36a11b2700/failed.json"),
                                 sha256="da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"),
                "foreign leased V5f semantic worker or predecessor")
    require(native["fits"] and native["epoch"]==145 and native["fleet"]==ref and
            0<=time.time()-native["recorded_unix_seconds"]<120,"foreign terminal or native price")
    last,last_workers,ready_after=audit()
    prefix_after=storage()
    require(last==witness and workers==last_workers,"public generation changed during price")
    store=mirrors["STORE"];metadata=store.lstat()
    require(store.resolve(strict=True)==store and store.is_dir() and metadata.st_uid==0 and
            metadata.st_mode & 0o7777==0o700 and metadata.st_dev==Path("/home/sol").stat().st_dev,
            "foreign 136 mirror directory")
    disk=os.statvfs(store)
    total=int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1])*1024
    basis=v6["price"](native,native["zero_candidate_floor"],prefix_before,prefix_after,
                      disk.f_bavail*disk.f_frsize,total)
    inputs=[mirrors["inspect_input"](p,h,disk.f_frsize) for p,h in
            ((mirrors["DOWNLOAD"],mirrors["DOWNLOAD_SHA"]),(path,digest))]
    missing=sum(x["required_bytes"] for x in inputs)
    floor=basis["complete_required_HOME_bytes"]+missing
    return dict(schema="horizon-145-bootstrap-136-mirror-price-v1",fleet=ref,native=native,
                provider=dict(path=str(native_package/"deployment-seal-receipt.json"),sha256=native_seal),basis=basis,
                semantic_worker=semantic_worker,
                audit=witness,ready_workers=workers,ready_growth_before=ready_before,ready_growth_after=ready_after,
                accepted144=terminal,prefix_before=prefix_before,prefix_after=prefix_after,
                mirror_inputs=inputs,missing_mirror_bytes=missing,required_with_mirrors_bytes=floor,
                available_HOME_bytes=basis["available_HOME_bytes"],remaining_after_mirrors_bytes=basis["available_HOME_bytes"]-floor,
                mirrors_fit=basis["memory_fits"] and basis["available_HOME_bytes"]>=floor,
                actual_mirror_writes=0,resource_credit_bytes=0,admission_granted=False)


if __name__=="__main__":
    if len(sys.argv) not in (3,4):
        raise SystemExit("price_recovery_mirrors.py FLEET_PATH FLEET_SHA256 [ACTIVE_V20_SEAL_SHA256]")
    result=capture(Path(sys.argv[1]),sys.argv[2],sys.argv[3] if len(sys.argv)==4 else None)
    print(json.dumps(result,sort_keys=True))
    sys.exit(0 if result["mirrors_fit"] else 1)
