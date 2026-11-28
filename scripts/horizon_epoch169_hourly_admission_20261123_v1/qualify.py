"""Qualify read-only preparation and guard/terminal contracts using the registered host evidence."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

HERE=Path(__file__).resolve().parent
h=runpy.run_path(str(HERE/"hourly.py"))
g=runpy.run_path(str(HERE/"hourly_gate.py"))
w=runpy.run_path(str(HERE/"watch.py"))
need=h["need"]


def reference(p):
    return dict(path=str(p),sha256=h["sha"](p))


def check(output):
    need(os.geteuid()==0 and output.parent==h["ROOT"] and output.name.startswith("epoch169-hourly-admission-qa-"),
         "use a new private host qualification output")
    output.mkdir(mode=0o700)
    cases=[]
    def case(name, fn, fails=False):
        try:
            value=fn()
        except ValueError as e:
            if not fails: raise
            cases.append(dict(name=name,expected_denial=str(e)));return
        need(not fails,"negative case unexpectedly passed "+name)
        cases.append(dict(name=name,passed=True))
        return value
    def put(name, obj):
        path=output/name
        with path.open("xb") as f:
            f.write((json.dumps(obj,indent=2,sort_keys=True)+"\n").encode())
            f.flush(); os.fsync(f.fileno())
        path.chmod(0o400)
        return reference(path)

    qfile=h["ROOT"]/"survivor172-cadence-20261122-v1/forecast-five-091757-20261123-v1/CHECKED_PROJECTION.json"
    proj=h["pin"](qfile,"53d927d34dddbfc21ce2d88f4055de33e20d95057280a58dcb575f6a751c8448")
    native=h["bound"](proj["native_capacity"]);quote=case("five live owners and seven progressing audit reservations",lambda:h["price"](native,proj))
    need(quote["margin"]==17_513_154_234 and not quote["native_admission_eligible"],"different 09:17 margin")
    put("SCREEN.json",quote)
    case("unfunded source and workspace",lambda:h["price"](dict(native,available_HOME_bytes=quote["protected_HOME"]),proj),True)
    case("new 136 loan or actor",lambda:h["price"](dict(native,candidate136=dict(native["candidate136"],occupied=True)),proj),True)
    case("changed audit roster",lambda:h["price"](dict(native,recovery_obligations=dict(native["recovery_obligations"],public_workers=[])),proj),True)
    plans=h["pin"](h["RESTORE"],h["RESTORE_SHA"])
    for row in plans["plans"]:
        argv=row["argv"];option=lambda key:argv[argv.index(key)+1]
        size=int(option("--expected-size")); uri=option("--versioned-uri")
        shared=dict(size=size,md5_base64=option("--expected-md5"),crc32c_base64=option("--expected-crc32c"))
        local=dict(shared,sha256="ab"*32);remote=dict(shared,generation=row["generation"],versioned_uri=uri)
        record=dict(schema="jetstreamer-bound-gcs-snapshot-restore-v1",script_sha256=plans["approved_restorer"]["sha256"],
                    generation=row["generation"],versioned_uri=uri,destination=option("--destination"),gcloud_account=option("--gcloud-account"),
                    billing_project=option("--billing-project"),r2_mutations=False,remote_mutations=False,file=local,remote_object=remote)
        ep=str(row["epoch"])
        case(ep+" transfer receipt fixture",lambda:h["restore_receipt"](row,record))
        case(ep+" foreign generation",lambda:h["restore_receipt"](row,dict(record,generation=row["generation"]+1)),True)
        case(ep+" body checksum drift",lambda:h["restore_receipt"](row,dict(record,file=dict(local,md5_base64="BAD"))),True)
    try:
        h["sources"]()
    except ValueError as err:
        real_source_status=str(err)
        need(real_source_status.startswith("waiting for epoch"),"unexpected source check "+real_source_status)
    else:
        real_source_status="both real receipts validated"
    put("ACTUAL_SOURCE_STATUS.json",dict(status=real_source_status))
    recipe=h["launch_recipe"]()
    need(recipe["producer_argv"]==g["command"](),"payload entry point and operator recipe diverged")
    put("PAYLOAD.json",recipe)
    service=output/h["UNIT"];service.write_text(h["producer_service"]());service.chmod(0o400)
    watcher=output/"horizon-169-hourly-terminal-20261123-v1.service"
    watcher.write_bytes((HERE/watcher.name).read_bytes());watcher.chmod(0o400)
    verify=subprocess.run(["systemd-analyze","verify","--man=no",service,watcher],capture_output=True,text=True,timeout=30)
    need(verify.returncode==0,"PID1 service file invalid "+verify.stderr)
    put("SYSTEMD_VERIFY.json",dict(code=verify.returncode,stderr=verify.stderr))
    case("default worker and node transport bindings",lambda:need(str(h["NODE_ALIAS"]) in recipe["producer_argv"] and
         g["WORKER"]==h["WORKER_ALIAS"],"native aliases differ"))
    release=h["pin"](h["RELEASE"],h["RELEASE_SHA"])
    for key in ("node","worker"):
        case("sealed release image "+key,lambda:need(h["sha"](Path(release[key]["path"]))==release[key]["sha256"],"different release image"))
    iid="12"*16
    sample_iid="34"*16
    floor=quote["protected_HOME"]
    cap=2_097_152_000+quote["worker_growth"]
    plan=h["guard_plan"](iid,floor,cap);pref=put("STATIC_FIXTURE_PLAN.json",plan)
    argv=h["guard_argv"](Path(pref["path"]),pref["sha256"])
    put("STATIC_FIXTURE_GUARD_ARGV.json",argv)
    case("sealed guard in immutable production shape",lambda:need(h["sha"](h["GUARD"])==h["GUARD_SHA"],"guard image differs"))
    native_argv=argv[-6:]+["--validate-plan-only"]
    validated=json.loads(subprocess.check_output(native_argv,timeout=15))
    need(validated["unit"]==h["UNIT"] and validated["validated"] and validated["resource_samples_taken"]==0 and
         not validated["producer_signaled"] and not validated["protective_guard_proven"],"guard validator result")
    put("NATIVE_STATIC_GUARD_VALIDATION.json",validated)
    first=json.loads((h["OLD"]/"FIRST_GUARD.json").read_bytes()); sample=copy.deepcopy(h["bound"](first["receipt"]))
    sample.update(producer_invocation_id=iid,guard_invocation_id=sample_iid,plan_sha256=pref["sha256"],
                  maximum_root_physical_bytes=cap,minimum_free_bytes=floor,available_bytes=floor+123456)
    sample["root_physical_observation"].update(maximum_physical_bytes=cap,conservative_physical_bytes=2_097_152_000)
    sample["producer"].update(invocation_id=iid,cgroup="/system.slice/"+h["UNIT"])
    producer=dict(first["producer"],Id=h["UNIT"],InvocationID=iid)
    timer=dict(first["timer"],Id=h["GUARD_UNIT"]+".timer",Triggers=h["GUARD_UNIT"]+".service")
    manager=dict(first["guard"],Id=timer["Triggers"],TriggeredBy=timer["Id"],InvocationID=sample_iid)
    ck=lambda s:h["first_guard"](s,plan,pref["sha256"],producer,timer,manager)
    case("timer-driven first guard schema applied to hourly owner",lambda:ck(sample))
    for k,v in (("producer_stop_enabled",False),("trip_reason","root-physical-budget"),("workers",[[345,121]]),
                ("available_bytes",floor-1),("producer_invocation_id","89"*16),("guard_invocation_id","89"*16)):
        case("reject first guard "+k,lambda:ck(dict(sample,**{k:v})),True)
    grant=dict(schema="epoch169-hourly-private-postguard-release-v1",unit=h["UNIT"],invocation_id=iid,pid=112,
               start_ticks=232,boot_id="a1"*16,issued_unix_seconds=1000,producer_cpu_micros=3_000_000,
               guard_cpu_micros=1_000_000,memory_max=68<<30,guard_memory_max=1<<30,canonical_publication_authorized=False)
    for key in ("first_guard_sha256","native_post_guard_price_sha256","registered_watcher_sha256","verified_source_receipt_sha256",
                "guard_plan_sha256","snapshot_sha256"):
        grant[key]="cd"*32
    ack=lambda a:g["verify_grant"](a,iid,112,232,"a1"*16,1012)
    case("original gate accepts actual named conditions",lambda:ack(grant))
    for k,v in (("pid",113),("registered_watcher_sha256",""),("issued_unix_seconds",500),
                ("canonical_publication_authorized",True),("memory_max",69<<30)):
        case("reject grant "+k,lambda:ack(dict(grant,**{k:v})),True)
    manifest=dict(schema_version=1,epoch=169,output_slot_start=73_238_441,output_slot_count=6778,
                  bootstrap=dict(slot=73_238_440,accounts_hash=w["BOOT_HASH"]),
                  terminal=dict(slot=73_245_218,accounts_hash=w["TERMINAL_HASH"],slot_complete=True),
                  runtime=dict(runtime_profile="solana-v1.5.8",runtime_admission="candidate"),
                  worker_executable_sha256=w["WORKER"],archive_sha256="69"*32)
    case("hourly terminal manifest",lambda:w["auth_manifest"](manifest))
    for k,v in (("output_slot_count",237219),("worker_executable_sha256","00"*32),("bootstrap",manifest["terminal"])):
        case("reject terminal "+k,lambda:w["auth_manifest"](dict(manifest,**{k:v})),True)
    def lines(m):
        return [(x+"\n").encode() for x in m]
    feature="epoch169 diagnostic bank feature at slot 73239086 entry 164: per_byte_logging_cost active=false activated_slot=None"
    stream=lines([feature,"historical checkpoint slot=73245218 bank_hash=xyz accounts_hash="+w["TERMINAL_HASH"]+" last_blockhash=xyz complete=true writes=1",
                   "horizon archive complete: slots=6778 blocks=1 txs=23 bytes=456 (payload 123 uncompressed)",
                   "published verified historical segment evidence "+str(w["MANIFEST"])])
    case("ordered private terminal proof",lambda:need(w["classify"](stream,"success",False,456)=="completed-private-span","terminal proof"))
    case("guard stop prevents any completion",lambda:need(w["classify"](stream,"success",True,456)=="interrupted-or-unclassified","guard stop"))
    case("wrong archive length",lambda:need(w["classify"](stream,"success",False,457)=="interrupted-or-unclassified","length"))
    wrong=w["TARGET"]+"Some(InstructionError { instruction_index: 2, error: ComputationalBudgetExceeded })"
    mismatch=lines([feature,"WARN  jetstreamer_node] replay failure: historical worker batch failed from slot 1 "+wrong,
                    "error: historical worker batch failed from slot 1 "+wrong])
    case("original signed discrepancy",lambda:need(w["classify"](mismatch,"failure",False)=="diagnosed-target-mismatch","mismatch"))
    runpy.run_path(str(HERE/"provider_fixture.py"))["cases"](native,case,need)
    cached=runpy.run_path(str(HERE/"prepare.py"))["indexes"]()
    put("ACTUAL_COMPACT_INDEX_AND_GENESIS.json",cached)
    return put("QUALIFIED.json",dict(cases=cases,source_status=real_source_status,native_static_guard=validated,
               release=release,cases_passed=len(cases),source={p.name:reference(p) for p in sorted(HERE.glob("*.py"))},
               fixture_invocation_only=True,live_gcs_calls=0,live_r2_calls=0,real_workload_start=False))


if __name__=="__main__":
    parser=argparse.ArgumentParser(__doc__)
    parser.add_argument("output",type=Path)
    args=parser.parse_args()
    print(json.dumps(check(args.output),sort_keys=True))
