"""Read-only pricing and invocation preparation for the epoch 169 private hourly diagnostic."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import stat

HOME = Path("/home/sol")
PRIVATE = HOME / ".jetstreamer-private"
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
LANE = PRIVATE / "epoch169-hourly-source-20261123-v1"
DEST = LANE / "v158"
RUN = LANE / "hourly-run"
BIND = Path("/run/horizon-169-hourly")
CONTROL = ROOT / "epoch169-hourly-admission-20261123-v1"
OLD = ROOT / "epoch169-focused-admission-20261120-v4"
GUARD = ROOT / "epoch170-retry9-recovery-20261120-v1/guard-v1/guard"
GUARD_SHA = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
RELEASE = ROOT / "epoch169-hourly-release-proof-1795425829301762377/HANDOFF.json"
RELEASE_SHA = "18ea5efb5b49dc56972c6c725f0e5b12aad029b085ef1a7162cc2077a8a25bb2"
RESTORE = LANE / "SOURCE_RESTORE_PLANS_081757.json"
RESTORE_SHA = "e22357c68c672ba35425a454dd49eacb366eccbf8a5e0e6a524ca2f89f793b00"
QA = LANE / "HOURLY_SOURCE_AND_TARGET_QA.json"
QA_SHA = "4ea867e664a7676b864df86155493006fe4f5cf282f121974d59006bd0be8544"
MODEL = ROOT / "survivor172-cadence-20261122-v1/hourly169-after084757-20261123-v1/CHECKED_PROJECTION.json"
MODEL_SHA = "48fe295aa8c79f229bc83c595f1f901517c832c067a1a7ec1a4a87154871959d"
OLD_CPU = "803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc"
SIX_CPU = "e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb"
UNIT = "horizon-qualify-169-focused-hourly-20261123-v1.service"
GUARD_UNIT = "horizon-guard-169-focused-hourly-20261123-v1"
GIB = 1 << 30
# Reserve part of the existing 16 MiB margin for fixed root-owned dispatch metadata.
# Put all growing logs, guard receipts, leases, and worker scratch inside the guarded tree.
CONTROL_BUDGET = 8 << 20
NODE_ALIAS = BIND / "jetstreamer-node"
WORKER_ALIAS = BIND / "v158-worker"
SOURCE = PRIVATE / "epoch169-focused-diagnostic-20261117-v1/v158"
INDEX = PRIVATE / "epoch169-standard-lane-20261109-v1/output/compact-indexes/169"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def pin(path, expected):
    data = path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == expected, f"changed receipt {path}")
    return json.loads(data)


def bound(ref):
    return pin(Path(ref["path"]), ref["sha256"])


def same_file(path, row):
    first = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(first.st_mode) and first.st_nlink == 1,
         f"unexpected source {path}")
    for key, value in (("device", first.st_dev), ("inode", first.st_ino), ("size", first.st_size),
                       ("mtime_ns", first.st_mtime_ns)):
        need(row[key] == value, f"{path} {key} differs from receipt")
    return first


def restore_receipt(plan, report):
    args = plan["argv"]
    def option(name):
        return args[args.index(name) + 1]
    generation = int(option("--versioned-uri").split("#")[1])
    dest = Path(option("--destination"))
    need(report["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1" and
         report["script_sha256"] == pin(RESTORE, RESTORE_SHA)["approved_restorer"]["sha256"] and
         report["generation"] == generation == plan["generation"] and
         report["versioned_uri"] == option("--versioned-uri") and report["destination"] == str(dest) and
         report["gcloud_account"] == option("--gcloud-account") and
         report["billing_project"] == option("--billing-project") and
         report["r2_mutations"] is False and report["remote_mutations"] is False, "wrong generation or restore provenance")
    remote, local = report["remote_object"], report["file"]
    need(remote["generation"] == generation and remote["versioned_uri"] == report["versioned_uri"] and
         remote["size"] == local["size"] == int(option("--expected-size")) and
         remote["md5_base64"] == local["md5_base64"] == option("--expected-md5") and
         remote["crc32c_base64"] == local["crc32c_base64"] == option("--expected-crc32c") and
         bool(re.fullmatch("[0-9a-f]{64}", local["sha256"])), "unjoined remote or restored checksum")
    return dest, local


def sources():
    plans = pin(RESTORE, RESTORE_SHA)["plans"]
    need([p["epoch"] for p in plans] == [146,169], "changed transfer order")
    restored = {}
    for p in plans:
        args = p["argv"]
        receipt = Path(args[args.index("--receipt") + 1])
        try:
            raw = receipt.read_bytes()
        except FileNotFoundError as exc:
            raise ValueError(f"waiting for epoch {p['epoch']} generation {p['generation']} restore receipt {receipt}") from exc
        report = json.loads(raw)
        dest, row = restore_receipt(p, report)
        restored[str(p["epoch"])] = {"receipt": str(receipt), "sha256": hashlib.sha256(raw).hexdigest(),
                                      "file": row, "observed_at_utc": report["observed_at_utc"]}
        if p["epoch"] == 169:
            st = same_file(dest,row)
            need(st.st_uid == 1001 and not st.st_mode & 0o077 and st.st_dev == HOME.stat().st_dev and
                 sha(dest) == row["sha256"], "hourly Bank identity or digest changed")
            after = same_file(dest,row)
            need(st.st_ctime_ns == after.st_ctime_ns, "hourly Bank changed during source inspection")
            restored["169"]["verified_ctime_ns"]=after.st_ctime_ns
    return restored


def price(native, projection, account_staging=True):
    previous = pin(OLD / "POST_GUARD_CAPACITY.json", OLD_CPU)
    full = pin(ROOT / "epoch172-full-half-core-20261120-v1/POST_GUARD_CAPACITY.json", SIX_CPU)
    handoff = pin(RELEASE, RELEASE_SHA)
    evidence = pin(QA, QA_SHA)
    need(handoff["source_commit"] == "807a0ba0603a1fa588307940b84554916c901144" and
         evidence["qualified_restore_plan"]["sha256"] == RESTORE_SHA, "different hourly route")
    need(previous["simultaneous_cpu_upper_bound_micros"] == 63_250_000 and
         full["complete_cpu_quota_micros"] == native["complete_cpu_quota_micros"] == 64_000_000 and
         previous["complete_memory_plus_reserve_bytes"] == full["complete_memory_plus_reserve_bytes"] ==
         native["complete_memory_plus_reserve_bytes"] == 810_658_050_048, "changed actor funding")
    old_owner = native["closed_focused169"]
    need(full["owners"]["169"]["iid"] == old_owner["producer_invocation_id"] ==
         "0dfa0d36fbc246c28443a1c90a82c9cb", "different previous focused actor")
    for key in ("admission","terminal","guard_retirement"):
        bound(old_owner[key])
    terminal = bound(old_owner["terminal"])
    for key in ("closed_log","private_output"):
        row = terminal[key]
        st = same_file(Path(row["path"]),row)
        need(st.st_ctime_ns == row["ctime_ns"], "original 169 evidence changed")
    need(native["candidate136"]["occupied"] is False and native["candidate136"]["loan_micros"] == 0
         and set(native["survivors"]) == {"172"} and set(native["replacements"]) == {"166","167","168","170"},
         "different 136/171 donor or peer topology")
    need(native["resource_credit_bytes"] == 0, "incomplete fleet or audit")
    need(projection["latest_fleet"] == native["fleet"], "different projection and price fleet")
    public_workers = runpy.run_path(str(Path(__file__).with_name("actor.py")))["public_workers"]
    workers = public_workers(native, bound(native["fleet"]))
    base = native["complete_required_HOME_bytes"]
    protected = max(base, base-native["recovery_obligations"]["missing_mirror_bytes"]+
                    projection["audit_growth_and_mirror_bytes"])
    available = min(native["available_HOME_bytes"],projection["conservative_available_home"])
    plans = pin(RESTORE, RESTORE_SHA)["plans"]
    staging = sum(r["new_allocated_allowance"] for r in plans) if account_staging else 0
    workspace = pin(MODEL,MODEL_SHA)["size_scenario"]["additional_private_workspace_including_25pct"]
    need(workspace == 68_117_473_606, "different private workspace model")
    need(available >= protected + staging + workspace and
         native["available_memory_bytes"] >= native["required_available_memory_bytes"], "insufficient HOME or memory")
    booking = native["bookings"]["169"]
    need(booking["cap_bytes"] == 96*GIB and booking["physical_bytes"]+booking["remaining_bytes"] ==
         booking["cap_bytes"], "lost predecessor booking")
    return dict(fleet=native["fleet"],protected_HOME=protected,available_HOME=available,
                future_staging=staging,private_workspace=workspace,worker_growth=workspace-CONTROL_BUDGET,
                fixed_control_allowance=CONTROL_BUDGET,margin=available-protected-staging-workspace,
                original_cap=booking["cap_bytes"],original_remaining=booking["remaining_bytes"],
                added_cpu_micros=0,added_memory_bytes=0,producer_cpu_micros=3_000_000,guard_cpu_micros=1_000_000,
                producer_memory=68*GIB,guard_memory=GIB,credit_for_retirement=0,public_audit_children=len(workers),
                native_admission_eligible=native.get("admission_eligible") is not False,forecast_only=True)


def launch_recipe():
    handoff = pin(RELEASE, RELEASE_SHA)
    evidence = pin(QA, QA_SHA)
    snap = LANE / "inputs" / evidence["snapshot_manifest"].splitlines()[0]
    archive = DEST / "epoch-169-through-73245218.jet"
    return dict(unit=UNIT, guard_timer=GUARD_UNIT+".timer", regular_lock="/run/horizon-epoch171-to136-g1.operation.lock",
                gate_script=str(BIND/"hourly_gate.py"), protected_worker_tree=str(LANE),
                producer_argv=list(map(str,[NODE_ALIAS,"169",DEST,"--verify","--qualification-end-slot=73245218",
                               f"--snapshot-archive={snap}",f"--epoch-hashes={DEST}/epoch-hashes-169-focused.txt",
                               f"--horizon-output={archive}",f"--replay-scratch={DEST}/scratch"])),
                private_run_root=str(RUN/"private"),tmpdir=str(RUN/"tmp"),log=str(RUN/"producer.log"),
                read_only_binds=[[handoff["node"]["path"],str(NODE_ALIAS)],
                                 [handoff["worker"]["path"],str(WORKER_ALIAS)],
                                 [str(SOURCE/"compact-indexes/168"),str(DEST/"compact-indexes/168")],
                                 [str(INDEX),str(DEST/"compact-indexes/169")],
                                 [str(SOURCE/"genesis.tar.bz2"),str(DEST/"genesis.tar.bz2")]],
                immutable_inputs=[str(snap),str(DEST/"epoch-hashes-169-focused.txt")],
                time_bounds=dict(bootstrap_gate_seconds=90,guard_first_seconds=1,guard_interval_seconds=5),
                source_hash_manifest=evidence["snapshot_manifest"],source_hash_manifest_sha256=evidence["snapshot_manifest_sha256"],
                terminal_slot=73_245_218,terminal_hash=evidence["archived_sources"][1]["accounts_hash"],
                target=evidence["signed_target"]["slot"],output=str(archive),replay_launch_authorized=False,
                canonical_publication_authorized=False)


def guard_plan(iid, floor, cap):
    need(re.fullmatch("[0-9a-f]{32}", iid) and int(iid,16) and floor>0 and cap>0, "invalid guard binding")
    return dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=UNIT,invocation_id=iid,
                filesystem=str(HOME),minimum_free_bytes=floor,worker_root=str(LANE),maximum_worker_vmas=3_500_000,
                maximum_root_physical_bytes=cap,receipt_directory=str(LANE/"hourly-guard-receipts"))


def producer_service():
    recipe = launch_recipe()
    lines = {}
    template = Path(__file__).resolve().parents[1] / "horizon_epoch169_focused_admission_20261120_v1/producer.service"
    if not template.exists():
        template=Path(__file__).resolve().with_name("g4-producer.service")
    need(sha(template) == "0cd2a78c8f67483be1af6f5fe63cbfb2b05a455fc6dfece4f9798f9ba1379fc4",
         "different predecessor service hardening")
    binds = recipe["read_only_binds"] + [[str(CONTROL/"sealed/hourly_gate.py"),str(BIND/"hourly_gate.py")]]
    lines.update(ExecPaths=f"{NODE_ALIAS} {WORKER_ALIAS} {DEST}/scratch",ReadWritePaths=f"{DEST} {RUN}",
                 ReadOnlyPaths=" ".join(recipe["immutable_inputs"] + [str(DEST/"genesis.tar.bz2"),
                                      str(DEST/"compact-indexes/168"),str(DEST/"compact-indexes/169")]),
                 BindReadOnlyPaths=" ".join(f"{src}:{dst}" for src,dst in binds),
                 Description="Guarded private epoch 169 hourly Bank reproduction",WorkingDirectory=str(DEST),
                 ExecStart=f"/usr/bin/python3 -IB {BIND}/hourly_gate.py",
                 StandardOutput=f"append:{RUN}/producer.log",StandardError=f"append:{RUN}/producer.log")
    result = []
    for row in template.read_text().splitlines():
        key = row.split("=",1)[0]
        result.append(f"{key}={lines.pop(key)}" if key in lines else row)
    need(not lines, "missing predecessor service property")
    idx=result.index("[Unit]")+1
    result[idx:idx]=["OnSuccess=horizon-169-hourly-terminal-20261123-v1.service","OnFailure=horizon-169-hourly-terminal-20261123-v1.service"]
    return "\n".join(result)+"\n"


def guard_argv(plan_path, plan_sha):
    prev = pin(OLD/"GUARD_ARGV.json","b9874a84eb7d127d4be36ba23593985218f101a6247c04131d53ea6c4ee65624")
    old_unit = "horizon-qualify-169-focused-20261120-v4.service"
    old_guard = "horizon-guard-169-focused-20261120-v4"
    need(prev[-6] == str(GUARD) and prev[-4:] == ["--plan-sha256",
         "3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58","--self-sha256",GUARD_SHA],
         "different predecessor guard")
    receipts = LANE/"hourly-guard-receipts"
    args = []
    for v in prev[:-6]:
        v = v.replace(old_unit,UNIT).replace(old_guard,GUARD_UNIT)
        for src,dst in ((OLD/"guard-receipts",receipts),(OLD/"guard.stdout",receipts/"guard.stdout"),
                        (OLD/"guard.stderr",receipts/"guard.stderr")):
            v = v.replace(str(src),str(dst))
        args.append(v)
    return ["/usr/bin/systemd-run",*args,str(GUARD),str(plan_path),"--plan-sha256",plan_sha,"--self-sha256",GUARD_SHA]


def first_guard(sample, plan, plan_sha, producer, timer, manager):
    iid = plan["invocation_id"]
    need(plan == guard_plan(iid,plan["minimum_free_bytes"],plan["maximum_root_physical_bytes"]),
         "different physical or service guard")
    need(sample["schema"]=="jetstreamer-horizon-standalone-guard-sample-v1" and
         sample["guard_sha256"]==GUARD_SHA and sample["plan_sha256"]==plan_sha and
         sample["producer_invocation_id"]==producer["InvocationID"]==iid and producer["Id"]==UNIT and
         producer["ActiveState"]=="active" and producer["SubState"]=="running" and
         producer["Job"]=="" and producer["NRestarts"]=="0" and int(producer["MainPID"])>1 and
         sample["producer"]["pid"]==int(producer["MainPID"]) and sample["producer"]["invocation_id"]==iid and
         sample["producer"]["cgroup"]=="/system.slice/"+UNIT and sample["producer"]["active"]=="active" and
         sample["producer"]["sub"]=="running" and sample["producer"]["restarts"]==0, "unbound first guard owner")
    need(timer["Id"]==GUARD_UNIT+".timer" and timer["ActiveState"]=="active" and timer["Job"]=="" and
         timer["Triggers"]==manager["Id"]==GUARD_UNIT+".service" and manager["Job"]=="" and
         manager["TriggeredBy"]==timer["Id"] and manager["InvocationID"]==sample["guard_invocation_id"] and
         re.fullmatch("[0-9a-f]{32}",timer["InvocationID"]) and int(timer["InvocationID"],16) and
         manager["Result"]=="success" and manager["ExecMainStatus"]=="0", "first sample was not a timer completion")
    observed=sample["root_physical_observation"]
    need(sample["workers"]==[] and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None and
         sample["worker_observation_error"] is None and sample["root_physical_observation_error"] is None and
         sample["minimum_free_bytes"]==plan["minimum_free_bytes"]<=sample["available_bytes"] and
         sample["maximum_worker_vmas"]==3_500_000 and sample["maximum_root_physical_bytes"]==
         observed["maximum_physical_bytes"]==plan["maximum_root_physical_bytes"] and
         0 < observed["conservative_physical_bytes"] <= plan["maximum_root_physical_bytes"] and
         observed["exceeds_budget"] is False and sample["scratch_deleted"] is False and
         sample["r2_mutations"] is False and sample["remote_mutations"] is False and
         sample.get("DATA_fulfillment") is None and sample["bounded_measurement"] is False and
         sample["bounded_canary"] is None and sample["native_main"] is None, "first sample lacks clean pre-payload protection")

def main():
    parser = argparse.ArgumentParser(__doc__)
    commands = parser.add_subparsers(dest="command",required=True)
    quote = commands.add_parser("price")
    quote.add_argument("projection",type=Path)
    quote.add_argument("sha256")
    commands.add_parser("recipe")
    commands.add_parser("service")
    commands.add_parser("sources")
    args = parser.parse_args()
    if args.command == "service":
        print(producer_service(),end="")
        return
    if args.command == "price":
        projection=pin(args.projection,args.sha256)
        result=price(bound(projection["native_capacity"]),projection)
    elif args.command == "sources":
        result=sources()
    else:
        result=launch_recipe()
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__ == "__main__":
    main()
