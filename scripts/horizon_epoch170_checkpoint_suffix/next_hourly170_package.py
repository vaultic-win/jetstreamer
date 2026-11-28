"""Seal the next private 170 package and bind the workerless namespace proof."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import next_hourly170 as n
from following_prepare import git, need, read, reference, save, seal

ROOT = n.ROOT
INTERFACE = ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json"


def local(name):
    path = ROOT/name
    ref = reference(path)
    need(path.resolve(strict=True) == path and path.stat().st_uid == 0, "unsafe local receipt " + name)
    return read(ref), ref


def package(custody_ref, predecessor_ref, staged_ref):
    os.umask(0o077)
    source = n.source()
    predecessor, stage = read(predecessor_ref), read(staged_ref)
    terminal = n.predecessor(predecessor["closed_comparison"],source["endpoints"][0])
    need(terminal == predecessor["actual_terminal"] and stage["predecessor"] == predecessor_ref
         and stage["no_replay_started"] and not stage["release_created"],
         "mismatched sealed predecessor or empty layout")
    static, ready = local("STATIC_GUARD_READY.json")
    need(stage["static_guard"] == ready and read(static["source"]) == source
         and [row["status"] for row in static["checks"]] == [0,1,1,1]
         and not static["worker_executed"], "different static gate or guard")
    bootstrap = n.local_bootstrap(custody_ref,source["endpoints"][0])
    source.update(predecessor=predecessor_ref, staged_layout=staged_ref,
                  closed_comparison=predecessor["closed_comparison"], preceding_terminal=terminal,
                  bootstrap=bootstrap, bootstrap_custody=custody_ref,
                  checkpoint_names="".join(p["name"]+"\n" for p in source["endpoints"]))
    body = n.service(source,bootstrap["path"])
    destination = ROOT/"package"
    if destination.exists():
        receipt = reference(destination/"deployment-seal-receipt.json")
        members = read(receipt)["members"]
        need(read(receipt)["destination"] == str(destination)
             and all(reference(destination/row["name"])["sha256"] == row["sha256"] for row in members)
             and read(reference(destination/"source.json")) == source
             and (destination/n.UNIT).read_text() == body, "different existing sealed successor")
        return dict(package=receipt,source=reference(destination/"source.json"),
                    provenance=reference(destination/"PROVENANCE.json"),
                    service=reference(destination/n.UNIT),no_worker_started=True)
    repo = Path(__file__).resolve().parents[2]
    revision = git(repo,"rev-parse","HEAD").decode().strip()
    git(repo,"merge-base","--is-ancestor",revision,"origin/account-updates")
    for name in ("next_hourly170.py","next_hourly170_package.py","following_prepare.py"):
        path = Path(__file__).with_name(name).resolve()
        need(git(repo,"show",f"{revision}:{path.relative_to(repo)}") == path.read_bytes(),
             "unpublished package source " + name)

    staging = ROOT/"package-source-v1"
    staging.mkdir(mode=0o700,exist_ok=True)
    need(staging.resolve(strict=True) == staging and staging.stat().st_uid == 0
         and not staging.stat().st_mode & 0o077, "foreign staging")
    source_ref = save(staging/"source.json",source)
    from closed_successor import persist
    persist(staging/"epoch-hashes.txt",source["checkpoint_names"].encode())
    persist(staging/n.UNIT,body.encode())
    source_proof = save(staging/"PROVENANCE.json",dict(source_revision=revision,static=ready,
        source=source_ref,predecessor=predecessor_ref,custody=custody_ref))
    members = {name:(staging/name,0o444) for name in ("source.json","epoch-hashes.txt",n.UNIT,"PROVENANCE.json")}
    for name in ("gate","guard"):
        tool = Path(static[name]["path"])
        need(reference(tool) == static[name], "changed static " + name)
        members[name] = tool,0o555
    receipt = seal(ROOT/"package",members,ROOT/"PACKAGE_PLAN.json")
    return dict(package=receipt,source=reference(ROOT/"package/source.json"),
                provenance=source_proof, service=reference(ROOT/"package"/n.UNIT), no_worker_started=True)


def document(preflight_ref):
    preflight = read(preflight_ref)
    source, src = local("package/source.json")
    stage = read(source["staged_layout"])
    spec = reference(ROOT/"package"/n.UNIT)
    deploy = reference(ROOT/"package/deployment-seal-receipt.json")
    namespaces = read(preflight["namespace"])
    need(preflight["source"] == src and preflight["service"] == spec and preflight["seal"] == deploy
         and preflight["scope"] == [source["first"],source["last"]] and preflight["route_accepted"]
         and not preflight["worker_executed"] and namespaces["report"]["private_mounts"]
         and namespaces["report"]["scratch"]["bytes"] == source["scratch_noswap_tmpfs"]
         and namespaces["report"]["limits"]["memory.max"] == str(source["producer_memory"])
         and namespaces["no_host_scratch_payload"] and stage["no_replay_started"],
         "different workerless namespace or exact source preflight")
    old = read(n.OLD_SCOPE)
    profile = dict(old["profile"], bootstrap=source["endpoints"][0]["slot"], first=source["first"],
        last=source["last"], positions=source["positions"], checkpoints=[source["endpoints"][1]["name"]],
        host_unit=n.UNIT, sealed_package=deploy, namespace=preflight["namespace"])
    guard = n.UNIT.replace("-qualify-","-guard-")
    run = Path(source["run"])
    return dict(schema="horizon-170-next-hourly-writer-interface-v1", profile=profile, source_packet=src,
        previous_interface=n.OLD_SCOPE, predecessor=source["predecessor"], retained_comparison=source["closed_comparison"],
        staged_layout=source["staged_layout"], following_input=dict(single_copy=True, archive=source["bootstrap"],
            custody=source["bootstrap_custody"]), expected_producer_unit=n.UNIT, expected_guard_unit=guard,
        expected_guard_timer=guard.replace(".service",".timer"), bootstrap=profile["bootstrap"],
        first_new_slot=source["first"], last=source["last"], run=str(run), log=str(run/"producer.log"),
        barrier=str(ROOT/"barrier/allow"), guard_receipts=str(ROOT/"guard-receipts"),
        namespace=preflight["namespace"], source_preflight=preflight_ref,
        guard_sha=reference(ROOT/"package/guard")["sha256"], guard_seal=deploy,
        actor_path=str(ROOT/"SUCCESSOR_ACTOR.json"), release_path=str(ROOT/"SUCCESSOR_RELEASE.json"),
        plan_path=str(ROOT/"ACTUAL_GUARD_PLAN.json"), enrollment_path=str(ROOT/"WRITER_ENROLLMENT.json"),
        no_worker_started=True, publication_authorized=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase",choices=("seal","interface"))
    parser.add_argument("path")
    parser.add_argument("sha256")
    args = parser.parse_args()
    pin = dict(path=args.path,sha256=args.sha256)
    if args.phase == "seal":
        result = package(pin,reference(ROOT/"PREDECESSOR_READY.json"),reference(ROOT/"STAGED_LAYOUT.json"))
    else:
        result = save(INTERFACE,document(pin))
    print(json.dumps(result,sort_keys=True))
