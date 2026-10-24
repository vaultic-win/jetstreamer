#!/usr/bin/env python3
"""Prepare an unarmed epoch 223 uploader from actual local V3 publication metadata.

Reads only sealed metadata, gate files and named executables. Never reads an
archive, runs a command, installs a service, samples resources or accesses R2.
The existing wrapper auditor and root deployment remain separate requirements.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

FULL = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9"
PLUGIN = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547"
DIGEST = re.compile(r"[0-9a-f]{64}")
TOOLS = {
    "private_verifier": "jetstreamer-epoch223-private-verify",
    "progressive": "jetstreamer-r2-progressive",
    "uploader": "jetstreamer-r2",
    "boundary_verifier": "archive_boundaries",
    "boundary_script": "verify_horizon_boundaries_progressive.sh",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "aliased path")
    return path


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_file(path, maximum, immutable=True):
    path = canonical(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1,
            "evidence must be a root-owned singly linked regular file")
    require(before.st_size <= maximum and not before.st_mode & (0o222 if immutable else 0o022),
            "evidence mode or bound differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        require(identity(os.fstat(source.fileno())) == identity(before),
                "evidence changed before read")
        data = source.read(maximum + 1)
        require(identity(os.fstat(source.fileno())) == identity(before),
                "evidence changed during read")
    require(identity(path.lstat()) == identity(before) and len(data) == before.st_size,
            "evidence namespace changed")
    return data


def bound(binding, maximum, basename=None, immutable=True):
    require(set(binding) == {"path", "sha256"} and DIGEST.fullmatch(binding["sha256"]),
            "invalid evidence binding")
    path = Path(binding["path"])
    require(basename is None or path.name == basename, "foreign executable name")
    data = read_file(path, maximum, immutable=immutable)
    require(hashlib.sha256(data).hexdigest() == binding["sha256"], "evidence digest differs")
    if basename is not None:
        require(path.stat().st_mode & 0o111, "tool is not executable")
    return data


def directory(path):
    path = canonical(path)
    metadata = path.stat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
            and not metadata.st_mode & 0o022, "unsafe receipt directory")
    return path


def validate_publication(publication, plan, verifier):
    require(publication["schema"] == "jetstreamer-exact-epoch223-v3-publication-receipt-v1"
            and publication["epoch"] == 223 and publication["committed"] is True
            and publication["original_assembly_preserved"] is True,
            "actual committed V3 publication is required")
    require(publication["full_verifier_sha256"] == FULL
            and publication["plugin_pipeline_sha256"] == PLUGIN
            and publication["private_runner_sha256"] == verifier["sha256"],
            "publication uses different full, current plugin or private runner")
    require(plan["schema"] == "jetstreamer-private-epoch223-v3-publication-plan-v1"
            and plan["artifact_publication_authorized"] is True
            and plan["verifier"] == verifier
            and plan["verification"] == publication["context"]["verification"]
            and plan["archive_sha256"] == publication["archive_sha256"]
            and plan["archive_bytes"] == publication["archive_bytes"],
            "publication plan or verified archive binding differs")
    require(DIGEST.fullmatch(publication["archive_sha256"])
            and 0 < publication["archive_bytes"] <= 160 << 30, "archive metadata differs")
    for value in [publication, plan]:
        require(value["remote_mutations"] is False and value["r2_mutations"] is False,
                "local evidence claims remote authority")
    require(publication["runtime_registry_promoted"] is False
            and publication["retirement_authorized"] is False
            and plan["runtime_registry_promotion_authorized"] is False,
            "local evidence grants unrelated authority")


def prepare(request):
    require(set(request) == {"schema", "publication", "private_verifier", "progressive",
                            "uploader", "boundary_verifier", "boundary_script",
                            "boundary_receipt_directory"}, "unknown request fields")
    require(request["schema"] == "jetstreamer-epoch223-v3-delivery-binding-request-v1",
            "foreign request schema")
    publication = json.loads(bound(request["publication"], 8 << 20, immutable=False))
    plan_binding = publication["context"]["plan"]
    plan = json.loads(bound(plan_binding, 4 << 20))
    for key, name in TOOLS.items():
        bound(request[key], 128 << 20, name)
    validate_publication(publication, plan, request["private_verifier"])
    roots = {key: directory(plan[key])
             for key in ["full_receipt_directory", "plugin_receipt_directory"]}
    require(roots["full_receipt_directory"] != roots["plugin_receipt_directory"],
            "full and plugin receipt roots overlap")
    gates = []
    for role, tool in [("full", FULL), ("plugin", PLUGIN)]:
        path = roots[f"{role}_receipt_directory"] / f"epoch-223.{role}.ok"
        data = read_file(path, 256, immutable=False)
        expected = f"{publication['archive_sha256']} {tool} {request['private_verifier']['sha256']}\n"
        require(data == expected.encode("ascii"), f"actual {role} gate differs")
        gates.append({"path": str(path), "sha256": hashlib.sha256(data).hexdigest()})
    boundary = directory(request["boundary_receipt_directory"])
    verifier = request["private_verifier"]["sha256"]
    argv = [request["progressive"]["path"], request["uploader"]["path"],
            "/home/ubuntu/horizon", "/home/ubuntu/.jetstreamer-private/r2-receipts", "223", "223",
            "--poll-seconds=1800", "--concurrency=16", "--legacy-part-size-mib=64",
            f"--full-receipt-directory={roots['full_receipt_directory']}",
            f"--full-verifier-sha256={FULL}", f"--full-verifier-script-sha256={verifier}",
            f"--plugin-receipt-directory={roots['plugin_receipt_directory']}",
            f"--plugin-pipeline-sha256={PLUGIN}", f"--plugin-verifier-script-sha256={verifier}",
            f"--boundary-receipt-directory={boundary}",
            f"--boundary-verifier-sha256={request['boundary_verifier']['sha256']}",
            f"--boundary-verifier-script-sha256={request['boundary_script']['sha256']}",
            "--defer-epochs=223-223"]
    wrapper = ("#!/usr/bin/zsh\nset -eu\n"
               ": ${HORIZON_S3_ENDPOINT:?}\n: ${HORIZON_ACCESS_KEY_ID:?}\n"
               ": ${HORIZON_SECRET_ACCESS_KEY:?}\nunset HORIZON_PUBLIC_BASE_URL\n\nexec "
               + shlex.join(argv) + "\n")
    return wrapper, {"schema": "jetstreamer-epoch223-v3-delivery-binding-proposal-v1",
                     "publication": request["publication"], "publication_plan": plan_binding,
                     "request": request, "actual_gate_bindings": gates, "argv": argv,
                     "archive_body_read": False, "resource_sample_taken": False,
                     "service_armed": False, "uploader_executed": False, "r2_mutations": False,
                     "local_retirement_authorized": False,
                     "wrapper_audit_and_root_sealing_still_required": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("--output-wrapper", type=Path, required=True)
    parser.add_argument("--output-evidence", type=Path, required=True)
    args = parser.parse_args()
    wrapper, evidence = prepare(json.loads(read_file(args.request, 4 << 20)))
    evidence["wrapper_sha256"] = hashlib.sha256(wrapper.encode()).hexdigest()
    for path, data in [(args.output_wrapper, wrapper),
                       (args.output_evidence, json.dumps(evidence, indent=2) + "\n")]:
        require(path.is_absolute(), "proposal output must be absolute")
        directory(path.parent)
        with path.open("x") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    print(json.dumps({"wrapper": str(args.output_wrapper),
                      "sha256": evidence["wrapper_sha256"], "armed": False}))


if __name__ == "__main__":
    main()
