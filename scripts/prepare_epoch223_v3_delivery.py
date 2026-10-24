#!/usr/bin/env python3
"""Render an offline epoch 223 V3 delivery template from supplied metadata.

No referenced executable, receipt, gate, archive or snapshot is opened. This
renderer performs no integrity, ownership, publication or R2 policy check. Rust
publisher/uploader checks and root wrapper audit/sealing remain authoritative.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex

FULL = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9"
PLUGIN = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547"
DIGEST = re.compile(r"[0-9a-f]{64}")
TOOLS = ("private_verifier", "progressive", "uploader", "boundary_verifier", "boundary_script")
ROOTS = ("full_receipt_directory", "plugin_receipt_directory", "boundary_receipt_directory")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def render(metadata):
    # These are template grammar checks, never observations of named files.
    require(set(metadata) == {"schema", "publication_evidence", *TOOLS, *ROOTS},
            "unknown template fields")
    require(metadata["schema"] == "jetstreamer-epoch223-v3-delivery-template-input-v1",
            "foreign template schema")
    for key in ("publication_evidence", *TOOLS):
        binding = metadata[key]
        require(set(binding) == {"path", "sha256"}
                and Path(binding["path"]).is_absolute()
                and DIGEST.fullmatch(binding["sha256"]), "invalid binding syntax")
    for key in ROOTS:
        require(Path(metadata[key]).is_absolute(), "receipt path must be absolute")
    verifier = metadata["private_verifier"]["sha256"]
    argv = [metadata["progressive"]["path"], metadata["uploader"]["path"],
            "/home/ubuntu/horizon", "/home/ubuntu/.jetstreamer-private/r2-receipts", "223", "223",
            "--poll-seconds=1800", "--concurrency=16", "--legacy-part-size-mib=64",
            f"--full-receipt-directory={metadata['full_receipt_directory']}",
            f"--full-verifier-sha256={FULL}", f"--full-verifier-script-sha256={verifier}",
            f"--plugin-receipt-directory={metadata['plugin_receipt_directory']}",
            f"--plugin-pipeline-sha256={PLUGIN}", f"--plugin-verifier-script-sha256={verifier}",
            f"--boundary-receipt-directory={metadata['boundary_receipt_directory']}",
            f"--boundary-verifier-sha256={metadata['boundary_verifier']['sha256']}",
            f"--boundary-verifier-script-sha256={metadata['boundary_script']['sha256']}",
            "--defer-epochs=223-223"]
    wrapper = ("#!/usr/bin/zsh\n# Unverified offline template: root audit and sealing required.\n"
               "set -eu\n: ${HORIZON_S3_ENDPOINT:?}\n: ${HORIZON_ACCESS_KEY_ID:?}\n"
               ": ${HORIZON_SECRET_ACCESS_KEY:?}\nunset HORIZON_PUBLIC_BASE_URL\n\nexec "
               + shlex.join(argv) + "\n")
    proposal = {"schema": "jetstreamer-epoch223-v3-delivery-template-proposal-v1",
                "input_metadata": metadata, "argv": argv, "template_only": True,
                "referenced_files_opened": False, "input_integrity_validated": False,
                "source_or_publication_qualified": False, "authoritative_receipt": False,
                "runtime_operation_performed": False, "resource_sample_taken": False,
                "service_armed": False, "uploader_executed": False, "r2_decision_made": False,
                "deployment_authorized": False,
                "rust_checks_wrapper_audit_and_root_sealing_still_required": True}
    return wrapper, proposal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--output-wrapper", type=Path, required=True)
    parser.add_argument("--output-proposal", type=Path, required=True)
    args = parser.parse_args()
    wrapper, proposal = render(json.loads(args.metadata.read_text()))
    proposal["template_sha256"] = hashlib.sha256(wrapper.encode()).hexdigest()
    for path, text in [(args.output_wrapper, wrapper),
                       (args.output_proposal, json.dumps(proposal, indent=2) + "\n")]:
        with path.open("x") as output:
            output.write(text)
    print(json.dumps({"template": str(args.output_wrapper),
                      "sha256": proposal["template_sha256"], "armed": False}))


if __name__ == "__main__":
    main()
