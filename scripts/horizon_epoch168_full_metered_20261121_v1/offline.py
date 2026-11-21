#!/usr/bin/python3 -I
"""Read-only, no-network preflight of the sealed payload. Stop before Bank creation."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def need(condition, message):
    if not condition:
        raise ValueError(message)


def ident(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def measure(item):
    path = Path(item["path"])
    need(path.resolve(strict=True) == path and os.statvfs(path).f_flag & os.ST_RDONLY,
         f"source must be an exact read-only path: {path}")
    with path.open("rb") as f:
        before = ident(os.fstat(f.fileno()))
        need(before == item["identity"], f"source replaced: {path}")
        digest = hashlib.file_digest(f, "sha256").hexdigest()
        need(before == ident(os.fstat(f.fileno())) == ident(path.lstat()), f"source changed: {path}")
    return digest


def frame(sequence, variant, tail=b""):
    body = struct.pack("<QI", sequence, variant) + tail
    return struct.pack("<I", len(body)) + body


def field(text):
    return struct.pack("<Q", len(text)) + text.encode()


def protocol(worker, env):
    response = struct.pack("<H", 5) + field("solana-v1.5.6") + struct.pack("<I", 0)
    for text in ("v1.5.6", "01e4d0a1e9917701d1a148e1043b0ccf545c27f1",
                 "rustc 1.49.0 (e1884a8e3 2020-12-29)", "x86_64-unknown-linux-gnu",
                 "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"):
        response += field(text)
    suffix = frame(2, 4) + frame(3, 5)
    p = subprocess.run([worker], env=env, input=frame(1, 0, struct.pack("<H", 5))+suffix,
                       capture_output=True, check=True, timeout=15)
    need(p.stdout == frame(1, 0, response)+suffix, "corrected worker protocol differs")
    return hashlib.sha256(p.stdout).hexdigest()


def main(root):
    package = root / "runtime"
    need(os.geteuid() == 1001 and os.getegid() == 1003 and os.statvfs(package).f_flag & os.ST_RDONLY,
         "original source user and sealed read-only runtime required")
    j = json.loads((package/"payload.json").read_bytes())
    subprocess.run(["/usr/bin/sha256sum", "--check", "--status", "SHA256SUMS"], cwd=package, check=True)
    for name, (_, sha) in j["members"].items():
        with (package/name).open("rb") as f:
            need(hashlib.file_digest(f,"sha256").hexdigest()==sha, f"wrong package member: {name}")
    hashes = {}
    for item in [j["genesis"], j["bootstrap_file"]]:
        result = measure(item)
        need(result == item["sha256"], "retained genesis or bootstrap digest differs")
        hashes[item["path"]] = result
    for pair in j["indexes"]:
        a, b = pair["source"], pair["independent_trace_copy"]
        need(a["identity"][0:2] != b["identity"][0:2], "index copies share an inode")
        result = measure(a)
        need(result == measure(b), "independent retained indexes differ")
        target = root/"ledger/compact-indexes"/Path(pair["target"]).parent.name/Path(pair["target"]).name
        need(ident(target.lstat()) == a["identity"] and os.statvfs(target).f_flag & os.ST_RDONLY,
             "fixture ledger does not project the retained index inode")
        hashes[a["path"]] = result
    marker = Path(j["retained_terminal_partial"]["path"])
    need(ident(marker.lstat()) == j["retained_terminal_partial"]["identity"], "prior diagnostic partial changed")
    env = j["environment"].copy()
    worker = package/"jetstreamer-historical-worker-v1-5-6"
    env.update(JETSTREAMER_PRIVATE_RUN_ROOT=str(root/"private"),
               JETSTREAMER_HISTORICAL_WORKER_V1_5_6=str(worker))
    protocol_digest = protocol(worker, env)
    missing = root/"deliberately-absent-worker"
    need(not missing.exists(), "fixture missing-worker sentinel exists")
    env["JETSTREAMER_HISTORICAL_WORKER_V1_5_6"] = str(missing)
    args = j["regular_node_argv"].copy()
    args[0], args[2] = str(package/"jetstreamer-node"), str(root/"ledger")
    args[5] = "--cohort-manifest="+str(package/"preflight-168-v4.json")
    bad = args.copy()
    bad[6] = "--cohort-manifest-fingerprint=sha256:" + "00"*32
    wrong = subprocess.run(bad, env=env, capture_output=True, text=True, timeout=25)
    need(wrong.returncode and "fingerprint" in wrong.stderr.lower() and str(missing) not in wrong.stderr,
         "wrong manifest did not stop at fingerprint admission")
    run = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
    log = run.stdout + run.stderr
    for witness in ("root-checkpoint cohort 168-168 bound sealed preflight " + args[6].split("=",1)[1],
                    "generation 1634787413893700 at slot 72575704",
                    "root-checkpoint cohort verification bound its bootstrap and 1 root checkpoint(s) through epoch 168",
                    f"starting isolated solana-v1.5.6 worker {missing}",
                    "error: historical worker startup failed:", "No such file"):
        need(witness in log, f"native admission missing {witness}: {log[-3000:]}")
    need(run.returncode and not (root/"ledger/epoch-168.jet").exists() and not (root/"ledger/epoch-168.jet.sha256").exists(),
         "unexpected offline publication")
    print(json.dumps({"epoch":168,"invocation":os.environ["INVOCATION_ID"],"cgroup":Path("/proc/self/cgroup").read_text().strip(),
        "input_digests":hashes,"native_argv":args,"native_result":log,"wrong_manifest_result":wrong.stderr,
        "protocol_response_sha256":protocol_digest,"prior_partial_identity":j["retained_terminal_partial"]["identity"],
        "network_allowed":False,"bank_restored":False,"archive_created":False}))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
