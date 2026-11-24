"""Resolve the archive reader after a reviewed standalone operator-tool change."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE = "58709604dfa4c97336c2e1f6fac53b862ed6f17f"
BRIDGE = "06607089e5762e61a82e0f6b2da0ae1adbf16634"
GUARD_BRIDGE = "80e86a24fba065d17ad97321878cdb9e3ee38dc3"
HOME = Path("/home/sol")
REPO = HOME / "workspace/jetstreamer"
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
FAST = RT / "fast-range-residency-20261121-v1"
RUN = FAST / "build-c4ba06a4993142f0b97354a9b48c48b6"
ORIGINAL = FAST / "production-reader-v1/qualification.json"
ORIGINAL_SHA = "c715952c42ac45b2ebce0a104fee239ff0e5374e18ca2613a569a8f4e91bc36a"
EVIDENCE = RT / "archive-reader-epoch145-bridge-06607089-v1"
GUARD_EVIDENCE = RT / "archive-reader-epoch145-guard-80e86a24-v1"
BINARY = "jetstreamer-utils/src/horizon_boundary_bridge_bin.rs"
MODULE = "jetstreamer-utils/src/horizon_boundary_bridge/native_full.rs"
GUARD = "jetstreamer-utils/src/horizon_standalone_guard_bin.rs"
SCOPES = ["Cargo.toml", "Cargo.lock", ".cargo", "src", "jetstreamer-firehose", "jetstreamer-horizon",
          "jetstreamer-plugin", "jetstreamer-utils", "vendor", "build.rs", "rust-toolchain", "rust-toolchain.toml"]
POH = "historical-runtime/v1_0_8/worker/src/poh_backend.rs"
SOURCE = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/source/"
GENERATED = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/build/release/build/jetstreamer-utils-575d2aaad9679d50/out/"


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path, digest):
    return {"path": str(path), "sha256": digest}


def read(path, digest):
    path = Path(path)
    st = path.lstat()
    check(path.resolve(strict=True) == path and path.is_file() and st.st_uid == 0 and st.st_nlink == 1
          and not st.st_mode & 0o022, f"untrusted artifact {path}")
    raw = path.read_bytes()
    check(sha(raw) == digest, f"changed artifact {path}")
    return raw


def git(*args, data=None):
    return subprocess.run(["runuser", "-u", "sol", "--", "/usr/bin/git", "-C", str(REPO), *args],
                          input=data, capture_output=True, check=True).stdout


def blob_hashes(commit, paths):
    names = sorted(paths)
    data = git("cat-file", "--batch", data=b"".join((commit + ":" + path + "\n").encode() for path in names))
    values = {}
    offset = 0
    for path in names:
        line = data.index(b"\n", offset)
        fields = data[offset:line].split()
        check(len(fields) == 3 and fields[1] == b"blob", "missing Git input " + path)
        start = line + 1
        end = start + int(fields[2])
        check(data[end:end + 1] == b"\n", "incomplete Git input")
        values[path] = sha(data[start:end])
        offset = end + 1
    check(offset == len(data), "extra Git response")
    return values


def checked_transition(candidate):
    if candidate == BRIDGE:
        expected = {
            MODULE: ":000000 100644 " + "0" * 40 + " a2e29705a34d6128c85bd459149889a98b4fefa8 A",
            BINARY: ":100644 100644 4335f85511ed25a205b1d71235e91dff282bb894 11d41120919f99f8b2e7d08d5845dde85a675c1c M",
        }
    else:
        check(candidate == GUARD_BRIDGE, "unknown reader equivalence target")
        expected = {
            GUARD: ":100644 100644 586ff69471846a477db4373912646abecc75299d 826129fa61932fd05c4c3b81d7e2fc86a1666023 M",
        }
    git("merge-base", "--is-ancestor", BASE, candidate)
    changed = git("diff", "--no-renames", "--raw", "--no-abbrev", BASE, candidate,
                  "--", *SCOPES, POH).decode().splitlines()
    check(set(changed) == {f"{entry}\t{path}" for path, entry in expected.items()}
          and len(changed) == len(expected), "different reader scope transition")
    return changed, set(expected)


def compatible_branch():
    tip = git("rev-parse", "origin/account-updates").decode().strip()
    git("merge-base", "--is-ancestor", BASE, tip)
    for candidate in (BASE, BRIDGE, GUARD_BRIDGE):
        if not git("diff", "--name-only", candidate, tip, "--", *SCOPES, POH):
            git("merge-base", "--is-ancestor", candidate, tip)
            return candidate, tip
    raise ValueError("current reader inputs differ from the reviewed source trees")


def original_reader():
    old = json.loads(read(ORIGINAL, ORIGINAL_SHA))
    check(old["reader_commit"] == BASE, "wrong original reader")
    for b in old["source_build_evidence"] + [old["pipeline"], old["full_verifier"]]:
        read(b["path"], b["sha256"])
    return old


def evidence(candidate, old):
    transition, changed_paths = checked_transition(candidate)
    manifest = json.loads(read(RUN / "input-after.json", "09a47e240ac15fe50a3e9d065fbc3b2df3a8f85e904276d9dfe3264e6b059c2c"))["members"]
    check(len(manifest) == 402 and blob_hashes(BASE, manifest) == manifest, "original physical build and source differ")
    current = blob_hashes(candidate, set(manifest) | changed_paths)
    check({p for p, v in current.items() if v != manifest.get(p)} == changed_paths, "different manifest delta")

    depsha = "8ec83e63f1bbf91617d4dbaafeba901c544cc568943d8c50607a58746329f789"
    raw = read(RUN / "horizon_pipeline.d", depsha).decode().split()
    check(raw[0].endswith("/build/release/horizon_pipeline:"), "foreign production dep-info")
    paths = sorted(p.removeprefix(SOURCE) for p in raw[1:] if p.startswith(SOURCE))
    check(len(paths) == len(set(paths)) == 172 and set(paths) <= manifest.keys() and all(current[p] == manifest[p] for p in paths)
          and {x for x in raw[1:] if not x.startswith(SOURCE)} == {GENERATED + n for n in ("clickhouse", "embed_clickhouse.rs")}
          and not set(paths) & changed_paths and "jetstreamer-utils/src/lib.rs" in paths, "different compiler inputs")
    tools = json.loads(read(RUN / "input-before.json", "09a47e240ac15fe50a3e9d065fbc3b2df3a8f85e904276d9dfe3264e6b059c2c"))
    check(tools["members"] == manifest, "inputs changed around the actual build")
    artsha = "24efa12cb51b7d05c91851567ec390872238e13c27c50c876a8999c664e0beba"
    artifacts = [json.loads(line) for line in read(RUN / "artifacts.jsonl", artsha).splitlines()]
    for name, kind, rel in (("jetstreamer_utils", "lib", "jetstreamer-utils/src/lib.rs"),
                            ("horizon_pipeline","bin","src/bin/horizon_pipeline.rs")):
        hits = [a for a in artifacts if a.get("reason") == "compiler-artifact" and a["target"]["name"] == name]
        check(len(hits) == 1 and hits[0]["target"]["kind"] == [kind] and hits[0]["target"]["src_path"] == SOURCE + rel
              and hits[0]["features"] == [] and not hits[0]["profile"]["test"], "different cargo target " + name)
    check(not any(path in a.get("target", {}).get("src_path", "") for a in artifacts for path in changed_paths),
          "operator executable included in production reader build")
    full = json.loads(read(FAST / "archive-publication-58709604/full-verifier-inputs.json",
                           "647534293418f676b1a60791d2b76d6b853a061d125e87147dbe304335a2ad84"))
    check(full["equivalent_at"] == BASE and full["external_module"] == POH, "different full-verifier origin")
    for path, obj in full["trees"].items():
        check(git("rev-parse", candidate + ":" + path).decode().strip() == obj, "full verifier input changed: " + path)
    schema = "horizon-reader-standalone-guard-equivalence-v1" if candidate == GUARD_BRIDGE else "horizon-reader-boundary-tool-equivalence-v1"
    obj = dict(schema=schema, original=ref(ORIGINAL, ORIGINAL_SHA),
               reader_commit=candidate, predecessor_commit=BASE, original_cargo_artifacts=ref(RUN / "artifacts.jsonl", artsha),
               depinfo=ref(RUN / "horizon_pipeline.d", depsha), paths=paths, changed_git_blobs=transition,
               full_verifier_trees=full["trees"], original_manifest_members=402,
               current_manifest_sha256=sha(encode(current)), pipeline=old["pipeline"], full_verifier=old["full_verifier"])
    return obj


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True)+"\n").encode()


def store(path, value):
    raw = encode(value)
    if path.exists():
        read(path, sha(raw))
    else:
        with path.open("xb") as f:
            os.fchmod(f.fileno(), 0o400)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return ref(path, sha(raw))


if __name__ == "__main__":
    check(os.geteuid() == 0 and sys.flags.isolated and len(sys.argv) == 1, "requires root isolated execution")
    baseline, tip = compatible_branch()
    old = original_reader()
    if baseline == BASE:
        qualification = ref(ORIGINAL, ORIGINAL_SHA)
    else:
        source = evidence(baseline, old)
        directory = GUARD_EVIDENCE if baseline == GUARD_BRIDGE else EVIDENCE
        directory.mkdir(mode=0o700, exist_ok=True)
        source_ref = store(directory / "compiled-equivalence.json", source)
        qualified = dict(old, reader_commit=baseline,
                         source_build_evidence=[*old["source_build_evidence"], ref(ORIGINAL, ORIGINAL_SHA), source_ref])
        qualification = store(directory / "qualification.json", qualified)
    print(json.dumps(dict(reader_commit=baseline, qualified_branch=tip, qualification=qualification)))
