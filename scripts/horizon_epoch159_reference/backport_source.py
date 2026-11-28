"""Reproduce the isolated epoch 159 five-file backport and check the old Cargo inputs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent
SPEC = json.loads((HERE / "v156-backport.json").read_bytes())
WORKTREE = "historical-runtime/v1_5_6"
PROTOCOL_SCHEMA = "historical-runtime/protocol-schema"
ARCHIVED_GIT_DB = "solana-7a5d8113b7344779"
CARGO_149_GIT_DB = "solana-58d818797bb1766e"
REGISTRY = "github.com-1ecc6299db9ec823"
BINARY = "jetstreamer-historical-worker-v1-5-6"


def check(ok, detail):
    if not ok:
        raise ValueError(detail)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(repo), "-C", repo, *args])


def registry_sources(lock, cache):
    packages = lock["package"]
    sources = {row["name"]: row for row in packages if row["name"] in
               ("solana-sdk", "solana-runtime", "solana-vote-program")}
    check(len([row for row in packages if row["name"] in sources]) == len(sources) == 3,
          "unexpected SDK, runtime or vote package identity")
    git_source = "git+https://github.com/solana-labs/solana.git?rev=" + SPEC["solana"] + "#" + SPEC["solana"]
    check(sources["solana-sdk"]["source"] == sources["solana-vote-program"]["source"] == git_source
          and "source" not in sources["solana-runtime"], "different Solana dependency graph")
    count = 0
    byte_count = 0
    for row in packages:
        source = row.get("source")
        if not source or source == git_source:
            continue
        check(source == "registry+https://github.com/rust-lang/crates.io-index", "unexpected Cargo source")
        name, version = row["name"], row["version"]
        path = cache / "registry/cache" / REGISTRY / f"{name}-{version}.crate"
        expected = row.get("checksum") or lock["metadata"][f"checksum {name} {version} ({source})"]
        data = path.read_bytes()
        check(digest(data) == expected, f"locked crate mismatch at {path}")
        byte_count += len(data)
        count += 1
    check((len(packages), count, byte_count) == (294, 275, 33530687), "wrong complete lock inventory")
    return dict(packages=len(packages), registry_archives=count, registry_bytes=byte_count)


def originals(repo, cache):
    rev = SPEC["original_jetstreamer"]
    check(git(repo, "rev-parse", rev + ":" + WORKTREE).decode().strip()
          == SPEC["original_worker_tree"], "different v1.5.6 source tree")
    check(git(repo, "rev-parse", rev + ":" + PROTOCOL_SCHEMA).decode().strip()
          == SPEC["original_protocol_schema_tree"], "different shared protocol schema tree")
    checkout = cache / "git/checkouts" / ARCHIVED_GIT_DB / SPEC["solana"][:7]
    check(git(checkout, "rev-parse", "HEAD").decode().strip() == SPEC["solana"], "different Solana checkout")
    bare = cache / "git/db" / CARGO_149_GIT_DB
    tree_ref = SPEC["solana"] + "^{tree}"
    check(git(bare, "rev-parse", "--verify", tree_ref) == git(checkout, "rev-parse", "--verify", tree_ref),
          "Cargo 1.49 cache has a different locked Solana tree")
    lock = git(repo, "show", f"{rev}:{WORKTREE}/Cargo.lock")
    result = registry_sources(tomllib.loads(lock.decode()), cache)
    paths = {}
    for name, row in SPEC["changes"].items():
        if name.startswith("runtime/"):
            member = WORKTREE + "/vendor/solana-runtime-1.5.6/" + name.removeprefix("runtime/")
            raw = git(repo, "show", rev + ":" + member)
        else:
            raw = git(checkout, "show", SPEC["solana"] + ":" + name)
        check(digest(raw) == row["preimage"], "different preimage: " + name)
        paths[name] = raw
    patch = HERE / "v156-check-init-vote.patch"
    check(digest(patch.read_bytes()) == SPEC["patch_sha256"], "different feature patch")
    return result, checkout, paths


def prepare(repo, cache, dest):
    result, checkout, sources = originals(repo, cache)
    dest.mkdir(mode=0o700, exist_ok=False)
    ws = dest / "workspace"
    for target, tree in ((ws, SPEC["original_worker_tree"]),
                         (dest / "protocol-schema", SPEC["original_protocol_schema_tree"])):
        target.mkdir()
        archive = git(repo, "archive", tree)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar.getmembers():
                check(member.isfile() or member.isdir(), "unexpected historical source link")
            tar.extractall(target, filter="data")
    chome = dest / "cargo"
    (chome / "registry").mkdir(parents=True)
    for name in ("index", "cache"):
        (chome / "registry" / name).symlink_to(cache / "registry" / name, target_is_directory=True)
    db = chome / "git/db" / CARGO_149_GIT_DB
    db.parent.mkdir(parents=True)
    db.symlink_to(cache / "git/db" / CARGO_149_GIT_DB, target_is_directory=True)
    private = chome / "git/checkouts" / CARGO_149_GIT_DB / SPEC["solana"][:7]
    private.parent.mkdir(parents=True)
    private.mkdir()
    git(private, "init", "-q")
    objects = Path(git(checkout, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip())
    (private / ".git/objects/info/alternates").write_text(str(objects) + "\n")
    git(private, "checkout", "-q", "--detach", SPEC["solana"])
    (private / ".cargo-ok").write_bytes((checkout / ".cargo-ok").read_bytes())
    staging = dest / "five-sources"
    for name, raw in sources.items():
        f = staging / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(raw)
    subprocess.run(["patch", "--batch", "--fuzz=0", "--forward", "--no-backup-if-mismatch", "-p1",
                    "-i", HERE / "v156-check-init-vote.patch"], cwd=staging, check=True)
    for name, row in SPEC["changes"].items():
        target = (ws / "vendor/solana-runtime-1.5.6" / name.removeprefix("runtime/")
                  if name.startswith("runtime/") else private / name)
        data = (staging / name).read_bytes()
        check(digest(data) == row["candidate"] and digest(target.read_bytes()) == row["preimage"],
              "source materialization mismatch: " + name)
        target.write_bytes(data)
    for name in ("target", "tmp"):
        (dest / name).mkdir()
    return dict(result, workspace=str(ws), prepared_root=str(dest), patch_sha256=SPEC["patch_sha256"])


def check_graph(metadata, dest):
    packages = json.loads(metadata.read_bytes())["packages"]
    required = {"solana-sdk": "sdk", "solana-vote-program": "programs/vote"}
    private = dest / "cargo/git/checkouts" / CARGO_149_GIT_DB / SPEC["solana"][:7]
    for name, tail in required.items():
        pkg, = [p for p in packages if p["name"] == name]
        check(pkg["source"].endswith("#" + SPEC["solana"]) and
              Path(pkg["manifest_path"]).resolve() == private / tail / "Cargo.toml", "wrong effective " + name)
    pkg, = [p for p in packages if p["name"] == "solana-runtime"]
    check(pkg["source"] is None and Path(pkg["manifest_path"]).resolve() ==
          dest / "workspace/vendor/solana-runtime-1.5.6/Cargo.toml", "wrong effective runtime")
    for name, row in SPEC["changes"].items():
        path = (dest / "workspace/vendor/solana-runtime-1.5.6" / name.removeprefix("runtime/")
                if name.startswith("runtime/") else private / name)
        check(digest(path.read_bytes()) == row["candidate"], "changed effective source " + name)


def check_build(dest):
    check_graph(dest / "metadata.json", dest)
    all_artifacts = [json.loads(line) for line in (dest.parent / "release.jsonl").read_text().splitlines()]
    required = {"solana-sdk", "solana-vote-program", "solana-runtime", BINARY}
    compiled = {row["package_id"].split()[0] for row in all_artifacts
                if row.get("reason") == "compiler-artifact" and row["fresh"] is False}
    check(required <= compiled, "release reused or omitted a changed crate")
    binary = dest / "target/release" / BINARY
    product, = [row for row in all_artifacts if row.get("target", {}).get("name") == BINARY
                and row.get("executable") == str(binary)]
    check(not product["fresh"] and binary.stat().st_size > 0 and
          digest(binary.read_bytes()) != SPEC["original_worker_sha256"], "unidentified release worker")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("check", "prepare", "check-graph", "check-build"))
    p.add_argument("--repo", type=Path, default=HERE)
    p.add_argument("--cache", type=Path, default=Path.home() / ".cargo")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    if a.action == "check":
        print(json.dumps(originals(a.repo, a.cache)[0], sort_keys=True))
    elif a.action == "prepare":
        check(a.output and a.output.is_absolute(), "provide a fresh absolute output within paid HOME scratch")
        print(json.dumps(prepare(a.repo, a.cache.resolve(), a.output), sort_keys=True))
    else:
        check(a.output and a.output.is_absolute(), "provide the prepared absolute output")
        if a.action == "check-build":
            check_build(a.output)
        else:
            check_graph(a.output / "metadata.json", a.output)


if __name__ == "__main__":
    main()
