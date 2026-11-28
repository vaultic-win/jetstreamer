"""Exercise the real strict CLI in a private network without a bootstrap Bank."""
import os
import subprocess
import sys
from pathlib import Path

node, directory = map(Path, sys.argv[1:])
assert os.getuid() != 0
assert [p.name for p in Path("/sys/class/net").iterdir()] == ["lo"]
inputs = Path("/usr/local/lib/jetstreamer/epoch141-strict-suffix-inputs")
worker = Path("/usr/local/lib/jetstreamer/horizon-v1425-corrected-default-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25")
snapshot = directory / "snapshot-61328765-8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY.tar.zst"
checkpoint = inputs / "epoch-hashes.txt"
digest = "843e0a479dcd3f7634f026ab8f0f4857fb52778e1769059397c972e605d6078c"
marker = "verified private epoch 141 suffix source, 13183 blocks through 61343999"
env = {
    "PATH": "/usr/bin:/bin",
    "HOME": str(directory),
    "RUST_LOG": "info",
    "RAYON_NUM_THREADS": "1",
    "TOKIO_WORKER_THREADS": "1",
    "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME": "1",
    "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST": str(inputs / "manifest.json"),
    "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256": digest,
    "JETSTREAMER_HISTORICAL_WORKER_V1_4_25": str(worker),
}
def check(name, reason, *, accepted=False, hashes=checkpoint, snap=snapshot, end=61414189,
          output="epoch141-suffix-through-checkpoint-61414189.jet", extra=(), changes=None):
    folder = directory / name
    folder.mkdir(mode=0o700)
    args = [str(node), "141", str(folder), "--verify", "--epoch141-strict-suffix",
            f"--snapshot-archive={snap}", f"--epoch-hashes={hashes}", f"--qualification-end-slot={end}",
            f"--replay-scratch={folder}", f"--horizon-output={folder / output}", *extra]
    local = {**env, "JETSTREAMER_PRIVATE_RUN_ROOT": str(folder / "private"), **(changes or {})}
    result = subprocess.run(args, env=local, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=15)
    print(name, result.returncode, result.stdout[-900:], flush=True)
    assert result.returncode == 2 and reason in result.stdout and ((marker in result.stdout) == accepted), name
    assert not (folder/output).exists() and not (folder/"private").exists(), name
    assert not list(folder.glob("*.sha256")), name

check("missing-bootstrap", "epoch 141 bootstrap archive", accepted=True)
snapshot.write_bytes(b"\x28\xb5\x2f\xfd")
check("short-bootstrap", "bootstrap archive size differs", accepted=True)
snapshot.unlink()
check("wrong-bootstrap", "requires the trusted 61328765 snapshot", snap=directory / snapshot.name.replace("8LfMX", "9LfMX"))
check("wrong-terminal", "requires the trusted 61328765 snapshot", end=61343999)
check("canonical-output", "fresh private", output="epoch-141.jet")
check("duplicate", "duplicate --epoch141-strict-suffix", extra=["--epoch141-strict-suffix"])
check("missing-binding", "corrected manifest binding absent", changes={"JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256": ""})
check("forced-legacy", "forced legacy set", changes={"JETSTREAMER_FORCE_LEGACY_INDEX": "1"})
check("wrong-worker", "expected the sealed strict v1.4.25 worker", changes={"JETSTREAMER_HISTORICAL_WORKER_V1_4_25": "/bin/false"})
check("wrong-source", "qualified Old Faithful", changes={"JETSTREAMER_HTTP_BASE_URL": "http://127.0.0.1:8"})
bad = directory / "missing-root.txt"
bad.write_text(checkpoint.read_text().splitlines()[0]+"\n")
check("absent-descendant", "independently trusted accounts hash at 61414189", hashes=bad)
bad.write_text(checkpoint.read_text().replace("3Nqh4", "4Nqh4"))
check("wrong-descendant", "independently trusted accounts hash at 61414189", hashes=bad)
print("12 strict normal CLI cases passed", flush=True)
