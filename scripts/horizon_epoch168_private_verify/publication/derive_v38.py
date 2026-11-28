"""Issue the two-thread epoch 168 allocation into every V38 complete roster."""
import ast
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parents[1]
sys.path[:0] = [str(SCRIPTS / "horizon_epoch170_checkpoint_suffix"),
                 str(SCRIPTS / "horizon_epoch143_bounded_entry_20261126_v1/writer")]
import following_prepare as f
from derive143_bootstrap_retry import read_package

PRICES = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
OLD = PRICES / "issued-price-v37"
NEW = PRICES / "issued-price-v38"
OP = f.ROOT / "epoch168-exact-publication-v1/admission-tools-v2"


def members(directory, revision, predecessor, operator):
    f.need(predecessor["path"] == str(OLD / "deployment-seal-receipt.json")
           and operator["path"] == str(OP / "deployment-seal-receipt.json"),
           "different 168 provider lineage")
    previous = read_package(OLD, predecessor["sha256"])
    native = read_package(OP, operator["sha256"])
    binary = native["publication"][0]
    f.need(native["publication"][1] == 0o555, "non-executable publisher admission")
    files = {}
    for name, (blob, mode) in previous.items():
        if name.endswith(".py"):
            blob = blob.replace(bytes(OLD), bytes(NEW))
        files[name] = (blob, mode)
    f.need(b"next_hourly170_roster.py" in files["capacity.py"][0]
           and "fourth162_price.py" in files and "compact169_residency.py" in files,
           "missing 170, 162 or 169 registration")
    old = b"    return runpy.run_path(str(STOPPED.parent/'next_hourly170_roster.py'))['register'](core,finished)"
    data, mode = files["capacity.py"]
    f.need(data.count(old) == 1, "V37 complete roster return changed")
    import hashlib
    digest = hashlib.sha256(binary).hexdigest()
    code = f"""    registered = runpy.run_path(str(STOPPED.parent/'next_hourly170_roster.py'))['register'](core,finished)
    native = Path({str(OP / 'publication')!r})
    immutable(native, {digest!r})
    immutable(native.with_name('deployment-seal-receipt.json'), {operator['sha256']!r})
    proc = subprocess.run([str(native), 'account'], input=json.dumps(registered), text=True,
                          check=True, capture_output=True, timeout=120)
    return json.loads(proc.stdout)"""
    files["capacity.py"] = (data.replace(old, code.encode()), mode)
    history = json.loads(files["SOURCE.json"][0])
    history.update(revision=revision, prior_shared_price=predecessor,
                   publication168_admission=operator, publication168_binary_sha256=digest)
    files["SOURCE.json"] = (json.dumps(history, indent=2).encode() + b"\n", 0o444)
    directory.mkdir(mode=0o700)
    rows = {}
    for name, (blob, mode) in files.items():
        if name.endswith(".py"):
            ast.parse(blob.decode(), filename=name)
        path = directory / name
        path.write_bytes(blob)
        rows[name] = path, mode
    return rows
