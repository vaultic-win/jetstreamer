"""Derive the complete V27 provider from the sealed V26 and register the qualified 157 operator."""
import ast
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "horizon_epoch170_checkpoint_suffix"),
                str(HERE.parent / "horizon_epoch143_bounded_entry_20261126_v1/writer")]
import following_prepare as f
from derive143_bootstrap_retry import read_package

OLD = f.ROOT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v26"
NEW = OLD.with_name("issued-price-v27")
PREVIOUS = dict(path=str(OLD/"deployment-seal-receipt.json"),
                sha256="07ae0724f9b912604f56827b27a8236e16b93b20b6b7790c14063511dd6458f6")


def members(directory, revision):
    files = read_package(OLD, PREVIOUS["sha256"])
    counts = {n:data.count(bytes(OLD)) for n,(data,_) in files.items() if bytes(OLD) in data}
    f.need(counts == {"capacity.py":1,"continuation_price.py":1,"successor_price.py":3},
           "V26 self bindings changed")
    for name in counts:
        data, mode = files[name]
        files[name] = data.replace(bytes(OLD),bytes(NEW)), mode
    files["serial157_operator.py"] = (HERE/"registered157.py").read_bytes(), 0o444
    files["reclamation_price.py"] = (HERE/"reclamation_price.py").read_bytes(), 0o444
    data, mode = files["capacity.py"]
    marker = b"'price143_floor_retry.py'}"
    f.need(data.count(marker) == 1, "different V26 member manifest")
    data = data.replace(marker,b"'price143_floor_retry.py','reclamation_price.py'}")
    data += b'''
def cleanup157_roster(phase):
    whole = whole_roster()
    observed = whole["epoch157_lanej_rotation"]
    need(not observed["holder"] and not observed["metadata"], "157 sublease already occupied")
    project = runpy.run_path(str(STOPPED.parent/"reclamation_price.py"))["project"]
    return dict(whole=whole, candidate=project(whole,phase))
'''
    files["capacity.py"] = data, mode
    provenance = json.loads(files["SOURCE.json"][0])
    provenance.update(revision=revision, prior_shared_price=PREVIOUS,
                      reclamation_source=str(HERE.relative_to(HERE.parents[1])))
    files["SOURCE.json"] = (json.dumps(provenance,indent=2)+"\n").encode(), 0o444
    directory.mkdir(mode=0o700)
    result = {}
    for name,(blob,mode) in files.items():
        if name.endswith(".py"):
            ast.parse(blob.decode(), filename=name)
        path = directory/name
        path.write_bytes(blob)
        result[name] = path, mode
    return result
