"""Check the exact custody object and manifest using the existing signed R2 transport."""
import hashlib
import json
import runpy
from pathlib import Path

here = Path(__file__).resolve().parent
transport = here / "holding_identity.py"
assert hashlib.sha256(transport.read_bytes()).hexdigest() == "c5bce8fcd86af9948a44d0eef1badd56e9c269719b7a885223132159dd50d8ac"
api = runpy.run_path(str(transport))
r2 = api["client"]()
head = api["head"]
body = api["small_body"]
owner = json.loads(body(r2, head(r2, "node_02/owner.json")))
assert owner == {"schema": "jetstreamer-horizon-holding-owner-v2", "host": "dev-samjohnson", "prefix": "node_02/"}
sha = "5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0"
etag = '"74116d5a8c0705daf0a190730ff3d78a-225"'
manifest_sha = "46b23d41f1e2c7818d0224bacee1f6396071505bf7119676574b0d17ef4eb878"
manifest = head(r2, "node_02/manifests/" + manifest_sha + ".json")
wire = body(r2, manifest)
assert hashlib.sha256(wire).hexdigest() == manifest_sha
blob = head(r2, "node_02/objects/" + sha + ".blob", etag)
assert blob["status"] == 200 and blob["length"] == 15067873514 and blob["etag"] == etag
assert blob["metadata"]["sha256"] == sha
print(json.dumps({"owner": owner, "blob": blob, "manifest": json.loads(wire), "manifest_sha256": manifest_sha}))
