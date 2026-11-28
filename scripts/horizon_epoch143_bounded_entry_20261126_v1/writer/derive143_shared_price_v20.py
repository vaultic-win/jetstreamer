"""Include the verified epoch 167 assembly account in every complete shared quote."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_v53 import member_plan
from derive143_shared_price_v19 import NEW as OLD

NEW = OLD.with_name("issued-price-v20")
SEAL = "c1d09d2382e6dfb6d9eb7520d910ddefac252e713575c21e6df8f47bc10e488e"
ASSEMBLY_SEAL = "65697772d54ae49cd4740d69160bf3979d8f464e7509bdc213695c8dc2769842"
ASSEMBLY_IMAGE = "648d0fe147c4bd34f36750d7e12d1248b42cfd73e196b4e997ff48d623f12093"


def derive(stage, revision):
    files = read_package(OLD, SEAL)
    for name, count in (("capacity.py",1),("continuation_price.py",1),("successor_price.py",3)):
        raw, mode = files[name]
        source = raw.decode()
        if source.count(str(OLD)) != count:
            raise ValueError("unexpected V19 self references for " + name)
        files[name] = (source.replace(str(OLD),str(NEW)).encode(),mode)
    raw, mode = files["capacity.py"]
    s = change(raw.decode(),"from hashlib import sha256\n","from hashlib import sha256\nimport json\n")
    s = change(s,"    return dict(schema='horizon-168-post-assembly-six-owner-price-v1', base_169=base",
                  "    result = dict(schema='horizon-168-post-assembly-six-owner-price-v1', base_169=base")
    line = "                closed_143=base['native']['raw']['closed143'], **final)"
    s = change(s,line,line+f"""
    assembly = RT / "epoch167-assembly-20261127-v1/turnover-tools-v1"
    executable = assembly / "turnover"
    immutable(assembly / "deployment-seal-receipt.json", "{ASSEMBLY_SEAL}")
    immutable(executable, "{ASSEMBLY_IMAGE}")
    accounting = subprocess.run([str(executable), "account"], input=json.dumps(result),
                                text=True, check=True, capture_output=True, timeout=120)
    merged = json.loads(accounting.stdout)
    need(merged["fleet"] == result["fleet"] and merged["writer"] == result["writer"]
         and merged["closed_143"] == result["closed_143"] and merged["preparation_only"] == prep143
         and merged["resource_credit_bytes"] == 0, "167 accounting changed the underlying owner authority")
    return merged""")
    files["capacity.py"] = (s.encode(),mode)
    source=json.loads(files["SOURCE.json"][0])
    source.update(revision=revision,prior_shared_price=dict(
        path=str(OLD/"deployment-seal-receipt.json"),sha256=SEAL),
        assembly_account_seal=ASSEMBLY_SEAL,assembly_account_executable=ASSEMBLY_IMAGE)
    files["SOURCE.json"] = ((json.dumps(source,indent=2)+"\n").encode(),0o444)
    return member_plan(files,stage,NEW)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]),sys.argv[2]),indent=2))
