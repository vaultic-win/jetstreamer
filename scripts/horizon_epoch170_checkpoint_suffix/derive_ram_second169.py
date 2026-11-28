"""Advance the bilateral V8 roster to the equal-cost second epoch 169 attempt."""
import ast
from pathlib import Path

import following_prepare as f
from derive_gap_price import one
from derive_ram_live import DEST as PREVIOUS

DEST = PREVIOUS.with_name("issued-price-v9")
SEAL = "6f72f2bda956edd0ac17eca4527530650a549e79546b923bcf9900cfaf91d758"


def members(staging, revision):
    old_ref = dict(path=str(PREVIOUS/"deployment-seal-receipt.json"),sha256=SEAL)
    old = f.read(old_ref)
    f.need(old["destination"]==str(PREVIOUS), "incorrect bilateral V8 provider")
    staging.mkdir(mode=0o700,exist_ok=True)
    result = {}
    for row in old["members"]:
        name = row["name"]
        prior = PREVIOUS/name
        f.need(prior.parent==PREVIOUS and f.reference(prior)["sha256"]==row["sha256"], "V8 provider changed")
        if name == "SOURCE.json":
            continue
        if name == "retry169_peer.py":
            code = Path(__file__).with_name("ram170_second169.py").read_text()
        else:
            code = prior.read_text()
        if name in ("capacity.py","continuation_price.py","successor_price.py"):
            count = 3 if name=="successor_price.py" else 1
            f.need(code.count(str(PREVIOUS))==count, "different V8 provider identity set")
            code=code.replace(str(PREVIOUS),str(DEST))
        if name=="successor_price.py":
            prefix="horizon-qualify-169-hourly-retry-20261128-"
            f.need(code.count(prefix+"v1.service")==2, "different first 169 retry roster")
            code=code.replace(prefix+"v1.service",prefix+"v2.service")
        if name=="after_stop.py":
            code=one(code,"    retry['reserve_169'](core, native)",
                  "    retry['reserve_169'](core, native)\n    runpy.run_path(str(directory/'retry169_peer.py'))['bind'](core, native)")
        ast.parse(code,filename=name)
        output=staging/name
        output.write_text(code)
        result[name]=(output,0o444)
    manifest=staging/"SOURCE.json"
    f.save(manifest,dict(revision=revision,branch="origin/account-updates",bilateral_v8=old_ref,
        second_169_scope="322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e",
        epoch170_scope="cf7836a48efd71f886924a07657101691d27d24f6ccf05cbe7938b4be1daedaf",replay_authorized=False))
    result[manifest.name]=(manifest,0o444)
    return result
