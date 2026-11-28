"""Compose the 169 dual census and the 170 scratch reservation on the immutable V7 price."""
import ast
from pathlib import Path

from derive_gap_price import one
import following_prepare as f

BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
OLD = BASE / "issued-price-v7"
SEAL = "8f9377d8b0405d60fb7687b4195b8c69b45451f864971358d902b4221df748ee"
PEER = f.ROOT / "epoch169-hourly-retry-20261128-v1/roster-v1"
PEER_SEAL = "c07e0827f8bc7fe26e46f644b03e0012def68ad666a026df243a1238cd52c353"
DEST = BASE / "issued-price-v8-prestart"
RETRY = "horizon-qualify-170-from-73760367-ram-20261128-v1.service"


def extend(name, source):
    """Retain both of 169's native censuses, including its original terminal."""
    if name == "capacity.py":
        source = one(source, str(PEER / name), str(DEST / name))
        source = one(source, "'gap170_capacity.py','retry169_peer.py'",
                     "'gap170_capacity.py','retry169_peer.py','ram170_capacity.py'")
        source = one(source, "def base_for_retry_only():", "def whole_roster():")
        # Each issuer consumes the fully charged common quote through its own
        # native gate. This provider grants no independent 162 dispatch.
        start = source.index("def quote(*, phase, held_invocation, profile, enrollment):")
        return source[:start]
    if name == "continuation_price.py":
        return one(source, str(PEER), str(DEST))
    if name == "successor_price.py":
        f.need(source.count(str(PEER)) == 3, "different native roster path guards")
        return source.replace(str(PEER), str(DEST))
    if name == "after_stop.py":
        source = one(source, "    gap170 = gap['owner'](core,fleet)", """    retry = runpy.run_path(str(directory/'ram170_capacity.py'))
    stopped_gap = retry['stopped_gap'](core, fleet, gap)
    gap170 = retry['before_issue'](core, fleet)""")
        source = one(source, "    native['independent_gap170'] = gap170",
                     "    native['independent_gap170'] = None\n    native['ram_gap170'] = gap170")
        marker = "    gap['debit'](core,native)"
        source = one(source, marker, marker+"""
    retry['charge'](core, native, stopped_gap)
    retry['reserve_169'](core, native)""")
        return one(source, "gap['owner'](core,fleet)==gap170",
                   "retry['stopped_gap'](core,fleet,gap)==stopped_gap and retry['before_issue'](core,fleet)==gap170")
    return source


def members(staging, revision):
    old = dict(path=str(OLD/"deployment-seal-receipt.json"), sha256=SEAL)
    expected = dict(path=str(PEER/"deployment-seal-receipt.json"), sha256=PEER_SEAL)
    seal = f.read(expected)
    f.need(seal["destination"] == str(PEER) and f.read(old)["destination"] == str(OLD), "unregistered provider")
    files = {}
    staging.mkdir(mode=0o700,exist_ok=True)
    for entry in seal["members"]:
        name = entry["name"]
        previous = PEER/name
        f.need(previous.parent == PEER and f.reference(previous)["sha256"] == entry["sha256"], "changed 169 roster member")
        if name == "SOURCE.json":
            proof = f.read(f.reference(previous))
            f.need(proof["predecessor"] == old and proof["operator"]["sha256"] ==
                   "8e87b305ba3957ca579a9eafa696eb2410f2498869c31922a8460dc5935943ed", "different 169 census")
            continue
        body = extend(name, previous.read_text())
        ast.parse(body,filename=name)
        dst=staging/name
        dst.write_text(body)
        files[name]=(dst,0o444)
    extra=Path(__file__).with_name("ram170_capacity.py")
    files[extra.name]=(extra,0o444)
    manifest=staging/"SOURCE.json"
    f.save(manifest,dict(branch="origin/account-updates",revision=revision,predecessor=old,
                         peer169=expected,replay_authorized=False))
    files[manifest.name]=(manifest,0o444)
    return files
