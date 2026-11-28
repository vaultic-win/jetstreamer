"""Advance the common V9 reservation to the third 169 and carry the second 162 output."""
import argparse
import ast
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import following_prepare as f
from derive_gap_price import one


BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
PREVIOUS = BASE / "issued-price-v9"
DEST = BASE / "issued-price-v10"
OLD_SEAL = "d97547403106754db04ef006b72e5e4f60f6d92a90723a3fc312f7bb56bb0066"
SCOPE = "7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
THIRD_PEER = "66f24b837f2168ff4474ab07def6d50470527334dd91e7570502c424b9da0283"
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def extend(name, code):
    if name in ("capacity.py", "continuation_price.py", "successor_price.py"):
        count = 3 if name == "successor_price.py" else 1
        f.need(code.count(str(PREVIOUS)) == count, "unexpected V9 self bindings in " + name)
        code = code.replace(str(PREVIOUS), str(DEST))
    if name == "successor_price.py":
        old = "horizon-qualify-169-hourly-retry-20261128-v2.service"
        f.need(code.count(old) == 2, "different V9 native 169 census")
        code = code.replace(old, old.replace("-v2.service", "-v3.service"))
    if name == "capacity.py":
        code = one(code, "'ram170_capacity.py','ram170_live.py'}",
                   "'ram170_capacity.py','ram170_live.py','next162_reservation.py'}")
        marker = "    return dict(schema='horizon-168-post-assembly-six-owner-price-v1', base_169=base,"
        code = one(code, marker,
                   "    runpy.run_path(str(STOPPED.parent/'next162_reservation.py'))['reserve'](peer, proof, base, row, final)\n"
                   + marker)
    return code


def reviewed(file, revision, observed):
    key = str(file.relative_to(REPO))
    content = file.read_bytes()
    f.need(content == f.git(REPO, "show", revision + ":" + key)
           and content == f.git(REPO, "show", observed + ":" + key), "different merged source " + key)
    return content


def members(staging, revision, observed):
    old_ref = dict(path=str(PREVIOUS / "deployment-seal-receipt.json"), sha256=OLD_SEAL)
    old = f.read(old_ref)
    f.need(old["destination"] == str(PREVIOUS), "different V9 predecessor")
    f.git(REPO, "merge-base", "--is-ancestor", revision, observed)
    f.need(f.git(REPO, "rev-parse", "origin/account-updates").decode().strip() == observed, "remote reference changed")
    third = HERE.parent / "horizon_epoch169_hourly_retry" / "third_peer.py"
    reserve = HERE / "next162_reservation.py"
    sources = {}
    for path in (Path(__file__).resolve(), HERE/"derive_gap_price.py", HERE/"following_prepare.py",
                 HERE/"closed_successor.py", third, reserve):
        reviewed(path, revision, observed)
        sources[str(path.relative_to(REPO))] = f.reference(path)["sha256"]
    f.need(f.reference(third)["sha256"] == THIRD_PEER, "unexpected third 169 observer")
    result = {}
    for row in old["members"]:
        name = row["name"]
        prior = PREVIOUS / name
        f.need(prior.parent == PREVIOUS and f.reference(prior)["sha256"] == row["sha256"], "V9 member changed")
        if name == "SOURCE.json":
            continue
        code = third.read_text() if name == "retry169_peer.py" else extend(name, prior.read_text())
        ast.parse(code, filename=name)
        dest = staging / name
        dest.write_text(code)
        result[name] = (dest, 0o444)
    dest = staging / reserve.name
    dest.write_bytes(reserve.read_bytes())
    ast.parse(dest.read_text(), filename=dest.name)
    result[dest.name] = (dest, 0o444)
    source = staging / "SOURCE.json"
    f.save(source, dict(branch="origin/account-updates", revision=revision, observed=observed,
                        predecessor=old_ref, source_sha256=sources, third_169_scope=SCOPE,
                        second_162_additional_home=(3 << 30) + (64 << 20),
                        replay_authorized=False))
    result[source.name] = (source, 0o444)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--observed", required=True)
    args = parser.parse_args()
    staging = Path(tempfile.mkdtemp(prefix="third169-common-source.", dir=BASE))
    deployment = members(staging, args.commit, args.observed)
    print(f.seal(DEST, deployment, staging/"plan.json"))
