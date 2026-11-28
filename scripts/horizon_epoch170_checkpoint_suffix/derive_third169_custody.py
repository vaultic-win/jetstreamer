"""Read the two exact HOME guard records referenced by the V10 terminal binding."""
import argparse
import ast
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import following_prepare as f
from derive_gap_price import one
from derive_third169_price import BASE, DEST as BEFORE, REPO, reviewed


DEST = BASE / "issued-price-v10-custody"
SEAL = "c346fe0f510dd89bdde9fde4f8142ef0b7b4ac8b7f41a1b6b7d7d699daa38831"
GUARD = Path("/home/sol/.jetstreamer-private/epoch169-hourly-retry-20261128-v2/hourly-guard-receipts")
PINNED = {
    str(GUARD/"stop-intent.json"): "adf7cd91e0af1f7f6307ab11f5e951c9d75bf7aaf5a3b12cea20fadf9d4b6b4a",
    str(GUARD/"stop-completion.json"): "8be50829930c5ca075b5b33478dfab18544364656b391576b053e4b3474d4c65",
}


def extend(name, code):
    if name in ("capacity.py", "continuation_price.py", "successor_price.py"):
        count = 3 if name == "successor_price.py" else 1
        f.need(code.count(str(BEFORE)) == count, "different V10 self bindings in " + name)
        code = code.replace(str(BEFORE), str(DEST))
    if name == "successor_price.py":
        marker = '    need(path.is_relative_to(RT) and path.resolve(strict=True) == path, "foreign evidence " + str(path))'
        allowed = "    pinned = " + repr(PINNED) + "\n"
        return one(code, marker, allowed +
                   '    home_guard = str(path) in pinned and sha == pinned[str(path)]\n'
                   '    need((path.is_relative_to(RT) or home_guard) and path.resolve(strict=True) == path, '
                   '"foreign evidence " + str(path))')
    return code


def issue(revision, observed):
    old_ref = dict(path=str(BEFORE/"deployment-seal-receipt.json"), sha256=SEAL)
    old = f.read(old_ref)
    f.need(old["destination"] == str(BEFORE), "different third 169 provider")
    f.git(REPO, "merge-base", "--is-ancestor", revision, observed)
    f.need(f.git(REPO, "rev-parse", "origin/account-updates").decode().strip() == observed, "remote reference changed")
    here = Path(__file__).resolve()
    for name in (here.name, "derive_third169_price.py", "following_prepare.py", "derive_gap_price.py", "closed_successor.py"):
        reviewed(here.with_name(name), revision, observed)
    staging = Path(tempfile.mkdtemp(prefix="third169-custody-source.", dir=BASE))
    members = {}
    for row in old["members"]:
        name = row["name"]
        prior = BEFORE / name
        f.need(prior.parent == BEFORE and f.reference(prior)["sha256"] == row["sha256"], "V10 member changed")
        if name == "SOURCE.json":
            continue
        code = extend(name, prior.read_text())
        ast.parse(code, filename=name)
        destination = staging / name
        destination.write_text(code)
        members[name] = (destination, 0o444)
    closure = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-retry-20261128-v2/WORKER_ALIAS_STOP.json")
    stop_ref = dict(path=str(closure), sha256="c09b0bf82efe4c970a0810219bdccb03a1869333a30cd1fef39e9034dfc40e02")
    stopped = f.read(stop_ref)
    records = {stopped[key]["path"]: stopped[key]["sha256"] for key in ("stop_intent", "stop_completion")}
    f.need(records == PINNED, "different native guard records")
    for path, digest in records.items():
        f.read(dict(path=path, sha256=digest))
    source = staging / "SOURCE.json"
    old_source = f.read(f.reference(BEFORE/"SOURCE.json"))
    f.save(source, dict(old_source, revision=revision, observed=observed, predecessor=old_ref,
                        guard_receipts=PINNED, closure=stop_ref, correction_source=f.reference(here)))
    members[source.name] = (source, 0o444)
    return f.seal(DEST, members, staging/"plan.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--observed", required=True)
    args = parser.parse_args()
    print(issue(args.commit, args.observed))
