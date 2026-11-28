"""Extend the V12 complete roster to the fourth epoch 169 private gate."""
import argparse
import ast
from pathlib import Path
import sys
import tempfile


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import following_prepare as f
from derive_third169_price import reviewed


BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
OLD = BASE / "issued-price-v12"
DEST = BASE / "issued-price-v13"
SEAL = "df17ab9a76fe24273e807d32f49d3b8b5287e8be4885ac339d3370323652c302"
PEER = HERE.parent / "horizon_epoch169_hourly_retry/fourth_peer.py"
PEER_SHA = "6bbf689919cd0446f0621914257e3a86291e7ddd7abce7a0c4ac326cb2651ad1"
SCOPE = "f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5"
PEER162 = HERE.parent / "horizon_epoch162_split_scratch/second_retry_peer.py"
PEER162_SHA = "f4d1735d0139ca30b4fd55da6cad62669eb7bdeb9aa916bbae8b51518a50f34d"
INTERFACE162 = dict(path=str(f.ROOT / "epoch162-second-replay-20261128-v2/RETRY_INTERFACE.json"),
                    sha256="c010fe101d3edafb732bbf87f7f8de7fd41a11d9b8b967e14ac5a4f372a8e279")


def extend(name, source):
    references = {"capacity.py": 1, "continuation_price.py": 1, "successor_price.py": 3}
    if name in references:
        f.need(source.count(str(OLD)) == references[name], "unrecognized V12 self binding in " + name)
        source = source.replace(str(OLD), str(DEST))
    if name == "successor_price.py":
        unit = "horizon-qualify-169-hourly-retry-20261128-v3.service"
        f.need(source.count(unit) == 2, "unexpected V12 private 169 native membership")
        source = source.replace(unit, unit.replace("-v3.service", "-v4.service"))
        unit = "horizon-qualify-162-second-replay-20261128-v1.service"
        f.need(source.count(unit) == 1, "unexpected V12 second 162 native membership")
        source = source.replace(unit, unit.replace("-v1.service", "-v2.service"))
    if name == "after_assembly.py":
        marker = "    paid169 = min(snapshot['paid169'], cap['resident'](later))"
        f.need(source.count(marker) == 1, "different original 169 charge computation")
        source = source.replace(marker, "    runpy.run_path(str(Path(__file__).with_name('frozen169_output.py')))['reconcile'](core, native, a, later, amounts)\n" + marker)
    if name == "capacity.py":
        marker = "'frozen162_image.py','second162_peer.py'}"
        f.need(source.count(marker) == 1, "different roster membership validator")
        source = source.replace(marker, "'frozen162_image.py','second162_peer.py','frozen169_output.py'}")
    return source


def build(staging, commit, observed):
    repo = HERE.parent.parent
    f.git(repo, "merge-base", "--is-ancestor", commit, observed)
    f.need(f.git(repo, "rev-parse", "origin/account-updates").decode().strip() == observed,
           "different observed campaign revision")
    frozen = HERE / "frozen169_output.py"
    inputs = (Path(__file__).resolve(), PEER, PEER162, frozen, HERE / "derive_third169_price.py",
              HERE / "following_prepare.py", HERE / "derive_gap_price.py", HERE / "closed_successor.py")
    sources = {}
    for file in inputs:
        reviewed(file, commit, observed)
        sources[str(file.relative_to(repo))] = f.reference(file)["sha256"]
    f.need(f.reference(PEER)["sha256"] == PEER_SHA and f.reference(PEER162)["sha256"] == PEER162_SHA,
           "unrecognized fourth 169 or second 162 retry peer")
    retry162 = f.read(INTERFACE162)
    f.need(retry162["unit"] == "horizon-qualify-162-second-replay-20261128-v2.service"
           and retry162["field"] == "current_private162_second_retry", "different second 162 retry interface")
    pinned = dict(path=str(OLD / "deployment-seal-receipt.json"), sha256=SEAL)
    previous = f.read(pinned)
    f.need(previous["destination"] == str(OLD), "different V12 price")
    files = {}
    replacements = {"retry169_peer.py": PEER, "second162_peer.py": PEER162}
    for item in previous["members"]:
        name = item["name"]
        file = OLD / name
        f.need(file.parent == OLD and f.reference(file)["sha256"] == item["sha256"], "V12 member changed")
        if name == "SOURCE.json":
            continue
        code = replacements[name].read_text() if name in replacements else extend(name, file.read_text())
        ast.parse(code, filename=name)
        dest = staging / name
        dest.write_text(code)
        files[name] = (dest, 0o444)
    files[frozen.name] = (frozen, 0o444)
    original = f.read(f.reference(OLD / "SOURCE.json"))
    manifest = staging / "SOURCE.json"
    f.save(manifest, dict(original, revision=commit, remote_observed=observed, v12_provider=pinned,
                          fourth_169_sources=sources, fourth_169_scope=SCOPE, fourth_169_peer=PEER_SHA,
                          second_162_retry_interface=INTERFACE162, second_162_retry_peer=PEER162_SHA))
    files[manifest.name] = (manifest, 0o444)
    return files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--observed", required=True)
    args = parser.parse_args()
    stage = Path(tempfile.mkdtemp(prefix="fourth169-roster-source.", dir=BASE))
    print(f.seal(DEST, build(stage, args.commit, args.observed), stage / "plan.json"))
