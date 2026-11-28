"""Keep the fourth 169 and replacement 162 on the full roster while pricing the third 170."""
import ast
from pathlib import Path

import following_prepare as f
from derive_gap_price import one

BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
PREVIOUS = BASE / "issued-price-v13"
DEST = BASE / "issued-price-v14"
SEAL = "0bbf64c190819a9f4e54e763ba4979c8bd98bdbd90f489878649d89c4333b677"
THIRD = f.ROOT / "epoch170-from-73760367-ram-20261128-v3"
SCOPE = dict(path=str(THIRD / "RAM_GAP170_WRITER_INTERFACE.json"), sha256="b148b13e8ef0bfff8bb40992eb267068668dac71590908806fe6ded15dff7151")
OBSERVER = "1eac71ad427b6f67421199403e8f6782823d0052e98aec9793b7a7497f3ae0e3"
HERE = Path(__file__).resolve().parent
RETRY162 = HERE.parent / "horizon_epoch162_split_scratch/second_retry_peer.py"
INTERFACE162 = dict(path=str(f.ROOT / "epoch162-second-replay-20261128-v2/RETRY_INTERFACE_V3.json"),
                    sha256="2192e657ff4cf56a9404dc41cf5d3223cb437afa3eb7225676b4116d95c18712")
SECOND_OBSERVER = "5c8d82782a94087bb5622ee35a0daa5b71a3904973308647833750528e062f25"


def members(staging, revision):
    previous = dict(path=str(PREVIOUS / "deployment-seal-receipt.json"), sha256=SEAL)
    old = f.read(previous)
    scope = f.read(SCOPE)
    observer = f.read(dict(path=str(THIRD / "observer-modules-v1/deployment-seal-receipt.json"), sha256=OBSERVER))
    f.need(old["destination"] == str(PREVIOUS)
           and observer["destination"] == str(THIRD / "observer-modules-v1")
           and scope["previous_ram_terminal"]["sha256"] == "31ae2a5041a3ac5b4876826047b920093debb7ef5d9747d0e578a54fae2ec896"
           and scope["previous_ram_drain"]["sha256"] == "5ad6e6935de5042a5e12a18e32a930d50fb3aa3e343f35028263cec6647cd937",
           "different third 170 receiver or stopped bootstrap")
    history = f.read(f.reference(PREVIOUS / "SOURCE.json"))
    f.need(history["fourth_169_scope"] == "f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5"
           and history["second_162_retry_interface"]["sha256"] == "c010fe101d3edafb732bbf87f7f8de7fd41a11d9b8b967e14ac5a4f372a8e279",
           "different 169 or 162 owner")
    f.need(f.reference(RETRY162)["sha256"] == "24f4676bb7a6ad7a1e198241c912c2ff25b45936483018004c32309c552b7148"
           and f.read(INTERFACE162)["provider"]["sha256"] == "051fcc7f5a7ef31a8fa6fb31372d029c83428e5c4eceb1eecc6dd7235fd64393",
           "different corrective 162 guard provider")
    staging.mkdir(mode=0o700)
    files = {}
    for item in old["members"]:
        name = item["name"]
        path = PREVIOUS / name
        f.need(path.parent == PREVIOUS and f.reference(path)["sha256"] == item["sha256"], "changed V13 member " + name)
        if name == "SOURCE.json":
            continue
        source = path.read_text()
        if name in ("capacity.py", "continuation_price.py", "successor_price.py"):
            f.need(source.count(str(PREVIOUS)) == (3 if name == "successor_price.py" else 1), "unregistered V13 self binding " + name)
            source = source.replace(str(PREVIOUS), str(DEST))
        if name == "ram170_live.py":
            files["second_ram170_live.py"] = (path, 0o444)
            source = source.replace("from-73760367-ram-20261128-v2", "from-73760367-ram-20261128-v3")
            source = one(source, SECOND_OBSERVER, OBSERVER)
            source = source.replace("ram170_second_", "ram170_third_")
            f.need(source.count("first_ram170_live.py") == 2, "missing preceding RAM receiver")
            source = source.replace("first_ram170_live.py", "second_ram170_live.py").replace("first RAM producer is still running", "second RAM producer is still running")
        elif name == "capacity.py":
            source = one(source, "'first_ram170_live.py'", "'first_ram170_live.py','second_ram170_live.py','fourth169_residency.py'")
        elif name == "second162_peer.py":
            source = RETRY162.read_text()
        elif name == "ram170_residency.py":
            source = (HERE / name).read_text()
        elif name == "after_stop.py":
            marker = "    before = core.availability()"
            source = one(source, marker, "    fourth = runpy.run_path(str(directory/'fourth169_residency.py'))\n"
                         "    fourth_before = fourth['sample'](core,receiver,fleet,retry169,residency)\n" + marker)
            marker = "    verification = cap['verification168'](fleet['retry9_auxiliary_commitments'])"
            source = one(source, marker, "    fourth_after = fourth['sample'](core,receiver,fleet,retry169,residency)\n"
                         "    fourth['apply'](core,native,fourth_before,fourth_after,first['row169'])\n" + marker)
        elif name == "after_assembly.py":
            marker = "    paid169 = min(snapshot['paid169'], cap['resident'](later))"
            source = one(source, marker, marker + "\n    core.need(not paid169 and a['phase']==later['phase']=='terminal', "
                         "'original and replacement 169 resident accounting overlaps')")
        elif name == "successor_price.py":
            source = one(source, "horizon-qualify-170-from-73760367-ram-20261128-v2.service",
                         "horizon-qualify-170-from-73760367-ram-20261128-v3.service")
        ast.parse(source, filename=name)
        dest = staging / name
        dest.write_text(source)
        files[name] = (dest, 0o444)
    helper=HERE / "fourth169_residency.py"
    files[helper.name]=(helper,0o444)
    manifest = staging / "SOURCE.json"
    f.save(manifest, dict(history, revision=revision, fourth_169_v13_provider=previous, third_ram170_scope=SCOPE,
                          third_ram170_observer=OBSERVER, corrected_second162_interface=INTERFACE162,
                          fourth169_residency_source=f.reference(helper)["sha256"], retained_second_170_terminal=scope["previous_ram_terminal"],
                          retained_second_170_drain=scope["previous_ram_drain"]))
    files[manifest.name] = (manifest, 0o444)
    return files
