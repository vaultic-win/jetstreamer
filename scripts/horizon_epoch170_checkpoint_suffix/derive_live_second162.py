"""Extend the issued 169/170 price with the independently enrolled second 162 actor."""
import ast
from pathlib import Path

import following_prepare as f
from derive_gap_price import one
from second162_peer import INTERFACE, PROVIDER, READER, UNIT


BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
OLD = BASE / "issued-price-v11"
DEST = BASE / "issued-price-v12"
PREVIOUS = dict(path=str(OLD / "deployment-seal-receipt.json"),
                sha256="d9c5e6a5a3e103ef161992da326d15def22da320e409b269938fdb92252192dc")


def extend(name, source):
    references = {"capacity.py": 1, "continuation_price.py": 1, "successor_price.py": 3}
    if name in references:
        f.need(source.count(str(OLD)) == references[name], "unexpected provider path in " + name)
        source = source.replace(str(OLD), str(DEST))
    helper = "runpy.run_path(str(Path(__file__).with_name('second162_peer.py')))"
    if name == "capacity.py":
        source = one(source, "'next162_reservation.py','frozen162_image.py'}",
                     "'next162_reservation.py','frozen162_image.py','second162_peer.py'}")
        source = one(source, "    peer = runpy.run_path(str(module))",
                     f"    peer = {helper}['first_peer'](runpy.run_path(str(module)))")
        marker = "    return dict(schema='horizon-168-post-assembly-six-owner-price-v1', base_169=base"
        source = one(source, marker, f"""    second = {helper}
    before = base['native']['second_162_before']
    after = second['sample'](peer, fleet, base['writer'])
    second['apply'](need, base, final, before, after)
    core = runpy.run_path(str(STOPPED.parent/'continuation_price.py'))['prior']
    latest = runpy.run_path(str(STOPPED.parent/'following_peers.py'))['current_writer']
    need(core.current_fleet()[1] == base['fleet'] and latest(core,base['provider']) == base['writer'],
         'changed fleet or writer after second 162 recheck')
""" + marker)
    elif name == "following_peers.py":
        marker = "    peer162 = runpy.run_path(str(ISSUED/'peer162.py'))"
        source = one(source, marker, f"""    second = {helper}
    peer162 = second['first_peer'](runpy.run_path(str(ISSUED/'peer162.py')))""")
        marker = "    b = peer162['current'](fleet)"
        source = one(source, marker, marker + "\n    second_before = second['sample'](peer162, fleet, writer)")
        source = one(source, "row169=a, row162=b, writer=writer,",
                     "row169=a, row162=b, second_162=second_before, writer=writer,")
    elif name == "after_stop.py":
        marker = "    if gap170:\n        native[170]"
        source = one(source, marker, """    second = first['second_162']['owner']
    if second and second['phase'] != 'terminal':
        core.need(162 not in native, 'two 162 actors claim the same reservation')
        native[162] = second['unit']
""" + marker)
        marker = "    raw = current['price']('stopped', native169=first['row169'], native162=first['row162'],"
        source = one(source, marker, """    core.need(first['row162']['phase'] == 'terminal', 'first 162 is outside closed custody')
    raw = current['price']('stopped', native169=first['row169'], native162=first['second_162']['owner'],""")
        marker = "    native['independent_retry169'] = retry169"
        source = one(source, marker, "    native['second_162_before'] = first['second_162']\n" + marker)
    elif name == "successor_price.py":
        source = one(source, 'and native162["unit"]["Id"] == "horizon-qualify-162-first-hourly-completion-20261127-v2.service",',
                     f'and native162["unit"]["Id"] == "{UNIT}",')
    return source


def members(staging, revision):
    previous = f.read(PREVIOUS)
    f.need(previous["destination"] == str(OLD), "unexpected V11 provider")
    files = {}
    staging.mkdir(mode=0o700)
    for item in previous["members"]:
        name = item["name"]
        member = OLD / name
        f.need(member.parent == OLD and f.reference(member)["sha256"] == item["sha256"],
               "V11 provider member changed: " + name)
        if name == "SOURCE.json":
            continue
        source = extend(name, member.read_text())
        ast.parse(source, filename=name)
        dest = staging / name
        dest.write_text(source)
        files[name] = (dest, 0o444)
    helper = Path(__file__).with_name("second162_peer.py")
    files[helper.name] = (helper, 0o444)
    manifest = staging / "SOURCE.json"
    history = f.read(f.reference(OLD / "SOURCE.json"))
    f.save(manifest, dict(history, revision=revision, v11_provider=PREVIOUS,
                          second162_scope=INTERFACE, second162_operator=PROVIDER, second162_reader=READER))
    files[manifest.name] = (manifest, 0o444)
    return files
