"""Extend the sealed v6 whole-roster provider for the separate 170 owner; preserve its 143 retry."""
import ast
from pathlib import Path

import following_prepare as f

BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
OLD = BASE / "issued-price-v6"
DEST = BASE / "issued-price-v7"
OLD_SEAL = "834e0502085a31dd0cc7a035eb96c7b00144d05d172fa4b1649633343dd34fa0"
OLD_CAPACITY = "dc2f6f03ff83089c3d8874b85a49bf2503bcdd32012397c78ce8f12bdcb7138b"


def one(text, before, after):
    f.need(text.count(before) == 1, "changed v6 source: " + before)
    return text.replace(before, after)


def extend(name, source):
    if name == "capacity.py":
        source = one(source, "STOPPED = ROOT / 'issued-price-v6/capacity.py'",
                     "STOPPED_V6 = ROOT / 'issued-price-v6/capacity.py'\nSTOPPED = ROOT / 'issued-price-v7/capacity.py'")
        old = "{'path':str(STOPPED_V5), 'sha256':'091c06051762b277db141d19ebed0fec815fdd22804e7ff81fe7f296de0a1804'}"
        source = one(source, old, old + ", {'path':str(STOPPED_V6), 'sha256':'" + OLD_CAPACITY + "'}")
        return one(source, "names = MODULES | {'after_stop.py','scan_handback.py'}",
                   "names = MODULES | {'after_stop.py','scan_handback.py','gap170_capacity.py'}")
    if name == "continuation_price.py":
        source = one(source, 'with_name("issued-price-v6")', 'with_name("issued-price-v7")')
        source = one(source, 'def price(phase, *, native169=None, native162=None):',
                     'def price(phase, *, native169=None, native162=None, gap170=None):')
        return one(source, 'hourly_replacement=replacement["iid"] if replacement else None, **options)',
                   'hourly_replacement=replacement["iid"] if replacement else None, gap170=gap170, **options)')
    if name == "successor_price.py":
        source = one(source, 'RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v6"',
                     'RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v7"')
        source = one(source, "hourly_replacement=None, native169=None, native162=None):",
                     "hourly_replacement=None, native169=None, native162=None, gap170=None):")
        marker = '    need(units == expected, "replay owner changed: "+repr(units ^ expected))'
        return one(source, marker, '''    if gap170 is not None:
        unit = "horizon-qualify-170-from-73760367-20261128-v1.service"
        actual = state(unit)
        need(Path(__file__).resolve().parent == RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v7"
             and phase == "start" and actual["Id"] == gap170["unit"] == unit
             and actual["InvocationID"] == gap170["invocation"] and actual["MainPID"] == str(gap170["pid"])
             and actual["MemoryMax"] == str(48*G) and actual["CPUQuotaPerSecUSec"] == "6s"
             and actual["MemorySwapMax"] == "0" and not actual["Job"], "unregistered epoch 170 gap")
        expected.add(unit)
''' + marker)
    if name == "after_stop.py":
        source = one(source, 'def observations(core, fleet, raw, first):', 'def observations(core, fleet, raw, first, gap170):')
        marker = "    actual = {line.split()[0] for line in core.cmd("
        source = one(source, marker, '''    if gap170:
        native[170] = dict(Id=gap170["unit"], InvocationID=gap170["invocation"])
''' + marker)
        marker = "    stopped_ref = stopped(core,current,fleet)"
        source = one(source, marker, marker + """
    gap = runpy.run_path(str(directory/'gap170_capacity.py'))
    gap170 = gap['owner'](core,fleet)""")
        source = one(source, "native162=first['row162'])", "native162=first['row162'],gap170=gap170)")
        source = source.replace("observations(core,fleet,raw,first)", "observations(core,fleet,raw,first,gap170)")
        marker = "    verification = cap['verification168']("
        source = one(source, marker, """    native['independent_gap170'] = gap170
    gap['debit'](core,native)
""" + marker)
        marker = "    core.need(stopped(core,current,fleet)==stopped_ref and "
        return one(source, marker, "    core.need(gap['owner'](core,fleet)==gap170 and stopped(core,current,fleet)==stopped_ref and ")
    return source


def members(staging, revision):
    expected = dict(path=str(OLD / "deployment-seal-receipt.json"), sha256=OLD_SEAL)
    manifest = f.read(expected)
    f.need(manifest["destination"] == str(OLD), "different v6 package")
    files = {}
    staging.mkdir(mode=0o700, exist_ok=True)
    for item in manifest["members"]:
        name = item["name"]
        prior = OLD / name
        f.need(prior.parent == OLD and f.reference(prior)["sha256"] == item["sha256"], "v6 member changed")
        if name == "SOURCE.json":
            continue
        data = extend(name, prior.read_text())
        ast.parse(data, filename=name)
        target = staging / name
        target.write_text(data)
        files[name] = (target, 0o444)
    extra = Path(__file__).with_name("gap170_capacity.py")
    files[extra.name] = (extra, 0o444)
    binding = staging / "SOURCE.json"
    f.save(binding, dict(branch="origin/account-updates", revision=revision, predecessor=expected,
                         replay_authorized=False))
    files[binding.name] = (binding, 0o444)
    return files
