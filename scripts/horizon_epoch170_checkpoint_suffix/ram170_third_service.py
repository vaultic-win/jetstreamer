"""Project a fresh RAM-backed working tree while preserving both stopped attempts."""
from pathlib import Path

import following_prepare as f
from ram170_second_service import ROOT as OLD, UNIT as OLD_UNIT

ROOT = OLD.with_name('epoch170-from-73760367-ram-20261128-v3')
UNIT = OLD_UNIT.replace('20261128-v2.service', '20261128-v3.service')
OLD_SEAL = '19a4426a03738d2094b2e6101e175c7b1b9e438efd49f03381cec6b44bfb5496'
BUILD = '8b4323986500f1f5580ba4d12e5844e31966e83657f395d0c64e8dbd6ce62c5f'


def service():
    seal = f.read(dict(path=str(OLD/'package/deployment-seal-receipt.json'), sha256=OLD_SEAL))
    member, = (m for m in seal['members'] if m['name'] == OLD_UNIT)
    path = OLD/'package'/OLD_UNIT
    f.need(f.reference(path)['sha256'] == member['sha256'], 'different second RAM service')
    source = path.read_text()
    f.need(source.count(str(OLD)+'/package/') == 2 and source.count(str(OLD)+'/barrier:') == 1
           and 'from-73760367-to-73766969-ram-v2/scratch:rw,nosuid,nodev,exec,noswap' in source,
           'second RAM service lost its private paths')
    return source.replace(str(OLD)+'/package/', str(ROOT)+'/package/').replace(str(OLD)+'/barrier:',str(ROOT)+'/barrier:').replace('from-73760367-to-73766969-ram-v2', 'from-73760367-to-73766969-ram-v3')


def package(staging, path):
    seal = f.read(dict(path=str(OLD/'package/deployment-seal-receipt.json'), sha256=OLD_SEAL))
    proof = f.read(dict(path=str(path/'BUILD.json'), sha256=BUILD))
    f.need(proof['invocation']=='8d26a0bf44ea437a933478a934d48c10' and set(proof['outputs'])=={'gate','guard','gap-checkpoints'},
           'unregistered third native build')
    members = {}
    for m in seal['members']:
        name = m['name']
        orig = OLD/'package'/name
        f.need(orig.parent == OLD/'package' and f.reference(orig)['sha256']==m['sha256'], 'changed original input')
        if name not in (*proof['outputs'],'build.json','SHA256SUMS',OLD_UNIT):
            members[name] = (orig,0o444)
    for name, sha in proof['outputs'].items():
        f.need(f.reference(path/name)['sha256']==sha,'changed third native executable')
        members[name] = (path/name,0o555)
    members['build.json'] = (path/'BUILD.json',0o444)
    unit = staging/UNIT
    unit.write_text(service())
    members[UNIT] = (unit,0o444)
    return members
