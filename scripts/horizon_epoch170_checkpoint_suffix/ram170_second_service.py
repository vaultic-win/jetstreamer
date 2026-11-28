"""Project a fresh RAM-backed working tree while preserving the first attempt."""
from pathlib import Path

import following_prepare as f
from ram170_capacity import ROOT as OLD, UNIT as OLD_UNIT

ROOT = OLD.with_name('epoch170-from-73760367-ram-20261128-v2')
UNIT = OLD_UNIT.replace('20261128-v1.service', '20261128-v2.service')
OLD_SEAL = '8e75d3793628da23d999b07c857b9bebfa0bdf0ab8e2f945ffc389345244b69c'
BUILD = '6aa6074a31f75c19e7f318e6c8d91acd3351d995c099b23410a031711e810890'


def service():
    seal = f.read(dict(path=str(OLD/'package/deployment-seal-receipt.json'), sha256=OLD_SEAL))
    member, = (m for m in seal['members'] if m['name'] == OLD_UNIT)
    path = OLD/'package'/OLD_UNIT
    f.need(f.reference(path)['sha256'] == member['sha256'], 'different first RAM service')
    source = path.read_text()
    f.need(source.count(str(OLD)+'/package/') == 2 and source.count(str(OLD)+'/barrier:') == 1
           and 'from-73760367-to-73766969-ram-v1/scratch:rw,nosuid,nodev,exec,noswap' in source,
           'first RAM service lost its private paths')
    return source.replace(str(OLD)+'/package/', str(ROOT)+'/package/').replace(str(OLD)+'/barrier:',str(ROOT)+'/barrier:').replace('from-73760367-to-73766969-ram-v1', 'from-73760367-to-73766969-ram-v2')


def package(staging, path):
    seal = f.read(dict(path=str(OLD/'package/deployment-seal-receipt.json'), sha256=OLD_SEAL))
    proof = f.read(dict(path=str(path/'BUILD.json'), sha256=BUILD))
    f.need(proof['invocation']=='a9ac15c8bc264b61a589bfc42109f743' and set(proof['outputs'])=={'gate','guard','gap-checkpoints'},
           'unregistered second native build')
    members = {}
    for m in seal['members']:
        name = m['name']
        orig = OLD/'package'/name
        f.need(orig.parent == OLD/'package' and f.reference(orig)['sha256']==m['sha256'], 'changed original input')
        if name not in (*proof['outputs'],'build.json','SHA256SUMS',OLD_UNIT):
            members[name] = (orig,0o444)
    for name, sha in proof['outputs'].items():
        f.need(f.reference(path/name)['sha256']==sha,'changed second native executable')
        members[name] = (path/name,0o555)
    members['build.json'] = (path/'BUILD.json',0o444)
    unit = staging/UNIT
    unit.write_text(service())
    members[UNIT] = (unit,0o444)
    return members
