"""Extend the corrected third-169 roster to the second RAM-gap worker and its resident pages."""
import ast
from pathlib import Path

import following_prepare as f
from derive_gap_price import one

BASE = f.ROOT/'epoch162-first-hourly-completion-20261127-v2'
PREVIOUS = BASE/'issued-price-v10-custody'
DEST = BASE/'issued-price-v11'
SECOND = f.ROOT/'epoch170-from-73760367-ram-20261128-v2'
SCOPE = dict(path=str(SECOND/'RAM_GAP170_WRITER_INTERFACE.json'),sha256='1a4439dc22ccb3345fd9e472acc517198a26a0401793173af0ff268db4249cfc')
OBSERVER = '5c8d82782a94087bb5622ee35a0daa5b71a3904973308647833750528e062f25'
FIRST_OBSERVER = 'e94b0211cfa973e0ca708259c3ec7e611b5cfd6b831d27c9530167d96b3c8bee'
SEAL = '14bf9fe1d72a2c4b81c534881b3a3ccff6366eadba91311ee2d4da3caee9f1bd'


def second_owner(code):
    code=one(code,'import hashlib','import hashlib\nimport runpy')
    code=code.replace('from-73760367-ram-20261128-v1','from-73760367-ram-20261128-v2')
    code=one(code,FIRST_OBSERVER,OBSERVER)
    for name in ('status','contract','native','workspace'):
        code=code.replace('ram170_'+name,'ram170_second_'+name)
    code=one(code,'    folder=ROOT/', "    previous=runpy.run_path(str(Path(__file__).with_name('first_ram170_live.py')))\n    previous['receiver'](core)\n    folder=ROOT/")
    code=one(code,'    callback=receiver(core)\n    callback.contract.stopped_owner(fleet)',
             "    previous=runpy.run_path(str(Path(__file__).with_name('first_ram170_live.py')))\n    core.need(previous['owner'](core,fleet) is None, 'first RAM producer is still running')\n    callback=receiver(core)\n    callback.contract.stopped_owner(fleet)")
    return code


def members(staging, revision):
    old_ref=dict(path=str(PREVIOUS/'deployment-seal-receipt.json'),sha256=SEAL)
    old=f.read(old_ref);scope=f.read(SCOPE)
    f.need(old['destination']==str(PREVIOUS) and scope['previous_ram_drain']['sha256']=='1db663cb2987c894ad070f3587325ca8cea1416c70ae1564b421da87386b9d48',
           'different predecessor or second 170 custody')
    staging.mkdir(mode=0o700,exist_ok=True)
    files={}
    for m in old['members']:
        name=m['name'];path=PREVIOUS/name
        f.need(path.parent==PREVIOUS and f.reference(path)['sha256']==m['sha256'],'changed third-169 roster member')
        if name=='SOURCE.json': continue
        code=path.read_text()
        if name in ('capacity.py','continuation_price.py','successor_price.py'):
            n=3 if name=='successor_price.py' else 1
            f.need(code.count(str(PREVIOUS))==n,'changed base operator paths: '+name)
            code=code.replace(str(PREVIOUS),str(DEST))
        if name=='ram170_live.py':
            code=second_owner(code)
            files['first_ram170_live.py']=(path,0o444)
        if name=='successor_price.py':
            code=one(code,'unit = "horizon-qualify-170-from-73760367-ram-20261128-v1.service"',
                          'unit = "horizon-qualify-170-from-73760367-ram-20261128-v2.service"')
        if name=='capacity.py':
            code=one(code,"'ram170_live.py'", "'ram170_live.py','first_ram170_live.py','ram170_residency.py'")
        if name=='capacity.py':
            code=one(code,"'next162_reservation.py'}", "'next162_reservation.py','frozen162_image.py'}")
            anchor="    runpy.run_path(str(STOPPED.parent/'next162_reservation.py'))['reserve'](peer, proof, base, row, final)"
            code=one(code,anchor,anchor+"\n    runpy.run_path(str(STOPPED.parent/'frozen162_image.py'))['reconcile'](peer, base, row, final)")
        if name=='after_stop.py':
            code=one(code,'    before = core.availability()', '''    residency = runpy.run_path(str(directory/'ram170_residency.py'))
    resident_before = residency['sample'](core, live, gap170)
    before = core.availability()''')
            marker="    verification = cap['verification168'](fleet['retry9_auxiliary_commitments'])"
            code=one(code,marker, '''    resident_after = residency['sample'](core, live, gap170)
    residency['apply'](core, native, resident_before, resident_after)
'''+marker)
        ast.parse(code,filename=name)
        output=staging/name;output.write_text(code);files[name]=(output,0o444)
    for name in ('ram170_residency.py','frozen162_image.py'):
        helper=Path(__file__).with_name(name);files[name]=(helper,0o444)
    original=f.read(f.reference(PREVIOUS/'SOURCE.json'));manifest=staging/'SOURCE.json'
    f.save(manifest,dict(original,revision=revision,third_169_custody_provider=old_ref,second_ram170_scope=SCOPE,
                         second_ram170_observer=OBSERVER,resident_method='bracketed exact-worker Pss_Anon, private noswap allocation and cgroup counters'))
    files[manifest.name]=(manifest,0o444)
    return files
