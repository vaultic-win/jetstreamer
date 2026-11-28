"""Derive the normal cadence package with the qualified observer and durable RSS retry."""
import hashlib
import json
from pathlib import Path
import sys


def replace(text, before, after):
    if text.count(before)!=1:
        raise ValueError('unexpected production source: '+before)
    return text.replace(before,after)


def sources(base, image, digest):
    """Apply only to the previously accepted host-clock package."""
    expected='972fcf1c1354b1620c6bc74b63fb612d9ef75235cde4fa80855ca96cf8abf5d2'
    if hashlib.sha256((base/'deployment-seal-receipt.json').read_bytes()).hexdigest()!=expected:
        raise ValueError('different clock predecessor')
    source={name:(base/name).read_text() for name in ('race166.py','cycle.py','guard_stops.py','consume')}
    race=source['race166.py']
    race=replace(race,'/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe',str(image))
    race=replace(race,'6b06665ac4dd0654f6684f4fd178787c37e30af332a657c6c5a6502c2f3e2ab8',digest)
    race=replace(race,'    if Path(path)==clock_recovery.CONFIG:',
                 "    import resident_clock\n    if Path(path).parent.parent.parent.name=='resident-census-recovery':\n        return resident_clock.scheduled(Path(path))\n    if Path(path)==clock_recovery.CONFIG:")
    source['race166.py']=race
    source['cycle.py']=replace(source['cycle.py'],'    return f,cfg,prevs',
               '    from resident_clock import resolve\n    f,cfg=resolve(ref,f,cfg)\n    return f,cfg,prevs')
    source['guard_stops.py']=replace(source['guard_stops.py'],'    from clock_recovery import view\n    fleet,cfg=view(fleet_ref,checked(fleet_ref),cfg)',
               '    from cycle import load_fleet\n    fleet,actual,_=load_fleet(fleet_ref)\n    need(actual==cfg,"changed registered scheduled config")')
    start=source['consume']
    start=replace(start,'    timer=$(jq -er .timer <<<"$meta")',
                  '    /usr/bin/python3 -B "$pkg/resident_clock.py" ensure "$fleet" "$sha"\n    timer=$(jq -er .timer <<<"$meta")')
    start=replace(start,'    while ! "$pkg/run-cycle.sh"','    disposition=$(/usr/bin/python3 -B "$pkg/resident_clock.py" decide "$fleet" "$sha" "$sample" "$binding")\n    if [[ $disposition == reschedule ]]; then continue; fi\n    [[ $disposition == publish ]]\n    while ! "$pkg/run-cycle.sh"')
    source['consume']=start
    return source


if __name__=='__main__':
    base,image,digest,destination=map(str,sys.argv[1:])
    for name, code in sources(Path(base),Path(image),digest).items():
        if name.endswith('.py'):
            compile(code,name,'exec')
        (Path(destination)/name).write_text(code)
