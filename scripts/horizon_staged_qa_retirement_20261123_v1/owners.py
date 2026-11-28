"""Reconcile the candidate paths with current owner declarations and the fleet."""
import json
import os
import re
import subprocess
from pathlib import Path

SYSTEM_ROOTS = ('/etc/systemd','/run/systemd/transient','/run/systemd/system','/etc/cron.d','/etc/crontab',
                '/var/spool/cron','/home/sol/.config/systemd','/root/.config/systemd',
                '/usr/local/lib/systemd','/run/user/1001/systemd')
CONTROL_SUFFIXES = {'.service','.timer','.path','.sh','.py','.rs','.conf','.toml','.json','.jsonl'}

def require(ok, message):
    if not ok:
        raise RuntimeError(str(message))

def references(obj):
    if isinstance(obj,dict):
        for key, item in obj.items():
            if isinstance(key,str) and key.startswith('/'):
                yield Path(key)
            if key == 'path' and isinstance(item,str) and item.startswith('/'):
                yield Path(item)
            yield from references(item)
    elif isinstance(obj,list):
        for item in obj:
            yield from references(item)

def cold_units(names):
    result = {}
    for offset in range(0,len(names),48):
        keys = 'Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,Triggers,TriggeredBy,UnitFileState,FragmentPath'
        p = subprocess.run(['systemctl','show','-p',keys,*names[offset:offset+48]],capture_output=True)
        require(p.returncode in (0,4) and not p.stderr, ('native owners',p.stderr[:200]))
        for block in p.stdout.decode().strip().split('\n\n'):
            row = dict(line.split('=',1) for line in block.splitlines())
            name = row['Id']
            require(name not in result and row.get('MainPID','0') == row.get('ControlPID','0') == '0'
                    and not row['Job'] and not row.get('Triggers') and not row.get('TriggeredBy')
                    and row['SubState'] in ('dead','failed','exited')
                    and row.get('UnitFileState','') in ('','transient','disabled','masked'),
                    f'live or scheduled staging consumer: {name}')
            if row['LoadState'] == 'not-found':
                require(not row['FragmentPath'], f'replaced owner {name}')
            result[name] = row['SubState']
    require(set(result) == set(names),'missing owner response')
    return {v:list(result.values()).count(v) for v in set(result.values())}

def check(rows, manifest, initial, fleet, bindings, kernel):
    names = set(rows)
    classification = bindings['read'](Path(manifest['control_parent_classification']['path']))
    roots = [Path(s) for s in classification]
    patterns = [(root,re.compile(re.escape(os.fsencode(root.name))+
                  rb"""(?P<suffix>/[^\x00\s"',;\\}\]\)]*)?""")) for root in roots]
    def covered(p):
        return any(str(p) == s or p in Path(s).parents for s in names)
    def pinned_text(data, path):
        for root, pattern in patterns:
            for hit in pattern.finditer(data):
                suffix = os.fsdecode(hit['suffix'] or b'').strip('/')
                require(suffix and not covered(root/suffix), f'staging path or ancestor in current control: {path} -> {root/suffix}')
    proc = subprocess.run(['/usr/bin/rg','--threads','1','--no-config','--no-ignore','--hidden','-l','-F',
                           *[token for r in roots for token in ('-e',r.name)],'--',
                           *[p for p in SYSTEM_ROOTS if Path(p).exists()]],capture_output=True)
    require(proc.returncode in (0,1) and not proc.stderr,proc.stderr[:256])
    declarations = list(map(Path,os.fsdecode(proc.stdout).splitlines()))
    units = set(initial['native_referencing_units'])
    for p in declarations:
        if p.suffix in ('.service','.timer','.path'):
            units.add(p.name)
        else:
            raise RuntimeError(f'unclassified native or cron control mentions staging roots: {p}')
    unit_counts = cold_units(sorted(units))
    current = bindings['read'](fleet)
    route = Path(initial['route']['path'])
    require(bindings['fingerprint'](route)==initial['route']['sha256'], 'route changed')
    controls = {fleet, route, *[Path(v['path']) for v in initial['freezes']]}
    for doc in (current, bindings['read'](route),bindings['read'](Path(manifest['outside_booking_basis']['path']))):
        controls.update(p for p in references(doc) if p.suffix in CONTROL_SUFFIXES)
    for row in bindings['read'](route).get('reviewed_routes',{}).values():
        controls.update(Path(p) for p in row.get('inputs',[]) if Path(p).suffix in CONTROL_SUFFIXES)
    large = Path(manifest['large_control_sha256']['path'])
    require(bindings['fingerprint'](large)==manifest['large_control_sha256']['sha256'],'unreviewed large historical control')
    examined = 0
    for p in sorted(controls - {large}):
        # A missing historical evidence pathname cannot refer to an existing
        # source. Native unit disappearance is checked independently above.
        if not p.is_file():
            continue
        require(p.stat().st_size <= 16<<20, f'new oversized control requires review: {p}')
        pinned_text(p.read_bytes(), p)
        examined += 1
    for freeze in initial['freezes']:
        require(bindings['fingerprint'](Path(freeze['path'])) == freeze['sha256'],'compiler freeze changed')
    stamps = {name:row['source_stat'] for name,row in rows.items()}
    return {'fleet':str(fleet), 'pinned_controls':examined, 'closed_units':unit_counts,
            'declarations':len(declarations), 'kernel':kernel(stamps, sorted({Path(p).parent for p in names}))}
