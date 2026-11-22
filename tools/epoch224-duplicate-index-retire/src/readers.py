"""Enumerate configuration edges which can reopen the selected historical 224 index."""
import argparse,hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
from collections import defaultdict

PRIVATE=Path('/home/ubuntu/.jetstreamer-private')
ROOTS={'singleton':('adaptive-224-singleton-current-46b4b4a-v1','224-singleton-current'),
       'trace':('adaptive-224-trace-1ddcbc8-v1','224-trace-1ddcbc8'),
       'delta':('adaptive-224-account-delta-f160460-v1','224-account-delta-f160460'),
       'diagnostic':('qualification-224-singleton-diagnostic-8a4f843-v4','224-singleton-bounded-8a4f843')}
EXPECTED_MASKS={'delta': {'horizon-admit-224-account-delta-f160460-v1.service': 'a7c0b6d48400d176f6c0ff0f179f92c4b25432cadc854387b6291fa09c54e16f', 'horizon-monitor-recurring-224-account-delta-f160460-v1.timer': '90d484376a344e4a4aa78242992389c2ccaf8576b9b070fcb38bfe9cf0b49478', 'horizon-qualify-224-account-delta-f160460-v1.service': '2e63efdef157f0e9e5555f80e824f9fbc672fcfe88be178bf86904cd0d22d3c8'}, 'diagnostic': {'horizon-admit-224-bounded-8a4f843-v3.service': '8e867eb8084011f66a4ea53116b5e6ea55926e36ac229f8130a7ee0adc988711', 'horizon-monitor-recurring-224-singleton-bounded-8a4f843-v3.timer': 'e0316a28ba4fe2c53d91fc2b82d5020a56a05399cf8d33d98c6b13c1e5eb5c32', 'horizon-qualify-224-singleton-bounded-8a4f843-v3.service': 'aae8544fe534eeb50c26c0af03c14dd6ec244b25aebc6c19f75b8a76bac648c0'}, 'singleton': {'horizon-admit-224-singleton-current-v1.service': '1b12b7442f65701441a2aae9a98e94b734b344ed815cdbf587a783630f2624c2', 'horizon-admit-224-singleton-current-v2.service': '9078a940aa80bc57923e50c0b015b7454c2a1b348d3d7ab3e641c369540c05ca', 'horizon-controller-224-singleton-current-v1.service': 'd6356d5a4e4626affb55573e710f695529285d7af2acb66aed93acefd5472954'}, 'trace': {'horizon-admit-224-trace-1ddcbc8-v5.service': '5efc25a42357c81a703a55a6ea9068a7ea4b2d36f5ba331197c2bdb840835322', 'horizon-controller-224-trace-1ddcbc8-v1.service': '6c1ff0e1d2530874784624301ba2aac50ec6155c2b3d509b18023df119bcb09c', 'horizon-controller-224-trace-1ddcbc8-v2.service': '1f839ca4226d02cc14dd6ceb86d668c4438507277348f1a5f90f6dd3979537d8', 'horizon-controller-224-trace-1ddcbc8-v3.service': '625e07aa9a8890f871dcd2392bc3bd6d00037a2f3e9db55d3ee9d5d1627752b4'}}

def scan(selection, own=''):
    prefix,actor=ROOTS[selection]
    selected_root=PRIVATE/prefix
    relative='run-v2/output' if selection=='diagnostic' else 'lane-a/output'
    cid='epoch-224-bafyreibhabfaym35mtmufghs3mbocx5w5klok7t7irmwprr4rdmuvnoojy-mainnet-cid-to-offset-and-size.index'
    target=selected_root/relative/'compact-indexes/224'/cid
    # Extract complete pathname components. A sibling deployment, config/gcloud, logs or
    # provenance below the same historical root do not give access to the selected index.
    component=re.compile(rb'(?:/home/ubuntu/\.jetstreamer-private/)?'+re.escape(os.fsencode(prefix))+rb'(?![A-Za-z0-9_.-])(?:/[A-Za-z0-9_./+@=-]*)?')
    def relevant(blob):
        for match in component.finditer(blob):
            literal=Path(os.fsdecode(match[0]))
            candidate=literal if literal.is_absolute() else PRIVATE/literal
            if candidate==target or (candidate==selected_root or selected_root in candidate.parents) and candidate in target.parents:
                return True
        return False
    selectors={'singleton':['jetstreamer-root-sweep-horizon-224-singleton-current-v1-e224-224-lane-a-1.service',
               'horizon-controller-224-singleton-current-v1.service','horizon-controller-224-singleton-current-v2.service'],
               'trace':['jetstreamer-root-sweep-horizon-224-trace-1ddcbc8-v1-e224-224-lane-a-1.service',*[f'horizon-controller-224-trace-1ddcbc8-v{i}.service' for i in (1,2,3)]],
               'delta':['horizon-qualify-224-account-delta-f160460-v1.service'],
               'diagnostic':['horizon-qualify-224-singleton-bounded-8a4f843-v2.service','horizon-qualify-224-singleton-bounded-8a4f843-v3.service']}[selection]
    def activation(line):
        start=line.lstrip()
        names=re.findall(rb'(?<![A-Za-z0-9_.@-])[A-Za-z0-9_.@-]+\.(?:service|timer|path)(?![A-Za-z0-9_.@-])',line)
        if not any(os.fsdecode(name) in selectors for name in names):return False
        return (start.startswith((b'Wants=',b'Requires=',b'BindsTo=',b'Unit=',b'Activates=',b'OnFailure=',b'OnSuccess=',b'PropagatesReloadTo='))
                or re.search(rb'\bsystemctl\b[^\n]*(?:\bstart\b|\brestart\b|\btry-restart\b|\benable\b)',line) is not None)
    configuration=[Path(p) for p in ('/etc/systemd/system','/usr/lib/systemd/system','/usr/local/lib/systemd/system','/run/systemd/system','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late','/etc/systemd/user','/usr/lib/systemd/user','/etc/cron.d','/etc/crontab','/var/spool/cron/crontabs','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly','/etc/cron.monthly')]
    configuration.append(PRIVATE/'systemd-staging')
    for h in [Path('/root'),*Path('/home').iterdir()]:
        configuration.extend((h/'.config/systemd',h/'.local/share/systemd'))
    for user in Path('/run/user').glob('*'):
        configuration.extend(user/'systemd'/s for s in ('user','transient','generator','generator.early','generator.late'))
    recipe=re.compile(rb'/(?:var/lib/jetstreamer|usr/local/(?:bin|lib/jetstreamer)|home/ubuntu/(?:\.jetstreamer-private|workspace/jetstreamer/(?:scripts|tools))|run/horizon|tmp/horizon)[A-Za-z0-9_/+.@=,:-]+')
    budget=0;cached={};visited=set();hits=[];aliases=defaultdict(set);unresolved=[]
    def read(p):
        nonlocal budget
        if p in cached:return cached[p]
        n=p.stat().st_size
        if n>8<<20:raise ValueError('config exceeds metadata bound '+str(p))
        with p.open('rb') as f:
            head=f.read(128)
            if head.startswith(b'\x7fELF') or b'\0' in head:return b''
            f.seek(0);data=f.read((8<<20)+1)
        budget+=len(data)
        if len(data)!=n or budget>512<<20:raise ValueError('changed or oversized metadata graph')
        cached[p]=data
        return data
    def visit(p,ancestors):
        if p.is_symlink() and not p.exists():
            if (relevant(os.fsencode(p)) or relevant(os.fsencode(os.readlink(p)))):unresolved.append(str(p))
            return
        real=p.resolve(strict=True)
        if real==Path('/dev/null') or real in ancestors:return
        if real.is_dir():
            for child in p.iterdir():visit(child,ancestors|{real})
        elif real.is_file():aliases[real].add(str(p))
    for root in configuration:
        if root.exists():visit(root,set())
    def edges(data):
        return set(recipe.findall(data))
    def captured(data,trail):
        if relevant(data) or any(activation(line) for line in data.splitlines()):
            hits.append({'origin':trail[0],'chain':trail[1:],'sha256':hashlib.sha256(data).hexdigest()})
    def follow(p,trail):
        if len(trail)>16:raise ValueError('unresolved command depth')
        try:real=p.resolve(strict=True)
        except (FileNotFoundError,NotADirectoryError):return
        key=(trail[0],real)
        if key in visited or not real.is_file():return
        visited.add(key)
        if real.suffix.lower() in ('.env','.jet','.zst','.gz','.index','.so','.rlib','.bin','.lock','.ext4','.tar') or any(k in real.name.lower() for k in ('credential','secret')):return
        # Inspect the magic first so a large executable is never read as configuration.
        with real.open('rb') as fp:magic=fp.read(128)
        if magic.startswith(b'\x7fELF') or b'\0' in magic:return
        if not (real.suffix in ('.json','.py','.sh','.bash','.toml','.conf','.service','.timer','.path') or magic.startswith(b'#!')):return
        data=read(real);chain=[*trail,str(real)];captured(data,chain)
        # Enumerate executable/configuration edges. Receipt and archive references inside a JSON
        # are evidence; recurse through explicit configuration and command fields only.
        if real.suffix=='.json':
            try:obj=json.loads(data)
            except (json.JSONDecodeError,UnicodeDecodeError):
                # Some historical control paths carry JSON lines or a zero-byte marker.
                # Retain their direct hits and follow every literal recipe path.
                for item in edges(data):follow(Path(os.fsdecode(item)),chain)
                return
            def commands(v):
                if isinstance(v,dict):
                    for k,x in v.items():
                        if k.lower() in ('plan','configuration','settings','script','executable','command','argv','args','exec','config','launcher','wrapper','manifest','source_plan'):yield json.dumps(x).encode()
                        elif isinstance(x,(list,dict)):yield from commands(x)
                elif isinstance(v,list):
                    for x in v:yield from commands(x)
            literals=set().union(*(edges(x) for x in commands(obj)))
        else:literals=edges(data)
        for item in literals:follow(Path(os.fsdecode(item)),chain)
    for dest,names in aliases.items():
        if own and set(names)=={own} and str(dest)==own:continue
        data=read(dest)
        for name in sorted(names):
            service_data=b'\n'.join(line for line in data.splitlines() if not line.lstrip().startswith((b'#',b';',b'Description=',b'Documentation=',b'After=',b'Before=')))
            captured(service_data,[name])
            for line in data.splitlines():
                directive=line.lstrip()
                if directive.startswith((b'ExecStart',b'ExecStop',b'ExecReload',b'ExecCondition',b'EnvironmentFile=',b'WorkingDirectory=')) or '/cron' in name:
                    for item in edges(line):follow(Path(os.fsdecode(item)),[name])
    # An omitted or non-executable fragment by itself does not prove its original custody
    # or that PID 1 has noticed the mask. Reopen Main's original archive on each actual run.
    if own:
        base=Path('/var/lib/jetstreamer')/f'horizon224-index-{selection}-reader-closure-v169-v1'
        state=base.stat()
        if base.resolve()!=base or state.st_uid!=0 or stat.S_IMODE(state.st_mode)!=0o700:raise ValueError('reader archive custody')
        def sealed(p):
            st=p.lstat()
            if p.resolve()!=p or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o222 or st.st_size>8<<20:raise ValueError('unsealed original '+str(p))
            return p.read_bytes()
        closure=json.loads(sealed(base/'closed.json'));body=sealed(base/'archive.json')
        expected={'path':str(base/'archive.json'),'sha256':hashlib.sha256(body).hexdigest()}
        manifest=json.loads(body)
        if closure.get('archive')!=expected or closure.get('selection')!=selection or manifest.get('selection')!=selection or set(manifest['roots'])!=set(EXPECTED_MASKS[selection]):raise ValueError('different original closure')
        for unit,signature in EXPECTED_MASKS[selection].items():
            f=Path('/etc/systemd/system')/unit
            if not f.is_symlink() or f.readlink()!=Path('/dev/null') or hashlib.sha256(sealed(base/unit)).hexdigest()!=signature or manifest['roots'][unit]['sha256']!=signature:raise ValueError('original reader republished '+unit)
            for alias in manifest['roots'][unit]['aliases']:
                path=Path(alias['path'])
                if not path.is_symlink() or str(path.readlink())!=alias['link']:raise ValueError('historical alias changed')
            props=subprocess.run(['/usr/bin/systemctl','show','--all',unit,'--property=Id,LoadState,ActiveState,MainPID,ControlPID,ControlGroup,ExecStart,DropInPaths,Job'],capture_output=True,text=True)
            m=dict(l.split('=',1) for l in props.stdout.splitlines())
            if (props.returncode not in (0,4) or m.get('Id')!=unit or m.get('LoadState')!='masked' or m.get('ActiveState') not in ('inactive','failed')
                or any(m.get(k) for k in ('ControlGroup','ExecStart','DropInPaths','Job')) or any(m.get(k,'0')!='0' for k in ('MainPID','ControlPID'))
                or (Path('/sys/fs/cgroup/system.slice')/unit).exists()):raise ValueError('manager reader still live '+unit)
    return dict(selection=selection,files=len(aliases),inspected_command_sources=len(visited),remaining=hits,unresolved=unresolved)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('selection',choices=ROOTS);p.add_argument('--own',default='');a=p.parse_args()
    print(json.dumps(scan(a.selection,a.own),sort_keys=True))
