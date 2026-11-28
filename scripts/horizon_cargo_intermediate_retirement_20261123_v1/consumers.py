"""Recheck kernel and scheduler consumers of the closed compiler profiles."""
import hashlib
import json
import os
import re
import subprocess
import stat
from pathlib import Path


def call(args, timeout=180):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout).stdout


def require(ok, why):
    if not ok:
        raise RuntimeError(str(why))


def within(path, root):
    return path == root or path.startswith(root + '/')


def check_units(previous):
    names = sorted(previous)
    actual = {}
    for i in range(0, len(names), 64):
        props = 'Id,ActiveState,SubState,ControlPID,MainPID,Job,FragmentPath,DropInPaths'
        response = call(['/usr/bin/systemctl', 'show', '-p', props, *names[i:i+64]])
        for block in response.decode().strip().split('\n\n'):
            row = dict(line.split('=', 1) for line in block.splitlines())
            name = row['Id']
            require(name not in actual and row['MainPID'] == row['ControlPID'] == '0' and not row['Job']
                    and row['SubState'] in ('dead', 'failed', 'exited')
                    and row['FragmentPath'] == previous[name]['FragmentPath'], f'live/changed owner {name}')
            actual[name] = row['ActiveState'] + '/' + row['SubState']
    require(actual.keys() == previous.keys(), 'incomplete owner census')
    return {s: list(actual.values()).count(s) for s in set(actual.values())}


def kernel(rows, profiles):
    inodes = {(s[0], s[1]) for s in rows.values()}
    device, = {s[0] for s in rows.values()}
    inode_numbers = {s[1] for s in rows.values()}
    dev = f'{os.major(device):02x}:{os.minor(device):02x}'.encode()
    profiles = [str(p) for p in profiles]
    relative = [str(Path(v).relative_to('/home/sol')) for v in profiles]
    build_roots = {str(Path(p).parent.parent) for p in profiles}
    fds = maps = procs = 0
    namespaces = set()
    me = os.getpid()
    for proc in Path('/proc').glob('[0-9]*'):
        if int(proc.name) == me:
            continue
        try:
            args = (proc / 'cmdline').read_bytes().split(b'\0')
            if not any(args):  # kernel threads and zombies have no user FDs or mounts to retain
                continue
            procs += 1
            def check_path(label, target):
                require(not any(within(target, p) for p in profiles), f'process {proc.name} {label}: {target}')
            for field in ['cwd', 'root', 'exe', *['fd/' + f.name for f in (proc / 'fd').iterdir()]]:
                try:
                    path = proc / field
                    st = path.stat()
                    if field.startswith('fd/'):
                        fds += 1
                    require((st.st_dev, st.st_ino) not in inodes, f'open compiler inode: {path}')
                    if st.st_dev == device or field in ('cwd', 'root', 'exe'):
                        check_path(field, os.readlink(path))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            with (proc / 'maps').open('rb') as mapped:
                for line in mapped:
                    if dev not in line:
                        continue
                    seg = line.split(None, 5)
                    if seg[3] == dev:
                        maps += 1
                        require(int(seg[4]) not in inode_numbers, f'mapped compiler inode: {proc}')
            for arg in args:
                require(not any(os.fsencode(root + '/') in arg or os.fsencode(root) == arg for root in profiles),
                        f'process {proc.name} references compiler profile')
            exe = Path(os.readlink(proc / 'exe')).name
            if exe in {'cargo', 'rustc', 'rustdoc', 'sccache', 'ccache', 'ar', 'ld', 'ld.lld', 'gcc', 'clang', 'cc1', 'cc1plus'}:
                cwd = os.readlink(proc / 'cwd')
                require(not any(within(cwd, root) for root in build_roots), f'active builder {proc.name}')
                for item in (proc / 'environ').read_bytes().split(b'\0'):
                    if item.startswith(b'CARGO_TARGET_DIR='):
                        target = str((Path(cwd) / os.fsdecode(item.partition(b'=')[2])).resolve())
                        require(not any(within(target, str(Path(p).parent)) for p in profiles), 'live Cargo target')
            ns = (proc / 'ns/mnt').stat().st_ino
            if ns not in namespaces:
                for row in (proc / 'mountinfo').read_text().splitlines():
                    left, right = row.split(' - ', 1)
                    fields = left.split()
                    src, dst = [x.replace('\\040', ' ').replace('\\134', '\\') for x in fields[3:5]]
                    for profile, suffix in zip(profiles, relative):
                        for name in (src, dst):
                            require(not within(name, profile) and not within(name, '/' + suffix)
                                    and not ('.jetstreamer-private/' in name and
                                             (within(profile, name) or within('/' + suffix, name))),
                                    f'compiler profile bind in namespace {ns}: {name}')
                        require(suffix not in right, f'compiler-backed mount in {ns}')
                namespaces.add(ns)
        except (FileNotFoundError, ProcessLookupError):
            # A missing /proc file on a live non-zombie must never excuse the remainder.
            if proc.exists():
                try:
                    state = (proc / 'stat').read_bytes().rsplit(b') ', 1)[1][:1]
                except FileNotFoundError:
                    continue
                if state not in (b'Z', b'X'):
                    raise
    require(procs > 0 and namespaces and fds and maps, 'empty kernel census')
    return dict(user_processes=procs, fd_entries=fds, home_mappings=maps, mount_namespaces=len(namespaces))


def scan(roots, patterns, types, depth=None):
    command = ['/usr/bin/rg', '--threads', '1', '--no-config', '--no-ignore', '--hidden', '-l', '-F',
               '--max-filesize', '16M', '-g', '!**/.git/**', '-g', '!**/target/**', '-g', '!**/deps/**']
    for pat in patterns:
        command.extend(['-e', pat])
    for kind in types:
        command.extend(['-g', kind])
    if depth is not None:
        command.extend(['--max-depth', str(depth)])
    child = subprocess.run(command + ['--', *roots], capture_output=True, timeout=900)
    require(child.returncode in (0, 1) and not child.stderr, f'control scan failed: {child.stderr[:250]!r}')
    return set(map(Path, os.fsdecode(child.stdout).splitlines()))


def mentioned_bindings(obj):
    if isinstance(obj, dict):
        if isinstance(obj.get('path'), str) and isinstance(obj.get('sha256'), str):
            yield Path(obj['path'])
        for child in obj.values():
            yield from mentioned_bindings(child)
    elif isinstance(obj, list):
        for child in obj:
            yield from mentioned_bindings(child)


def inspection_evidence(path, aliases, directory_id, pins):
    """Recognize only the selected root-private inspection inode through its two known mounts."""
    pin = pins.get(path.name)
    if pin is None or path.parent not in aliases:
        return False
    require(re.fullmatch(r'inspection-[0-9]{19}\.json', path.name), 'invalid inspection filename')
    parent = path.parent
    require(parent.resolve(strict=True) == parent, 'aliased inspection parent')
    pfd = os.open(parent, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(pfd)
        require((st.st_dev, st.st_ino) == directory_id and st.st_uid == st.st_gid == 0
                and st.st_mode == stat.S_IFDIR | 0o700 and os.path.samestat(st, parent.lstat()),
                'changed inspection directory')
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=pfd)
        with os.fdopen(fd, 'rb') as file:
            st = os.fstat(fd)
            require((st.st_dev, st.st_ino) == (directory_id[0], pin['ino']) and st.st_uid == st.st_gid == 0
                    and st.st_mode == stat.S_IFREG | 0o400 and st.st_nlink == 1 and 0 < st.st_size <= 1 << 20,
                    'changed inspection file identity')
            checksum = hashlib.file_digest(file, 'sha256').hexdigest()
            after = os.stat(path.name, dir_fd=pfd, follow_symlinks=False)
            require(checksum == pin['sha256'] and os.path.samestat(st, after)
                    and after.st_ctime_ns == st.st_ctime_ns == os.fstat(fd).st_ctime_ns,
                    'changed inspection contents')
        return True
    finally:
        os.close(pfd)


def controls(base, bundle, profiles, rows, fleet, aliases, directory_id, inspections):
    survey = json.loads((bundle / 'live-survey.json').read_bytes())
    original = json.loads((bundle / 'indirect.json').read_bytes())
    previous = json.loads((bundle / 'indirect-source-lines.json').read_bytes())
    direct = json.loads((bundle / 'scheduler-evidence.json').read_bytes())
    allowed = set(json.loads((bundle / 'actual-controls.json').read_bytes())['concrete_direct_mentions_of_retained'])
    broad = sorted({x.split('/')[0] if not x.startswith('build/') else '/'.join(x.split('/')[:2]) for x in profiles})
    types = ['*.py', '*.sh', '*.rs', '*.bash', '*.toml', '*.service', '*.timer', '*.path', '*.conf']
    # Old and new effective systemd/cron controls and the current registered fleet/route.
    found = scan(original['control_roots'], broad, types)
    routes = Path(original['route'])
    route = json.loads(routes.read_bytes())
    bound = {p for obj in (json.loads(fleet.read_bytes()), route) for p in mentioned_bindings(obj)}
    bound.update(Path(x) for row in route['reviewed_routes'].values() for x in row.get('inputs', []))
    bound.update([routes, fleet])
    bound = {p for p in bound if p.is_absolute() and p.is_file() and p.stat().st_size <= 16 << 20
             and p.suffix in {'.json', '.jsonl', '.py', '.sh', '.rs', '.toml', '.service', '.timer', '.path'}}
    markers = [f'{p}/{part}/' for p, kind in profiles.items() for part in
               (('build', 'deps') if kind == 'compiler' else ('build',))]
    text_markers = [x[:-1] for x in markers]
    native_hits = scan(survey['roots'], text_markers, [])
    native_hits |= scan(survey['installed_roots'], text_markers, types + ['*.json', '*.jsonl'], depth=4)
    patterns = [(m, re.compile(re.escape(m.encode()) + rb'''([^\0"'\s,;\\}]+)''')) for m in markers]
    for path in found | bound | native_hits:
        if inspection_evidence(path, aliases, directory_id, inspections):
            continue
        data = path.read_bytes()
        has_marker = any(x.encode() in data for x in broad)
        if not has_marker:
            continue
        for marker, regex in patterns:
            for match in regex.finditer(data):
                candidate = str(base / marker / os.fsdecode(match[1]))
                require(candidate not in rows, f'file referenced by {path}: {candidate}')
        if str(path) in previous:
            # Rerun the original snippet extraction, including each newly introduced line.
            for line in data.splitlines():
                for term in broad:
                    i = line.find(term.encode())
                    if i >= 0:
                        snippet = line[max(0, i-95):i+len(term)+480].decode(errors='replace')
                        require(snippet in previous[str(path)], f'changed historical control: {path}')
        elif path in found:
            raise RuntimeError(f'new control mentions historical build root: {path}')
        elif path not in map(Path, direct):
            # An updated fleet/receipt may copy a literal qualified retained executable. Bound
            # JSON templates naming an unspecified target, or any newly selected file, refuse.
            for line in data.splitlines():
                for marker, regex in patterns:
                    if marker[:-1].encode() in line:
                        refs = [str(base / marker / os.fsdecode(m[1])) for m in regex.finditer(line)]
                        require(refs and all(p in allowed for p in refs), f'unreviewed new reference {path}')
    return dict(native_controls=len(native_hits), source_controls=len(found), current_bound_controls=len(bound))


def verify_linkage(base, profiles, rows, previous, omitted):
    selected = {Path(p).name for p in rows if p.endswith('.so')}
    prior = {(Path(p).stat().st_dev, Path(p).stat().st_ino): v for p, v in previous.items()}
    require(len(prior) == len(previous), 'retained executable set changed')
    seen = set()
    for profile in profiles:
        root = base / profile
        for directory in (root, root / 'deps'):
            for p in directory.iterdir():
                if str(p) in rows:
                    continue
                st = p.lstat()
                if not stat.S_ISREG(st.st_mode) or not (st.st_mode & 0o111 or str(p) in omitted):
                    continue
                ident = (st.st_dev, st.st_ino)
                if ident in seen:
                    continue
                with p.open('rb') as file:
                    if file.read(4) != b'\x7fELF':
                        continue
                require(ident in prior or str(p) in omitted, f'unreviewed retained ELF {p}')
                deps = re.findall(r'\(NEEDED\).*?\[([^]]+)\]', call(['/usr/bin/readelf', '--dynamic', '--wide', p]).decode())
                require(not any(Path(dep).name in selected for dep in deps) and
                        (ident not in prior or deps == prior[ident]), f'changed retained runtime linkage {p}')
                seen.add(ident)
    require(prior.keys() <= seen, 'missing retained ELF')
    return len(seen)
