"""Read-only host process and mount census for the stopped epoch 266 guest."""
import collections
import itertools
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

ROOT = Path('/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169')
IMAGE = Path('/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/private.ext4')
LOOP = Path('/dev/loop9')
PATHS = [os.fsencode(p) for p in (ROOT, IMAGE, LOOP)]
DEVICE = os.makedev(7, 9)
IMAGE_ID = (66305, 18335082)
DEADLINE = time.monotonic() + 270

def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def identity(proc):
    try:
        return (proc / 'stat').read_bytes().rsplit(b')', 1)[1].split()[19]
    except (ProcessLookupError, FileNotFoundError):
        return None

def geometry():
    root = ROOT.lstat()
    image = IMAGE.lstat()
    loop = LOOP.lstat()
    require((root.st_dev, root.st_ino) == (DEVICE, 2), 'guest root')
    require((image.st_dev, image.st_ino) == IMAGE_ID and image.st_size == 128 << 30
            and stat.S_ISREG(image.st_mode) and image.st_nlink == 1 and image.st_uid == 0
            and image.st_mode & 0o077 == 0, 'image identity')
    require(LOOP.resolve() == LOOP and stat.S_ISBLK(loop.st_mode) and loop.st_rdev == DEVICE, 'loop identity')
    require(ROOT.resolve() == ROOT and IMAGE.resolve() == IMAGE
            and Path('/sys/block/loop9/loop/backing_file').read_text().strip() == str(IMAGE), 'backing path')
    rows = [x.split() for x in Path('/proc/self/mountinfo').read_bytes().splitlines()]
    entry, = [x for x in rows if x[4] == PATHS[0]]
    require(entry[:1] == [b'1555'] and entry[2:4] == [b'7:9', b'/'] and entry[-3:-1] == [b'ext4', PATHS[2]], 'host mount identity')

def path_reference(data):
    return any(re.search(re.escape(path) + rb"(?:$|[/\s\x00\"',;])", data) for path in PATHS)

def process_links(proc):
    with os.scandir(proc/'fd') as entries:
        return check_links(proc, itertools.chain((proc/'cwd', proc/'root', proc/'exe'), (Path(e.path) for e in entries)))

def check_links(proc, links):
    count = 0
    refs = []
    for link in links:
        try:
            st = link.stat()
            if (st.st_dev == DEVICE or (st.st_dev, st.st_ino) == IMAGE_ID
                    or (stat.S_ISBLK(st.st_mode) and st.st_rdev == DEVICE)):
                refs.append(link.relative_to(proc).as_posix())
            count += 1
        except (FileNotFoundError, ProcessLookupError):
            pass
    return count, refs

def mapped(proc):
    # Check device and inode, including maps that no longer have a pathname.
    # Carry a partial line across reads; the host's replay maps can be hundreds of MiB.
    expr = rb'^\S+\s+\S+\s+\S+\s+(?:0*7:0*9\s+|0*103:0*1\s+18335082(?:\s|$))'
    pattern = re.compile(expr, re.M)
    carry = b''
    total = 0
    with (proc / 'maps').open('rb') as f:
        while chunk := f.read(512 << 10):
            total += len(chunk)
            require(total <= 1 << 30 and time.monotonic() < DEADLINE, 'maps limit')
            lines, _, carry = (carry + chunk).rpartition(b'\n')
            require(len(carry) < 65536, 'proc map row limit')
            if ((b'7:09' in lines or b'7:9 ' in lines or b'18335082' in lines) and pattern.search(lines)) or any(p in lines for p in PATHS):
                return True, total
    return bool(pattern.search(carry) or any(p in carry for p in PATHS)), total

def census():
    require(os.geteuid() == 0 and os.readlink('/proc/1/ns/mnt') == os.readlink('/proc/self/ns/mnt'), 'host namespace')
    geometry()
    namespaces = {}
    refs = []
    counts = collections.Counter()
    for proc in Path('/proc').glob('[0-9]*'):
        start = identity(proc)
        if not start:
            continue
        try:
            require(time.monotonic() < DEADLINE, 'process census timeout')
            ns = os.readlink(proc/'ns/mnt')
            if ns not in namespaces:
                mounts = (proc/'mountinfo').read_bytes().splitlines()
                exposures = []
                submounts = []
                for row in mounts:
                    fields = row.split()
                    if fields[2] == b'7:9':
                        exposures.append(row.decode())
                        require(fields[3:5] == [b'/', PATHS[0]] and fields[-3:-1] == [b'ext4', PATHS[2]], 'aliased target mount')
                    if fields[4].startswith(PATHS[0]+b'/'):
                        submounts.append(fields[4].decode())
                require(len(exposures) <= 1 and not submounts, 'nested or duplicate guest mount')
                namespaces[ns] = exposures
            cmd = (proc/'cmdline').read_bytes()
            if path_reference(cmd):
                refs.append([proc.name, 'command'])
            n, links = process_links(proc)
            counts['open_links'] += n
            refs.extend([proc.name, k] for k in links)
            match, size = mapped(proc)
            counts['maps_bytes'] += size
            if match:
                refs.append([proc.name, 'mapped'])
            counts['processes'] += 1
        except (FileNotFoundError, ProcessLookupError):
            if identity(proc) is not None and (proc/'ns/mnt').exists():
                raise
            counts['departed'] += 1
        after = identity(proc)
        require(after is None or start == after, 'PID reused')
    require(counts['processes'] > 1 and any(namespaces.values()), 'incomplete host census')
    geometry()
    return dict(invocation=os.environ['INVOCATION_ID'], census=dict(counts), namespaces=namespaces,
                references=refs, geometry=[1555, DEVICE, 2, *IMAGE_ID,128<<30], readonly_observation=True)

if __name__ == '__main__':
    print(json.dumps(census(), sort_keys=True))
