from pathlib import Path
import os, json, hashlib, stat, subprocess, time, datetime
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0100-20261109-v1'
sha = lambda b: hashlib.sha256(b).hexdigest()

def save(n, v):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def b(f):
    f = Path(f)
    return dict(path=str(f), sha256=sha(f.read_bytes()))
a = json.loads((p / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_PENDING_FINAL_DRAINS.json').read_text())
chain = [a['observer']]
bindings = chain + [a['fleet'], a['frame']]
assert len({x['path'] for x in bindings}) == len(bindings)

def actual_observer_writer(binding):
    v = json.loads(Path(binding['path']).read_text())
    at = datetime.datetime.strptime(v['recorded_at_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    end = datetime.datetime.strptime(v['completed_at_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    stamp = at.strftime('%H%M%S')
    rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '--since', (at - datetime.timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S UTC'), '--until', (end + datetime.timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S UTC'), '_PID=1', '_UID=0'], text=True).splitlines()]
    units = {x['UNIT'] for x in rows if 'observer' + stamp in x.get('UNIT', '') and x.get('UNIT', '').endswith('.service') and (x.get('JOB_RESULT') == 'done')}
    assert len(units) == 1, (binding, units)
    return units.pop()
units = [actual_observer_writer(x) for x in chain] + [json.loads((p / 'ROOT_CURRENT0100_FLEET_ORIGINAL_SUCCESS.json').read_text())['native']['Id'], json.loads((p / 'FRAME5-R4-capture-ORIGINAL-NATIVE-PID1.json').read_text())['native']['Id'], json.loads((p / 'FRAME5-R4-capability-ORIGINAL-NATIVE-PID1.json').read_text())['native']['Id']]
proofs = []
for unit in units:
    n = dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', unit, '-pId,MainPID,ControlPID,ControlGroup,NRestarts,InvocationID,Result,ExecMainStatus,ActiveState,SubState'], text=True).splitlines()))
    assert n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0'
    rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', unit], text=True).splitlines()]
    success = [x for x in rows if x.get('_PID') == '1' and x.get('_UID') == '0' and (x.get('UNIT') == unit) and (x.get('JOB_RESULT') == 'done')]
    assert success, (unit, 'original completed PID1 event unavailable')
    assert not n['InvocationID'] or any((x['INVOCATION_ID'] == n['InvocationID'] for x in success))
    assert n['Result'] == 'success' and n['ExecMainStatus'] == '0'
    cg = Path('/sys/fs/cgroup/system.slice') / unit
    assert not cg.exists() or all((not x.read_text().strip() for x in cg.rglob('cgroup.procs')))
    proofs.append(dict(unit=unit, native=n, original_PID1_completion=success))

def attrs(m):
    return dict(dev=m.st_dev, ino=m.st_ino, uid=m.st_uid, gid=m.st_gid, nlink=m.st_nlink, size=m.st_size, mode=stat.S_IMODE(m.st_mode), mtime_ns=m.st_mtime_ns, ctime_ns=m.st_ctime_ns)

def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
opened = []
done = []
try:
    for x in bindings:
        f = Path(x['path'])
        m = f.lstat()
        pm = f.parent.lstat()
        assert f.resolve() == f and f.suffix == '.json' and stat.S_ISREG(m.st_mode) and (m.st_uid == m.st_gid == 0) and (m.st_nlink == 1) and (stat.S_IMODE(m.st_mode) in [384, 420, 292]) and (pm.st_uid == 0) and (not pm.st_mode & 18)
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        assert attrs(os.fstat(fd)) == attrs(m) and digest(fd) == x['sha256']
        opened.append((x, f, fd, attrs(m)))
    targets = {(x[3]['dev'], x[3]['ino']) for x in opened}
    refs = []
    errors = []
    t = time.monotonic()
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        assert time.monotonic() - t < 30
        try:
            for f in proc.joinpath('fd').iterdir():
                try:
                    m = f.stat()
                    if (m.st_dev, m.st_ino) in targets:
                        refs.append(dict(pid=int(proc.name), fd=f.name))
                except (FileNotFoundError, ProcessLookupError):
                    pass
                except PermissionError as e:
                    errors.append(dict(pid=int(proc.name), errno=e.errno))
        except (FileNotFoundError, ProcessLookupError):
            pass
        except PermissionError as e:
            errors.append(dict(pid=int(proc.name), errno=e.errno))
    save('EXACT_GENERATED_METADATA_ORIGINAL_REFERENCE_CHECK.json', dict(bindings=bindings, external_references=refs, errors=errors, duration_seconds=time.monotonic() - t))
    assert not refs and (not errors), (refs, errors)
    save('EXACT_GENERATED_METADATA_FINALIZATION_INTENT.json', dict(writers=proofs, before=[dict(binding=x, metadata=m) for x, f, fd, m in opened], original_bytes_and_path_identity_preserved=True, no_memory_or_DATA_credit=True))
    for x, f, fd, before in opened:
        assert attrs(f.lstat()) == before and digest(fd) == x['sha256']
        target = before['mode'] if not before['mode'] & 146 else 292
        if before['mode'] != target:
            os.fchmod(fd, target)
            os.fsync(fd)
            dfd = os.open(f.parent, os.O_RDONLY | os.O_DIRECTORY)
            os.fsync(dfd)
            os.close(dfd)
        after = attrs(os.fstat(fd))
        assert attrs(f.lstat()) == after and digest(fd) == x['sha256'] and (after['mode'] == target)
        for k in ['dev', 'ino', 'uid', 'gid', 'nlink', 'size', 'mtime_ns']:
            assert before[k] == after[k]
        done.append(dict(binding=x, before=before, after=after, same_path_inode_bytes_digest_and_mtime=True))
    save('EXACT_GENERATED_METADATA_READONLY_FINALIZATION_RECEIPT.json', dict(schema='horizon-exact-closed-generated-metadata-readonly-finalization-v1', files=done, all_scoped_files_readonly=True, actual_closed_file_count=len(done), no_original_payload_path_inode_or_history_change=True, memory_credit_bytes=0, DATA_credit_bytes=0))
    save('ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json', dict(a, original_final_drains_pending=False, original_payload_and_outer_success=True, metadata_finalization=b(p / 'EXACT_GENERATED_METADATA_READONLY_FINALIZATION_RECEIPT.json'), original_writers_and_cgroups=proofs, complete_reader_pending=True))
    print('Finalized', len(done), 'exact original JSON files; genuine CLI capture and drained payload accepted', flush=True)
finally:
    for x, f, fd, m in opened:
        os.close(fd)
