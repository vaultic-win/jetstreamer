"""Whole-file comparison with leases held through quarantine and unlink."""
import contextlib
import fcntl
import hashlib
import os
import stat
from pathlib import Path


class PairedFiles:
    def __init__(self, state, rows, engine):
        self.state = state
        self.rows = sorted((Path(name), row) for name, row in rows.items())
        self.engine = engine
        self.sources = {}
        self.keepers = {}
        self.pairs = {}

    def require(self, condition, message):
        self.engine['require'](condition, message)

    @contextlib.contextmanager
    def leases(self):
        try:
            quarantine = self.state / 'quarantine'
            if os.path.lexists(quarantine):
                self.engine['secure_state'](quarantine)
                self.require({p.name for p in quarantine.iterdir()} <= {str(i) for i in range(len(self.rows))},
                             'foreign entry in existing quarantine')
            for i, (name, row) in enumerate(self.rows):
                self.open_pair(i, name, row)
            yield self
            self.check_keepers()
        finally:
            for fd in self.sources.values():
                os.close(fd)
            for fd, _, _ in self.keepers.values():
                os.close(fd)
            self.sources.clear()
            self.keepers.clear()

    def open_lease(self, path, expected, lock, *, moved=False):
        self.require(path.resolve(strict=True) == path, f'aliased member {path}')
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fcntl.fcntl(fd, fcntl.F_SETLEASE, lock)
            observed = self.engine['stamp'](os.fstat(fd))
            self.require(stat.S_ISREG(observed[2]) and observed[5] == 1 and observed == self.engine['identity'](path), path)
            self.require((observed[:-1] == expected[:-1] if moved else observed == expected), f'changed member {path}')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def captured_and_unlinked(self, i, row):
        # This engine uses a single batch covering the selected manifest. A root-private captured
        # receipt precedes the first unlink and binds the first whole-pair proof.
        intent = self.state / 'intent.json'
        batch = self.engine['read'](self.state / 'captured-0.json')
        self.require(batch['intent_sha256'] == self.engine['fingerprint'](intent)
                     and batch['start'] == 0 and batch['end'] == len(self.rows)
                     and batch['stamps'][str(i)][:-1] == row['source_stat'][:-1], f'no captured inode {i}')
        prior = self.engine['read'](intent)['controls']['body_proof']
        proof = Path(prior['path'])
        self.require(proof.parent == self.state and self.engine['fingerprint'](proof) == prior['sha256'], proof)
        before = self.engine['read'](proof)['pairs'][str(i)]
        self.require(before == {'source':str(self.rows[i][0]), 'keeper':row['keeper_path'],
                                'whole_sha256':row['whole_sha256_at_seal'], 'compared_bytes':row['source_stat'][6]},
                     f'no durable paired digest {i}')
        return prior['sha256']

    def open_pair(self, i, source, row):
        expected = row['source_stat']
        keeper = Path(row['keeper_path'])
        keeper_id = row['keeper_stat']
        self.require(expected[:2] != keeper_id[:2] and expected[6] == keeper_id[6], 'non-independent copy')
        self.require(i not in self.keepers, 'duplicate keeper registration')
        kfd = self.open_lease(keeper, keeper_id, fcntl.F_RDLCK)
        self.keepers[i] = (kfd, keeper, keeper_id)
        quarantine = self.state / 'quarantine' / str(i)
        exists, moved = os.path.lexists(source), os.path.lexists(quarantine)
        self.require(not (exists and moved), f'second original or foreign quarantine {source}')
        hasher = hashlib.sha256()
        entry = {'source':str(source), 'keeper':str(keeper), 'whole_sha256':row['whole_sha256_at_seal']}
        if not exists and not moved:
            entry['previously_unlinked_proof_sha256'] = self.captured_and_unlinked(i, row)
            with os.fdopen(os.dup(kfd), 'rb') as retained:
                hasher = hashlib.file_digest(retained, 'sha256')
        else:
            live = quarantine if moved else source
            if moved:
                self.require((self.state / 'intent.json').is_file(), 'unexpected preexisting quarantine')
            sfd = self.open_lease(live, expected, fcntl.F_WRLCK, moved=moved)
            self.sources[(expected[0], expected[1])] = sfd
            count = 0
            with os.fdopen(os.dup(kfd), 'rb') as right, os.fdopen(os.dup(sfd), 'rb') as left:
                while True:
                    a = left.read(2 << 20)
                    b = right.read(2 << 20)
                    self.require(a == b, f'paired file bodies differ: {source}')
                    if not a:
                        break
                    count += len(a)
                    hasher.update(a)
            self.require(count == expected[6], f'paired length changed: {source}')
            self.require(fcntl.fcntl(sfd, fcntl.F_GETLEASE) == fcntl.F_WRLCK, f'broken source lease: {source}')
            self.require(self.engine['stamp'](os.fstat(sfd)) == self.engine['identity'](live), live)
            entry['compared_bytes'] = count
        self.require(hasher.hexdigest() == row['whole_sha256_at_seal'], f'sealed digest mismatch: {source}')
        self.check_keeper(i)
        self.pairs[str(i)] = entry

    def check_keeper(self, i):
        fd, path, expected = self.keepers[i]
        self.require(fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK and
                     self.engine['stamp'](os.fstat(fd)) == expected == self.engine['identity'](path),
                     f'changed retained deployment copy: {path}')

    def check_keepers(self):
        for i in self.keepers:
            self.check_keeper(i)

    @contextlib.contextmanager
    def retained_source_lease(self, parent, name, expected, *, moved=False):
        # Reuse the exclusive open-file description that proved the entire pair.
        key = (expected[0], expected[1])
        fd = self.sources[key]
        stamp = self.engine['stamp'](os.fstat(fd))
        self.require(fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_WRLCK and
                     self.engine['state_of'](parent, name) == stamp and
                     (stamp[:-1] == expected[:-1] if moved else stamp == expected),
                     f'changed leased source before transition: {name}')
        self.check_keepers()
        yield fd
        self.require(fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_WRLCK, 'source lease broken while transitioning')
        if os.fstat(fd).st_nlink == 0:
            os.close(self.sources.pop(key))
