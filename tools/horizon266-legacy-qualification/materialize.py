"""Materialize byte-exact production modules and the native compact-cache call graph."""
import argparse, json, hashlib, subprocess
from pathlib import Path

WORKER='9d8e964b8adbfb6c417590fddc87fc915d056a4e'
DEPLOY='46b4b4ad551b9f7866a8aa6fb8569dc9e9917908'
HERE=Path(__file__).resolve().parent
NODE='jetstreamer-node/src/main.rs'
FIRE='jetstreamer-firehose/src/'
def digest(raw):return hashlib.sha256(raw).hexdigest()
def materialize(repo,dest):
    def git(*args):return subprocess.check_output(['git','-c','safe.directory='+str(repo),'-C',str(repo),*args])
    dest.mkdir(mode=0o700)
    rows=[]
    def copy(name,path,sections=None):
        raw=git('show',DEPLOY+':'+path)
        if raw!=git('show',WORKER+':'+path):raise ValueError('different historical production file '+path)
        content=raw.decode();parts=[]
        for first,after in sections or []:
            if content.count(first)!=1 or content.count(after)!=1:raise ValueError('ambiguous source boundary '+first)
            i=content.index(first);j=content.index(after,i)
            parts.append(content[i:j])
        out='\n'.join(parts).encode() if sections else raw
        (dest/name).write_bytes(out)
        rows.append(dict(name=name,original=path,git_blob=git('rev-parse',DEPLOY+':'+path).decode().strip(),original_sha256=digest(raw),fragment_sha256=digest(out),boundaries=sections))
    copy('index.rs',FIRE+'index.rs')
    copy('archive.rs',FIRE+'archive.rs')
    copy('epochs.rs',FIRE+'epochs.rs',[('pub const BASE_URL:', 'trait EpochReader:')])
    copy('network.rs',FIRE+'network.rs',[('pub fn create_http_client()', '/// Queries the current epoch')])
    copy('native.inc',NODE,[
        ('const COMPACT_INDEX_MAGIC:', 'const BANK_SNAPSHOTS_DIR:'),
        ('#[derive(Debug, Clone, Copy, PartialEq, Eq)]\nenum SlotPresenceState','#[derive(Debug)]\nstruct TransactionScheduler'),
        ('fn format_eta(duration:', 'fn read_rss_bytes()'),
        ('fn local_index_path(cache_dir:', 'enum CarriedRuntimeState')])
    lock=git('show',WORKER+':Cargo.lock')
    (dest/'Cargo.lock.original').write_bytes(lock)
    rows.append(dict(name='Cargo.lock.original',sha256=digest(lock)))
    for k in ('main.rs','build.py'):
        raw=(HERE/k).read_bytes();(dest/k).write_bytes(raw);rows.append(dict(name=k,sha256=digest(raw)))
    (dest/'provenance.json').write_text(json.dumps(dict(deployed=DEPLOY,compile_source=WORKER,files=rows),indent=2)+'\n')
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('repository',type=Path);a.add_argument('destination',type=Path);v=a.parse_args()
    materialize(v.repository,v.destination)
