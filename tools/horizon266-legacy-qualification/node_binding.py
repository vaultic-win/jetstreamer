"""Authenticate the deployed node bytes and historical Git source chain."""
import hashlib
import json
import stat
from pathlib import Path

V=Path('/var/lib/jetstreamer')
CHAIN=['horizon-contiguous-266-266-current-46b4b4a-v1',
       'horizon-contiguous-224-227-current-46b4b4a-bootstrap-v1',
       'horizon-contiguous-224-227-current-46b4b4a-v1',
       'horizon-contiguous-220-223-current-9d8e964-v1']
NODE='jetstreamer-node'
SHA='362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1'
COMMIT='9d8e964b8adbfb6c417590fddc87fc915d056a4e'
def require(ok,msg):
    if not ok:
        raise ValueError(msg)
def identity(p):
    s=p.lstat()
    require(p.resolve()==p and stat.S_ISREG(s.st_mode) and s.st_uid==0 and not (s.st_mode&0o022),str(p))
    with p.open('rb') as f:
        return dict(path=str(p),bytes=s.st_size,sha256=hashlib.file_digest(f,'sha256').hexdigest())
def binding():
    node=identity(V/CHAIN[0]/NODE)
    require(node['bytes']==48454432 and node['sha256']==SHA,'deployed image')
    chain=[]
    for old,new in zip(CHAIN,CHAIN[1:]):
        path=V/old/'deployment-seal-receipt.json'
        seal=json.loads(path.read_bytes())
        row,=[r for r in seal['members'] if r['name']==NODE]
        require(seal['destination']==str(V/old) and row['source']==str(V/new/NODE) and row['sha256']==SHA
                and row['bytes']==node['bytes'],str(path))
        chain.append(identity(path))
    p=V/CHAIN[-1]/'deployment-manifest.json'
    manifest=json.loads(p.read_bytes())
    require(manifest['repository_commit']==manifest['repository_remote_commit']==COMMIT and
            manifest['tracked_worktree_clean'] is True and manifest['node']==
            dict(source='/home/ubuntu/workspace/jetstreamer/target/release/jetstreamer-node',sha256=SHA),'original manifest')
    return dict(image=node,source_revision=COMMIT,original=identity(p),seals=chain)
if __name__=='__main__':
    print(json.dumps(binding(),indent=2))
