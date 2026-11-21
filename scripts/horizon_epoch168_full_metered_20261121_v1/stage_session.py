#!/usr/bin/python3 -I
"""Install the root-side epoch 168 session directly from the refetched campaign commit."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

D=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1")
REPO=Path("/home/sol/.jetstreamer-private/public-method-20261120/meter168-src")
MODULE="scripts/horizon_epoch168_full_metered_20261121_v1/"
SEALER=Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SELF="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def require(ok,reason):
    if not ok: raise ValueError(reason)


def write(path,raw):
    tmp=path.with_name("."+path.name+"-"+uuid.uuid4().hex)
    try:
        with tmp.open("xb") as f:
            f.write(raw);os.fchmod(f.fileno(),0o444);f.flush();os.fsync(f.fileno())
        try: os.link(tmp,path)
        except FileExistsError: require(path.read_bytes()==raw,"conflicting stage record "+str(path))
    finally: tmp.unlink(missing_ok=True)
    directory=os.open(path.parent,os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def encode(v):
    return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def stage(commit):
    require(os.geteuid()==0 and re.fullmatch("[0-9a-f]{40}",commit),"root and refetched source commit required")
    os.umask(0o077)
    git=["/usr/bin/git","--no-replace-objects","-c","safe.directory="+str(REPO),"-C",str(REPO)]
    remote=subprocess.check_output([*git,"remote","get-url","origin"],text=True).strip()
    require(remote=="git@github-matt-vaultic:vaultic-win/jetstreamer.git","wrong campaign remote")
    subprocess.run([*git,"merge-base","--is-ancestor",commit,"refs/remotes/origin/account-updates"],check=True)
    source=D/"session-source";source.mkdir(mode=0o700,exist_ok=True)
    dest=D/"session-v1"
    rows=[]
    for name in ("session.py","fit.py","status168.py"):
        raw=subprocess.check_output([*git,"cat-file","blob",commit+":"+MODULE+name])
        write(source/name,raw)
        rows.append(dict(name=name,source=str(source/name),sha256=digest(source/name),mode=0o444))
    require(subprocess.check_output([*git,"cat-file","blob",commit+":"+MODULE+"stage_session.py"])==Path(__file__).read_bytes(),
            "different deployment program")
    plan=D/"SESSION_SEAL_PLAN.json"
    write(plan,encode(dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(dest),members=rows)))
    require(digest(SEALER)==SELF,"different normal sealer")
    if not dest.exists():
        subprocess.run([SEALER,plan,"--plan-sha256",digest(plan),"--self-sha256",SELF],check=True)
    seal=dest/"deployment-seal-receipt.json"
    receipt=json.loads(seal.read_bytes())
    require(receipt["destination"]==str(dest) and receipt["plan_sha256"]==digest(plan)
            and {r["name"]:r["sha256"] for r in receipt["members"]}=={r["name"]:r["sha256"] for r in rows},
            "different sealed session")
    for r in rows: require(digest(dest/r["name"])==r["sha256"],"different installed source")
    result=dict(schema="horizon-168-normal-session-deployment-v1",branch="account-updates",source_commit=commit,
                seal=dict(path=str(seal),sha256=digest(seal)),members={r["name"]:r["sha256"] for r in rows},
                production_launch=False,archive_publication_authorized=False,r2_mutations=False)
    write(D/"SESSION_DEPLOYMENT.json",encode(result))
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    stage(sys.argv[1])
