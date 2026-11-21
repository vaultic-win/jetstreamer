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


def verifier_profile(seal_path,seal_sha,image_sha,build_sha):
    seal_path=Path(seal_path)
    require(seal_path.resolve(strict=True)==seal_path and seal_path.name=='deployment-seal-receipt.json'
            and seal_path.parent==D.parent/'epoch145-semantic-continuity-20261121-v1/tools-v4'
            and all(re.fullmatch('[a-f0-9]{64}',h) for h in (seal_sha,image_sha,build_sha)), 'invalid five-owner package')
    require(digest(seal_path)==seal_sha, 'different five-owner seal')
    seal=json.loads(seal_path.read_bytes())
    package=seal_path.parent
    require(seal['schema']=='jetstreamer-sealed-deployment-receipt-v1' and seal['sealer_sha256']==SELF and
            seal['destination']==str(package) and not seal['remote_mutations'], 'foreign five-owner seal')
    members={r['name']:r['sha256'] for r in seal['members']}
    def member(name,sha):
        p=package/name
        require(members.get(name)==sha and p.resolve(strict=True)==p and p.is_file() and p.stat().st_uid==0
                and not p.stat().st_mode & 0o022 and digest(p)==sha, 'unbound verifier member '+name)
        return dict(path=str(p),sha256=sha)
    return dict(image=member('export145',image_sha),build=member('build-proof.json',build_sha),
                seal=dict(path=str(seal_path),sha256=seal_sha))


def incident_profile(seal_sha):
    name="tools" if seal_sha=="e8ba73178277950ed2bcc976534f49af21413745c8244026fcb1502bea9adc7e" else "tools-v2"
    package=D.parent/"incident-replay-fit-20261121-v1"/name
    seal_path=package/"deployment-seal-receipt.json"
    require(seal_path.resolve(strict=True)==seal_path and seal_path.stat().st_uid==0 and
            re.fullmatch("[0-9a-f]{64}",seal_sha) and digest(seal_path)==seal_sha,"different incident provider seal")
    seal=json.loads(seal_path.read_bytes())
    require(seal["schema"]=="jetstreamer-sealed-deployment-receipt-v1" and seal["sealer_sha256"]==SELF and
            seal["destination"]==str(package) and not seal["remote_mutations"],"foreign incident provider")
    members={r["name"]:r["sha256"] for r in seal["members"]}
    require({"post-stop-fit","retire-original-timers.py"}<=members.keys(),"incomplete incident provider")
    for name,expected in members.items():
        p=package/name
        require(Path(name).name==name and p.resolve(strict=True)==p and p.is_file() and p.stat().st_uid==0
                and not p.stat().st_mode & 0o022 and digest(p)==expected,"changed incident member")
    return dict(seal=dict(path=str(seal_path),sha256=seal_sha),sealer_sha256=SELF,
                image=dict(path=str(package/"post-stop-fit"),sha256=members["post-stop-fit"]))


def stage(commit,seal_path,seal_sha,image_sha,build_sha,incident_seal):
    require(os.geteuid()==0 and re.fullmatch("[0-9a-f]{40}",commit),"root and refetched source commit required")
    os.umask(0o077)
    git=["/usr/bin/git","--no-replace-objects","-c","safe.directory="+str(REPO),"-C",str(REPO)]
    remote=subprocess.check_output([*git,"remote","get-url","origin"],text=True).strip()
    require(remote=="git@github-matt-vaultic:vaultic-win/jetstreamer.git","wrong campaign remote")
    subprocess.run([*git,"merge-base","--is-ancestor",commit,"refs/remotes/origin/account-updates"],check=True)
    source=D/"session-source-v4";source.mkdir(mode=0o700,exist_ok=True)
    dest=D/"session-v4"
    rows=[]
    for name in ("session.py","fit.py","status168.py","overlap.py","same_five.py","incident.py"):
        raw=subprocess.check_output([*git,"cat-file","blob",commit+":"+MODULE+name])
        write(source/name,raw)
        rows.append(dict(name=name,source=str(source/name),sha256=digest(source/name),mode=0o444))
    require(subprocess.check_output([*git,"cat-file","blob",commit+":"+MODULE+"stage_session.py"])==Path(__file__).read_bytes(),
            "different deployment program")
    profile=source/"same-five-image.json"
    write(profile,encode(verifier_profile(seal_path,seal_sha,image_sha,build_sha)))
    rows.append(dict(name=profile.name,source=str(profile),sha256=digest(profile),mode=0o444))
    incident=source/"incident-fit.json"
    write(incident,encode(incident_profile(incident_seal)))
    rows.append(dict(name=incident.name,source=str(incident),sha256=digest(incident),mode=0o444))
    plan=D/"SESSION_SEAL_PLAN_V4.json"
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
    write(D/"SESSION_DEPLOYMENT_V4.json",encode(result))
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    stage(*sys.argv[1:])
