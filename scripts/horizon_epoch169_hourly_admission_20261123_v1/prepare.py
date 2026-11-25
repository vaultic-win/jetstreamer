"""Check the restored Banks, validate retained indexes, and quote the gated hourly actor."""
import argparse
import json
from pathlib import Path
import runpy
import subprocess

HERE=Path(__file__).resolve().parent
h=runpy.run_path(str(HERE/"hourly.py"))
need=h["need"]
R=h["ROOT"]
OLD_PROVIDER=R/"incident-replay-fit-20261121-v1/tools-homefloor-145-rejoin-v4/post-stop-fit"
OLD_SEAL="ed0e272c1cf6df09bb19ff6049154cad9e55f21e96089f66e6f9e3d0f89da9cb"
OLD_IMAGE="176efc76182b210223953c44669ecd3352ff90023c666a38c5edcc8be2fe10a0"
CURRENT_PROVIDER=OLD_PROVIDER.parent.parent/"tools-homefloor-169-hourly-v2/post-stop-fit"


def indexes():
    old=h["SOURCE"]
    prefix=old/"compact-indexes/168"
    current=h["INDEX"]
    prior_name="epoch-168-bafyreigrdukjoi2647fzy7dbzbxcqygm54vogb6pbhhjhi6lowooruvnxa-mainnet-slot-to-cid.index"
    base="epoch-169-bafyreibnyugrtsptq5qsj6tdweurgpzl55f75t7ku5r7wpxtia6e7gojbm-mainnet-"
    slot=base+"slot-to-cid.index"
    cid=base+"cid-to-offset-and-size.index"
    need({p.name for p in prefix.iterdir()}=={prior_name} and {p.name for p in current.iterdir()}=={slot,cid},
         "incomplete compact indexes")
    rows=[]
    for path,ino,size,digest in ((prefix/prior_name,114556937,15_210_704,"17c705d901c6eaa710998b6706d06a892d16273e05227848a515870544ed4097"),
              (current/slot,105775778,15_250_890,"e8516d5682a15a53eeb978db80eb1a2542ec54720265a5f21c7fe43244068b4d"),
              (current/cid,105775786,4_322_853_290,None)):
        m=path.lstat()
        need(path.resolve(strict=True)==path and (m.st_uid,m.st_gid,m.st_mode&0o7777,m.st_nlink,m.st_dev,m.st_ino,m.st_size)==
             (1001,1003,0o600,1,64512,ino,size),"foreign cached index "+str(path))
        if digest:
            need(h["sha"](path)==digest,"changed compact slot index")
        else:
            with path.open("rb") as source:
                need((m.st_mtime_ns,m.st_ctime_ns)==(1794254702708567274,1794254702935568306)
                     and source.read(8)==b"compiszd","CID index does not match registered upstream comparison")
        n=path.lstat()
        need((n.st_ino,n.st_size,n.st_mtime_ns,n.st_ctime_ns)==(m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns),
             "index changed during validation")
        rows.append(dict(path=str(path),device=m.st_dev,inode=ino,size=size,sha256=digest,ctime_ns=m.st_ctime_ns,mtime_ns=m.st_mtime_ns))
    genesis=old/"genesis.tar.bz2"
    need(genesis.stat().st_size==20_144 and h["sha"](genesis)=="133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
         "missing mainnet genesis")
    return rows


def native_prestart(fleet, provider_seal):
    if provider_seal is None:
        provider, digest = OLD_PROVIDER, OLD_SEAL
        mode = []
    else:
        provider, digest = CURRENT_PROVIDER, provider_seal
        mode = ["--hourly169=prestart"]
    reference = dict(path=str(provider.parent/"deployment-seal-receipt.json"),sha256=digest)
    actor = runpy.run_path(str(HERE/"actor.py"))
    seal = actor["pinned"](reference)
    image, = (m for m in seal["members"] if m["name"]=="post-stop-fit" and m["mode"]=="0555")
    need(seal["destination"]==str(provider.parent) and h["sha"](provider)==image["sha256"] and
         (provider_seal is not None or image["sha256"]==OLD_IMAGE), "unqualified native price")
    native=json.loads(subprocess.check_output([provider,*mode,"145",fleet["path"],fleet["sha256"]],timeout=150))
    need(native["schema"]=="horizon-incident-replay-fit-v1" and native["fits"] and native["candidate"] is None and
         native["fleet"]==fleet and native["replay_launch_authorized"] is False and
         native.get("new_resource_measurements") is not False,"receipt-only price cannot admit the hourly actor")
    if provider_seal is not None:
        need(native.get("hourly169_provider")==reference and
             native["phase145"]["stage"]=="v5z-semantic-complete-drained", "unbound V5z handoff or hourly 169 provider")
    return native


def preflight(projection,sha,provider_seal=None):
    # Check input custody before taking a native sample.
    source=h["sources"]()
    report=h["bound"](dict(path=source["169"]["receipt"],sha256=source["169"]["sha256"]))
    bank=Path(report["destination"])
    meta=h["same_file"](bank,source["169"]["file"])
    need(source["169"]["verified_ctime_ns"]==meta.st_ctime_ns,"hourly Bank changed after full digest")
    frozen=h["pin"](projection,sha)
    fleet=frozen["latest_fleet"]
    native=native_prestart(fleet,provider_seal)
    screened=h["price"](native,frozen,account_staging=False)
    need(screened["native_admission_eligible"],"fresh native actor price required")
    return dict(snapshot_identity=[meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns],fleet=fleet,projection=dict(path=str(projection),sha256=sha),sources=source,source_indexes=indexes(),
                verified_release=h["pin"](h["RELEASE"],h["RELEASE_SHA"]),native=native,screen=screened,
                current_native_fit=True,grants=0,canonical_publication_authorized=False)


if __name__=="__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("projection",type=Path)
    cli.add_argument("sha256")
    cli.add_argument("--native-provider-seal",metavar="SHA256")
    args=cli.parse_args()
    try:
        result=preflight(args.projection,args.sha256,args.native_provider_seal)
    except (ValueError,FileNotFoundError) as error:
        print(json.dumps({"ready":False,"reason":str(error),"production_starts":0}))
        raise SystemExit(1)
    print(json.dumps(result,sort_keys=True))
