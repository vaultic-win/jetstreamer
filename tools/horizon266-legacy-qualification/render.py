"""Render bounded controller-owned systemd argv without submitting a unit."""
import argparse
import json
from pathlib import Path

MIB=1024*1024
V=Path('/var/lib/jetstreamer')
CACHE=V/'horizon266-index-acquire-v1/cache/sealed'
SERVICE=Path('/run/horizon266-legacy-source-v2')
BUILD_STAGE=Path('/run/horizon266-legacy-build-v2')
OUT=V/'horizon266-legacy-source-build-v2/result'
IMAGE=V/'horizon266-legacy-source-probe-v2/legacy-source'
MEMBERS=[
    (265,'epoch-265-bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu-mainnet-slot-to-cid.index'),
    (266,'epoch-266-bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu-mainnet-slot-to-cid.index'),
    (266,'epoch-266-bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu-mainnet-cid-to-offset-and-size.index'),
]
def render(phase,cpu):
    if cpu<0:
        raise ValueError('negative CPU')
    build=phase=='build'
    unit=f'horizon266-legacy-source-{phase}-v2.service'
    cap=(2048 if build else 1024)*MIB
    tmp=(512 if build else 32)*MIB
    common=['Type=exec','User=ubuntu','Group=ubuntu','Restart=no','UMask=0077','KillMode=control-group',
            'OOMPolicy=kill','OOMScoreAdjust=1000','MemoryAccounting=yes',f'MemoryMax={cap}','MemorySwapMax=0',
            'CPUAccounting=yes','CPUQuota=100%',f'AllowedCPUs={cpu}','TasksMax=96','IOAccounting=yes',
            'RuntimeMaxSec=900','TimeoutStopSec=15','ProtectSystem=strict','ProtectControlGroups=yes',
            'PrivateDevices=yes','PrivateMounts=yes','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=',
            f'TemporaryFileSystem=/tmp:rw,nosuid,nodev,size={tmp},mode=1777','InaccessiblePaths=/var/tmp /dev/shm',
            'StandardOutput=journal','StandardError=journal','LogRateLimitIntervalSec=30s','LogRateLimitBurst=100',
            'UnsetEnvironment=HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_S3_ENDPOINT JETSTREAMER_S3_ACCESS_KEY JETSTREAMER_S3_SECRET_KEY JETSTREAMER_S3_SESSION_TOKEN JETSTREAMER_VERSION']
    if build:
        props=['PrivateNetwork=yes','ProtectHome=read-only','RestrictAddressFamilies=AF_UNIX',
               'LimitFSIZE=134217728','WorkingDirectory=/tmp','ReadOnlyPaths='+str(BUILD_STAGE),'ReadWritePaths='+str(OUT)]
        command=['/usr/bin/python3','-I','-B',str(BUILD_STAGE/'build.py'),'--build']
    else:
        props=['ProtectHome=yes','RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX','LimitFSIZE=33554432',
               'WorkingDirectory='+str(SERVICE),'Environment=JETSTREAMER_NETWORK=mainnet JETSTREAMER_FORCE_LEGACY_INDEX=1 JETSTREAMER_ARCHIVE_BACKEND=http JETSTREAMER_COMPACT_INDEX_BASE_URL=https://files.old-faithful.net/ JETSTREAMER_HTTP_BASE_URL=https://files.old-faithful.net/']
        props.extend('BindReadOnlyPaths='+str(CACHE/name)+':'+str(SERVICE/'ledger/compact-indexes'/str(epoch)/name)
                     for epoch,name in MEMBERS)
        command=[str(IMAGE)]
    return dict(unit=unit,cpu=cpu,memory_cap_bytes=cap,private_tmpfs_bytes=tmp,
                requested_memory_bytes=cap+128*MIB,requested_disk_bytes=(768 if build else 64)*MIB,
                argv=['/usr/bin/systemd-run','--quiet','--unit='+unit,
                      *['--property='+p for p in common+props],'--',*command])
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['build','sample'])
    parser.add_argument('--cpu',type=int,required=True)
    a=parser.parse_args()
    print(json.dumps(render(a.phase,a.cpu),indent=2))
