#!/bin/bash
set -euo pipefail
mode=$1
shift
rt=/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1
base=/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work
recovery=/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1
dep=/home/sol/.jetstreamer-private/epoch145-fast-prefix-20261120-v1/deployment
repo=/home/sol/workspace/jetstreamer
holding=/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock
socket=$1
shift
test -S "$socket"
test "$(stat -c %u "$socket")" = 1001
opts=(-p Type=exec -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p MemoryMax=2147483648 -p MemorySwapMax=0 -p TasksMax=128 -p KillMode=control-group -p Restart=no -p UMask=0077 -p NoNewPrivileges=yes -p Delegate=yes -p PrivateTmp=yes -p ProtectSystem=strict -p ProtectHome=read-only -p "ReadWritePaths=$repo/.git" -p "BindReadOnlyPaths=$socket:/run/epoch145-owner-ssh" --setenv=HOME=/home/sol --setenv=SSH_AUTH_SOCK=/run/epoch145-owner-ssh --setenv=TOKIO_WORKER_THREADS=1 --setenv=RAYON_NUM_THREADS=1)
case "$mode" in
publish)
    fleet=$1
    full_iid=$2
    read -r fleet_sha _ < <(sha256sum "$fleet")
    read -r image_sha _ < <(sha256sum "$recovery/tools-v3/export145")
    test "$image_sha" = PINNED_CONTINUITY_SHA
    exec systemd-run --quiet --unit=horizon-holding-export145-20261121-v1 "${opts[@]}" -p RuntimeMaxSec=259500 -p "ReadWritePaths=$holding $rt $recovery/peer-terminals" -p EnvironmentFile=/etc/jetstreamer/horizon-r2.env -p "StandardOutput=append:$rt/network.stdout" -p "StandardError=append:$rt/network.stderr" -- "$recovery/tools-v3/export145" publish "$fleet" "$fleet_sha" "$full_iid" "$image_sha"
    ;;
*) exit 2;;
esac
