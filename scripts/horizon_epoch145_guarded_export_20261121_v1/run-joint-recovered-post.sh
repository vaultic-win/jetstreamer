#!/bin/bash
set -euo pipefail
rt=/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1
output=/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1
holding=/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock
read -r sha _ < <(sha256sum "$rt/joint-tools-v3/export145")
test "$#" = 1
test "$sha" = d06d53d81a3356f38666697c08d2a01165ba0853a319664d2d30cd0dc367e122
fleet=$1
read -r fsha _ < <(sha256sum -- "$fleet")
exec systemd-run --quiet --unit=horizon-holding-export145-20261121-v1 -p Type=exec -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p MemoryMax=2147483648 -p MemorySwapMax=0 -p TasksMax=128 -p KillMode=control-group -p Restart=no -p RuntimeMaxSec=259500 -p UMask=0077 -p NoNewPrivileges=yes -p PrivateNetwork=yes -p ProtectSystem=strict -p ProtectHome=read-only -p "ReadWritePaths=$rt $output $holding" -p "StandardOutput=append:$rt/post.stdout" -p "StandardError=append:$rt/post.stderr" -- "$rt/joint-tools-v3/export145" post-full "$fleet" "$fsha" "$sha"
