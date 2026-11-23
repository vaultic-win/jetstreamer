#!/bin/bash
set -euo pipefail
umask 077
pkg=/var/lib/jetstreamer/horizon_runtime_data/epoch169-g4-appendvec-20261123-v1/tools-v3
test "$(id -u)" = 0
test "$(realpath -e "$0")" = "$pkg/run"
test "$#" = 2
mode=$1
case "$mode" in qualify|check|execute) ;; *) exit 2 ;; esac
fleet=$(realpath -e "$2")
test "$fleet" = "$2"
test "$(basename "$fleet")" = ROOT_COMPLETE_OPERATIONAL_FLEET.json
test "$(dirname "$(dirname "$fleet")")" = /var/lib/jetstreamer/horizon_runtime_data
test "$(sha256sum "$pkg/retire169" | cut -d' ' -f1)" = PINNED_NATIVE_SHA
for action in qualify check execute; do
    test "$(systemctl show -p LoadState --value horizon-169-g4-appendvec-$action.service)" = not-found
done
# One shared mount makes the atomic sibling rename possible. Before reading any
# candidate, the native executable limits its writes to the two exact original parents.
exec systemd-run --quiet --collect --unit="horizon-169-g4-appendvec-$mode" --slice=horizonaudit.slice \
 -p Type=exec -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p IOWeight=10 -p MemoryMax=805306368 \
 -p MemorySwapMax=0 -p TasksMax=128 -p KillMode=control-group -p Restart=no -p RuntimeMaxSec=3600 \
 -p UMask=0077 -p PrivateNetwork=yes -p ProtectSystem=strict -p ProtectHome=read-only -p NoNewPrivileges=yes \
 -p ReadWritePaths=/home/sol/.jetstreamer-private -- "$pkg/retire169" "$mode" "$fleet"
