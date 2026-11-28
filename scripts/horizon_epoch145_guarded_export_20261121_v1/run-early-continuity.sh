#!/bin/bash
set -euo pipefail
mode=$1
fleet=$2
rt=/var/lib/jetstreamer/horizon_runtime_data/epoch145-guarded-export-20261121-v1
pkg=/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1
pub=/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1
output=/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1
view=/home/sol/.jetstreamer-private/epoch145-prefix-extract-materialized-view-20261121-v1
holding=/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock
case "$mode" in
recover-full-output)
    # This path opens only the fully materialized, frozen original inode.
    leaf="$output/.tmp36MvkN"
    if test -e "$output/epoch-145.jet"; then
        test ! -e "$leaf"
        leaf="$output/epoch-145.jet"
    fi
    test "$(stat -c '%d %i %h %u' -- "$leaf")" = '64512 103237059 1 0'
    test "$(stat -c '%s %a %g' -- "$leaf")" = '105610995833 400 0'
    test -d "$view"
    route=(-p "BindReadOnlyPaths=/var/lib/jetstreamer/horizon_runtime_data/epoch145-materialized-recovery-20261121-v1/view-template:$view" -p "BindReadOnlyPaths=$leaf:$view/epoch-145.jet" -p "ReadWritePaths=$rt/state $output $holding $pkg/peer-terminals")
    ;;
post-full)
    route=(-p "ReadWritePaths=$pub $output $holding $pkg/peer-terminals")
    ;;
*) exit 2;;
esac
read -r image_sha _ < <(sha256sum -- "$pkg/tools-v4/export145")
test "$image_sha" = PINNED_CONTINUITY_SHA
read -r fleet_sha _ < <(sha256sum -- "$fleet")
exec systemd-run --quiet --unit=horizon-holding-export145-20261121-v1 -p Type=exec -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p MemoryMax=2147483648 -p MemorySwapMax=0 -p TasksMax=128 -p KillMode=control-group -p Restart=no -p RuntimeMaxSec=259500 -p UMask=0077 -p NoNewPrivileges=yes -p PrivateNetwork=yes -p ProtectSystem=strict -p ProtectHome=read-only "${route[@]}" -p "StandardOutput=append:$pkg/$mode.stdout" -p "StandardError=append:$pkg/$mode.stderr" -- "$pkg/tools-v4/export145" "$mode" "$fleet" "$fleet_sha" "$image_sha"
