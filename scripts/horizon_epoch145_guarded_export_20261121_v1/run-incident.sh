#!/bin/bash
set -euo pipefail
umask 077
fleet=$1
rt=/var/lib/jetstreamer/horizon_runtime_data/epoch145-guarded-export-20261121-v1
pkg=/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1
output=/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1
view=/home/sol/.jetstreamer-private/epoch145-prefix-extract-materialized-view-20261121-v1
holding=/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock
leaf="$output/.tmp36MvkN"
test ! -e "$output/epoch-145.jet"
test "$(stat -c '%d %i %h %u %g %s %a' -- "$leaf")" = '64512 103237059 1 0 0 105610995833 400'
case "$(dirname "$(realpath -e -- "$0")")" in
    "$pkg/tools-v5") image="$pkg/tools-v5/export145" ;;
    "$pkg/tools-v5b") image="$pkg/tools-v5b/export145" ;;
    "$pkg/tools-v5c") image="$pkg/tools-v5c/export145" ;;
    "$pkg/tools-v5d") image="$pkg/tools-v5d/export145" ;;
    "$pkg/tools-v5e") image="$pkg/tools-v5e/export145" ;;
    "$pkg/tools-v5f") image="$pkg/tools-v5f/export145" ;;
    "$pkg/tools-v5g") image="$pkg/tools-v5g/export145" ;;
    "$pkg/tools-v5h") image="$pkg/tools-v5h/export145" ;;
    "$pkg/tools-v5i") image="$pkg/tools-v5i/export145" ;;
    "$pkg/tools-v5k") image="$pkg/tools-v5k/export145" ;;
    "$pkg/tools-v5q") image="$pkg/tools-v5q/export145" ;;
    "$pkg/tools-v5p") image="$pkg/tools-v5p/export145" ;;
    "$pkg/tools-v5o") image="$pkg/tools-v5o/export145" ;;
    "$pkg/tools-v5n") image="$pkg/tools-v5n/export145" ;;
    "$pkg/tools-v5m") image="$pkg/tools-v5m/export145" ;;
    "$pkg/tools-v5j") image="$pkg/tools-v5j/export145" ;;
    *) exit 1 ;;
esac
read -r image_sha _ < <(sha256sum -- "$image")
test "$image_sha" = PINNED_INCIDENT_SHA
read -r fleet_sha _ < <(sha256sum -- "$fleet")
if [[ $image == "$pkg/tools-v5q/export145" ]]; then
    exec /var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v8/run-recovery "$fleet"
fi
if [[ $image == "$pkg/tools-v5p/export145" ]]; then
    exec /var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v7/run-recovery "$fleet"
fi
if [[ $image == "$pkg/tools-v5o/export145" ]]; then
    exec /var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v6/run-recovery "$fleet"
fi
if [[ $image == "$pkg/tools-v5n/export145" ]]; then
    exec /var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v5/run-recovery "$fleet"
fi
if [[ $image == "$pkg/tools-v5m/export145" ]]; then
    exec /var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v4/run-recovery "$fleet"
fi
if [[ $image == "$pkg/tools-v5k/export145" ]]; then
    exec /var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v3/run-recovery "$fleet"
fi
if [[ $image == "$pkg/tools-v5h/export145" || $image == "$pkg/tools-v5i/export145" || $image == "$pkg/tools-v5j/export145" ]]; then
    "$image" check-serial-handback "$fleet" "$fleet_sha" "$image_sha"
fi
exec systemd-run --quiet --unit=horizon-holding-export145-20261121-v1 -p Type=exec -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p MemoryMax=2147483648 -p MemorySwapMax=0 -p TasksMax=128 -p KillMode=control-group -p Restart=no -p RuntimeMaxSec=259500 -p UMask=0077 -p NoNewPrivileges=yes -p PrivateNetwork=yes -p ProtectSystem=strict -p ProtectHome=read-only -p "BindReadOnlyPaths=/var/lib/jetstreamer/horizon_runtime_data/epoch145-materialized-recovery-20261121-v1/view-template:$view" -p "BindReadOnlyPaths=$leaf:$view/epoch-145.jet" -p "ReadWritePaths=$rt/state $output $holding" -p "StandardOutput=append:$pkg/incident-full-output.stdout" -p "StandardError=append:$pkg/incident-full-output.stderr" -- "$image" recover-full-output "$fleet" "$fleet_sha" "$image_sha"
