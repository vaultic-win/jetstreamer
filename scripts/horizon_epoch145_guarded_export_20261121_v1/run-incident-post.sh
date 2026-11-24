#!/bin/bash
set -euo pipefail
umask 077
mode=$1
fleet=$2
pkg=/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v7
case "$(dirname "$(realpath -e -- "$0")")" in
    "${pkg%/*}/tools-v8") pkg="${pkg%/*}/tools-v8" ;;
    "${pkg%/*}/tools-v9") pkg="${pkg%/*}/tools-v9" ;;
    "${pkg%/*}/tools-v10") pkg="${pkg%/*}/tools-v10" ;;
    "${pkg%/*}/tools-v13h") pkg="${pkg%/*}/tools-v13h" ;;
    "${pkg%/*}/tools-v13i") pkg="${pkg%/*}/tools-v13i" ;;
    "${pkg%/*}/tools-v13j") pkg="${pkg%/*}/tools-v13j" ;;
    "${pkg%/*}/tools-v13k") pkg="${pkg%/*}/tools-v13k" ;;
    "${pkg%/*}/tools-v13g") pkg="${pkg%/*}/tools-v13g" ;;
    "${pkg%/*}/tools-v13f") pkg="${pkg%/*}/tools-v13f" ;;
    "${pkg%/*}/tools-v13e") pkg="${pkg%/*}/tools-v13e" ;;
    "${pkg%/*}/tools-v13d") pkg="${pkg%/*}/tools-v13d" ;;
    "${pkg%/*}/tools-v13c") pkg="${pkg%/*}/tools-v13c" ;;
    "${pkg%/*}/tools-v13b") pkg="${pkg%/*}/tools-v13b" ;;
    "${pkg%/*}/tools-v13") pkg="${pkg%/*}/tools-v13" ;;
    "${pkg%/*}/tools-v12") pkg="${pkg%/*}/tools-v12" ;;
    "${pkg%/*}/tools-v11") pkg="${pkg%/*}/tools-v11" ;;
esac
pub=/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1
output=/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1
holding=/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock
test ! -e "$output/.tmp36MvkN"
test "$(stat -c '%d %i %s %u %g %a %h' "$output/epoch-145.jet")" = '64512 103237059 105610995833 0 0 400 1'
read -r image_sha _ < <(sha256sum -- "$pkg/export145")
test "$image_sha" = PINNED_POST_SHA
read -r fleet_sha _ < <(sha256sum -- "$fleet")
opts=(-p Type=exec -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p MemoryMax=2147483648 -p MemorySwapMax=0 -p TasksMax=128 -p KillMode=control-group -p Restart=no -p UMask=0077 -p NoNewPrivileges=yes -p RuntimeMaxSec=259500 -p ProtectSystem=strict -p ProtectHome=read-only)
args=("$mode" "$fleet" "$fleet_sha")
case "$mode" in
post-full)
    test "$#" = 2
    opts+=(-p PrivateNetwork=yes -p "ReadWritePaths=$pub $output $holding")
    ;;
publish)
    test "$#" = 4
    full_iid=$3
    socket=$4
    test -S "$socket"
    test "$(stat -c %u "$socket")" = 1001
    args+=("$full_iid")
    opts+=(-p Delegate=yes -p PrivateTmp=yes -p "ReadWritePaths=$pub $holding /home/sol/workspace/jetstreamer/.git" -p "BindReadOnlyPaths=$socket:/run/epoch145-owner-ssh"
           -p EnvironmentFile=/etc/jetstreamer/horizon-r2.env --setenv=HOME=/home/sol --setenv=SSH_AUTH_SOCK=/run/epoch145-owner-ssh --setenv=TOKIO_WORKER_THREADS=1 --setenv=RAYON_NUM_THREADS=1)
    ;;
*) exit 2 ;;
esac
if [[ $pkg == */tools-v13d || $pkg == */tools-v13e || $pkg == */tools-v13f || $pkg == */tools-v13g || $pkg == */tools-v13h || $pkg == */tools-v13i || $pkg == */tools-v13j || $pkg == */tools-v13k ]]; then
    version=v1
    if [[ $pkg == */tools-v13e ]]; then version=v2; fi
    provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5j-$version/post-stop-fit
    if [[ $pkg == */tools-v13f ]]; then provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5k-v1/post-stop-fit; fi
    if [[ $pkg == */tools-v13h ]]; then provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-v1/post-stop-fit; fi
    provider_args=()
    if [[ $pkg == */tools-v13i ]]; then
        provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1/post-stop-fit
        provider_args+=(--post-submission)
    fi
    if [[ $pkg == */tools-v13j ]]; then
        provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5o-136-v1/post-stop-fit
        provider_args+=(--post-submission)
    fi
    if [[ $pkg == */tools-v13k ]]; then
        provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5q-136-v1/post-stop-fit
        provider_args+=(--post-submission)
    fi
    if [[ $pkg == */tools-v13g ]]; then provider=/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5m-v1/post-stop-fit; fi
    "$provider" "${provider_args[@]}" 145 "$fleet" "$fleet_sha" | /usr/bin/jq -e --arg f "$fleet" --arg h "$fleet_sha" '
       .epoch == 145 and .fits == true and .candidate == null and .resource_credit_bytes == 0
       and .fleet == {path:$f,sha256:$h} and .phase145.stage == "v5j-semantic-complete"
       and .registered_retry11_holding.stage == "completed-copy"
       and .registered_cold168_holding.stage == "completed-copy"' > /dev/null
    if [[ $mode == publish ]]; then
        opts+=(--setenv=HORIZON_PUBLIC_BASE_URL=https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev)
    fi
fi
exec systemd-run --quiet --unit=horizon-holding-export145-20261121-v1 "${opts[@]}" -p "StandardOutput=append:$pub/incident-$mode.stdout" -p "StandardError=append:$pub/incident-$mode.stderr" -- "$pkg/export145" "${args[@]}" "$image_sha"
