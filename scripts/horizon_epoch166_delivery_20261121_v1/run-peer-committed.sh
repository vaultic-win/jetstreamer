#!/bin/bash
# Start the synchronous receiver using the root fleet that accepted the local commit.
set -euo pipefail
if [[ $# != 5 || $EUID != 0 ]]; then
    echo "usage (root): run-committed.sh prepare|sync FLEET FLEET_SHA SSH_SOCKET FIT_SHA" >&2
    exit 2
fi
mode=$1
fleet=$2
fleet_sha=$3
socket=$4
fit_sha=$5
[[ $mode == prepare || $mode == sync ]]
[[ $fleet_sha =~ ^[0-9a-f]{64}$ && $fit_sha =~ ^[0-9a-f]{64}$ ]]
rt=/var/lib/jetstreamer/horizon_runtime_data
pkg=$(dirname "$(realpath -- "${BASH_SOURCE[0]}")")
delivery=$(dirname "$pkg")
quota=100%
case "$delivery" in
    "$rt/epoch167-cold-delivery-20261122-v3")
        epoch=167
        unit=horizon-publish-167-cold-source-index-committed.service ;;
    "$rt/epoch167-current-delivery-20261121-v1")
        epoch=167
        unit=horizon-publish-167-source-index-committed.service ;;
    "$rt/epoch168-cold-delivery-20261123-v4")
        epoch=168
        unit=horizon-publish-168-cold-retry4-committed.service ;;
    "$rt/epoch170-cold-delivery-20261122-v13")
        epoch=170
        unit=horizon-publish-170-cold-retry13-committed.service ;;
    "$rt/epoch170-current-delivery-20261121-v1")
        epoch=170
        unit=horizon-publish-170-retry10-committed.service ;;
    "$rt/epoch172-current-delivery-20261121-v1")
        epoch=172
        quota=50%
        unit=horizon-publish-172-full-committed.service ;;
    *) echo "unrecognized committed-source package location" >&2; exit 2 ;;
esac
[[ $pkg == "$delivery/controller-tools" || $pkg == "$delivery/controller-tools-v2" || $pkg == "$delivery/controller-tools-v3" || $pkg == "$delivery/controller-tools-paid145" || $pkg == "$delivery/controller-tools-bounded" ]]
repo=/home/sol/workspace/jetstreamer
test -f "$delivery/TERMINAL_SUCCESS.json"
test -S "$socket"
test "$(stat -c %u "$socket")" = 1001
/usr/sbin/runuser -u sol -- env SSH_AUTH_SOCK="$socket" ssh-add -l >/dev/null
(cd "$pkg" && sha256sum --check --strict --status SHA256SUMS)
exec /usr/bin/systemd-run --quiet --unit="$unit" \
    -p Type=exec -p Restart=no -p KillMode=control-group -p UMask=0077 \
    -p "CPUQuota=$quota" -p CPUWeight=10 -p Nice=15 -p MemoryMax=2G -p MemorySwapMax=0 \
    -p TasksMax=128 -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=read-only \
    -p "ReadWritePaths=$repo/.git $delivery" -p "WorkingDirectory=$repo" \
    -p "BindReadOnlyPaths=$socket:/run/epoch${epoch}-publisher-ssh" \
    -p EnvironmentFile=/etc/jetstreamer/horizon-r2.env \
    --setenv=HOME=/home/sol --setenv=TMPDIR="$delivery" --setenv=SSH_AUTH_SOCK=/run/epoch${epoch}-publisher-ssh \
    --setenv=TOKIO_WORKER_THREADS=1 --setenv=RAYON_NUM_THREADS=1 \
    -- "$pkg/controller" "$mode" "$fleet" "$fleet_sha" "$fit_sha"
