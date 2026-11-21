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
delivery="$rt/epoch166-retry10-delivery-20261121-v1"
pkg="$delivery/controller-tools"
provider="$delivery/capacity-tools-v2/publication-fit"
bound_provider="$delivery/capacity-tools/publication-fit"
test "$(sha256sum -- "$provider" | cut -d' ' -f1)" = "$fit_sha"
repo=/home/sol/workspace/jetstreamer
test -f "$rt/epoch166-retry10-terminal-20261121-v1/TERMINAL_SUCCESS.json"
test -S "$socket"
test "$(stat -c %u "$socket")" = 1001
/usr/sbin/runuser -u sol -- env SSH_AUTH_SOCK="$socket" ssh-add -l >/dev/null
(cd "$pkg" && sha256sum --check --strict --status SHA256SUMS)
exec /usr/bin/systemd-run --quiet --unit=horizon-publish-166-retry10-committed.service \
    -p Type=exec -p Restart=no -p KillMode=control-group -p UMask=0077 \
    -p CPUQuota=100% -p CPUWeight=10 -p Nice=15 -p MemoryMax=2G -p MemorySwapMax=0 \
    -p TasksMax=128 -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=read-only \
    -p "ReadWritePaths=$repo/.git $delivery" -p "WorkingDirectory=$repo" \
    -p "BindReadOnlyPaths=$socket:/run/epoch166-publisher-ssh $provider:$bound_provider" \
    -p EnvironmentFile=/etc/jetstreamer/horizon-r2.env \
    --setenv=HOME=/home/sol --setenv=TMPDIR="$delivery" --setenv=SSH_AUTH_SOCK=/run/epoch166-publisher-ssh \
    --setenv=TOKIO_WORKER_THREADS=1 --setenv=RAYON_NUM_THREADS=1 \
    -- "$pkg/controller" "$mode" "$fleet" "$fleet_sha" "$fit_sha"
