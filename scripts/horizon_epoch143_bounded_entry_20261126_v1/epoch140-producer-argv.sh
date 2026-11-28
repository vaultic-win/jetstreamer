#!/usr/bin/env bash
set -euo pipefail
runtime=/var/lib/jetstreamer/horizon_runtime_data
suffix=${2:-v1}
[[ $suffix == v1 || $suffix == retry1 || $suffix == retry2 ]]
authority="$runtime/epoch140-suffix-recording-20261127-$suffix"
node="$runtime/epoch140-recording-build-20261122-v1/44153c667a564b36ad8feb7e7cffb5db/node/jetstreamer-node"
run="/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-$suffix"
snapshot=/home/sol/.jetstreamer-private/epoch140-snapshot-source-20261020-v1/download/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst
worker=/usr/local/lib/jetstreamer/horizon-v1425-corrected-default-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25
plan_digest=${1:?Pass the exact sealed node plan digest}
[[ $plan_digest =~ ^[0-9a-f]{64}$ && $plan_digest != 0000000000000000000000000000000000000000000000000000000000000000 ]]
argv=(
    /usr/bin/systemd-run
    --unit=horizon-epoch140-suffix-recording.service
    --property=Type=exec
    --property=User=sol
    --property=Group=horizon
    --property=Restart=no
    --property=KillMode=control-group
    --property=TimeoutStopSec=20s
    --property=Delegate=no
    --property=CPUQuota=200%
    --property=MemoryHigh=24696061952
    --property=MemoryMax=27917287424
    --property=MemorySwapMax=0
    --property=TasksMax=512
    --property=RuntimeMaxSec=1800
    --property=LimitCORE=0
    --property=ProtectHome=read-only
    --property=ProtectSystem=strict
    --property=ProtectControlGroups=yes
    --property=PrivateTmp=yes
    --property=NoNewPrivileges=yes
    --property=CapabilityBoundingSet=
    "--property=WorkingDirectory=$run"
    "--property=ReadWritePaths=$run"
    "--property=BindReadOnlyPaths=$node:/run/horizon140-suffix-node/jetstreamer-node $authority/static/hold-entry140:/run/horizon140-suffix-gate/hold-entry140 $authority/static/prefix-audit.json:/run/horizon140-suffix-plan/prefix-audit.json $authority/plan/plan.json:/run/horizon140-suffix-plan/plan.json $authority/barrier:/run/horizon140-suffix-gate/barrier $snapshot:/run/horizon140-suffix-snapshot/${snapshot##*/}"
    --property=StandardOutput=journal
    --property=StandardError=journal
    --setenv=JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1
    --setenv=JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS=600
    --setenv=JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS=60
    --setenv=JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS=900
    --setenv=JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS=120
    "--setenv=JETSTREAMER_HISTORICAL_WORKER_V1_4_25=$worker"
    "--setenv=TMPDIR=$run"
    --setenv=SOLANA_RAYON_THREADS=2
    --setenv=RAYON_NUM_THREADS=2
    --setenv=RUST_LOG=info,solana_metrics=off
    --
    /usr/bin/env /run/horizon140-suffix-gate/hold-entry140 "$plan_digest"
)
printf '%s\n' "${argv[@]}" | jq -Rsc 'split("\n")[:-1]'
