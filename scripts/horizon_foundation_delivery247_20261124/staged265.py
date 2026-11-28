"""Bind the independently checked epoch 265 archive to its staged publisher."""

from pathlib import Path

import staged250

PROFILE = staged250.Profile(
    epoch=265,
    unit="horizon-upload-265-staged-public-v260.service",
    predecessor="horizon-upload-265-ordinary-retry-v216.service",
    package=staged250.V / "horizon265-staged-recovery-v260-tools",
    plan=staged250.V / "horizon265-staged-recovery-v259/epoch-265-plan.json",
    plan_sha="7032695fedca1d632ac2ff20c0830b7c49eed183bfc4ded8ff25fc0f56555203",
    state=Path("/home/ubuntu/.jetstreamer-private/current-reader-delivery-265-staged-recovery-v259"),
    image=staged250.IMAGE,
    image_sha=staged250.IMAGE_SHA,
    etag="2bda3226eb3c4bbd11c9bb7b52053f21-2825",
    size=189538254413,
    memory_cap=10 << 30,
    old_status={
        "path": "/home/ubuntu/.jetstreamer-private/foundation-publication-status-repair.aIkorzZ0/265/completion.json",
        "sha256": "f89227885214144956209f6fc70f35e77e7dd6cfd8a1dc2101aa5500354fd8bc",
    },
    cpus="64-71",
)
