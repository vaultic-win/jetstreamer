"""Bind the independently checked epoch 248 archive to its staged publisher."""

from pathlib import Path

import staged250

PROFILE = staged250.Profile(
    epoch=248,
    unit="horizon-upload-248-staged-public-v259.service",
    predecessor="horizon-upload-248-ordinary-v213.service",
    package=staged250.V / "horizon248-staged-recovery-v259-tools",
    plan=staged250.V / "horizon248-staged-recovery-v258/epoch-248-plan.json",
    plan_sha="855f77c457d19a502a54129443b59798d93465bc601712b27580d04da0263c45",
    state=Path("/home/ubuntu/.jetstreamer-private/current-reader-delivery-248-staged-recovery-v258"),
    image=staged250.IMAGE,
    image_sha=staged250.IMAGE_SHA,
    etag="0da9fae324ac4bc403de9553a8110bef-2787",
    size=186974189938,
    memory_cap=10 << 30,
    old_status={
        "path": "/home/ubuntu/.jetstreamer-private/foundation-publication-status-repair.aIkorzZ0/248/completion.json",
        "sha256": "cd45fdb527166500083252f8f2d2dcf623707bb77dc35ab133d5f305263caddc",
    },
    cpus="56-63",
)
