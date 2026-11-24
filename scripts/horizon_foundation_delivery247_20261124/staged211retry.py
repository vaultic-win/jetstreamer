"""Select the epoch 211 successor after its boundary evidence custody repair."""

import staged211
import staged250

PROFILE = staged250.Profile(
    epoch=211,
    unit="horizon-upload-211-staged-recovery-v2.service",
    predecessor=staged211.UNIT,
    package=staged211.V / "horizon211-staged-custody-retry-v258",
    plan=staged211.PUBLISHED_PLAN,
    plan_sha=staged211.PUBLISHED_PLAN_SHA,
    state=staged211.STATE,
    image=staged250.IMAGE,
    image_sha=staged211.IMAGE_SHA,
    etag=staged211.ETAG,
    size=staged211.SIZE,
    memory_cap=10 << 30,
    old_status={
        "path": str(staged211.TERMINAL_REPAIR),
        "sha256": "61a15ed465adcbd126aab54623579973c22d132b07bf920b447f6d4e46cb4e94",
    },
    cpus="16-23",
)


def prior_drained(previous):
    assert staged211.terminal_repair(previous) == PROFILE.old_status


def load(original, previous):
    if not PROFILE.registration.exists():
        assert not PROFILE.registration.is_symlink()
        return None
    prior_drained(previous)
    predecessor = dict(original, claim=previous["claim"], spec=previous["spec"])
    retry = staged250.load(predecessor, PROFILE)
    return dict(
        retry, root_predecessor=original["claim"], prior_registration=previous["registration"],
        supports_pinned247=True,
    )
