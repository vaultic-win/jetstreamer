# Releasing Jetstreamer

GitHub Releases is Vaultic's distribution channel. A release consists of an
immutable `v<version>` tag and a GitHub release with source archives and notes
from `CHANGELOG.md`. Current automation does not publish prebuilt executables or
upload packages to crates.io. Existing crates.io and docs.rs versions remain
historical Anza releases.

## Create a release

1. Bump the workspace version and internal crate dependency versions together in
   `Cargo.toml`, update `Cargo.lock`, add a matching version section to
   `CHANGELOG.md`, and update the pinned installation examples.
2. Merge the change and wait for both the Rust and Nix push workflows to pass on
   the exact main commit being released.
3. Dispatch the Release workflow from main, selecting that full commit SHA:

   ```sh
   gh workflow run release.yml --repo vaultic-win/jetstreamer --ref main -f ref=<commit-sha>
   ```

The workflow reads the selected commit's workspace version and changelog. It uses
the repository's GitHub token, with write permission only in the publishing job,
and has no registry credentials or trusted-publisher prerequisite. The publishing
job uses the `prod` environment. The automation is checked out from the workflow revision; release source files
are read from GitHub at the selected commit. Current automation can therefore
inspect an older release tag.

## Retry and verify

A retry against the same commit leaves an existing published release unchanged.
If a tag exists at a different commit, the workflow stops. Never move a published
tag; bump the version for changed source. If a run created the tag but failed
before creating the release, rerun it against the same commit to finish.

Confirm that the tag resolves to the selected commit and that the release is
published. Inspect its generated source archives and notes. Test updates to the
release automation against an already published tag, such as `v0.10.0`, to check
its idempotent path without creating another release.

The first GitHub source release under this policy is
[0.10.0](https://github.com/vaultic-win/jetstreamer/releases/tag/v0.10.0). Its tag
predates the change to GitHub-only automation and remains unchanged.
