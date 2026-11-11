# Bundled ClickHouse

Jetstreamer embeds ClickHouse **26.10.2.103 stable**. Building `jetstreamer-utils`
uses `curl` to download an official release artifact over HTTPS, verifies its
SHA-256 against the digest committed in `build_support.rs`, and embeds the binary.
The build does not run an installer or execute the downloaded binary.

The artifact follows Cargo's `TARGET`, including during cross compilation:

| Target | Release artifact |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `clickhouse-common-static-26.10.2.103-amd64.tgz` |
| `aarch64-unknown-linux-gnu` | `clickhouse-common-static-26.10.2.103-arm64.tgz` |
| `x86_64-apple-darwin` | `clickhouse-macos` |
| `aarch64-apple-darwin` | `clickhouse-macos-aarch64` |

Other targets fail with an explicit error. Linux archives contribute only their
named regular `usr/bin/clickhouse` member; their scripts, links, and other files
are never unpacked. Runtime code gives its extracted copy executable permissions.

## Offline builds and caches

Set `JETSTREAMER_CLICKHOUSE_ARTIFACT` to a local copy of the artifact for your
target. The same committed checksum is required; the setting cannot substitute
an arbitrary executable or bypass verification. For Linux, supply the `.tgz`
archive, not an extracted binary. This also permits Nix to fetch the artifact
before entering the development shell.

Without that setting, verified downloads are cached in Cargo's `OUT_DIR` under a
name containing their digest. Each build-script run rechecks the cached artifact
and regenerates the embedded binary. Both files are tracked as build inputs so
changing either triggers verification again. A damaged cache is downloaded
again. Failed downloads and checksum mismatches are never promoted into it.

`DOCS_RS` retains the documentation-only bypass and embeds an empty byte slice.
Do not set it when building an executable that needs the bundled server/client.

## Pin provenance and updates

The four SHA-256 pins were read on November 11, 2026 from GitHub's `digest` fields
for the official [26.10.2.103 release](https://github.com/ClickHouse/ClickHouse/releases/tag/v26.10.2.103-stable)
(release ID `422510923`, published October 24). Asset IDs in table order are
`671246286`, `671248221`, `671250671`, and `671250835`. The Linux amd64 archive and
macOS arm64 executable were also downloaded and their hashes checked locally.

Updating ClickHouse requires reviewing the release, updating every artifact URL,
checksum, and archive member together, and testing the embedded server on the
supported platforms. Digests are part of the reviewed source; builds never fetch
replacement checksum files. A changed or replaced upstream asset fails closed.

The `clickhouse_artifact` integration tests use local fixtures to exercise target
selection, corrupted downloads and caches, interrupted download recovery,
verified local input, and archive member rejection. The test cases use no network;
the initial crate build still needs a cached, local, or downloadable artifact.
