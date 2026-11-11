# Changelog

## 0.10.0

This release includes the changes since the GitHub 0.9.0 release. The previous
crates.io release was 0.8.1.

- Replace the build-time ClickHouse installer script with pinned downloads and
  SHA-256 verification. Cached and offline artifacts must match the same
  committed digest. Builds never execute the downloaded installer.
- Pin the Nix development environment and read its Rust toolchain from
  `rust-toolchain.toml`. Add Linux validation in CI and update native setup
  instructions.
- Decode VATDebit rewards and Alpenglow transaction/instruction `BailOut`
  errors. Use Agave 4.4.0 and its compatible Solana SDK types.
- Make the Geyser loader opt-in through the `geyser` feature. Ordinary library
  consumers no longer require Agave's RocksDB patches; external Geyser users
  still need the patches documented in `jetstreamer-firehose/README.md`.
- Add the Vaultic polar terminal theme, with consistent chart colors, clearer
  labels, and `n/a` for unavailable system metrics.
- Pace archive reads by default, with `--turbo` for unpaced replay. Stop latest
  epoch discovery when availability checks fail.
- Close extracted ClickHouse executable handles before starting the process,
  fixing a Linux startup race.
- Point package metadata and contribution links to Vaultic. Release automation
  uses the repository's GitHub token and crates.io trusted publishing without
  requiring the former Anza GitHub App.

Rust 1.98.1 or newer is required. The Agave/Solana type changes and opt-in Geyser
loader can require changes in downstream applications. Horizon/account-updates
is maintained on its separate branch and is not included in this release.
