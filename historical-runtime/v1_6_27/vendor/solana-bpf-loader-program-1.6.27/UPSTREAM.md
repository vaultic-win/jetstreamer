# Vendored source record

- Repository: `https://github.com/solana-labs/solana`
- Tag/version: `v1.6.27`
- Commit: `c5d174c1701b795d702654a76ddd458c4d8b97ea`
- Imported subtree: `programs/bpf_loader/`
- Upstream Git tree: `a5c7e357e40fe8ec16d2855246bc10d45feaf1ba`
- License blob: `285adee28490f5a79e92b3e860e1af2f9b865f07`
- Required compiler/target: `rustc 1.51.0 (2fd73fabe 2021-03-23)`,
  `x86_64-unknown-linux-gnu`

Only the monorepo-relative runtime and SDK dependencies are redirected to the
sibling exact vendored runtime and exact upstream Git revision. Program source
is unchanged. Static linking supplies the exact v1.6.27 deprecated, standard,
and upgradeable BPF loader entrypoints during snapshot reconstruction.

`LICENSE-APACHE` is copied from the recorded upstream commit.
