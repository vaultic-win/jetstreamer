# Vendored source record

- Repository: `https://github.com/solana-labs/solana`
- Tag/version: `v1.6.25`
- Commit: `7de8a55b54d3e11058b82f9483bb405d143b455c`
- Imported subtree: `programs/bpf_loader/`
- Upstream Git tree: `6b7942c5806d43dc1b5ba7d77b4cd76db5a3a976`
- License blob: `285adee28490f5a79e92b3e860e1af2f9b865f07`
- Required compiler/target: `rustc 1.51.0 (2fd73fabe 2021-03-23)`,
  `x86_64-unknown-linux-gnu`

Only the monorepo-relative runtime and SDK dependencies are redirected to the
sibling exact vendored runtime and exact upstream Git revision. Program source
is unchanged. Static linking supplies the exact v1.6.25 deprecated, standard,
and upgradeable BPF loader entrypoints during snapshot reconstruction.

`LICENSE-APACHE` is copied from the recorded upstream commit.
