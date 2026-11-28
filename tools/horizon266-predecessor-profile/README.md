# Epoch 266 private predecessor profile

The sealed preparation fixes bootstrap slot 114,910,768 and terminal slot
114,923,430. The node executes 12,662 slot positions starting at 114,910,769
and emits 11,431 positions starting at epoch boundary 114,912,000. The
existing private, no-network CLI fixture reached the expected empty-snapshot
gate with the selected v1.8.11 worker and Horizon V2 writer.

Run the tool as root from a qualified build, passing the build's SHA-256.
`--check` validates the source evidence and renders the expected profile
digest. `--prepare` creates the empty runtime paths and seals the profile,
checkpoint filenames and namespace probe. Existing paths stop preparation.

```sh
horizon266-predecessor-profile --check SELF_SHA256
horizon266-predecessor-profile --prepare SELF_SHA256
```

The static preflight at
`/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1/preflight.json`
binds the sealed package, systemd unit syntax check, guard plan validation
and no-network namespace probe. The probe uses one CPU, 1 GiB memory, a
2 MiB written-file limit and a 30-second bound. It confirms read-only
projection of the sealed genesis and four indexes, private 128 GiB
`noswap` tmpfs, persistent output and access to a qualification-only prestart
token. The bootstrap projection in this probe carries the 144-byte sealed
checkpoint names. The exact generation-pinned bootstrap remains pending.

Use a fresh post-turnover roster to admit the exact intake, record
generation, size, CRC32C, MD5 and SHA-256 custody, then separately admit the
replay. Bind the merged dispatcher and scope source, recheck the actual
bootstrap projection, and require an invocation-bound live guard sample
before releasing the producer's prestart token. The earlier independent
checkpoint and full-prefix PoH comparison remain part of private terminal
qualification.
