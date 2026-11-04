# Epoch 207 metadata unblock

The native bootstrap is independently qualified by
`/var/lib/jetstreamer/horizon-native207-terminal-proof-v1/proof.json`, SHA-256
`ed39b654d78d4530f82877866d4474435beb353503ad1d3ebfcae04823489819`.
It proves the exact slot 89423444 input, accounts hash, zero replay entries and
zero bootstrap writes. It does not qualify a full epoch or either later root.

## Exact remaining metadata

| Field | Required value |
| --- | --- |
| Slot | 89523820 |
| Accounts hash | `7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik` |
| Generation | `1633927404656451` |
| Compressed size | 8419571372 bytes |
| CRC32C, base64 | `qIeOcA==` |
| MD5 | Unobserved; do not invent or infer remote absence |

The retained v2 preflight omitted this MD5. The offline v4 singleton preparation
preserves that history as `null`, rather than asserting the remote object is
composite. The original v1 singleton report remains immutable at
`/var/lib/jetstreamer/horizon-207-singleton-metadata-v1/preflight207-singleton.json`,
SHA-256 `a921cb0be8c518950b0611d2f03cfa05576655f3160be5732b2bc3157213a580`.
Its fingerprint is
`sha256:50896e94150b8ca275a628bf1c760d81b45a8e5ac7bb5425c7e0d0b0d2f8b1e4`.

The 2026-10-23 17:44:27 UTC generation-specific read failed during token refresh,
before obtaining object metadata. Its retained stdout is empty. That failure
proves neither object absence nor a remote HTTP response. The sealed blocker is
`/var/lib/jetstreamer/horizon-207-singleton-metadata-v1/root89523820-auth-blocked.json`.

A read-only filesystem inspection on 2026-10-23 found:

| Credential file, under `/home/ubuntu/.config/gcloud` | Modification time, UTC |
| --- | --- |
| `credentials.db` | 2026-10-22 23:35:14 |
| `access_tokens.db` | 2026-10-23 01:25:55 |

Both precede the known authentication failure. No credential content or token
was read, and no GCloud authentication/metadata request was retried. File times
are corroborating context, rather than a substitute for a successful read.

## Resume after an actual credential refresh

Refresh the `sam.johnson@anza.xyz` login in this host's
`/home/ubuntu/.config/gcloud` context. Refreshing another server or only its
application-default credentials does not establish this CLI's authorization.
Once that refresh is explicitly confirmed, capture one exact-generation read:

```sh
CLOUDSDK_CONFIG=/home/ubuntu/.config/gcloud \
CLOUDSDK_CORE_DISABLE_PROMPTS=1 \
  /home/linuxbrew/.linuxbrew/share/google-cloud-sdk/bin/gcloud \
  storage objects describe \
  'gs://mainnet-beta-ledger-us-ny5/89523820/snapshot-89523820-7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik.tar.zst#1633927404656451' \
  --account=sam.johnson@anza.xyz \
  --billing-project=principal-lane-200702 --format=json --quiet
```

Run the CLI as ubuntu, preserve its actual invocation/exit status and bounded raw
stdout, and seal the successful observation as root. Bind the current SDK path
and SHA-256, account, billing project, config directory and exact versioned URI.
Do not put credential material, access tokens or login URLs in evidence. A
failure must remain a blocker; do not loop or silently select another generation.

The offline Rust `jetstreamer-epoch207-root-metadata-candidate` tool prepares the
manifest change without GCloud, a snapshot restore, a resource observation or R2.
Its plan schema is `jetstreamer-private-epoch207-root-metadata-candidate-plan-v1`:
`raw_metadata` is a sealed root-owned `{path, sha256}` binding and `output` is
`/var/lib/jetstreamer/horizon-207-root-metadata-candidate-*/preflight207-singleton-candidate.json`.
Use `PLAN --plan-sha256 SHA --self-sha256 SHA` with the separately sealed binary.
The tool requires the complete exact object tuple, rejects conflicting aliases,
missing/noncanonical MD5s and unreviewed composite-object checksum policy, and
changes only the first root's MD5 before computing a new canonical fingerprint.

Its output is explicitly a candidate: it cannot authenticate a captured file's
transport origin and does not grant metadata admission. Bind and independently
check the successful authenticated CLI observation before sealing an admitted
v2 preflight. Preserve v1 and the failed read. Do not substitute a locally
computed archive MD5 or a successful bootstrap test for remote root metadata.

After that observation is accepted, prepare a fresh full-singleton admission
against the current complete fleet, century floor and remaining-growth/RSS claims.
Bind the native proof, new metadata fingerprint, exact node/worker and effective
command. Keep both roots 89523820 and 89855469 and all 530 slots after the final
root through 89855999. Qualify the actual guarded run, native terminal, complete
432000-slot output, independent full/current-plugin and boundary checks before
authenticated upload/readback and sidecar commit. Status must remain bound to the
actual active owner and use only `replay`, `verification`, `upload` or `readback`.

## Independent preparation for epochs 209–212

These retained packages have both bootstrap and terminal MD5 bindings already;
207's missing intermediate-root MD5 is not their blocker:

| Epoch | Retained package suffix | Bootstrap | Canonical final root | Final output slot | Slots after root |
| --- | --- | ---: | ---: | ---: | ---: |
| 209 | `horizon-focused-209-complete-span-store8-ca2e38b-v2` | 90287519 | 90719638 | 90719999 | 361 |
| 210 | `horizon-focused-210-complete-span-store8-ca2e38b-v1` | 90719638 | 91151575 | 91151999 | 424 |
| 211 | `horizon-focused-211-complete-span-store8-ca2e38b-v1` | 91151575 | 91583512 | 91583999 | 487 |
| 212 | `horizon-focused-212-complete-span-store8-ca2e38b-v1` | 91583512 | 92015419 | 92015999 | 580 |

All packages are under `/var/lib/jetstreamer`; each contains the bootstrap body,
genesis, preflight, successful generation-specific bootstrap metadata receipt,
and `snapshot-bindings-N.json` with exact URI/generation, size, CRC and MD5 for
both listed roots. Epoch 212's terminal binding is independently corroborated by
the retained epoch 213 bootstrap restore receipt; it is not an unknown MD5.

| Binding file | SHA-256 |
| --- | --- |
| 209 | `62fdbca7cfe8642c3e6d6bffab3161bf0dbd558a9eca3be6193ac1cc14ce9be0` |
| 210 | `877aeb63674523f1d4cc6937f993a57204bc39999e8e378ea84a6ac1ae5409a8` |
| 211 | `f48751ee91ab153ab185b5e14967d1adfc4681b2a3c46402bce9339e1e60d681` |
| 212 | `80cb65fdabb9f15cb68e14a7c905b6568be9ecda10f4950c6cd58305f847ac76` |

Useful next work is to construct closed v4 singleton metadata profiles from
those existing bindings, retain each canonical final-root check and its short
post-root tail, and prepare optimized cached-input native qualification plus
the exact capped v1.6.16 worker/guard/admission/status profiles. Existing focused
plans continue roughly 431000 slots into the next epoch; their software
capability does not qualify a shorter singleton, native Bank, peak resource
envelope or publication. Do not borrow 207's closed unit/root/harness identity
or claim launch readiness from the old focused package receipts. None of this
offline preparation requires retrying 207's expired GCloud credentials.
