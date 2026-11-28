# Epoch 168 native transport controls — source only

This independent Rust workspace authors 55 serial controls for the unchanged,
normally sealed `capture168` executable. No control has been compiled or run.
The retained `CARGO_RESOLUTION.json` records offline metadata resolution only.
It does not establish compiler, linker, native, capacity or guard acceptance.

The harness exercises actual child processes, TLS sockets, HTTP messages, file
writes, fsync failures, timeout waiting and a SIGKILL. It does not manufacture
successful execution evidence. Every generated result has a fixture schema,
denies admission/publication/replay authority, and lives beneath
`FIXTURE_ONLY_DO_NOT_ADMIT`. Even successful capture completion files inside
that tree describe synthetic bytes and must never be consumed as provider
acquisition evidence.

## Transport and isolation

Before creating threads, the harness enters fresh network and mount namespaces,
makes mount propagation private, and enables only its private loopback. It
binds a fixture hosts file over `/etc/hosts` and a fixture trust directory over
`/etc/ssl/certs`, both read-only and only inside that namespace. The actual
production hostname resolves to `127.0.0.1` there. The production image, URLs,
client builder, TLS verification and HTTP restrictions are unchanged.

A local OpenSSL TLS server listens on port 443. A separate port 444 records
forbidden proxy use. A temporary CA signs the good endpoint and wrong-hostname
endpoint; a different CA signs the untrusted endpoint. Private keys remain in
memory; the trusted public CA is retained. This arrangement expects Linux's
normal certificate lookup at `/etc/ssl/certs/ca-certificates.crt`, as used by
the selected reqwest 0.13 Rustls platform verifier. Failure to trust that
fixture is a failed baseline, never permission to disable TLS verification.

The first case must complete successfully or the suite stops. Normal transport
must use the exact eight-request HEAD/GET sequence, fixed Host, identity
encoding, If-Match and exact ranges. The fixture provides a 5,184,000-byte raw
index and a 128-byte synthetic CAR. Its target record is index 152191 with
offset 32 and length 8; the original fixture header is `[1, 0xa0]`. The expected
captured `input.car` is that header followed by bytes 32 through 39. Only the
oversized-index control advertises a virtual 512 MiB CAR; no large CAR body is
allocated or transferred for that control.

Each case retains the actual child PID, stdout/stderr, exit code or signal,
wall/monotonic timing, request and response headers, intended response body
length/hash, actual successful body-write count, and transport errors. A
successful server write is not asserted to be a client read; capture output
and actual child rejection/completion provide the other side of the evidence.
Unexpected extra connections, fixture I/O errors, missing injection tags,
supervisor kills and ordinary child crashes fail qualification. Errors drain
the child and server before a later case or return.

## Authored controls

`src/main.rs::CASES` and `SOURCE_INVENTORY.json` enumerate all 55 controls.

- Successful baseline and ignored-proxy environment controls.
- Wrong image, plan or funding digest; unknown foreign-URL field; absent
  funding acceptance; expired, future or overlong interval; symlink plan;
  occupied output with preserved sentinel.
- Untrusted TLS certificate and wrong TLS hostname.
- Weak, absent or duplicate ETag; absent or zero HEAD length; HEAD redirect.
- HTTP 200 range fallback, HTTP 412, redirect, changed/duplicate ETag, wrong
  range offset/total/length, gzip, chunked overflow framing, truncated body,
  and provider-version appearance/disappearance/change/duplication.
- Zero, outside-object, overflow, header-overlapping and oversized index
  records; nonminimal, oversized, overflowing, zero, truncated and changed
  CAR headers; changed final HEAD ETag or provider version.
- A real 30-second read timeout with delayed response body.
- Actual child ENOSPC on slot write and EIO on slot fsync or marker fsync;
  SIGKILL after marker fsync; deadline expiry after marker fsync; child-only
  realtime regression with the unchanged monotonic deadline still expiring.

The last six controls use the separately bound `fault-shim` cdylib via
`LD_PRELOAD` in only the selected child. Its `write`, `fsync` and
`clock_gettime` interceptors otherwise invoke the actual Linux syscalls.
Injection requires an exact member basename and emits a retained stderr tag.
Clock regression must produce a second observed-clock tag. A static image,
secure-execution loader or alternate libc clock path that bypasses the shim
causes failure rather than an assumed pass. No host clock is changed.

## Root-owned build and execution gates

Root must separately book and qualify the complete build and runtime scope:
source/images, dependency graph, native OpenSSL headers/libraries, linker,
target/cache, certificates, harness plus child peak memory, all retained case
outputs, logs and filesystem metadata. The dependency lock resolves 36
packages without new registry versions relative to the parent lock. It does
not prove native OpenSSL availability or compatibility. No resource amount,
compiler identity, artifact or guard receipt is accepted by this packet.

After actual build admission, these are command shapes, not executed recipes:

```text
cargo build --offline --locked --release --workspace --jobs 1 \
  --manifest-path NATIVE_SOURCE/Cargo.toml --target-dir ROOT_FUNDED_HOME_TARGET
cargo clippy --offline --locked --workspace --all-targets --jobs 1 \
  --manifest-path NATIVE_SOURCE/Cargo.toml --target-dir ROOT_FUNDED_HOME_TARGET -- -D warnings
```

The release outputs are `horizon-epoch168-native-qualification` and
`libhorizon_epoch168_native_fault_shim.so`. Root selects the actual toolchain,
locks, build source, full extern/native-library graph and guarded execution.
Normally seal the reviewed harness, shim and capture artifacts with actual
digests. This packet adds no production source changes and does not alter the
capture's separate 16 tests or extractor's 53 tests.

The runtime requires root with effective namespace/mount, loopback-network
and privileged-bind capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, and
`CAP_NET_BIND_SERVICE` where required), plus actual access to every bound
artifact. Prove these in the intended sandbox; do not infer them from UID or
the harness source. A service may prohibit namespace creation or mounts even
when those capabilities appear in its bounding set. Failure must remain a
failed gate. Keep the fixture inside an independently guarded/drained scope.

```text
NORMALLY_SEALED_HARNESS \
  --capture ABS_SEALED_CAPTURE --capture-sha256 ACTUAL_CAPTURE_SHA256 \
  --funding ABS_ROOT_FUNDING --funding-sha256 ACTUAL_FUNDING_SHA256 \
  --fault-image ABS_SEALED_SHIM --fault-sha256 ACTUAL_SHIM_SHA256 \
  --output NEW_ABSOLUTE_HOME_FIXTURE_DIRECTORY
```

The image, shim and supplied funding must be canonical, immutable, root-owned,
single-link regular files with separately supplied hashes. Root's funding
must genuinely bind the actual native guard/allocation and original interval;
the harness does not authenticate those external receipts. At least 120 seconds
must remain initially, and at least 45 seconds before each case. Root's total
original interval cannot exceed 900 seconds. The original start is retained
in shortened marker-deadline controls, and the 30-second socket control runs
first so those shortened intervals remain at least 30 seconds long. The
harness never extends that interval, fabricates acceptance or renews a clock.
Its 45-second child cap is an additional limit, not Root's actual guard.

Fixture plans and negative funding copies are generated as root-private,
immutable test inputs. They are not normally sealed production plans. The
funding false/expired/future/overlong cases deliberately invalidate copies;
all positive cases inherit Root's unchanged accepted contract. Child
environments are cleared except for the specific fixture variables.

Keep all outputs for inspection. This harness has no cleanup, network-origin
access, R2 operation, archive, sealer, admission or replay implementation.
Root must merge required source into `account-updates`, establish actual
source/artifact equivalence and preserve the existing campaign gates before
any separate operational epoch admission.

## Coverage limits that remain explicit

- This source is uncompiled and all 55 native cases are unrun. A generated
  `native-controls.json` is native fixture evidence only; Root's accepted
  successful guarded provider capture remains a separate decision.
- The privileged fixture environment does not prove the production sandbox's
  effective filesystem/network restrictions, native guard or resource limits.
- Wrong self digest exercises the running-image hash check, but does not
  exercise a pathname-replacement race against `/proc/self/exe`. Noncanonical
  ancestors, hard links, symlink funding, every custody permutation and clock
  renewal/rollback before budget construction are not claimed covered.
- Chunked overflow exercises actual transfer-framing rejection. HTTP
  Content-Length can clamp the application body, so it does not prove the
  downstream vector-overflow branch or rejection of all trailing TCP bytes.
  Ten continuation bytes exercise the varint overflow check; there is no
  claim that an unreachable unterminated-varint fallback ran. Truncated-header
  transport rejection is not proof of every short-buffer parser branch.
- Interposed storage failures are real errors observed by the actual capture
  child, not evidence of physical media failure. Clock interposition and the
  SIGKILL control must be observed in the exact qualified artifact graph.
- Certificate and synthetic CAR bytes prove controlled transport behavior,
  never provider generation, target semantics, canonical ancestry, extractor
  correctness, a replay fix, archive compatibility or R2 readback.

If additional production controls are needed, Root should review a separate
successor. No production endpoint override or relaxed verification is proposed.
