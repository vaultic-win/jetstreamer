# Epoch265 input capability capture

This source candidate performs only a 4096-byte CAR-header request and captures
completed negative probes. Main must review, build/test, publish, seal, admit and
execute it. No replay, upload, source-publication or resource-release authority
is produced. It does not launch systemd units.

`network-run` runs as ubuntu in the network probe service. It requires a fresh
empty `qualification-265-replacement-20261119-v1/network-proof` directory,
checks actual mount namespace IDs, readonly mounts and exact projected inode
identity before and after the request, invokes bounded curl, and writes a
no-clobber `native-result.json` under the separate charged directory
`/home/ubuntu/.jetstreamer-private/horizon265-network-native-evidence-20261119-v1`.
That directory must be empty, ubuntu-owned0700, and explicitly included in the
probe service ReadWritePaths. `network-proof` retains exactly headers and body;
no cleanup/relocation operation or production-root exception is needed. The actual dynamic invocation ID, helper PID
and hash, curl argv/hash, CAR root, byte count and hashes bind this result.
It rejects HTTP200, redirects, encoded/multipart responses, wrong ranges,
incorrect roots, truncation and more than4096 bytes. Curl has a60-second limit;
the oneshot service has a90-second `TimeoutStartSec` (not RuntimeMaxSec).

Capture commands, as root, after native terminal completion:

```
horizon265-capability network /var/lib/jetstreamer/PLAN.json PLAN_SHA256 HELPER_SHA256
horizon265-capability probes /var/lib/jetstreamer/PLAN.json PLAN_SHA256 HELPER_SHA256
```

Plans must be root-owned immutable regular files with exact digests. Paths and
actual IIDs come from Main's execution evidence; placeholders in the companion
examples are intentionally invalid. Use fresh root-owned private output
receipt directories. Capture writes no-clobber0400 receipts and fsyncs each
file and parent, never a filesystem-wide flush. A partial capture must be
preserved; retry into a new explicitly reviewed directory.

`network` requires the producer's network-related namespace, mounts and
full environment with one explicit input-only exception: the production
`horizon265-replacement-20261119-tokens-v1` directory is omitted from
ReadOnlyPaths and must remain absent, including dangling links, before/during/
after the probe and capture. Every other readonly and bind path remains exact.
Only the separate charged native diagnostics directory is added to
ReadWritePaths. Main must bind the exact exception object and
`Main_accepted_namespace_exception: true` in the immutable capture plan.
The receipt records this exception and `production_namespace_qualified: false`;
it proves the bounded input network path, never the later production startup
or guard-token namespace. The probe has a256MiB/32-task/1CPU envelope. The retained
unit is Type=oneshot, RemainAfterExit=yes; keep it active/exited until capture
completes. Genuine native output and subsequent PID1 completion are mandatory.
Header/body bytes are copied into the immutable command/journal evidence;
original paths, digests and complete file identities including `identity.bytes`
remain in the network proof. Identities and byte content are rechecked before
receipt publication, matching the launcher input reader contract.

`probes` reuses the retained filename probe unit/IID. Never rerun it. Main must
supply its actual argv and original output/work paths. The new fingerprint
probe uses an all-zero expected manifest fingerprint and a wrong snapshot
filename, with512MiB/64tasks/1CPU/30seconds and PrivateNetwork=yes. No correct
snapshot filename or additional node arguments are admitted. Exact selected
node and manifest bytes are hashed. The collector checks real expected error
messages from the original executable/PID/IID/command, later PID1 exit-code
failure, native status1, absent PID, drained cgroup, and empty output/work
directories twice. It rejects fingerprint failure in the filename probe.
The preexisting filename envelope must have finite memory<=1GiB, User/Group
ubuntu, NoNewPrivileges and zero swap; its original sandbox is not rewritten.
If the accepted original differs, review that actual evidence before changing
this source requirement; do not restart the successful negative test.

The output schemas match `horizon265-launch/src/inputs.rs`:

* `horizon265-service-effective-car-header-proof-v1` with exact compiled producer
  template SHA, HTTP206, expected epoch265 CID, service namespace proof and
  command/journal binding.
* `horizon265-selected-node-negative-probes-v1` referencing two
  `horizon265-selected-node-negative-probe-v1` receipts. Each references its
  immutable `actual_command_and_journal` JSON and retained PID1 terminal.

The collector does not assemble the overall input capability; Main must bind
these receipts with the accepted codec and native265 terminal evidence, then
seal the exact static input-capability package.

Source tests cover wrong CAR root/range/length/HTTP framing, changed effective
namespace/environment/resource properties, extra/substituted node arguments,
correct snapshot filename rejection, missing output/work census, and changed
ExecStart ignore-errors semantics. Additional integration regressions require
`identity.bytes`, exactly headers/body in network-proof, a native-result path
outside the production root, and omission of only the startup-token readonly
path. Build, tests and Clippy must be run by Main.
