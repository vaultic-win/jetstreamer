# November 19 capture qualification

The original capture passed all 16 tests with no filtering or ignored tests,
strict all-target Clippy, and its release build in the fixed HOME filesystem
documented in `BUILD_QUALIFICATION.md`. The successful test invocation was
`a77d182c03fd435e93a0e7ec1a84b08f`; the Clippy/release invocation was
`56cca424ec354f33b5dc241b3f85064b`. The preserved baseline production image has
SHA-256 `35cec52aa8cc5bfd93f9e6a9033df863e662e4b1c11a9dc48e36d136f991484c`.
This proves compilation and predicate tests, not transport or replay acceptance.

The next source revision extracts the unchanged production HTTP client policy
into `client_builder()` and adds a test-only local TLS server. The
`native-transport-tests` feature enables eight additional tests through the
actual `head` and `get` functions. They require root custody and an isolated
network namespace. Only test code trusts the public fixture CA or selects a
loopback endpoint. The production CLI still permits neither override.
Rustls 0.23.40 is an explicit dev dependency, already present in the pinned
graph. `capture-native-build.service` compiles the test binary without running
it as the unprivileged builder, then applies strict Clippy to all targets with
that feature. The native tests must subsequently run as root with bounded
private output.

All 24 tests (the original 16 and eight TLS tests) passed, with no ignored or
filtered tests, in native invocation `f3a3ef28982e438fbe45bbd81e9e3420`.
The exact test binary SHA-256 was
`ddf100fe538ddaa94ffaff864328afcd98b05efc60055224e1ea7856bcc6889b`.
The test build and strict feature-enabled all-target Clippy passed in invocation
`cf8cd310ebe94cdaba68b1e709caf7be`. Logs, terminal native properties and the
original baseline image are retained in the bounded build workspace's `work/logs`.
This exercises genuine local TLS, headers, response status, truncated streams,
the original deadline, output permissions and untrusted certificate rejection.
It does not cover the entire black-box capture/funding/fsync acceptance matrix.

## November 20 native qualification and historical source

The native harness completed all 55 cases on November 20. The receipt at
`work/native168-controls-v1/controls/native-controls.json` has SHA-256
`8fe3daa707a2c92a792ded315842e004d9ecb71a68ce39eca423fb1652527f1d`.
The unexecuted status in the sealed harness source inventory describes its
original handoff. The 05:25 UTC production capture stopped at the first CAR
HEAD because the provider omitted an ETag. Both the CAR and slot-range
objects also omitted ETags on bounded HTTP 206 responses.

At 05:33 UTC a separate read-only investigation verified the published epoch
CID against the CAR header and the SHA-256 of the epoch node. It followed
the authenticated subset, block, entry and transaction links to slot
72,728,191, entry 433, transaction 532. It verified the original wire
signature. The segment occupies inclusive CAR offsets 53,089,080,641 through
53,089,471,805. Its 391,165 bytes have SHA-256
`f3f7c415ae3519c0b48fc54812232b9f715ba6c0932d761733db8787adce125a`.
The provider publishes the root and checksum in its [epoch recap](https://files.old-faithful.net/168/168.recap.yaml).

The transaction metadata contains a successful Raydium swap. The final
program log records 199,916 of 200,000 compute units consumed. The saved
worker incident reports `ProgramFailedToComplete` at instruction zero.
The worker's raw VM error and pre-transaction bank state still need to be
recovered to explain the difference.

On the campaign host, the investigation is retained in
`work/epoch168-cid-investigation-v1` under the HOME-backed build directory
described in `BUILD_QUALIFICATION.md`. The investigation receipt digest is
`ac9c634002bf37bdfb47ba8f189efe71f0432036379dc5ec181952d351528991`.
The typed Protobuf text digest is
`bfad1e6b84fb321341aa7f9b0896b5996f27b51f7be3abe556b0c1a78a06ab9d`.

## November 20 extraction and parent verification

At 06:07 UTC the sealed extractor passed all 53 tests and processed the
391,224-byte original-header and slot fragment under the fleet's existing
2 GiB serial qualification allowance. All 16 output members matched
their recorded lengths and digests. The completion receipt SHA-256 is
`1bcf498ad2f06433e2ae00114a3ba079815b0273aae567fa04426992549fe12d`.

At 06:08 UTC a separate check followed the epoch and subset links to both
the parent at slot 72,728,190 and the target at 72,728,191. Starting
from the parent's final entry hash, it reproduced all 459 target entry
hashes, covering 554 transaction references and 800,000 PoH hashes.
The final hash was
`7a77adabc15ae916578d7be9c695d04c3379e15e5516d810b56e50df1ed586f4`.
This supplies the parent-hash evidence listed as missing in the
extractor's own report.

The retained bootstrap at slot 72,575,704 matched all 2,029,219,745 bytes
of US replica generation `1634787413893700` by CRC32C and MD5. Its local
SHA-256 is `f1a8902dcb00eb59266a2f688d05f7d406af1999eb78956bfd0c46056571ad04`.
Authenticated listings of all three regional replicas found this single
slot prefix in the interval from bootstrap through target. The intermediate
bank state and the worker's underlying VM error remain the replay dependencies.

The host receipt `epoch168-trace-worker-build-20261120-v1/SOURCE_EXTRACTION_COMPLETE.json`
under the HOME-backed runtime data directory binds the extractor, its tests,
the snapshot and the PoH result. Its SHA-256 is
`5eaa13bf58e7eca4df72ba29481973deec634aaecf04d83b9bdb30fd9aa0d3e9`.
The adjacent `CAPACITY_CORRECTION.json` records the omitted aggregate
memory check in the original build admissions and the end of those
invocations before the serial qualification.
