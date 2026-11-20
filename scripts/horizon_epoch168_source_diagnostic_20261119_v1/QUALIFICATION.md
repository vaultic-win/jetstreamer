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
recovered to explain the difference. The 53 extractor tests, native
extractor run and replay qualification remain outstanding.

On the campaign host, the investigation is retained in
`work/epoch168-cid-investigation-v1` under the HOME-backed build directory
described in `BUILD_QUALIFICATION.md`. The investigation receipt digest is
`ac9c634002bf37bdfb47ba8f189efe71f0432036379dc5ec181952d351528991`.
The typed Protobuf text digest is
`bfad1e6b84fb321341aa7f9b0896b5996f27b51f7be3abe556b0c1a78a06ab9d`.
