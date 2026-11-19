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
private output. They were unrun when this source revision was authored.

The 53 extractor tests, full transport/native acceptance matrix and historical
source/state proof remain required before any epoch168 recovery. No epoch168
source acquisition or replay has been launched by these compiler services.
