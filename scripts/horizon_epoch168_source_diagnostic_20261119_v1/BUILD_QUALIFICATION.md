# Capture qualification on home storage

The first capture build uses `capture-build.service`. This is a compiler/test
service, not a capture or replay deployment. It cannot reach the network.

Its only writable filesystem is a 4,294,967,296-byte, fully allocated ext4
image beneath `/home/sol/.jetstreamer-private/epoch168-source-diagnostic-build-20261119-v1`.
The image is Root-owned, mode 0600, mounted `nodev,nosuid` at `work`. The
unprivileged process cannot grow the backing image or write outside that mount.
Cargo output, its private cache metadata, temporary files and logs all reside
there. Cached registry sources are read-only. The kernel enforces the fixed
filesystem size, 2-GiB cgroup memory cap, zero swap, 256 tasks and one CPU before
any compiler runs. There is no deferred guard activation or startup grace period.
The service fails its mountpoint precondition if the private filesystem is absent.

Before the first build, a native systemd sandbox control with these properties
confirmed the actual loop mount, access to cached sources, successful private
temporary writes, and rejected a repository write with EROFS. The private image
is backed by HOME; it is neither storage on root nor a RAM-backed filesystem.

Admission preserves the complete 23:25 fleet, all three producers and the audit.
The latest epoch170 capacity receipt requires 7,877,678,686,002 available DATA
bytes and 663,964,131,328 available memory bytes. The capture adds a 4-GiB fixed
image, a 16-MiB outside metadata allowance, and a 2-GiB memory cap. Complete
projected memory including the audit and 16-GiB host reserve is 806,228,865,024
bytes, below the 810,902,843,392-byte host total. No historical resource claim is
released. Native preflight must recheck available space/memory, the immutable
image length and ownership, the actual mount and source containment before use.

The service is persistent and retains its real terminal invocation. It runs
only the 16 capture tests. A passing result does not qualify the transport
harness, extractor, original-byte capture or an epoch replay. Preserve failed
invocations; select distinct units for subsequent Clippy and release commands.
Do not extend this allocation to the substantially larger extractor build.

`SOURCE_MANIFEST.json` records the original packaged source. This document and
the service are later qualification additions. The 13 retained source/fixture
files remain byte-identical to `SOURCE_COPY.json`.
