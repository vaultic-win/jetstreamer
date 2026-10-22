# Private epoch-141 native admission

`jetstreamer-epoch141-native-admit` admits only the sealed `f1592d…` full-census
read-only native candidate on dev-samjohnson. It does not restore a snapshot,
open a database, install/start a service, launch replay, or access R2/network.
The existing full-census runner still independently validates all 18,283 RPC
targets, source/census bindings, complete retained member hashes, exact column
families and live SST references before its one bounded native read session.

The root-owned owner-only manifest keeps the existing
`jetstreamer-historical-performance-admission-v1` schema understood by that
runner, with a distinct `native_profile: epoch141-read-only-full-census-v2`.
It has no snapshot field and cannot be consumed as generic replay admission.
Required fields are the fixed `/home/sol` filesystem, `minimum_free_bytes` of at
least 4,740,696,923,590 + 32 GiB, at least 144 GiB available memory (128 GiB
protected/reserve plus a 16 GiB native envelope), one exact root-owned mode0555
native executable in `files`, and path/SHA bindings for `observer`, `fleet`,
`finalized_collection`, `family_policy` and `retained_collection`.

The complete metadata receipt must bind the actual terminal collector invocation,
all 18,283 target receipt entries, fixed census, plan, slots and false authority
flags. Admission only checks this header and digest; it does not claim the
native runner's independent full target reread. The accepted v2 observer and
complete assigned-range fleet must agree, fit the resource envelope and be at
most 30 minutes old. Every active controller/producer invocation is re-observed
before and after admission. A changed/restarted/missing owner, existing epoch141
owner, incomplete collector or armed/active native/check unit rejects admission.
Any newer or conflicting assigned-range fleet receipt also rejects admission,
including a later admission event carrying an older sample filename. Sample age
is measured from the observer timestamp, not extended by a late fleet writer.
Current filesystem free space and available memory must also pass unchanged
limits. No source/hidden-PoH/root/publication qualification is granted.

The constrained `native_unit` is `horizon-epoch141-native-full-census-NAME.service`;
`output` must be the absent `admission.json` directly under a root-private
`/var/lib/jetstreamer/horizon-native141-admission-NAME` directory. Seal the binary
and manifest independently. Invoke `MANIFEST --manifest-sha256 SHA
--self-sha256 SHA [--check-only]` in the qualified root read-only sandbox.
Check-only writes nothing. Actual success fsyncs a no-clobber private receipt
under the legacy receipt schema the native runner requires, explicitly denying
replay, publication and remote mutation. The runner retains its separate
300-second freshness gate and full-source checks. Keep any native attempt
non-restarting, bounded, guarded and private; qualification must precede launch.
