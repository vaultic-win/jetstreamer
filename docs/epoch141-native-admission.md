# Private epoch-141 native admission

`jetstreamer-epoch141-native-admit` admits only explicitly pinned sealed
read-only native generations on dev-samjohnson. The original `f1592d…` is bound
only to `epoch141-read-only-full-census-v2`. The rejection-evidence generation
`573ce1…`, under `horizon-epoch141-native-rejection-candidate-20261022-v1`, is
bound only to `epoch141-read-only-full-census-rejection-v3`; path, digest and
profile cannot be mixed. This profile retains strict planner rejection evidence
only after native close and complete source revalidation; see
[metadata rejection evidence](epoch141-native-metadata-rejection.md).
The separately tested first-target acquisition candidate `0e7f84…` is bound only
to `epoch141-read-only-first-target-acquisition-v4` and its exact distinct
`horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service`.
It uses the same protected reserve and 144 GiB memory requirement, with a separate
1 GiB incremental disk allowance: native code caps intent/final output at 192 MiB,
has no source copy or replay scratch, and rotates two 4 MiB native logs. Its own
256 MiB initial-output guard remains independent. This allowance cannot be used
for either full-census profile, whose 32 GiB allowance is unchanged. The protected
4,740,696,923,590-byte amount is inherited protection, not the century floor.
No profile admits an arbitrary executable. Admission does not restore a snapshot,
open a database, install/start a service, launch replay, or access R2/network.
The existing full-census runner still independently validates all 18,283 RPC
targets, source/census bindings, complete retained member hashes, exact column
families and live SST references before its one bounded native read session.

The root-owned owner-only manifest keeps the existing
`jetstreamer-historical-performance-admission-v1` schema understood by that
runner, with one of the three exact `native_profile` values above.
It has no snapshot field and cannot be consumed as generic replay admission.
Required fields are the fixed `/home/sol` filesystem, `minimum_free_bytes` of at
least 4,740,696,923,590 plus the selected profile's bound above, at least 144 GiB available memory (128 GiB
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
Current filesystem free space and available memory must also pass the selected
limits. No source/hidden-PoH/root/publication qualification is granted.

The complete active-owner census includes authenticated pipeline `unit` rows
as well as replay `controller`/`producer` rows. These carry the same exact live
invocation, zero-restart and race checks; a private verifier is not omitted from
resource admission or relabeled replay to make the census pass.

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
