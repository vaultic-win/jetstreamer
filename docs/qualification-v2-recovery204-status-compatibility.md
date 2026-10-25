# Qualification v2 status compatibility with recovery epoch 204

This isolated source successor starts at qualified combined source 962514fe.
No Cargo, build, target/cache access, source staging, runtime or R2 action was
performed. Tests below are prepared and unrun.

The existing 225–226 status model is v2 with omitted original 204/205 terminal
proofs. The combined helper lacked that implementation. The actual qualified
origin is commit 972a35a40b7d6aa0a0835a3cb645bd37788e266b (tree
a55733629eb5bd6dbb03018d6d67b9d2cddf5692), sealed helper SHA
617b5a30e7a50663c680f809bfbbff06a3d08349e9facbed6368d086ca604110.
Its preserved qualification.json SHA is
bca509d554443cee1e72c8fc24585ff122fabb66ee66e4720019584ba92a7518;
root-review SHA ad9280f7b2b9570588c06aab221c237efb87b7d86306f4869086ab1459e1a5e1;
deployment seal SHA a51601589567338b8610e90365b10d082ff49edb56afbc032df4975440f3abeb.
Those are historical lineage, not qualification of this merged successor.

The source restores that exact terminal-subset/live-original-205 implementation,
its source tests and immutable launch/journal fixtures. The top-level schema/run
integration is additive: current epoch 141 runtime/deadline/delivery policy and
all four profiles remain; v1 still requires all original epochs, and v2 selects
only the exact remainder proven by omitted/delegated original evidence. Missing
proofs, unknown epochs and nonpositive allowances still fail. Saved same-sample
v2 statuses cannot reintroduce originals or change phase. Existing live 205
verification matching/cleanup/delegation behavior is retained from qualified v2.
The original v2 test fixture iterates only the assigned 201–300 profiles, leaving
current epoch 141 tests and behavior separate.

An active recovery 204 row cannot be silently omitted or relabeled as a capped
continuation. Its v2 successor uses the existing exact fields unit, invocation_id,
phase and launch, with phase assembly-recovery204 and launch bound to the actual
actor launch. The old original-prefix launch/result/terminal-properties/journal
proofs remain independently required and unchanged. This does not recast the
failed capped assembler as successful.

A narrow shared fleet wrapper authenticates that successor through the already
qualified recovery Claim/peer path. It reconstructs the accepted row from the
complete accepted plan/claim, original recovery plan/admission/launch, actor
launch, genuine same-observer frame, policy, original failed source evidence and
all existing scope/custody checks. It checks current owner and original assembly
guard identities, closed stage ownership and frame freshness. It must equal the
raw accepted row. The qualification module passes complete saved and live before/
after censuses to this validator; it receives no normalized fleet or resource
credit. The raw active roster, original terminal history, unrelated owners,
guards, epoch clocks and ETA allowances stay intact.

The successor list must still describe every active replacement exactly once.
A missing/duplicate/foreign row, phase downgrade, substituted actor launch,
restarted owner/guard, late/stale frame or unbound accepted claim fails. The new
branch is epoch 204 only and uses the existing closed recovery stage namespaces;
it creates no generic successor type or new execution authority. The guard is
never removed from complete census equality.

Prepared regressions cover exact pure shape with mandatory real authentication,
unchanged raw fleet/original proof, missing proof/successor, foreign epoch, phase,
actor launch, duplicated replacement, original failure erasure, and guard census
omission/replacement. Existing qualified v2 terminal/race/205-delegation tests,
current epoch 141 tests, recovery Claim/frame/custody tests and complete package
suites remain required in bounded QA. Pure fixture acceptance does not prove
actual operator metadata or permit publication.

There are no dependency, manifest, build-script or compiler-option changes.
Production rebuild/capture/seal and actual status publication require new exact
artifact/qualification pins after QA. No epoch, archive, canonical sidecar,
retirement, replay or resource-release authority is granted.
