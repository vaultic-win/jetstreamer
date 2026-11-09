# Pinned allocation census source candidate

Actual0500actor722adc397ae24bb4b96d452783599f57 failed05:23:23 when Driver12's
eight complete-path retries each lost an accounts filename. The bound closedlog
records the exact unpacked/accounts path. Root already corrected/readback status
05:24:51; no new status/cadence/resource observation performed here.

Smallest scoped fix: ONLYresource_census.rs, preserving callerAPI and every resource
policy/admission/runtime clock. Driver12 currently queues all childPATHS from a
directory then stats them later. This creates a long discovery-to-stat window
under snapshot accounts churn; one vanished name restarts the entiretree.

Candidate pins each discovered inode immediately with openat(O_PATH|O_NOFOLLOW),
measures/charges its held st_blocks and processes it before reading the nextname.
Directory traversal uses checked pinned directoryFDs and a NEWopenat(".")/
fdopendir stream per pass. Dup would share EOF offsets and wrongly skip retries;
the candidate explicitly avoids that. Onlydepth-bounded FDs are held, no whole
tree/path queue. All FD/stream cleanup is RAII; no runtime filesystem mutation.

A regularfile unlinked AFTERpin remains physically referenced and its measured
blocks are charged from heldmetadata; absence never implies zero. A missing BEFOREpin entry still invalidates the
wholepass and consumes the existing8retry limit. A replaced filename requires
anewcompletepass; directory/root replacement or symlink/device/type/permission/
overflow/ceiling errors failclosed. Parent/rootidentity is rechecked; a detached
directory is never accepted as the admitted namespace. Whole-pass maximum_seen
is retained across retries; observed file/directory growth and replacementinode
blocks are charged immediately, so an observedceiling violation is never
forgotten even if a subsequent namespace retry would be possible. All30s/4Mentry/depth64 limits stay, with an additional
final deadline check. No accepted partialpass, guessedbytecredit or usagezero.

Seven ordinary regressioncontrols plus one ignoredRoot/Sol real openat/fdopendir/
other-thread unlink control are added. They cover all32/64discovered files being
unlinked AFTERpin in a singlecompletepass with fullblockcharge; old missing-before-
pin retry exhaustion; unlinkedlargeinode ceilingtrip; replacement forcingnewpass;
root/symlink change rejection; and fresh directoryoffsets finding a newlargefile
afterretry. Existingordinary/native/PID/VMAcases remain unchanged and must rerun.
Controls are source only and UNRUN. No new compiledimage/seal/pass is claimed.

Residual limitation: arbitrary sustained unlink BEFOREopen can still exhaust the
same8retries. This patch targets the observed delayed-pathlookup window; it does
not claim guaranteed atomic snapshots or a liveaccounts pass without qualification.
If realchurn still exceeds this safe bound, qualified owned-child quiescence
with proven ownership/guaranteedresume is a separate nextgate, not a reason to
increase retries/deadline, ignoremissing entries, acceptpartialusage or stop
unrelatedworkers. No signals/quiescence path is introduced by this candidate.

Full source and exactpatch PINNED_ALLOCATION_CENSUS.patch are here. Allfour full
UNSTARTEDcompilerrecipes derive acceptedDriver12R3graph with identical externs,
using a fresh disjointQA namespace. Root must book/qualify/seal and integrate
actual newDriver/Helper/Final/Operation/Frame pins; no hash guessed or gatewaived.
ActualRoot ANDSol nativecontrols must prove syscall access under intendedsandbox,
correct accounting under realchurn, boundedFDs/time and every hardnegative.

ChangedRust module passed a syntax-only rustfmt parse (stdout discarded; no
source mutation). No typecheck, Clippy or tests were run.
No builds, tests, bookings, deploys or launches; no existingQA/sealedsource/Git
or cloud mutation. All sourceoutside one census module is byte-identical to the
qualifiedDriver12graph. Root remains soleoperator and owns status/cadence.
