# Final6 fixed event deadline source candidate

Prepared ONLY from the actual Driver12-integrated Final5 QA source/graph. No old
QA or sealed artifact changed. No build/test/booking/status/cloud/resourcepoll/
Git/actor/guard/observer action. Root owns qualification and production admission.

Confirmed code defect: Watch::events() floors remaining Instant duration via
as_millis(), then treats poll()==0 as a terminal "timeout/error". A149.5ms wait
can therefore return an error before the original150ms deadline. Actual native8
discarded its returned error and then failed Instant::now()>=deadline; its0.15s
result is consistent with this bug. That historical receipt does NOT record the
error value/syscall, so poll0 cannot be uniquely proven as its observed cause.
Receipt/descriptor/custody failures must not be silently called timeouts.

Patch: round positive poll waits UP to integral milliseconds, retain i32timeout
cap, and on poll0 loop back to the SAME original Instant. EINTR retains that same
deadline. Real poll failures retain their OSerror and are labelled separately.
Recheck original deadline after readiness/read/parse and before guardacceptance,
so rounding/scheduler latency cannot authorize a late receipt. No clock renewed.
CLOSE_WRITE predicate/masks/parser/invalidation, shared256event cap, 22second
postrelease cap, original600/30/15 clocks, Driver12policy/lifecyclecustody/release
logic and every other module remain byte-identical to actual Final5.

Focused regression keeps the SAME150ms deadline and elapsed>=deadline assertion,
and strengthens it to require exact original-deadline-expired error cause. It
will report a genuine receipt/poll/descriptor/custody error instead of masking it.
One ordinary boundary control covers positive submillisecond/149.500001ms ceil,
zero rejection and i32cap; one ignored native control verifies a queued valid
Mainreceipt cannot revive an expired originaldeadline. Existing controls retained.

Exact patch: FINAL6_FIXED_DEADLINE.patch (two files). Fullsource under source/;
byte-exact predecessors under predecessor-final5/. All four full UNSTARTEDrecipes
derive actual Driver12 Final5 graph; compiler/extern arguments unchanged apart
from disjoint QA/unit namespaces. No newimage/hash/pass/booking/seal invented.

Root qualification required: four strict compilers; actual newcensus(expected
38ordinary/10ignored); allordinary and all10native controls using NEWnormally
sealedtestimage, including oldnative8 and newexpiredqueued test. Preserve old
fourcompiler/37ordinary/native0–7 successes AND native8failure as historical
evidence, not qualification for changedbytes. Use real deploymentsealer and exact
newartifact hashes, then integrate actual successor consumers. Both changedRust files passed a syntax-only rustfmt parse (stdout discarded;
no source mutation). No compiler/typecheck/Clippy/tests run here.
The unchanged22s-vs30speriodicguard fit limitation remains separate; no budget
extension/extra guardfire or healthyactorrestart is authorized by this patch.
