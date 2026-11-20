# Epoch 265 startup and retained timer deadlines

The first full replay attempt reached its genuine first protective guard, but
failed the final current-fleet census before the restore token was sealed.
The retained epoch 250 and 251 guards rolled over during that census. Their
receipts were only 28 seconds old: manually starting a guard had not established
a new 60-second timer window. The exact invocation check correctly rejected the
changed guards. The candidate was stopped before its node or worker started;
its original state and empty token directory remain preserved.

The next candidate uses separate v2 producer, guard, token, state and output
namespaces. After the complete launch preflight, its launcher reads the actual
typed PID1 monotonic deadline for each retained timer, with unchanged guard and
timer snapshots before and after the reads. It requires at least 30 seconds
until the earliest next firing. An insufficient window rejects before producer
activation. The startup deadline is also capped five seconds before that firing,
in addition to the original admission lease and 50-second setup limit.

Prepare the inactive candidate separately. For launch, bind a genuinely
completed natural guard firing and its actual remaining timer window, capture
fresh admission, and invoke launch consecutively. Do not assume that manually
starting a guard resets its pending timer deadline. Do not insert a second
preflight or preparation between capture and launch. The launcher still runs
its own full preflight, genuine first candidate guard, final complete census
and immutable token checks.

The v2 source is not runtime qualification. Its changed templates require their
own capability and prestart controls, corresponding consumer bindings, published
source and fresh complete admission. Retain the failed v1 attempt in the fleet
history and prove its stopped, token-free, unused state before accepting any
release of its obligations. A concurrently running delivery service must remain
in the fleet and reservation ledger throughout replacement admission.

The current admission validates the exact live epoch 247 uploader independently
from replay and producer finalization. It retains its 7 GB memory ceiling,
185,370,916,960 bytes of readback and temporary growth, and 3 TB free-space floor.
The fleet's JSON owner evidence binds the original native manager capture;
the mapped uploader image, command and invocation must still match.

Transferring the failed v1 candidate reservation requires an explicit cancellation
decision and a fresh native check. The original failed invocation must have no
main-process execution history, an empty token directory, no successful startup
handoff, inactive controls and drained kernel and process groups. Admission saves
that evidence and preserves v1's inherited free-space floor while charging the
full v2 candidate envelope. It cannot silently remove an existing retained
reservation or treat the failed attempt as a completed replay. The root-only
ignored custody test exercises these actual retained inputs without starting work.
