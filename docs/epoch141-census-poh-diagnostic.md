# Complete epoch141 private PoH diagnostic

`jetstreamer-epoch141-census-poh-diagnostic` consumes only the exact corrected
all-target native acquisition, after clean terminal success, native close and
complete retained-source revalidation. An absent final receipt, a provisional
target, a different/restarted invocation or incomplete raw coverage is rejected.
The immutable plan must bind the final acquisition digest independently.

The tool reuses the existing finalized metadata collector's full validation:
all 18,283 targets, original request/response bindings, fixed gap census and
parent/final blockhash anchors. It binds the reviewed typed snapshot clock,
native comparison and unchanged pinned runtime clock inheritance. Every acquired
target must occur in the exact order, with its exact path, SHA-256 and parent.

For each target it decodes the original metadata and shreds, checks the original
batch endpoints and final entry hash, and executes the existing complete PoH
chain verifier from the independently finalized parent hash. It does not change
the recorded connectivity bit, call the connected recovery route, create a
runtime boundary input, or promote any route. Complete success accounts for
84,597 hidden/final boundaries. Diagnostic chain failures are retained per target
and included in the complete failure census; input, native-owner and resource
failures are fatal, never normalized into chain success.

Output is no-clobber root-private JSON beneath a distinct OS-filesystem directory,
not replay scratch or the data filesystem. The exact output directory must be
empty before start. Its 256-MiB output bound and 100-GiB OS reserve are independent
of every live replay guard. Execution is bounded to six hours, 90 seconds per
target and 51.2 million hash steps per target. Deploy with a separately qualified
nonrestarting systemd sandbox, no network, read-only inputs and a hard memory/CPU
envelope. Qualification and fresh resource admission precede launch.

After processing, every raw target and output is rehashed, all finalized metadata
is revalidated, and the exact terminal native identity is rechecked before the
final manifest. Partial results remain provisional. Even complete diagnostic
chain success explicitly denies source completeness, historical liveness,
canonical ancestry, runtime boundary use, replay, publication and R2 mutation.
Those independent trust, root, plugin and delivery gates remain outstanding.
