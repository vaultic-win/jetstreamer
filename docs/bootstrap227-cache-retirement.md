# Exact epoch-227 duplicate snapshot retirement

`jetstreamer-bootstrap227-cache-retire` is a fixed-case local lifecycle tool.
It can unlink only the original 10,261,480,487-byte compressed bootstrap in the
`attempt-045716-v1` cache. It cannot select another epoch, directory, snapshot,
archive or receipt, launch replay, change a service, or access R2.

The immutable deployment at `horizon-stage227-bootstrap-dcaafc6-v1` is preserved.
Both snapshot copies are independently rehashed. The tool requires the exact
generation-bound acquisition and file identity, an independently sealed
exact-package CLI/schema capability receipt, the deployment seal and complete
member set, immutable root ownership, and distinct singly linked snapshot
inodes. The original acquisition receipt is preserved, including its historical
cache identity; it is not rewritten to claim that the retired path still exists.

The exact acquisition service must still be authenticated as its original
zero-restart `active/exited` `RemainAfterExit=yes` owner, with successful exit and
no main process. A complete fail-closed process command/map/cwd/root/exe/fd scan
and staged-unit scan must find no references to the exact cache file. These are
lifecycle safety checks, not another replay/resource observation loop.

Seal the binary with the native deployment sealer, precreate the exact root-only
receipt directory, then run the sealed binary with its independent self SHA and
`--check-only` in a bounded persistent unit. Inspect the successful no-clobber
`check.json` before executing with `--retire CHECK_SHA256`. Execution repeats the
entire proof, serializes through a nonblocking file lock, fsyncs a no-clobber
intent before unlinking that one file, fsyncs its parent, and durably records
completion only after absence and preserved-copy identity checks. A valid
intent-only interruption can resume under the same binary/check binding;
foreign intents, changed identities and completed attempts fail closed.

The receipt records physical cache bytes and free space separately: concurrent
replay allocation means the free-space delta need not equal the removed size.
Retirement does not prove epoch-227 resource admission, native restore, replay,
canonical root, plugin checks or publication, and does not authorize epoch 205.
Fresh coordinated admission remains necessary before any new replay lane.
