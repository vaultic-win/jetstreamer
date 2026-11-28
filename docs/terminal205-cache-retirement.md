# Exact terminal-205 duplicate input retirement

`jetstreamer-terminal205-cache-retire` can unlink only the original compressed
snapshot at slot 88,991,050 in `attempt-0743-v1`. It cannot select the different
88,559,361 bootstrap used by the bounded epoch-205 resource experiment, another
epoch, a directory, an archive, a receipt, or an R2 object.

The verified immutable input bundle at `horizon-terminal205-input-e94ae66-v1`
remains. The fixed native-205 preparation independently binds that deployed
snapshot path, SHA-256, length, checkpoint and remaining 949-slot suffix. This is
an input-path preservation check, not native-restore qualification. The tool
does not run the dormant comparator and does not interpret preparation's false
execution or retirement flags as authority. Its separate local duplicate-cache
lifecycle policy is the only mutation it implements.

The tool requires the exact acquisition receipt (including original invocation,
generation, hashes and cache identity), the bundle seal and entire three-member
payload census, full independent hashes of both snapshots, root ownership,
immutable modes, single links and distinct inodes. The acquisition service is
now collected: the manager must report `not-found/inactive/dead` with no process,
invocation, triggers or commands. That default manager state is explicitly not
proof of past successful acquisition; the independently hash-bound native
acquisition receipt supplies that evidence. Any replacement service fails the
gate. Exact process and staged-unit scans must find no cache references.

Seal the binary with the native deployment sealer. Precreate its fixed root-only
receipt directory, then run `BIN SELF_SHA --check-only` in a persistent bounded
unit. Inspect and hash the successful `check.json`; execution requires
`BIN SELF_SHA --retire CHECK_SHA`. It repeats the proof and uses the same tested
no-clobber receipts, file lock, identity checks, exact-file unlink and directory
fsync primitives as the separate epoch-227 cache lifecycle. An intent-only
interruption is resumable under the identical binary/check binding. Changed or
foreign evidence fails closed. The already-deployed epoch-227 binary is unchanged.

The original acquisition receipt remains historical evidence even after its
cache path is retired; the completion receipt records absence and the preserved
copy. Physical removed bytes and filesystem free space are distinct observations
because healthy replay continues allocating. Neither this cleanup nor spare disk
authorizes native restore, a new replay lane, suffix assembly, canonical sidecars
or publication. All fresh resource and independent verification gates remain.
