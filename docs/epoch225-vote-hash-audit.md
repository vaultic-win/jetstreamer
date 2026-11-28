# Epoch 225 vote-hash bracket

`jetstreamer-epoch225-vote-audit` is an offline, non-authorizing evidence checker for
the exact traced invocation `14cf7df9e73b4e459aea0ee2ad896ce2`. It does not run a
replay, select a runtime, repair a Bank, create a sidecar, or access R2.

The trace captures Bank/SlotHashes at slot 97,199,878. The parent at 97,199,877
has reconstructed hash `G6BFd1oz8QNkVMdPsrqkJBEF8UBpeGsbfWEEdP4ysJiJ`, but the
canonical successful vote expects
`3uMcx4shPW8rToYyXRQgiD9DSzx5qDCv2uFw9NanuWPK`.

The checker binds a complete JSONL journal export, a finalized `getBlock` request
for slot 97,199,878, and its full `jsonParsed` response. Export journals with
`journalctl --all -n all -o json`: without `--all`, systemd replaces the large
SlotHashes `MESSAGE` with JSON null even though its text output displays it.
The checker rejects null messages, foreign identities, truncated/duplicate trace
entries, missing transaction statuses, request/response mismatch, an earlier
disagreeing successful vote, a missing immediate-predecessor vote, and a mismatch
at any other observed vote tip. It requires the exact failing signature at
transaction index 189 and a unique 512-member captured SlotHashes sequence.

All prior successful votes must agree with captured hashes. A matching vote for
97,199,876 plus the disagreement at 97,199,877 establishes a local divergence
bracket, not a proof of every earlier Bank or the underlying account/freeze cause.
Do not attribute this failure to the earlier skipped-slot gap merely from its
presence. The next source investigation is the execution and freeze of
97,199,877. Do not repeat the unchanged canary or force either Bank hash.

An optional, jointly bound `parent_request` / `parent_response` pair accepts the
finalized raw-JSON block at 97,199,877. The checker audits wire-header writability,
instruction program/account indexes, canonical status and balances, and requires
the one observed candidate: transaction 224, signature
`4tURm7ubHwvAth4yE8T87NRXh84akr9AhbDYWckdMsgoQVn4TQiBkkLvjBfcM78PVWzn7R4cboadPBgBduENRY7d`,
marks SPL Token at key 6 writable while invoking and passing it; its canonical
lamports remain 1,089,991,680. Upstream v1.6.25's `Message::is_writable` demotes
called program keys, whereas v1.6.20's implementation does not. This is a concrete
source-shape lead, not proof that it causes the actual Bank hash divergence.
Keep `underlying_cause_proven: false` until differential execution/checkpoint
evidence establishes it. Neither optional input grants runtime promotion.

## Invocation

```text
jetstreamer-epoch225-vote-audit PLAN --plan-sha256 HEX --self-sha256 HEX
```

The root-owned, immutable plan has schema
`jetstreamer-private-epoch225-vote-audit-plan-v1`, `journal`, `request`, and
`response` objects with exact absolute `path` and `sha256` fields, and one
absolute `output` path below a root-owned mode-0700 directory. Inputs must be
root-owned, non-writable, singly linked regular files, at most 32 MiB each.
The checker revalidates open-file and path identities, hashes every input, and
checks its own running executable digest. Seal the binary and inputs with the
normal reviewed Rust deployment sealer after tests and source publication.

The no-clobber, fsynced receipt binds all inputs, the plan and executable,
canonical predecessor vote evidence, and the divergence bracket. Every replay,
promotion, publication, and R2 authority field remains false. Source corrections
still need regressions, immutable qualification, canonical checkpoint and current
plugin verification, fresh resource admission, and normal publication gates.
