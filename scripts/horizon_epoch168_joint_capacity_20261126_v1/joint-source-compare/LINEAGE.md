# Private epoch 168 seam lineage

Run `horizon-168-joint-lineage PLAN PLAN_SHA256` once the joint run has a clean terminal receipt, both ordered-event comparisons have completed, and the retry4 selection has been independently decoded. The command reads bounded evidence files and emits one JSON binding to stdout. The underlying archives are read by the separately qualified decoder and selection verifier.

The plan schema is `horizon-epoch168-private-joint-lineage-plan-v1`. Include four members, each an object containing `path` and `sha256` with a canonical absolute pathname and the SHA-256 of that file's bytes.

- `joint_terminal` points to the established joint state directory's `TERMINAL.json`.
- `joint_manifest` points to the joint output's `epoch-168-joint-checkpoints.jet.segment.json`.
- `selected_prefix` points to the independent retry4 selection evidence.
- `comparison` points to the native comparator capture described below.

The plan and captured evidence are root-owned. The joint and pinned retry6 manifests are owned by the producer account (UID 1001). The files must be single-link regular files and exclude group or other write permission.

## Native comparator capture

The capture's schema is `horizon-epoch168-private-joint-comparison-native-v1`. Capture these members from the successful direct execution of the sealed comparator under a dedicated systemd service invocation.

| Member | Value |
| --- | --- |
| `unit` | Service name with the `.service` suffix |
| `invocation_id` | The service's systemd invocation ID |
| `uid` | Comparator process UID as a journal-format string (`"0"` or `"1001"`) |
| `argv` | The exact sealed comparator path, `--compare-joint`, and the closed joint archive SHA-256 |
| `executable_sha256` | The SHA-256 recorded for `horizon-168-joint-compare` in the pinned deployment seal |
| `sources` | Path and SHA-256 references named `retry4`, `retry6`, and `joint` for the three archives, as pinned by the checker |
| `joint_manifest` | Same path and digest reference as the plan's joint manifest |
| `stdout` | Three original journal JSON records in order for `predecessor_overlap`, `successor_overlap`, and `comparison_complete` |
| `pid1_event` | Original journal JSON record for PID 1's successful completion of the same unit and invocation |

Preserve the original journal fields, including `MESSAGE`, `_TRANSPORT`, `_SYSTEMD_INVOCATION_ID`, `_SYSTEMD_UNIT`, `_PID`, `_UID`, `_EXE`, `_BOOT_ID`, and `__REALTIME_TIMESTAMP` for stdout. The checker derives the decoder report by taking each `MESSAGE` and appending a newline. It hashes those bytes in the resulting binding.

## Retry4 selection evidence

The admitted selector runs `horizon-168-retry4-select --select-retry4-prefix` on the pinned, closed retry4 source. The selection uses a seekable view of the compressed whole buckets, with a rewritten first bucket, a partial final bucket, and a rebuilt header and index. It hashes the full retained source and the exact selected bytes, compares both rewritten boundaries against independently decoded source events, and decodes the entire selected archive. The command prints one JSON evidence record and writes zero physical archive bytes.

Use `epoch168_lineage_handoff.py verify LAUNCH CAPTURE RESULT.stdout OUTPUT_DIR` with the selector's original root-owned stdout. The helper checks the admitted invocation's successful PID 1 journal event and authenticates the corrected lineage executable from the same sealed deployment as the selector. The plan binds both proofs to the comparison and selection.

The selection evidence schema is `horizon-epoch168-private-selected-prefix-evidence-v1`. Record `source_archive_sha256`, `selected_archive_sha256`, `selected_semantic_sha256`, `first_slot`, `last_slot`, `terminal_blockhash`, `raw_start`, `raw_end_exclusive`, and `independently_decoded` from the verified selection ending at slot 72,994,766. The raw range comes from the selected output's account events. The comparator's predecessor range must end at the same exclusive raw cursor in the retained source.

The resulting `translated_v4_predecessor` keeps the eight matched consensus fields from the joint checkpoint at slot 72,994,766, adds the legacy accounts-hash kind, and uses the verified retry4 selection's exclusive write cursor. The resulting receipt includes the independent joint and retry6 checkpoint records with their original raw cursors and write counts.
