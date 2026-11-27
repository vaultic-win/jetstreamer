# Epoch 168 private assembly sources

The epoch is slots 72,576,000 through 73,007,999 inclusive. Use the independently selected retry4 archive view through 72,994,766 and the retry6 archive view starting at 72,994,767. These views cover 418,767 and 13,233 slots. The joint archive corroborates both sides of the seam and the 73,007,829 ordinary root. Its range is evidence and contributes no output slots.

The interrupted retry4 file is 119,320,128,606 bytes with SHA-256 `cdde7f4da26d0d608f9546883aba787c903e093fc800bd570288e803c0aefc3d`. The sealed selector supplies the independent selected byte digest, semantic digest and raw cursor. The complete retry6 source is 5,777,373,749 bytes with SHA-256 `4a3356c72e2216a8f0a76d0f4ce3d9272d98dadf66deba46e40fa8396e170cea`. Its source manifest reaches 73,015,141. The secondary view clips it at the actual epoch end. Both readers use 128-slot buckets and runtime revision `01e4d0a1` with worker SHA-256 `b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541`.

## Next evidence step

After the independently decoded retry4 selection and native joint comparator receipts are bound by `horizon-168-joint-lineage`, pass the resulting root-owned lineage binding and its digest to the sealed source-view tool.

```sh
horizon-168-source-views --check-assembly-sources LINEAGE_BINDING_JSON LINEAGE_SHA256
```

The check confirms root-owned evidence, source identities, both indexed ranges, the retry6 restart snapshot SHA-256, the seam Bank state, and the initial retry6 PoH anchor. It reads headers and indexes and decodes zero archive payloads. The standalone `--inspect-assembly-layout` checks the live source headers and indexes before the lineage binding exists.

After the source check, a separately admitted read-only qualification can run the following command under the approved CPU and RAM limits. Run the sealed source-view tool in `horizon-qualify-168-assembly-sources-20261127-v1.service`. Bind its stdout and the exact clean PID1 terminal event to the same lineage in the root-owned `horizon-epoch168-assembly-source-native-acceptance-v1` receipt. Record `unit`, `invocation_id`, `source_tool_sha256`, `source_tool_deployment`, `qualified_report`, `lineage`, `pid1_terminal_event`, `archive_bytes_written` (zero), and `publication_authorized` (false). It hashes the complete retry6 archive, uses the existing in-memory boundary selection to clip it, compares both regenerated boundaries to the original events, decodes the selected suffix and derives its exact terminal blockhash, raw cursor, and V4 provenance bytes. The accepted retry4 selection already supplies the equivalent independent prefix proof.

```sh
horizon-168-source-views --qualify-assembly-sources LINEAGE_BINDING_JSON LINEAGE_SHA256
```

The source qualification needs zero physical archive bytes. The retry6 clip reads the 5.78 GB closed source and produces only memory-backed boundary frames and an index. A fresh fit should price one decoder, bounded memory and its small stdout and evidence files, and account for any comparator or selector still running.

## Private assembly and later acceptance

Use the ordinary `merge_checkpoint_restart_segments` V4 entry with `RuntimeSegmentSource::new` for each seekable selected view. Retry4's interrupted physical container cannot satisfy a complete-source check on its own. The existing `PrefixView` supplies its index, and `selected_prefix::cut` builds the complete selected reader for each source. Pass the accepted selected byte digests and terminal blockhashes. The merger rehashes each exact reader, checks PoH across the epoch, and rebases both raw ranges into one contiguous archive write-version space. Keep the independently observed legacy checkpoint fields and both distinct raw cursors at the handoff. The exact retry6 restart snapshot is SHA-256 `9b1b06509adcb48f96d5186fc946401b1c3e8c6fdda3d8366a356623ae5ec5f4`, bound by its sealed launch payload.

Use the root-owned, empty, mode-0700 output directory at `/home/sol/.jetstreamer-private/epoch168-private-assembly-20261127-v1/output`. Its separate HOME leaf keeps output outside the existing joint replay tree and its narrower cap. Admit 128 GiB (137,438,953,472 bytes) for one output plus 64 MiB for logs and receipts. Keep the source files and every other live and holding commitment charged. The selected readers require no archive-sized scratch.

The root-owned plan uses schema `horizon-epoch168-private-assembly-plan-v1`. Bind the exact `lineage`, `qualification`, `qualification_native`, and `admission` by path and SHA-256. Set `unit` to `horizon-assemble-168-private-20261127-v1.service`, `output_directory` to the absolute output path, `maximum_archive_bytes` to 137438953472, `evidence_allowance_bytes` to 67108864, and `publication_authorized` to false. Bind `minimum_home_free_bytes`, `memory_max_bytes`, `cpu_quota_micros`, and `admission_expires_unix_seconds` to the fresh admission.

The admission uses schema `horizon-epoch168-private-v4-assembly-admission-v1`. Retain the plan's unit, output, qualification, cap, limits and expiration. Bind `capacity_basis` to the fresh complete-fleet resource quote. Set `epoch` to 168, `swap_bytes` and `resource_credit_bytes` to zero. Record `booked_assembly_home_bytes`, `available_home_bytes`, and `required_available_home_bytes` against the exact peak and existing guard floors. Record `required_available_memory_bytes`, `available_memory_bytes`, and `complete_cpu_quota_micros` after including assembly. Set `fits` and `all_existing_commitments_retained` only after both the separate output booking and the absolute free-space equation pass.

```sh
horizon-168-source-views --check-private-assembly-plan PLAN_JSON PLAN_SHA256
horizon-168-source-views --assemble-private PLAN_JSON PLAN_SHA256
```

Run assembly in the exact non-restarting, network-isolated systemd unit, with the admitted CPU and memory limits, zero swap, and all input paths read-only. Make only the output leaf writable. The assembler verifies its native cgroup limits and records the invocation ID. Its sink checks physical HOME availability and the output cap before each write. A successful exit leaves the private archive and its receipt under no-clobber names.

An assembled output needs independent full-archive validation, exact epoch edges and V4 provenance checks, and current `account-updates` plugin playback before the ordinary publication workflow. The source qualification retains the original candidate runtime admission and carries no assembly or publication authority.
