# The root controller writes these artifacts after its locked, read-only admission.
# SHA256SUMS is checked by coreutils in the unit before this schema is evaluated.
def sha: type == "string" and test("^[a-f0-9]{64}$");
def commit: type == "string" and test("^[a-f0-9]{40}$");
def reference: (.path | type == "string") and (.sha256 | sha);
def one(array): if (array | length) == 1 then array[0] else error("invalid evidence count") end;
def digest_map:
  (split("\n") | map(select(length > 0) | capture("^(?<digest>[a-f0-9]{64})  (?<path>[^\\r\\n]+)$"))) as $lines
  | if ($lines | length) == ($lines | unique_by(.path) | length)
    then $lines | map({key:.path,value:.digest}) | from_entries
    else error("duplicate receipt bindings")
    end;
($instance | tonumber) as $epoch
| one($scope) as $request
| one($ready) as $recheck
| one($owner) as $closure
| one($quote) as $fit
| one($reader) as $current
| one($before) as $prior
| one($admit) as $admission
| ($ticket | digest_map) as $digests
| $request.argv[0] as $elf
| ($elf | sub("/horizon_pipeline$"; "")) as $image
| [
    $elf, ($image + "/main-acceptance.json"), ($image + "/public-range-qualification.json"),
    "/proc/sys/kernel/random/boot_id", "request.json", "inventory.json", "ownership.json",
    "job/current/ADMISSION.json", "job/current/AUTHENTICATED_RECHECK.json",
    "job/current/PREDECESSOR.json", "job/current/FIT.json", "job/current/CURRENT_READER.json"
  ] as $required
| ($digests | keys) == ($required | sort)
  and $epoch >= 149 and $epoch <= 156
  and $epoch == $request.epoch
  and $request.predecessor == $epoch - 1
  and $request.argv[1] == "\($epoch):\($epoch)"
  and $recheck.schema == "horizon-ready-strict-audit-scope-v1"
  and $recheck.scope == [$epoch,$epoch] and $recheck.eligible_ranges == [[$epoch,$epoch]]
  and $recheck.objects == [$request.readiness] and $request.readiness.ready == true
  and $recheck.inventory_sha256 == $digests["inventory.json"]
  and $closure.withdrawal_message == "d22771c4-4516-89d4-b3db-605c089cee9a"
  and ($closure.epochs_released | index($epoch) != null) and ($closure.evidence | reference)
  and $fit.epoch == $epoch and ($fit.fleet | reference)
  and $fit.cgroup == "horizonaudit.slice" and $fit.cpu_quota_percent == 100
  and $fit.memory_max_bytes == 2147483648 and $fit.memory_swap_max_bytes == 0
  and $fit.tasks_max == 32 and $fit.additional_archive_bytes == 0
  and $fit.fits == true and $fit.campaign_lock == "/run/horizon-epoch171-to136-g1.operation.lock"
  and ($current.branch_commit | commit) and $current.binary.path == $elf
  and $current.binary.sha256 == $digests[$elf]
  and $current.main_acceptance_sha256 == $digests[$image + "/main-acceptance.json"]
  and $current.range_qualification_sha256 == $digests[$image + "/public-range-qualification.json"]
  and $current.partitions == 256 and $current.max_active_partitions == 1
  and $current.minimum_thread_stack_bytes == 67108864
  and ($current.compiled_input_equivalence | reference)
  and (
    if $epoch == 149 then
      $digests["job/current/PREDECESSOR.json"] == "f91e7a158ce64ab2f0d6be6c8f29499d086660a07831d1775299c5eebe0336f7"
    else
      ($prior.schema == "horizon-ready-range-verified-v1" and $prior.range == [($epoch-1),($epoch-1)]
       and $prior.exit.success == true and ($prior.epochs | length) == 1 and $prior.epochs[0].epoch == $epoch-1)
      or ($prior.epoch == $epoch-1 and $prior.authenticated_readiness_rechecked == true
          and $prior.pinned_archive_identity_rechecked == true and ($prior.full_plugin_report | reference))
    end
  )
  and $admission.schema == "horizon-anza-ready-audit-admission-v1" and $admission.epoch == $epoch
  and ($admission.issued_unix_seconds | type == "number") and ($admission.valid_until_unix_seconds | type == "number")
  and $admission.issued_unix_seconds <= now and now < $admission.valid_until_unix_seconds
  and $admission.fit_sha256 == $digests["job/current/FIT.json"]
  and $admission.readiness_sha256 == $digests["job/current/AUTHENTICATED_RECHECK.json"]
