// Exact successful warmup is a prerequisite, never canonical-prefix evidence.
const WARMUP_PROOF: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/proof.json";
const WARMUP_SHA: &str = "6790592b9188e7c4a3d32171a326b743f84fc6c5b5ad07f94182c104876b7028";
const NATIVE_PROOF: &str =
    "/var/lib/jetstreamer/horizon-native223-input-proof-release-v1/input-proof.json";
const NATIVE_SHA: &str = "a76a8e809e1c4fd102461620a45bf09021dd00a660b6a68834b0ec9086e7711a";
const PREFIX_FLOOR: u64 = 2_000_000_000_000;
const PREFIX_WHOLE_ROOT: u64 = 471_798_691_840;
const PREFIX_MEMORY_MAX: u64 = 225_000_000_000;
const PREFIX_MEMORY_HIGH: u64 = 150_000_000_000;
const PREFIX_MEMORY_RESERVE: u64 = 480u64 << 30;
fn prefix_warmup_valid(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-warmup223-native20-terminal-v2"
            && v["epoch"] == 223
            && v["invocation_id"] == "58ab3d9221a6452685b8eab3ceabdb49"
            && v["unit"] == "horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service"
            && v["bounded_warmup_complete"] == true
            && v["terminal_outcome"] == "bounded-warmup-complete"
            && v["output"]["kind"] == "resource"
            && v["output"]["passed"] == true
            && v["output"]["preserved"]["sha256"]
                == "4040a077d90eca93e0208485a86131b1541564527acc4ab9de746292e32504d3"
            && v["terminal_manager"]["Result"] == "success"
            && v["terminal_manager"]["ExecMainStatus"] == "0"
            && v["terminal_manager"]["MainPID"] == "0"
            && v["terminal_manager"]["NRestarts"] == "0",
        "native20 full-prefix requires actual successful exact warmup"
    );
    for key in [
        "canonical_prefix_qualified",
        "native_restart_qualified",
        "suffix_qualified",
        "assembly_qualified",
        "full_epoch_qualified",
        "full_plugin_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "ordinary_replay_authorized",
        "replay_launch_authorized",
        "full_cold_epoch_peak_qualified",
        "remote_mutations",
        "r2_mutations",
        "repair_closed",
    ] {
        ensure!(v[key] == false, "warmup proof incorrectly grants {key}");
    }
    Ok(())
}
fn prefix_bound_json(path: &str, sha: &str) -> Result<Value> {
    bound_file(Path::new(path), sha, 1 << 20)?;
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() <= 1 << 20 && hex(&Sha256::digest(&bytes)) == sha,
        "prefix prerequisite changed while read"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn prefix_prerequisites() -> Result<()> {
    prefix_warmup_valid(&prefix_bound_json(WARMUP_PROOF, WARMUP_SHA)?)?;
    let native = prefix_bound_json(NATIVE_PROOF, NATIVE_SHA)?;
    ensure!(
        native["native_input_qualified"] == true
            && native["entry_replay"] == false
            && native["repair_closed"] == false,
        "native20 cold input remains unqualified"
    );
    Ok(())
}
fn prefix_available_memory(text: &str) -> Result<u64> {
    ensure!(text.len() <= 65536, "prefix meminfo bounds");
    let rows = text
        .lines()
        .filter_map(|s| s.strip_prefix("MemAvailable:"))
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "prefix MemAvailable missing/duplicate");
    let fields = rows[0].split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 2 && fields[1] == "kB",
        "prefix MemAvailable units"
    );
    fields[0]
        .parse::<u64>()?
        .checked_mul(1024)
        .context("prefix available-memory overflow")
}
fn prefix_resource_values(free: u64, available: u64, starting: bool) -> Result<()> {
    let disk = if starting { MINIMUM_FREE } else { PREFIX_FLOOR };
    let memory = PREFIX_MEMORY_RESERVE
        .checked_add(if starting { PREFIX_MEMORY_MAX } else { 0 })
        .context("prefix memory overflow")?;
    ensure!(
        free >= disk && available >= memory,
        "native20 prefix protected host resources no longer fit"
    );
    Ok(())
}
fn prefix_runtime_resources(p: &Plan) -> Result<()> {
    prefix_resource_values(
        free_bytes(&p.run_root)?,
        prefix_available_memory(&fs::read_to_string("/proc/meminfo")?)?,
        false,
    )
}
fn prefix_start_resources(p: &Plan) -> Result<()> {
    ensure!(
        MINIMUM_FREE == PREFIX_FLOOR + PREFIX_WHOLE_ROOT,
        "prefix floor/envelope mismatch"
    );
    prefix_resource_values(
        free_bytes(&p.run_root)?,
        prefix_available_memory(&fs::read_to_string("/proc/meminfo")?)?,
        true,
    )?;
    let group = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    ensure!(group.canonicalize()? == group, "prefix cgroup redirected");
    let page =
        u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).context("prefix page size")?;
    ensure!(
        page > 0 && page.is_power_of_two(),
        "prefix invalid page size"
    );
    for (name, requested) in [
        ("memory.max", PREFIX_MEMORY_MAX),
        ("memory.high", PREFIX_MEMORY_HIGH),
        ("memory.swap.max", 0),
    ] {
        ensure!(
            fs::read_to_string(group.join(name))?
                .trim()
                .parse::<u64>()?
                == requested / page * page,
            "prefix kernel memory cap differs:{name}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod prerequisite_tests {
    use super::*;
    fn proof() -> Value {
        let mut v = json!({"schema":"jetstreamer-private-warmup223-native20-terminal-v2","epoch":223,"invocation_id":"58ab3d9221a6452685b8eab3ceabdb49","unit":"horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service","bounded_warmup_complete":true,"terminal_outcome":"bounded-warmup-complete","output":{"kind":"resource","passed":true,"preserved":{"sha256":"4040a077d90eca93e0208485a86131b1541564527acc4ab9de746292e32504d3"}},"terminal_manager":{"Result":"success","ExecMainStatus":"0","MainPID":"0","NRestarts":"0"}});
        for key in [
            "canonical_prefix_qualified",
            "native_restart_qualified",
            "suffix_qualified",
            "assembly_qualified",
            "full_epoch_qualified",
            "full_plugin_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "runtime_promotion_authorized",
            "ordinary_replay_authorized",
            "replay_launch_authorized",
            "full_cold_epoch_peak_qualified",
            "remote_mutations",
            "r2_mutations",
            "repair_closed",
        ] {
            v[key] = json!(false);
        }
        v
    }
    #[test]
    fn full_prefix_cannot_reuse_failed_other_or_promoted_warmup() {
        let good = proof();
        prefix_warmup_valid(&good).unwrap();
        for (pointer, value) in [
            ("/bounded_warmup_complete", json!(false)),
            ("/invocation_id", json!("13a5f755a196442e991c6930b410c04f")),
            ("/terminal_manager/ExecMainStatus", json!("130")),
            ("/output/passed", json!(false)),
            ("/output/preserved/sha256", json!("0".repeat(64))),
            ("/canonical_prefix_qualified", json!(true)),
            ("/publication_authorized", json!(true)),
            ("/repair_closed", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(prefix_warmup_valid(&bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn full_prefix_resources_include_output_and_preserve_runtime_floor() {
        assert_eq!(MINIMUM_FREE, PREFIX_FLOOR + PREFIX_WHOLE_ROOT);
        let available = PREFIX_MEMORY_RESERVE + PREFIX_MEMORY_MAX;
        prefix_resource_values(MINIMUM_FREE, available, true).unwrap();
        assert!(prefix_resource_values(MINIMUM_FREE - 1, available, true).is_err());
        assert!(prefix_resource_values(MINIMUM_FREE, available - 1, true).is_err());
        prefix_resource_values(PREFIX_FLOOR, PREFIX_MEMORY_RESERVE, false).unwrap();
        assert!(prefix_resource_values(PREFIX_FLOOR - 1, PREFIX_MEMORY_RESERVE, false).is_err());
        assert!(prefix_resource_values(PREFIX_FLOOR, PREFIX_MEMORY_RESERVE - 1, false).is_err());
        assert_eq!(
            prefix_available_memory("MemAvailable: 42 kB\n").unwrap(),
            43008
        );
        for text in [
            "",
            "MemAvailable: 42 MB",
            "MemAvailable: 1 kB\nMemAvailable: 2 kB",
        ] {
            assert!(prefix_available_memory(text).is_err());
        }
    }
}
