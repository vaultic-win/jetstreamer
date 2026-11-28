//! Bind checkpoint-bounded replays to the ordinary fleet reserves.
use super::*;

pub(super) struct Focused {
    pub epoch: u64,
    pub unit: &'static str,
    pub guard: &'static str,
    pub cpus: &'static str,
    pub scratch_cap: u64,
    pub receipt_disk: u64,
    pub producer_memory: u64,
    root: &'static str,
    first: u64,
    last: u64,
    kind: &'static str,
    preflight_schema: &'static str,
    state: &'static str,
    preflight_sha: &'static str,
    profile_sha: &'static str,
}

pub(super) const LOADER_296: Focused = Focused {
    epoch: 296,
    unit: "horizon-qualify-296-loader-upgrade-focused-v2.service",
    guard: "horizon-296-loader-upgrade-focused-protective-v2",
    cpus: "56-63",
    scratch_cap: 160 << 30,
    receipt_disk: 64 << 20,
    producer_memory: 173_207_977_984,
    root: "/home/ubuntu/.jetstreamer-private/qualification-296-loader-upgrade-focused-v2",
    first: 127_953_994,
    last: 127_961_108,
    kind: "epoch296-private-loader-upgrade-diagnostic",
    preflight_schema: "foundation-epoch296-focused-loader-preflight-v1",
    state: "/var/lib/jetstreamer/horizon296-loader-upgrade-focused-v2",
    preflight_sha: "d93ae64c1058439379dafd6e9ffe3c1622ffaa9c8bbf8f16c8d505704c54e260",
    profile_sha: "f6318333fc088dee3c6109cb6434eba0fddb916ed6ed143bfd7ffca27a59beba",
};

pub(super) const GAP_230: Focused = Focused {
    epoch: 230,
    unit: "horizon-qualify-230-short-gap-v1.service",
    guard: "horizon-230-short-gap-protective-v1",
    cpus: "72-79",
    scratch_cap: 208 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 225_000_000_000,
    root: "/home/ubuntu/.jetstreamer-private/qualification-230-short-gap-v1",
    first: 99_383_573,
    last: 99_430_284,
    kind: "epoch230-private-short-gap",
    preflight_schema: "foundation-epoch230-focused-short-gap-preflight-v1",
    state: "/var/lib/jetstreamer/horizon230-short-gap-runtime-v1",
    preflight_sha: "1b9a96e850cb4b050f2f64ee90665399dbddc7c9b2a71fe5afb32796b2518dcb",
    profile_sha: "95aebc954169426d79663a297b8c445a9c3ca5b759a84fc96e51cd5f77313982",
};

pub(super) const HOURLY_230: Focused = Focused {
    epoch: 230,
    unit: "horizon-qualify-230-middle-hourly-first-v1.service",
    guard: "horizon-230-middle-hourly-first-protective-v1",
    cpus: "72-79",
    scratch_cap: 208 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 225_000_000_000,
    root: "/home/ubuntu/.jetstreamer-private/qualification-230-middle-hourly-first-v1",
    first: 99_437_434,
    last: 99_476_782,
    kind: "epoch230-private-first-hourly-window",
    preflight_schema: "foundation-epoch230-middle-hourly-first-runtime-preflight-v1",
    state: "/var/lib/jetstreamer/horizon230-middle-hourly-first-runtime-v1",
    preflight_sha: "fae42b5f5183a21bed46786ddc0d23819ee1eadec8c84f9dd1a3f6debbec113b",
    profile_sha: "f54a68b09830f1ae8048b4a1db29ad63f0d10cba02d34a6a06b19dbeb3f7eaab",
};

pub(super) const SECOND_HOURLY_230: Focused = Focused {
    epoch: 230,
    unit: "horizon-qualify-230-middle-hourly-second-v1.service",
    guard: "horizon-230-middle-hourly-second-protective-v1",
    cpus: "48-55",
    scratch_cap: 208 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 225_000_000_000,
    root: "/home/ubuntu/.jetstreamer-private/qualification-230-middle-hourly-second-v1",
    first: 99_476_783,
    last: 99_516_304,
    kind: "epoch230-private-second-hourly-window",
    preflight_schema: "foundation-epoch230-middle-hourly-second-runtime-preflight-v1",
    state: "/var/lib/jetstreamer/horizon230-middle-hourly-second-runtime-v1",
    preflight_sha: "b7d2b77d99c3d42d6e85b9b724876ba700f6c598df75ade8bcc7db945907edda",
    profile_sha: "76787b9a49ef39f2ae2e7cb6053abdc4e1d075301527e72b1878f9165c9cfe38",
};

pub(super) const FIRST_7871_230: Focused = Focused {
    epoch: 230,
    unit: "horizon-qualify-230-first-7871-v1.service",
    guard: "horizon-230-first-7871-protective-v1",
    cpus: "48-55",
    scratch_cap: 90 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 225_000_000_000,
    root: "/home/ubuntu/.jetstreamer-private/qualification-230-first-7871-v1",
    first: 99_437_434,
    last: 99_445_304,
    kind: "epoch230-private-first-7871-window",
    preflight_schema: "foundation-epoch230-first-7871-runtime-preflight-v1",
    state: "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1",
    preflight_sha: "3c0d5ac1c970cffa0473fa3c5d01ad2466f7d041b4fe25dc7cdb65039688a3ea",
    profile_sha: "7d3a7c8bad8d3b257622800874a92a278d287a6b1cd6d377f729c2e139e9f4fd",
};

pub(super) const V1627_230: Focused = Focused {
    epoch: 230,
    unit: "horizon-qualify-230-v1627-window-v1.service",
    guard: "horizon-230-v1627-window-protective-v1",
    cpus: "48-55",
    scratch_cap: 90 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 225_000_000_000,
    root: "/home/ubuntu/.jetstreamer-private/qualification-230-v1627-window-v1",
    first: 99_461_592,
    last: 99_468_089,
    kind: "epoch230-private-v1627-window",
    preflight_schema: "foundation-epoch230-v1627-window-preflight-v1",
    state: "/var/lib/jetstreamer/horizon230-v1627-replay-runtime-v1",
    preflight_sha: "8301ba667e1f440365cc40dcdbe4b5f69fa6d224e2e754734738908345b35cca",
    profile_sha: "1e300ad51ba5f75a91af2f68c80241dd90a5c6d279b630de8f92f882655b43d5",
};

pub(super) const ADJACENT_230: Focused = Focused {
    epoch: 230,
    unit: "horizon-qualify-230-adjacent-99445304-v1.service",
    guard: "horizon-230-adjacent-99445304-protective-v1",
    cpus: "48-55",
    scratch_cap: 96 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 225_000_000_000,
    root: "/home/ubuntu/.jetstreamer-private/qualification-230-adjacent-99445304-v1",
    first: 99_445_305,
    last: 99_461_591,
    kind: "epoch230-private-adjacent-99445304-window",
    preflight_schema: "foundation-epoch230-adjacent-replay-preflight-v1",
    state: "/var/lib/jetstreamer/horizon230-adjacent-99445304-runtime-v1",
    preflight_sha: "e2482b9f1a94143620adae00bc4aef749b7004fa32fd2e7671643d62f7d9470a",
    profile_sha: "d01cf1c1a583c41e885ea74f57aea21a5e5178554e94bca16d01674a5bff1d1b",
};

const V1627_INVOCATION: &str = "6c878d138821422d8a848d6bd16d63a9";
const V1627_LAUNCH_SHA: &str =
    "3a2f5a058c76a59707af77f98973c283d4542c8308d5a514a22ae1cb6534a7a6";
const V1627_TERMINAL: &str =
    "/var/lib/jetstreamer/horizon230-v1627-terminal-collector-state-v1/evidence/terminal-evidence.json";
const V1627_ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-230-v1627-window-v1/work/output/epoch-230-v1-6-27-diagnostic.jet";

pub(super) const RESTORE_258: Focused = Focused {
    epoch: 258,
    unit: "horizon-qualify-258-native-restore-v1.service",
    guard: "horizon-258-native-restore-protective-v1",
    cpus: "56-63",
    scratch_cap: 96 << 30,
    receipt_disk: 64 << 20,
    producer_memory: 160 << 30,
    root: "/home/ubuntu/.jetstreamer-private/qualification-258-native-restore-v1",
    first: 111_455_044,
    last: 111_455_044,
    kind: "epoch258-private-native-restore",
    preflight_schema: "foundation-epoch258-native-restore-preflight-v1",
    state: "/var/lib/jetstreamer/horizon258-native-restore-runtime-v1",
    preflight_sha: "ac7cef6418be874cf8437171323fa2f9f1c1cf84ce41917096df4c489f270c6d",
    profile_sha: "1cc91a3e939dd93920ddc6efbd720b9f558b00b3f27d2b6d654362068d2af035",
};

pub(super) const RESTORE_260: Focused = Focused {
    epoch: 260,
    unit: "horizon-qualify-260-native-restore-v1.service",
    guard: "horizon-260-native-restore-protective-v1",
    cpus: "56-63",
    scratch_cap: 96 << 30,
    receipt_disk: 64 << 20,
    producer_memory: 160 << 30,
    root: "/home/ubuntu/.jetstreamer-private/qualification-260-native-restore-v1",
    first: 112_316_757,
    last: 112_316_757,
    kind: "epoch260-private-native-restore",
    preflight_schema: "foundation-epoch260-native-restore-preflight-v1",
    state: "/var/lib/jetstreamer/horizon260-native-restore-runtime-v1",
    preflight_sha: "06e13588b0a57910215304785a2160dd94925a4f95dd9cbaa5951ddec153e04d",
    profile_sha: "8f8b33dd3aad7a27924d22bf8c28ffa061baf0a781c68aadb8d716be50c2be23",
};

pub(super) const OVERLAP_266: Focused = Focused {
    epoch: 266,
    unit: "horizon-qualify-266-hourly-overlap-114929697-v1.service",
    guard: "horizon-266-hourly-overlap-114929697-protective-v1",
    cpus: "32-39",
    scratch_cap: 16 << 30,
    receipt_disk: 256 << 20,
    producer_memory: 256 << 30,
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-hourly-overlap-114929697-v1",
    first: 114_923_431,
    last: 114_929_697,
    kind: "epoch266-private-hourly-overlap",
    preflight_schema: "foundation-epoch266-hourly-overlap-preflight-v1",
    state: "/var/lib/jetstreamer/horizon266-hourly-overlap-114929697-runtime-v1",
    preflight_sha: "1e014dac29ed075242cccd2d226c75a3088712540a90a7358b1cecee4df04b65",
    profile_sha: "494849a05eb8b63f1770c5ae54dc63a1cc1dfadbd09b235c3938ee28393d08ea",
};

pub(super) const OVERLAP_266_EXCLUSIVE: &str = "30,32-39,94,96-103";

pub(super) const PREDECESSOR_266: Focused = Focused {
    epoch: 266,
    unit: "horizon-qualify-266-original-predecessor-v1.service",
    guard: "horizon-266-original-predecessor-protective-v1",
    cpus: OVERLAP_266.cpus,
    scratch_cap: OVERLAP_266.scratch_cap,
    receipt_disk: OVERLAP_266.receipt_disk,
    producer_memory: OVERLAP_266.producer_memory,
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-original-predecessor-v1",
    first: 114_910_769,
    last: 114_923_430,
    kind: "epoch266-private-original-predecessor",
    preflight_schema: "foundation-epoch266-original-predecessor-static-preflight-v1",
    state: "/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1",
    preflight_sha: "de5680f4fc6634529348c9701f639a66cf333c7296f69a7645dc97f1297bc4ae",
    profile_sha: "7ed80c05ae0e1c706a271452d9b0dcb516c651fd0f97a2ec3f1c61a477a30f21",
};
const PREDECESSOR_PROFILE: &str =
    "/var/lib/jetstreamer/horizon266-original-predecessor-static-v1/profile.json";
const PREDECESSOR_CUSTODY: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-predecessor-intake-stage-v1/custody.json",
    "afd03e2258229848a2878f1c2ff75b424ebf810b79fec65788c75ac5111a5959",
);

pub(super) const TRACE_296: Focused = Focused {
    epoch: 296,
    unit: "horizon-qualify-296-loader-log-v3.service",
    guard: "horizon-296-loader-log-protective-v3",
    cpus: "56-63",
    scratch_cap: 112 << 30,
    receipt_disk: 64 << 20,
    producer_memory: 173_207_977_984,
    root: "/home/ubuntu/.jetstreamer-private/qualification-296-loader-log-v3",
    first: 127_953_994,
    last: 127_961_108,
    kind: "epoch296-private-loader-log-diagnostic",
    preflight_schema: "foundation-epoch296-loader-log-preflight-v1",
    state: "/var/lib/jetstreamer/horizon296-loader-log-v3",
    preflight_sha: "6e8be02054f2d53f51636239e2372572892dd8571f318c9af5342c2f2fe22b3f",
    profile_sha: "a65a727024c8cc64796ce89daf0fe0ec134117a20907a8fa030526e1cfe7a073",
};

pub(super) const FEATURE_296: Focused = Focused {
    epoch: 296,
    unit: "horizon-qualify-296-feature-account-v4.service",
    guard: "horizon-296-feature-account-protective-v4",
    cpus: "56-63",
    scratch_cap: 112 << 30,
    receipt_disk: 64 << 20,
    producer_memory: 173_207_977_984,
    root: "/home/ubuntu/.jetstreamer-private/qualification-296-feature-account-v4",
    first: 127_953_994,
    last: 127_961_108,
    kind: "epoch296-private-feature-account-qualification",
    preflight_schema: "foundation-epoch296-feature-account-preflight-v4",
    state: "/var/lib/jetstreamer/horizon296-feature-account-v4",
    preflight_sha: "76227fad5187badf638fff0220a12499f7133de851400e7b770fba712fdf05f7",
    profile_sha: "975056b8b99b13a3d43c5b118e9f2a2ba45b2f46f1bcb9f074f0509f28d8620d",
};

pub(super) const SCOPES: [&Focused; 13] = [
    &GAP_230,
    &HOURLY_230,
    &SECOND_HOURLY_230,
    &FIRST_7871_230,
    &V1627_230,
    &ADJACENT_230,
    &RESTORE_258,
    &RESTORE_260,
    &OVERLAP_266,
    &PREDECESSOR_266,
    &LOADER_296,
    &TRACE_296,
    &FEATURE_296,
];

pub(super) fn feature_296_terminal(n: &mut Native) -> Result<(Bound, Bound)> {
    let scope = &FEATURE_296;
    let state = Path::new(scope.state);
    let terminal_path = state.join("terminal.json");
    ensure!(
        terminal_path.try_exists()?,
        "epoch 296 full replay requires the corrected worker's verified checkpoint and drained guard"
    );
    let checkpoint = Bound::new(&terminal_path, hash(&terminal_path)?);
    let terminal = checkpoint.sealed()?;
    let launch_path = state.join("cadence-registration.json");
    let launch_ref = Bound::new(&launch_path, hash(&launch_path)?);
    let launch = launch_ref.sealed()?;
    let profile_ref = Bound::new(state.join("profile.json"), scope.profile_sha);
    let profile = profile_ref.sealed()?;
    let worker = binding(&profile["worker"])?;
    let worker_directory = worker
        .path
        .parent()
        .context("epoch 296 sealed worker directory")?;
    let build = binding(&profile["worker_build"])?.sealed()?;
    let deployment = binding(&profile["worker_deployment"])?.sealed()?;
    let invocation = text(&launch, "invocation_id")?;
    ensure!(
        terminal["schema"] == "foundation-epoch296-feature-account-terminal-v1"
            && terminal["epoch"] == scope.epoch
            && terminal["state"] == "checkpoint-verified"
            && terminal["invocation_id"] == invocation
            && terminal["guard_drained"] == true
            && terminal["canonical_epoch_publication_authorized"] == false
            && terminal["checkpoint"] == profile["terminal_checkpoint"]
            && terminal["checkpoint"]["slot"] == scope.last
            && terminal["launch"] == json!(launch_ref)
            && terminal["worker"] == json!(worker)
            && launch["profile"] == json!(profile_ref)
            && launch["worker"] == json!(worker)
            && launch["kind"] == scope.kind
            && launch["unit"] == scope.unit
            && build["exit_status"] == 0
            && build["canonical_feature_accounts_regression_passed"] == true
            && build["artifact"]["sha256"] == worker.sha256
            && deployment["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && worker
                .path
                .file_name()
                .is_some_and(|name| name == "jetstreamer-historical-worker-v1-8-11")
            && deployment["destination"] == json!(worker_directory)
            && deployment["members"]
                .as_array()
                .is_some_and(|members| members.iter().any(|member| {
                    member["name"] == "jetstreamer-historical-worker-v1-8-11"
                        && member["sha256"] == worker.sha256
                        && member["mode"] == "0555"
                })),
        "epoch 296 terminal qualification differs from the sealed corrected worker"
    );
    worker.artifact()?;
    feature_296_drained(n, invocation)?;
    Ok((worker, checkpoint))
}

pub(super) fn feature_296_drained(n: &mut Native, invocation: &str) -> Result<()> {
    drained(n, FEATURE_296.unit, FEATURE_296.guard, invocation)
}

pub(super) fn drained(n: &mut Native, producer: &str, guard: &str, invocation: &str) -> Result<()> {
    let timer = n.show_fields(&format!("{guard}.timer"), "ActiveState,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive" && timer["Job"] == "",
        "{guard} timer is still active"
    );
    for unit in [producer.to_owned(), format!("{guard}.service")] {
        let row = n.show_fields(
            &unit,
            "ActiveState,InvocationID,MainPID,ControlPID,ControlGroup,Job,Result",
        )?;
        ensure!(
            matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
                && row["MainPID"] == "0"
                && row["ControlPID"] == "0"
                && row["ControlGroup"] == ""
                && row["Job"] == ""
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(&unit)
                    .exists(),
            "owner {unit} has not drained"
        );
        if unit == producer {
            ensure!(
                row["ActiveState"] == "inactive"
                    && row["Result"] == "success"
                    && (row["InvocationID"] == "" || row["InvocationID"] == invocation),
                "{producer} terminal invocation changed"
            );
        }
    }
    Ok(())
}

fn overlap_private_tmpfs(path: &str, mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        let mut mount_fields = left.split_whitespace().skip(4);
        if mount_fields.next() != Some(path)
            || !mount_fields
                .next()
                .is_some_and(|options| options.split(',').any(|option| option == "rw"))
        {
            return false;
        }
        let mut superblock = right.split_whitespace();
        superblock.next() == Some("tmpfs")
            && superblock
                .nth(1)
                .is_some_and(|flags| flags.split(',').any(|flag| flag == "noswap"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focused_guard_stems_allow_service_and_timer_lookup() {
        for scope in SCOPES {
            assert!(
                !scope.guard.ends_with(".service") && !scope.guard.ends_with(".timer"),
                "expected a guard unit stem for {}",
                scope.unit
            );
        }
    }

    #[test]
    fn overlap_requires_exact_writable_no_swap_tmpfs() {
        let line = "29 1 0:47 / /scope/work/scratch rw,nosuid,nodev - tmpfs tmpfs rw,size=134217728k,noswap";
        assert!(overlap_private_tmpfs("/scope/work/scratch", line));
        assert!(!overlap_private_tmpfs("/scope/work", line));
        assert!(!overlap_private_tmpfs(
            "/scope/work/scratch",
            &line.replace(",noswap", "")
        ));
        assert!(!overlap_private_tmpfs(
            "/scope/work/scratch",
            &line.replace("rw,nosuid", "ro,nosuid")
        ));
        assert!(!overlap_private_tmpfs(
            "/scope/work/scratch",
            &line.replace("- tmpfs ", "- ext4 ")
        ));
    }

    #[test]
    fn overlap_prices_simultaneous_tmpfs_and_resident_output() {
        assert_eq!(
            OVERLAP_266.producer_memory + OVERLAP_266.control_memory() + (1 << 30),
            258 << 30
        );
        assert_eq!(
            OVERLAP_266.scratch_cap + OVERLAP_266.receipt_disk,
            17_448_304_640
        );
        assert_eq!(OVERLAP_266.last - OVERLAP_266.first + 1, 6267);
    }
}

pub(super) fn second_hourly_drained(n: &mut Native) -> Result<()> {
    let state = Path::new(SECOND_HOURLY_230.state);
    let terminal = Bound::new(state.join("terminal.json"),
        "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56").sealed()?;
    let launch = Bound::new(state.join("cadence-registration.json"),
        "c2aea886494f66ed6e2077422894abf68f644a346181da989ac869d9aba43cac");
    let registered = launch.sealed()?;
    let invocation = "a0a94d2d42984804877c1a80fc934585";
    ensure!(
        terminal["schema"] == "foundation-epoch230-middle-hourly-second-terminal-v1"
            && terminal["unit"] == SECOND_HOURLY_230.unit
            && terminal["state"] == "local-segment-committed"
            && terminal["launch"] == json!(launch)
            && terminal["invocation_id"] == invocation
            && terminal["checkpoint"]["slot"] == SECOND_HOURLY_230.last
            && terminal["guard_drained"] == true
            && registered["unit"] == SECOND_HOURLY_230.unit
            && registered["invocation_id"] == invocation,
        "epoch 230 replacement lacks the exact prior terminal and launch"
    );
    drained(n, SECOND_HOURLY_230.unit, SECOND_HOURLY_230.guard, invocation)
}

pub(super) fn first_7871_drained(n: &mut Native) -> Result<Bound> {
    let reference = Bound::new(Path::new(FIRST_7871_230.state).join("terminal.json"),
        "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2");
    let receipt = reference.sealed()?;
    let invocation = "02b7dd1683d24efbabf6b5c2f8ff6a43";
    ensure!(
        receipt["schema"] == "foundation-epoch230-first-7871-terminal-v1"
            && receipt["unit"] == FIRST_7871_230.unit
            && receipt["invocation_id"] == invocation
            && receipt["state"] == "local-segment-committed"
            && receipt["guard_drained"] == true
            && receipt["checkpoint"]["slot"] == FIRST_7871_230.last,
        "epoch 230 checkpoint window requires the verified closure of its predecessor"
    );
    drained(n, FIRST_7871_230.unit, FIRST_7871_230.guard, invocation)?;
    Ok(reference)
}

fn v1627_terminal_matches(
    row: &Value,
    receipt: &Value,
    terminal: &Value,
    launch: &Bound,
    boot: &str,
) -> Result<()> {
    let pid = text(&row["producer"], "MainPID")?.parse::<u64>()?;
    ensure!(
        row["epoch"] == V1627_230.epoch
            && row["phase"] == "diagnostic-qualification"
            && row["producer"]["Id"] == V1627_230.unit
            && row["producer"]["InvocationID"] == V1627_INVOCATION
            && row["launch_receipt"] == json!(launch.path)
            && row["launch_receipt_sha256"] == launch.sha256
            && receipt["schema"] == "foundation-epoch230-v1627-private-drain-v1"
            && receipt["unit"] == V1627_230.unit
            && receipt["invocation_id"] == V1627_INVOCATION
            && receipt["state"] == "local-segment-committed"
            && receipt["launch"] == json!(launch)
            && receipt["guard_drained"] == true
            && receipt["publication_authorized"] == false
            && terminal["schema"] == "foundation-epoch230-v1627-private-terminal-evidence-v1"
            && terminal["epoch"] == V1627_230.epoch
            && terminal["unit"] == V1627_230.unit
            && terminal["invocation_id"] == V1627_INVOCATION
            && terminal["launch"] == json!(launch)
            && terminal["producer_pid"] == pid
            && terminal["boot_id"] == boot
            && terminal["producer_drained"] == true
            && terminal["producer_exit_status"] == 0
            && terminal["native_manifest_complete_verified"] == true
            && terminal["first_slot"] == V1627_230.first
            && terminal["last_slot"] == V1627_230.last
            && terminal["slot_count"] == V1627_230.last - V1627_230.first + 1
            && terminal["terminal_checkpoint"]["slot"] == V1627_230.last
            && terminal["archive"]["path"] == V1627_ARCHIVE
            && terminal["publication_authorized"] == false,
        "closed epoch 230 evidence does not bind the sampled v1.6.27 window"
    );
    Ok(())
}

pub(super) fn v1627_230_drained(n: &mut Native, row: &Value) -> Result<Option<Bound>> {
    let state = Path::new(V1627_230.state);
    let path = state.join("terminal.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let reference = Bound::new(&path, hash(&path)?);
    let receipt = reference.sealed()?;
    let launch = Bound::new(state.join("cadence-registration.json"), V1627_LAUNCH_SHA);
    launch.sealed()?;
    let terminal_ref = binding(&receipt["native_terminal"])?;
    ensure!(
        terminal_ref.path == Path::new(V1627_TERMINAL),
        "foreign epoch 230 v1.6.27 terminal evidence"
    );
    let terminal = terminal_ref.sealed()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    v1627_terminal_matches(row, &receipt, &terminal, &launch, &boot.trim().replace('-', ""))?;
    let archive = fs::symlink_metadata(V1627_ARCHIVE)?;
    let identity = &terminal["archive"]["identity"];
    let nanos =
        |seconds: i64, fraction: i64| seconds.checked_mul(1_000_000_000)?.checked_add(fraction);
    ensure!(
        archive.is_file()
            && archive.dev() == num(identity, "device")?
            && archive.ino() == num(identity, "inode")?
            && archive.len() == num(identity, "bytes")?
            && nanos(archive.mtime(), archive.mtime_nsec()).context("archive mtime overflow")?
                == identity["mtime_ns"].as_i64().context("archive mtime missing")?
            && nanos(archive.ctime(), archive.ctime_nsec()).context("archive ctime overflow")?
                == identity["ctime_ns"].as_i64().context("archive ctime missing")?,
        "the retained epoch 230 v1.6.27 archive changed after terminal verification"
    );
    drained(n, V1627_230.unit, V1627_230.guard, V1627_INVOCATION)?;
    Ok(Some(reference))
}

#[cfg(test)]
#[test]
fn v1627_releases_only_the_exact_verified_private_window() {
    let launch = Bound::new(
        Path::new(V1627_230.state).join("cadence-registration.json"),
        V1627_LAUNCH_SHA,
    );
    let boot = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let row = json!({
        "epoch": 230, "phase": "diagnostic-qualification", "launch_receipt": launch.path,
        "launch_receipt_sha256": launch.sha256,
        "producer": {"Id": V1627_230.unit, "InvocationID": V1627_INVOCATION, "MainPID": "1234"},
    });
    let receipt = json!({
        "schema": "foundation-epoch230-v1627-private-drain-v1", "unit": V1627_230.unit,
        "invocation_id": V1627_INVOCATION, "state": "local-segment-committed",
        "guard_drained": true, "launch": launch, "publication_authorized": false,
    });
    let mut terminal = json!({
        "schema": "foundation-epoch230-v1627-private-terminal-evidence-v1",
        "epoch": 230, "unit": V1627_230.unit, "invocation_id": V1627_INVOCATION,
        "launch": launch, "producer_pid": 1234, "boot_id": boot, "producer_drained": true,
        "producer_exit_status": 0, "native_manifest_complete_verified": true,
        "first_slot": 99_461_592, "last_slot": 99_468_089, "slot_count": 6_498,
        "terminal_checkpoint": {"slot": 99_468_089},
        "archive": {"path": V1627_ARCHIVE}, "publication_authorized": false,
    });
    v1627_terminal_matches(&row, &receipt, &terminal, &launch, boot).unwrap();
    let mut undrained = receipt.clone();
    undrained["guard_drained"] = json!(false);
    assert!(v1627_terminal_matches(&row, &undrained, &terminal, &launch, boot).is_err());
    assert!(v1627_terminal_matches(&row, &receipt, &terminal, &launch, "other").is_err());
    terminal["slot_count"] = json!(6497);
    assert!(v1627_terminal_matches(&row, &receipt, &terminal, &launch, boot).is_err());
}

pub(super) fn overlap_266_drained(n: &mut Native, row: &Value) -> Result<Option<Bound>> {
    const INVOCATION: &str = "08c5881b215e45c8b0c257a6a417535a";
    const LAUNCH_SHA: &str = "0c7965332b7f1fe9be70eca870d15f6d6a33eaa683f72eb449b22578ea839404";
    const NATIVE_TERMINAL: &str =
        "/var/lib/jetstreamer/horizon266-hourly-overlap-114929697-terminal-v1/terminal-evidence.json";
    let state = Path::new(OVERLAP_266.state);
    let path = state.join("terminal.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let reference = Bound::new(&path, hash(&path)?);
    let receipt = reference.sealed()?;
    let launch = Bound::new(state.join("cadence-registration.json"), LAUNCH_SHA);
    let terminal_ref: Bound = serde_json::from_value(receipt["native_terminal"].clone())?;
    ensure!(terminal_ref.path == Path::new(NATIVE_TERMINAL), "foreign epoch 266 terminal evidence");
    let terminal = terminal_ref.sealed()?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let original_pid = text(&row["producer"], "MainPID")?.parse::<u64>()?;
    ensure!(
        row["phase"] == "diagnostic-qualification"
            && row["producer"]["InvocationID"] == INVOCATION
            && row["launch_receipt"] == json!(launch.path)
            && row["launch_receipt_sha256"] == LAUNCH_SHA
            && receipt["schema"] == "foundation-epoch266-private-overlap-drain-v1"
            && receipt["unit"] == OVERLAP_266.unit
            && receipt["invocation_id"] == INVOCATION
            && receipt["launch"] == json!(launch)
            && receipt["guard_drained"] == true
            && terminal["schema"] == "foundation-epoch266-private-overlap-terminal-evidence-v1"
            && terminal["unit"] == OVERLAP_266.unit
            && terminal["launch"] == json!(launch)
            && terminal["producer_invocation"] == INVOCATION
            && terminal["producer_pid"] == original_pid
            && terminal["boot_id"] == boot_id
            && terminal["producer_drained"] == true
            && terminal["producer_exit_status"] == 0
            && terminal["native_manifest_complete_verified"] == true
            && terminal["first_slot"] == OVERLAP_266.first
            && terminal["last_slot"] == OVERLAP_266.last
            && terminal["publication_authorized"] == false,
        "closed epoch 266 evidence does not bind the sampled overlap"
    );
    drained(n, OVERLAP_266.unit, OVERLAP_266.guard, INVOCATION)?;
    Ok(Some(reference))
}

fn validate_predecessor_266_drain(
    row: &Value,
    launch_ref: &Bound,
    launch: &Value,
    receipt: &Value,
    native: &Value,
    boot: &str,
) -> Result<()> {
    let invocation = text(launch, "invocation_id")?;
    let pid = text(&row["producer"], "MainPID")?.parse::<u64>()?;
    ensure!(
        row["epoch"] == 266
            && row["phase"] == "diagnostic-qualification"
            && row["producer"]["Id"] == PREDECESSOR_266.unit
            && row["producer"]["InvocationID"] == invocation
            && row["launch_receipt"] == json!(launch_ref.path)
            && row["launch_receipt_sha256"] == launch_ref.sha256
            && launch["main_pid"] == pid
            && launch["unit"] == PREDECESSOR_266.unit
            && receipt["schema"] == "foundation-epoch266-private-predecessor-drain-v1"
            && receipt["epoch"] == 266
            && receipt["unit"] == PREDECESSOR_266.unit
            && receipt["invocation_id"] == invocation
            && receipt["launch"] == json!(launch_ref)
            && receipt["guard_drained"] == true
            && receipt["state"] == "local-segment-committed"
            && receipt["publication_authorized"] == false
            && native["schema"] == "foundation-epoch266-private-predecessor-terminal-evidence-v1"
            && native["epoch"] == 266
            && native["unit"] == PREDECESSOR_266.unit
            && native["launch"] == json!(launch_ref)
            && native["invocation_id"] == invocation
            && native["boot_id"] == boot
            && native["producer_drained"] == true
            && native["producer_exit_status"] == 0
            && native["replay_first_slot"] == PREDECESSOR_266.first
            && native["first_slot"] == 114_912_000
            && native["last_slot"] == PREDECESSOR_266.last
            && native["positions"] == PREDECESSOR_266.last - 114_912_000 + 1
            && native["native_manifest_complete_verified"] == true
            && native["full_prefix_normalized_match"] == true
            && native["terminal_consensus_fields_match"] == true
            && native["publication_authorized"] == false,
        "closed epoch 266 evidence does not bind the sampled predecessor"
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn predecessor_drain_cannot_release_an_unverified_or_replaced_owner() {
    let launch_ref = Bound::new("/launch.json", "a".repeat(64));
    let iid = "b".repeat(32);
    let boot = "c".repeat(32);
    let unit = PREDECESSOR_266.unit;
    let row = json!({
        "epoch":266, "phase":"diagnostic-qualification",
        "producer":{"Id":unit, "InvocationID":iid, "MainPID":"123"},
        "launch_receipt":launch_ref.path, "launch_receipt_sha256":launch_ref.sha256,
    });
    let launch = json!({"main_pid":123, "unit":unit, "invocation_id":iid});
    let mut receipt = json!({
        "schema":"foundation-epoch266-private-predecessor-drain-v1",
        "epoch":266, "unit":unit, "invocation_id":iid, "launch":launch_ref,
        "guard_drained":true, "state":"local-segment-committed", "publication_authorized":false,
    });
    let mut native = json!({
        "schema":"foundation-epoch266-private-predecessor-terminal-evidence-v1",
        "epoch":266, "unit":unit, "launch":launch_ref, "invocation_id":iid, "boot_id":boot,
        "producer_drained":true, "producer_exit_status":0,
        "replay_first_slot":PREDECESSOR_266.first, "first_slot":114_912_000,
        "last_slot":PREDECESSOR_266.last, "positions":11_431,
        "native_manifest_complete_verified":true, "full_prefix_normalized_match":true,
        "terminal_consensus_fields_match":true, "publication_authorized":false,
    });
    let check = |receipt: &Value, native: &Value, boot: &str| {
        validate_predecessor_266_drain(&row, &launch_ref, &launch, receipt, native, boot)
    };
    check(&receipt, &native, &boot).unwrap();
    assert!(check(&receipt, &native, "replaced-boot").is_err());
    native["full_prefix_normalized_match"] = json!(false);
    assert!(check(&receipt, &native, &boot).is_err());
    native["full_prefix_normalized_match"] = json!(true);
    receipt["guard_drained"] = json!(false);
    assert!(check(&receipt, &native, &boot).is_err());
}

pub(super) fn predecessor_266_drained(n: &mut Native, row: &Value) -> Result<Option<Bound>> {
    let state = Path::new(PREDECESSOR_266.state);
    let path = state.join("terminal.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let reference = Bound::new(&path, hash(&path)?);
    let receipt = reference.sealed()?;
    let launch_ref = binding(&receipt["launch"])?;
    let native = binding(&receipt["native_terminal"])?;
    ensure!(
        launch_ref.path == state.join("cadence-registration.json")
            && native.path == Path::new("/var/lib/jetstreamer/horizon266-predecessor-terminal-collector-state-v1/evidence/terminal-evidence.json"),
        "foreign epoch 266 predecessor drain paths"
    );
    let launch = launch_ref.sealed()?;
    let native = native.sealed()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().replace('-', "");
    validate_predecessor_266_drain(row, &launch_ref, &launch, &receipt, &native, &boot)?;
    drained(n, PREDECESSOR_266.unit, PREDECESSOR_266.guard, text(&launch, "invocation_id")?)?;
    Ok(Some(reference))
}

impl Focused {
    pub(super) fn control_memory(&self) -> u64 {
        if self.epoch == 266 {
            1 << 30
        } else {
            CONTROLLER_MEMORY
        }
    }

    pub(super) fn quote_key(&self) -> String {
        format!("focused_{}_quote", self.epoch)
    }

    fn profile(&self) -> Bound {
        let path = if self.unit == PREDECESSOR_266.unit {
            PathBuf::from(PREDECESSOR_PROFILE)
        } else {
            Path::new(self.state).join("profile.json")
        };
        Bound::new(path, self.profile_sha)
    }

    pub(super) fn predecessor_custody(&self) -> Result<Bound> {
        ensure!(self.unit == PREDECESSOR_266.unit, "foreign predecessor scope");
        let reference = Bound::new(PREDECESSOR_CUSTODY.0, PREDECESSOR_CUSTODY.1);
        let custody = reference.sealed()?;
        let profile = self.profile().sealed()?;
        let input = &custody["input"];
        let snapshot = &profile["bootstrap"];
        let path = Path::new(text(input, "path")?);
        let meta = fs::symlink_metadata(path)?;
        let identity = &input["identity"];
        ensure!(
            custody["schema"] == "foundation-epoch266-predecessor-input-custody-v1"
                && custody["profile"] == json!(self.profile())
                && custody["whole_file_sha256_rechecked"] == true
                && custody["actual_readonly_projection_verified"] == true
                && custody["publication_authorized"] == false
                && input["root_sealed"] == true
                && input["path"] == snapshot["path"]
                && input["sha256"] == snapshot["sha256"]
                && input["generation"] == snapshot["generation"]
                && input["bytes"] == snapshot["bytes"]
                && meta.is_file()
                && meta.uid() == 0
                && meta.mode() & 0o222 == 0
                && meta.nlink() == 1
                && path.canonicalize()? == path
                && num(identity, "device")? == meta.dev()
                && num(identity, "inode")? == meta.ino()
                && num(input, "bytes")? == meta.len()
                && identity["mtime"] == json!([meta.mtime(), meta.mtime_nsec()])
                && identity["ctime"] == json!([meta.ctime(), meta.ctime_nsec()]),
            "epoch 266 predecessor bootstrap custody changed"
        );
        Ok(reference)
    }

    pub(super) fn preflight(&self) -> Result<Bound> {
        let state = Path::new(self.state);
        let reference = Bound::new(state.join("preflight.json"), self.preflight_sha);
        let receipt = reference.sealed()?;
        let profile_ref = self.profile();
        let profile = profile_ref.sealed()?;
        let proven_inputs = if self.unit == PREDECESSOR_266.unit {
            self.predecessor_custody()?;
            let guard = binding(&receipt["static_guard_validation"])?.sealed()?;
            receipt["replay_first_slot"] == self.first
                && receipt["output_first_slot"] == 114_912_000
                && receipt["profile"] == json!(profile_ref)
                && guard["validated"] == true
                && guard["plan_sha256"] == profile["static_guard_plan"]["sha256"]
        } else if self.unit == ADJACENT_230.unit {
            let custody = Bound::new(
                "/var/lib/jetstreamer/horizon230-adjacent-input-99445304-v1/custody.json",
                "5fa272e357fb8c8f2b939f3ea332ff3b241a3a2d2252e225ff763bd479d27ca2",
            );
            let source = custody.sealed()?;
            let guard = binding(&receipt["guard_validation"])?.sealed()?;
            receipt["first_slot"] == self.first
                && receipt["profile"] == json!(profile_ref)
                && receipt["bootstrap_custody"] == json!(custody)
                && profile["bootstrap_custody"] == receipt["bootstrap_custody"]
                && source["snapshot"]["slot"] == self.first - 1
                && source["prepared_window"]["last_slot"] == self.last
                && receipt["host_guard_sees_empty_placeholders"] == true
                && receipt["worker_execution"] == false
                && guard["validated"] == true
                && guard["plan_sha256"] == profile["static_guard_plan"]["sha256"]
        } else {
            receipt["first_slot"] == self.first
                && receipt["snapshot_sha256_rechecked"] == true
                && receipt["private_namespace_validated"] == true
                && receipt["static_guard_validated"] == true
                && receipt["writable_private_state_validated"] == true
        };
        ensure!(
            receipt["schema"] == self.preflight_schema
                && receipt["epoch"] == self.epoch
                && receipt["last_slot"] == self.last
                && proven_inputs
                && receipt["publication_authorized"] == false
                && profile["unit"] == self.unit
                && profile["run_root"] == self.root
                && profile["guarded_whole_tree_cap_bytes"] == self.scratch_cap
                && profile["properties"]["AllowedCPUs"] == self.cpus
                && profile["properties"]["MemoryMax"] == self.producer_memory.to_string()
                && profile["guard"]["path"] == STANDARD_GUARD,
            "epoch {} focused preflight or profile differs from the measured scope",
            self.epoch
        );
        Ok(reference)
    }

    pub(super) fn live(&self, n: &mut Native) -> Result<LiveReplay> {
        let preflight = self.preflight()?;
        let state = Path::new(self.state);
        let registration = state.join("cadence-registration.json");
        let reference = Bound::new(&registration, hash(&registration)?);
        let launch = reference.sealed()?;
        let profile_ref = binding(&launch["profile"])?;
        let profile = profile_ref.sealed()?;
        let admission = binding(&launch["admission"])?.sealed()?;
        let quote = binding(&admission["roster"])?.sealed()?;
        let plan = binding(&launch["guard_plan"])?;
        let body = plan.sealed()?;
        let sample_ref = binding(&launch["active_guard"])?;
        let sample = sample_ref.json()?;
        let node = Bound::new(
            text(&profile["node"], "path")?,
            text(&profile["node"], "sha256")?,
        );
        node.artifact()?;
        let owner = n.show_fields(self.unit, OWNER_FIELDS)?;
        let invocation = text(&launch, "invocation_id")?;
        let pid = text(&owner, "MainPID")?.parse::<u64>()?;
        let ticks = process_ticks(pid)?;
        let running = fs::metadata(format!("/proc/{pid}/exe"))?;
        let sealed = fs::metadata(&node.path)?;
        if let Some(bytes) = profile["node"]["bytes"].as_u64() {
            ensure!(sealed.len() == bytes, "focused replay node size changed");
        }
        let floor = num(&body, "minimum_free_bytes")?;
        ensure!(
            launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
                && launch["kind"] == self.kind
                && launch["epoch"] == self.epoch
                && launch["unit"] == self.unit
                && launch["run_root"] == self.root
                && launch["launched"] == true
                && launch["canonical_epoch_publication_authorized"] == false
                && launch["node_path"] == json!(node.path)
                && launch["worker"] == profile["worker"]
                && launch["main_pid"] == pid
                && profile_ref == self.profile()
                && admission["schema"]
                    == format!("foundation-epoch{}-focused-admission-v1", self.epoch)
                && admission["profile"] == launch["profile"]
                && admission["admitted"] == true
                && admission["publication_authorized"] == false
                && quote[self.quote_key()]["preflight"] == json!(preflight)
                && quote["capacity"]["fits"] == true
                && quote["capacity"]["candidate_disk_bytes"]
                    == self.scratch_cap + self.receipt_disk
                && quote["capacity"]["candidate_total_memory_bytes"]
                    == self.producer_memory + self.control_memory() + (1 << 30)
                && quote["capacity"]["guard_floor_bytes"] == floor
                && body["filesystem"] == "/"
                && body["worker_root"] == self.root
                && body["unit"] == self.unit
                && body["invocation_id"] == invocation
                && body["maximum_root_physical_bytes"] == self.scratch_cap
                && sample["plan"] == json!(plan.path)
                && sample["plan_sha256"] == plan.sha256
                && sample["guard_sha256"] == profile["guard"]["sha256"]
                && owner["AllowedCPUs"] == profile["properties"]["AllowedCPUs"]
                && (running.dev(), running.ino()) == (sealed.dev(), sealed.ino()),
            "epoch {} focused replay booking or invocation changed",
            self.epoch
        );
        if self.epoch == 266 {
            let released = binding(&launch["guard_release_fit"])?.sealed()?;
            let mount = format!("{}/work/scratch", self.root);
            let mountinfo = fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;

            let scope_bound = if self.unit == PREDECESSOR_266.unit {
                let custody = json!(self.predecessor_custody()?);
                launch["bootstrap_custody"] == custody
                    && quote[self.quote_key()]["bootstrap_custody"] == custody
                    && released["schema"] == "foundation-epoch266-original-predecessor-guard-release-fit-v1"
            } else {
                launch["lossless_restore"] == profile["restore_receipt"]
                    && released["schema"] == "foundation-epoch266-hourly-overlap-guard-release-fit-v1"
            };
            ensure!(
                launch["diagnostic_only"] == true
                    && launch["predecessor_native_tuple_qualified"] == false
                    && launch["cursor_normalization_qualified"] == false
                    && scope_bound
                    && released["invocation_id"] == invocation
                    && released["roster"] == admission["roster"]
                    && released["guard_plan"] == launch["guard_plan"]
                    && released["publication_authorized"] == false
                    && overlap_private_tmpfs(&mount, &mountinfo),
                "epoch 266 diagnostic guard release or private tmpfs changed"
            );
        }
        let memory =
            super::live::finite_owner(&owner, self.unit, invocation, self.producer_memory)?;
        Ok(LiveReplay {
            reference,
            unit: self.unit,
            owner,
            memory,
            ticks,
            guard_booking: json!({"sample":sample_ref,"floor_bytes":floor,"cap_bytes":self.scratch_cap}),
            receipt_disk: self.receipt_disk,
        })
    }
}
