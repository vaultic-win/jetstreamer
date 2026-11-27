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

pub(super) const SCOPES: [&Focused; 9] = [
    &GAP_230,
    &HOURLY_230,
    &SECOND_HOURLY_230,
    &FIRST_7871_230,
    &RESTORE_258,
    &RESTORE_260,
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

impl Focused {
    pub(super) fn quote_key(&self) -> String {
        format!("focused_{}_quote", self.epoch)
    }

    pub(super) fn preflight(&self) -> Result<Bound> {
        let state = Path::new(self.state);
        let reference = Bound::new(state.join("preflight.json"), self.preflight_sha);
        let receipt = reference.sealed()?;
        let profile = Bound::new(state.join("profile.json"), self.profile_sha).sealed()?;
        ensure!(
            receipt["schema"] == self.preflight_schema
                && receipt["epoch"] == self.epoch
                && receipt["first_slot"] == self.first
                && receipt["last_slot"] == self.last
                && receipt["snapshot_sha256_rechecked"] == true
                && receipt["private_namespace_validated"] == true
                && receipt["static_guard_validated"] == true
                && receipt["writable_private_state_validated"] == true
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
                && profile_ref.path == state.join("profile.json")
                && profile_ref.sha256 == self.profile_sha
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
                    == self.producer_memory + CONTROLLER_MEMORY + (1 << 30)
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
