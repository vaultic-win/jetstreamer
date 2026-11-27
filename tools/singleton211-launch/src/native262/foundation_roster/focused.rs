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
    &RESTORE_258,
    &RESTORE_260,
    &OVERLAP_266,
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
    let scope = &FEATURE_296;
    let timer = n.show_fields(&format!("{}.timer", scope.guard), "ActiveState,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive" && timer["Job"] == "",
        "epoch 296 feature guard timer is still active"
    );
    for unit in [scope.unit.to_owned(), format!("{}.service", scope.guard)] {
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
            "epoch 296 feature owner {unit} has not drained"
        );
        if unit == scope.unit {
            ensure!(
                row["ActiveState"] == "inactive"
                    && row["Result"] == "success"
                    && (row["InvocationID"] == "" || row["InvocationID"] == invocation),
                "epoch 296 feature terminal invocation changed"
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

impl Focused {
    pub(super) fn control_memory(&self) -> u64 {
        if self.unit == OVERLAP_266.unit {
            1 << 30
        } else {
            CONTROLLER_MEMORY
        }
    }

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
        if self.unit == OVERLAP_266.unit {
            let released = binding(&launch["guard_release_fit"])?.sealed()?;
            let mount = format!("{}/work/scratch", self.root);
            let mountinfo = fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;

            ensure!(
                launch["diagnostic_only"] == true
                    && launch["predecessor_native_tuple_qualified"] == false
                    && launch["cursor_normalization_qualified"] == false
                    && launch["lossless_restore"] == profile["restore_receipt"]
                    && released["schema"]
                        == "foundation-epoch266-hourly-overlap-guard-release-fit-v1"
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
