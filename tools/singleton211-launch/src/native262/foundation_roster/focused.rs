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

pub(super) const SCOPES: [&Focused; 3] = [&GAP_230, &RESTORE_258, &LOADER_296];

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
