//! Exact epoch 223 control/spawn candidates over the complete af098020 ledger.
//! Pending candidate actors are charged in full, never hidden as free capacity.
use super::*;

const GIB: u64 = 1 << 30;
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Actor {
    unit: String,
    invocation_id: String,
    pid: u32,
    start_ticks: u64,
    cgroup: String,
    boot_id: String,
    executable: BoundFile,
    expected_exec_start: String,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    job_kind: String,
    phase: String,
    local_floor_bytes: u64,
    runtime_plan: BoundFile,
    producer: Actor,
    guard: Actor,
    issuer: Actor,
    driver_qualification: BoundFile,
    guard_qualification: BoundFile,
}
fn valid_unit(s: &str, prefix: &str) -> bool {
    s.starts_with(prefix)
        && s.ends_with(".service")
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn same_command(a: &str, b: &str) -> bool {
    a.split(" ; start_time=")
        .next()
        .unwrap_or(a)
        .trim_end_matches(" }")
        == b.trim_end_matches(" }")
}
impl Context {
    pub(super) fn names(&self) -> Result<BTreeSet<String>> {
        self.shape()?;
        Ok([
            self.producer.unit.clone(),
            self.guard.unit.clone(),
            self.issuer.unit.clone(),
        ]
        .into_iter()
        .collect())
    }
    fn shape(&self) -> Result<()> {
        let prefix = match self.job_kind.as_str() {
            "bracket" => "horizon-qualify-223-demotion-bracket-",
            "native-input" => "horizon-native-input-223-demotion-",
            _ => bail!("unknown223candidate purpose"),
        };
        ensure!(
            matches!(self.phase.as_str(), "control" | "spawn")
                && valid_unit(&self.producer.unit, prefix)
                && valid_unit(&self.guard.unit, "horizon-guard-223-demotion-")
                && valid_unit(&self.issuer.unit, "horizon-admit-223-demotion-"),
            "foreign223candidate actors"
        );
        ensure!(
            self.local_floor_bytes > 0,
            "223 candidate local floor missing"
        );
        let actors = [&self.producer, &self.guard, &self.issuer];
        let mut pids = BTreeSet::new();
        let mut iids = BTreeSet::new();
        for a in actors {
            ensure!(
                a.pid > 1
                    && a.start_ticks > 0
                    && private_prefix::iid(&a.invocation_id)
                    && a.invocation_id != "0".repeat(32)
                    && pids.insert(a.pid)
                    && iids.insert(a.invocation_id.clone())
                    && a.cgroup == format!("/system.slice/{}", a.unit),
                "223candidate actor collision"
            );
        }
        Ok(())
    }
    pub(super) fn candidate(&self) -> Result<maintenance_capacity::Candidate> {
        self.shape()?;
        let (disk, main) = match (self.phase.as_str(), self.job_kind.as_str()) {
            ("control", _) => (GIB, 16 * GIB),
            ("spawn", "bracket") => (471_798_691_840, 225_000_000_000),
            ("spawn", "native-input") => (301 * GIB, 128 * GIB),
            _ => bail!("unclosed223candidate"),
        };
        Ok(maintenance_capacity::Candidate {
            additional_bytes: disk,
            memory_max_bytes: main
                .checked_add(2 * GIB)
                .context("223candidate memory overflow")?,
            minimum_protected_disk_bytes: self.local_floor_bytes,
        })
    }
    fn validate_plan(&self) -> Result<()> {
        let plan = bound_json(&self.runtime_plan)?;
        if self.job_kind == "bracket" {
            ensure!(
                plan["schema"] == "jetstreamer-epoch223-demotion-runtime-plan-v3"
                    && plan["mode"] == "bracket"
                    && plan["plan"]["unit"] == self.producer.unit
                    && plan["plan"]["minimum_free_bytes"] == self.local_floor_bytes
                    && plan["plan"]["terminal_slot"] == 96_544_588u64
                    && plan["plan"]["target_slot"] == 96_544_588u64,
                "223bracket allocation plan changed"
            );
        } else {
            ensure!(
                plan["schema"] == "jetstreamer-epoch223-demotion-native-supervisor-plan-v1"
                    && plan["unit"] == self.producer.unit
                    && plan["harness"]["sha256"]
                        == "a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b"
                    && plan["bootstrap_slot"] == 96_335_538u64,
                "223native allocation plan changed"
            );
        }
        let q = bound_json(&self.driver_qualification)?;
        let g = bound_json(&self.guard_qualification)?;
        ensure!(
            q["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
                && q["executable_sha256"] == self.producer.executable.sha256
                && q["producer_roles_qualified"] == true
                && g["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
                && g["executable_sha256"] == self.guard.executable.sha256
                && g["protective_guard_qualified"] == true,
            "223candidate producer/guard are not qualified immutable roles"
        );
        Ok(())
    }
    fn actor(&self, a: &Actor, row: &Value, max: u64, high: u64, user: &str) -> Result<Value> {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        ensure!(
            a.boot_id == boot.trim()
                && row["Id"] == a.unit
                && row["InvocationID"] == a.invocation_id
                && row["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(a.pid)
                && row["ControlGroup"] == a.cgroup
                && row["NRestarts"] == "0"
                && row["ActiveState"] == "active"
                && row["SubState"] == "running"
                && row["ExecStart"]
                    .as_str()
                    .is_some_and(|s| same_command(s, &a.expected_exec_start)),
            "223candidate actor changed"
        );
        let stat = fs::read_to_string(format!("/proc/{}/stat", a.pid))?;
        ensure!(
            stat.rsplit_once(')')
                .context("223candidate stat")?
                .1
                .split_whitespace()
                .nth(19)
                .context("223candidate start ticks")?
                .parse::<u64>()?
                == a.start_ticks
                && fs::read_to_string(format!("/proc/{}/cgroup", a.pid))?.trim()
                    == format!("0::{}", a.cgroup)
                && fs::read_link(format!("/proc/{}/exe", a.pid))? == a.executable.path,
            "223candidate process reused"
        );
        let actual = private157::file_binding(&a.executable.path)?;
        ensure!(
            actual["sha256"] == a.executable.sha256,
            "223candidate executable differs"
        );
        let props = singleton227_capture::properties(
            &a.unit,
            "Type,User,Restart,MemoryMax,MemoryHigh,MemorySwapMax",
        )?;
        singleton227_capture::require(
            &props,
            &[
                ("Type", "exec"),
                ("User", user),
                ("Restart", "no"),
                ("MemorySwapMax", "0"),
            ],
        )?;
        let root = Path::new("/sys/fs/cgroup").join(a.cgroup.trim_start_matches('/'));
        ensure!(
            root.canonicalize()? == root,
            "223candidate cgroup redirected"
        );
        let read = |name: &str| -> Result<u64> {
            Ok(fs::read_to_string(root.join(name))?.trim().parse()?)
        };
        let charge = read("memory.current")?;
        ensure!(
            read("memory.max")? == max
                && read("memory.high")? == high
                && read("memory.swap.max")? == 0
                && charge <= max,
            "223candidate hard cap/high/swap changed"
        );
        Ok(
            json!({"actor":a,"hard_cap_bytes":max,"memory_high_bytes":high,
            "current_charge_bytes":charge,"full_candidate_cap_charged":true,"allocation_credit_bytes":0}),
        )
    }
    pub(super) fn peer_view(
        &self,
        f: &Value,
        current: &BTreeMap<String, Value>,
    ) -> Result<(BTreeMap<String, Value>, Value)> {
        self.shape()?;
        let names = self.names()?;
        for active in f["active"]
            .as_array()
            .context("223candidate accepted producer roster")?
        {
            let owner = singleton227_admission::active_owner(active)?;
            ensure!(
                !names.contains(owner["Id"].as_str().context("223candidate roster name")?),
                "223candidate cannot replace or discount an accepted producer"
            );
        }
        self.validate_plan()?;
        let main_user = if self.job_kind == "bracket" {
            "ubuntu"
        } else {
            "root"
        };
        let producer = self.actor(
            &self.producer,
            current
                .get(&self.producer.unit)
                .context("223candidate producer omitted")?,
            16 * GIB,
            14 * GIB,
            main_user,
        )?;
        let guard = self.actor(
            &self.guard,
            current
                .get(&self.guard.unit)
                .context("223candidate guard omitted")?,
            GIB,
            768 << 20,
            "root",
        )?;
        let issuer = self.actor(
            &self.issuer,
            current
                .get(&self.issuer.unit)
                .context("223candidate issuer omitted")?,
            GIB,
            768 << 20,
            "root",
        )?;
        let mut view = current.clone();
        for name in names {
            view.remove(&name);
        }
        let evidence = json!({"schema":"jetstreamer-epoch223-demotion-candidate-accounting-v1","context":self,
            "actors":{"producer":producer,"guard":guard,"issuer":issuer},
            "candidate_memory_max_bytes":self.candidate()?.memory_max_bytes,
            "producer_and_guard_and_issuer_full_caps_charged":true,"allocation_credit_bytes":0,
            "raw_accepted_fleet_unchanged":true,"accepted_producer_removed":false});
        Ok((view, evidence))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    context: Context,
    resource_basis: Value,
    output: PathBuf,
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("compute-demotion223-capacity")?;
    ensure!(unsafe { libc::geteuid() } == 0, "223capacity requires root");
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-epoch223-demotion-capacity-spec-v1"
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::{}", s.context.issuer.cgroup),
        "223capacity must run beneath the exact live issuer"
    );
    let candidate = s.context.candidate()?;
    let capacity =
        maintenance_capacity::check_demotion223(&s.resource_basis, candidate, &s.context)?;
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-epoch223-demotion-capacity-result-v1",
        "spec":private157::binding(&binding),"self_sha256":self_sha,"context":s.context,
        "upstream_accounting_source_commit":"af09802051463086cf8f47de3bf200717d84e094","capacity":capacity,
        "native_execution_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    println!("{}", private157::file_binding(&s.output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn actor(unit: &str, pid: u32, id: &str) -> Actor {
        Actor {
            unit: unit.into(),
            invocation_id: id.repeat(32),
            pid,
            start_ticks: 1,
            cgroup: format!("/system.slice/{unit}"),
            boot_id: "fixture".into(),
            executable: BoundFile {
                path: "/sealed/fixture".into(),
                sha256: "a".repeat(64),
            },
            expected_exec_start: "fixture-only".into(),
        }
    }
    fn context() -> Context {
        let b = BoundFile {
            path: "/sealed/fixture".into(),
            sha256: "a".repeat(64),
        };
        Context {
            job_kind: "bracket".into(),
            phase: "control".into(),
            local_floor_bytes: 245_383_154_903,
            runtime_plan: b.clone(),
            producer: actor(
                "horizon-qualify-223-demotion-bracket-fixture.service",
                11,
                "a",
            ),
            guard: actor("horizon-guard-223-demotion-fixture.service", 12, "b"),
            issuer: actor("horizon-admit-223-demotion-fixture.service", 13, "c"),
            driver_qualification: b.clone(),
            guard_qualification: b,
        }
    }
    #[test]
    fn candidate_charges_all_three_full_caps_without_current_charge_credit() {
        let mut c = context();
        assert_eq!(c.candidate().unwrap().memory_max_bytes, 18 * GIB);
        c.phase = "spawn".into();
        assert_eq!(
            c.candidate().unwrap().memory_max_bytes,
            225_000_000_000 + 2 * GIB
        );
        c.job_kind = "native-input".into();
        c.producer = actor("horizon-native-input-223-demotion-fixture.service", 11, "a");
        assert_eq!(c.candidate().unwrap().memory_max_bytes, 130 * GIB);
    }
    #[test]
    fn accepted_candidate_is_rejected_before_any_host_probe() {
        let c = context();
        let f = json!({"active":[{"producer":{"Id":c.producer.unit}}]});
        let error = c.peer_view(&f, &BTreeMap::new()).unwrap_err().to_string();
        assert!(error.contains("cannot replace or discount an accepted producer"));
    }
    #[test]
    fn foreign_legacy_or_borrowed_actor_cannot_be_a_candidate_exemption() {
        let mut c = context();
        c.producer.unit = prefix223_native20::UNIT.into();
        assert!(c.names().is_err());
        let mut c = context();
        c.issuer.pid = c.producer.pid;
        assert!(c.names().is_err());
        let mut c = context();
        c.guard.invocation_id = c.producer.invocation_id.clone();
        assert!(c.names().is_err());
    }
}
