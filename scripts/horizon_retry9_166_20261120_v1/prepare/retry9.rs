//! Bind the zero-peer restart to the five closed predecessor generations.
use super::*;

const ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root-zero-166167-stop-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json";
const ROOTS_SHA: &str = "d9e8ae44c9726811b2104cac494b4ccc4a5ef3cb7bf56e5cadec6bf6f9b4be89";

struct Stop {
    epoch: u64,
    generation: u64,
    package: &'static str,
    state: &'static str,
    invocation: &'static str,
    completion: &'static str,
    intent: &'static str,
}

const STOPS: &[Stop] = &[
    Stop {
        epoch: 166,
        generation: 7,
        package: "retry7-preparation-20261118-v1",
        state: "guard-state-recovery-v2",
        invocation: "03fa3ce80d8c4769a1e9dec548cdbeca",
        completion: "846c5f57fa2600a1aec5ee9ac0d3a32590b97d6982a66cc5db091f2fadda390e",
        intent: "68ca26b67441deed9931c84b08d864aadf252613662fac65ee91711df9f1d97d",
    },
    Stop {
        epoch: 167,
        generation: 6,
        package: "retry3-preparation-20261113-v1",
        state: "guard-state",
        invocation: "fdfadeb7b76d4760a37983b402fd2771",
        completion: "7982bdde1db49f77d1fe3bcfd41dc2f8be91ccdd0ed22ee451beac765e48f3ac",
        intent: "f7215f2ca0a510a9468bc9c9b427639e1339bb1fb2e9099a745babe9158f0ee4",
    },
    Stop {
        epoch: 166,
        generation: 8,
        package: "retry8-preparation-20261119-v1",
        state: "guard-state-recovery-v2",
        invocation: "4f09db5f45074244a45b06aeef932d1d",
        completion: "b99e26a6836609dc68b4c646eb19ce2b2c0edd0d7547c80b1e0b517be4875b08",
        intent: "f663f933ec2ceba6ed27c9d863a126a23027b16f9bd2d40c4074cae2a61e496c",
    },
    Stop {
        epoch: 167,
        generation: 7,
        package: "retry3-preparation-20261113-v1",
        state: "guard-state",
        invocation: "a680103e76f546faaf469aa80c35fa3b",
        completion: "5b51b01a57f5c717ef6397cad6bcc6b01ac72336e84d02d2b9354c99ee3fd5aa",
        intent: "dd5f515167b27bc1541c73d57e98c2bfab975ee0e1b6ca051be28a4b79f8f946",
    },
    Stop {
        epoch: 170,
        generation: 6,
        package: "retry6-170-preparation-20261118-v1",
        state: "guard-state",
        invocation: "ebd212d2045145259449d1d5c3d65353",
        completion: "3601e2dabb55f7c3ca9ed8f91c253588f301b51a87c42ba9ece18f73fab48264",
        intent: "22344407c7f7f034eae858791636fc0275c7b12c2bee1a5326e18dd1560700fb",
    },
];

impl Stop {
    fn receipts(&self) -> (Bound, Bound) {
        let dir = PathBuf::from(format!(
            "/var/lib/jetstreamer/{}/epoch{}/local3retry{}/{}/receipts",
            self.package, self.epoch, self.generation, self.state
        ));
        (
            Bound {
                path: dir.join("stop-completion.json"),
                sha256: self.completion.into(),
            },
            Bound {
                path: dir.join("stop-intent.json"),
                sha256: self.intent.into(),
            },
        )
    }

    fn validate(&self, completion: &Value, intent: &Value, intent_path: &Path) -> Result<()> {
        let terminal = &completion["terminal"];
        ensure!(
            completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
                && completion["intent"] == intent_path.to_str().context("intent path")?
                && completion["producer_invocation_id"] == self.invocation
                && terminal["invocation_id"] == self.invocation
                && terminal["active"] == "inactive"
                && terminal["sub"] == "dead"
                && terminal["pid"] == 0
                && terminal["restarts"] == 0
                && completion["scratch_deleted"] == false
                && completion["remote_mutations"] == false
                && completion["r2_mutations"] == false
                && intent["producer_invocation_id"] == self.invocation
                && intent["reason"] == "DATA-fulfillment-observation-failed"
                && intent["sample"]["producer_stop_enabled"] == true,
            "closed predecessor evidence differs for epoch {} retry{}",
            self.epoch,
            self.generation
        );
        Ok(())
    }
}

pub(super) fn shape(p: &Plan) -> Result<()> {
    ensure!(
        p.epoch == 166
            && p.attempt == "local3retry9"
            && p.resident_memory
                .as_ref()
                .is_some_and(|r| r.owners.is_empty()),
        "166 retry9 requires the zero-peer resource profile"
    );
    for s in STOPS {
        let (completion, intent) = s.receipts();
        s.validate(&bound(&completion)?, &bound(&intent)?, &intent.path)?;
        let e = s.epoch;
        let g = s.generation;
        for name in [
            format!("horizon-qualify-{e}-replacement-local3retry{g}-20261110-v1.service"),
            format!("horizon-guard-replacement-{e}-local3retry{g}-20261110-v1.service"),
            format!("horizon-guard-replacement-{e}-local3retry{g}-20261110-v1.timer"),
        ] {
            ensure!(
                p.closed_units.contains(&name),
                "missing closed predecessor {name}"
            );
        }
    }
    let b = p
        .retry9_precreated_roots
        .as_ref()
        .context("three successor roots receipt required")?;
    ensure!(
        b.path == Path::new(ROOTS) && b.sha256 == ROOTS_SHA,
        "wrong precreation binding"
    );
    let proof = bound(b)?;
    ensure!(
        proof["owner"] == "/root"
            && proof["active_replay_workers"] == 0
            && proof["replay_admission"] == false,
        "wrong precreation proof"
    );
    let roots = proof["roots"].as_array().context("three successor roots")?;
    ensure!(roots.len() == 3, "wrong root count");
    let home = fs::metadata("/home/sol")?;
    for ((epoch, generation), row) in [(166, 9), (167, 8), (170, 7)].into_iter().zip(roots) {
        let path = PathBuf::from(format!(
            "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1/replacement-local3retry{generation}-20261110-v1"
        ));
        let stat = directory(&path)?.metadata()?;
        ensure!(
            row["path"] == path.to_str().context("root path")?
                && row["epoch"] == epoch
                && stat.dev() == home.dev()
                && row["dev"] == stat.dev()
                && row["ino"] == stat.ino()
                && stat.uid() == 1001
                && stat.gid() == 1003
                && stat.mode() & 0o7777 == 0o700,
            "precreated root identity changed: {}",
            path.display()
        );
    }
    let b = &p
        .data_fulfillment
        .as_ref()
        .context("DATA proof required")?
        .contract
        .contract;
    let contract = bound(&Bound {
        path: b.path.clone(),
        sha256: b.sha256.clone(),
    })?;
    let witness = bound(&serde_json::from_value(
        contract["qualified_native_witness"].clone(),
    )?)?;
    ensure!(
        witness["recorded_unix_seconds"]
            .as_u64()
            .context("guard witness time")?
            >= proof["captured"].as_u64().context("precreation time")?,
        "guard witness predates successor roots"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn five_native_stops_verify_and_reject_a_live_predecessor() {
        for s in STOPS {
            let (c, i) = s.receipts();
            let mut completion = bound(&c).unwrap();
            let intent = bound(&i).unwrap();
            s.validate(&completion, &intent, &i.path).unwrap();
            completion["terminal"]["pid"] = json!(1);
            assert!(s.validate(&completion, &intent, &i.path).is_err());
        }
    }
}
