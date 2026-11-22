//! Epoch 170 cold replay using the two closed AccountsDb trees and the original bank inputs.
use super::*;

pub const EPOCH: u64 = 170;
pub const CAP: u64 = 384 << 30;
const BOOT_SLOT: u64 = 73439777;
const CHECKPOINT_SLOT: u64 = 73871796;
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1";
pub const OLD: &str = "epoch170-retry9-recovery-20261120-v1";
pub const PREVIOUS_GUARD_ARGV: &str =
    "a2fee2fead63561e983cf9cc489962e671ee2b3e6a734d0bf74e4d572b11d4b3";
const PREVIOUS: &str = "replacement-local3retry7-20261110-v1/replacement-local3retry9-20261110-v1";
const OLD_UNIT: &str = "horizon-qualify-170-replacement-local3retry9-20261110-v1.service";
const PRIOR_UNIT: &str = "horizon-qualify-170-replacement-local3retry10-20261121-v1.service";
const PRIOR_IID: &str = "a456b826ce1c4634a2df66d66c5cc07f";
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1";
const INPUTS: &str = "/usr/local/lib/jetstreamer/horizon-standard-local-input170-20261110-v1";
const BOOT: &str = "snapshot-73439777-AAfuW4HhAkKNYunC4zf6ipDSCUYsnVfoLMFrmBeb5Sbs.tar.zst";
const BOOT_SHA: &str = "1fff1c4d4c76f56f7b5ba6ba17f379d7811cddb3e314043829ceb864205cab0a";
const MANIFEST_SHA: &str = "61f9138b49c6db69b6e683214d51c82f042b4afc693ccf71a29972b093f820d8";
const FINGERPRINT: &str = "sha256:a18e763167b4cd47833f89627209ea7b5e08e55de16152df612e2c0d9be05890";
const CHECKPOINT_HASH: &str = "29vpNnumVyQE5dpygpinJJWj7UHXe8zU2H3Z71ojXhke";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const ORIGINAL_ARGV_SHA: &str = "3c15a722a6937816dc824f6656ca8b8dc96cbcdc5e145cf9eebc719846b9a09a";
const CLEAN: &str = "epoch170-closed-accounts-20261122-v1";
const PREDECESSOR: &str = "epoch170-retry10-recovery-20261121-v1";
const ORIGINAL_PROFILE_SHA: &str =
    "1596f281f699b48f4e4c7e65adf1070e4961d604d38997a7747ffe60dc536782";

#[cfg(epoch170_retry11)]
mod generation {
    pub(super) const ROOT_INODE: u64 = 113704962;
    pub(super) const LOG_INODE: u64 = 113704964;
    pub const BASE: &str = "epoch170-retry11-rebook-20261122-v1";
    pub const UNIT: &str = "horizon-qualify-170-replacement-local3retry11-20261122.service";
    pub const TIMER: &str = "horizon-guard-170-replacement-local3retry11-20261122.timer";
    pub const ATTEMPT: &str = "replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry11-20261122";
    pub const GUARD_SHA: &str = "c7d8990d133ff6cb479404ff5fc875780661446bb1aab185265bb37b52e54a40";
    pub const GSEAL: &str = "81cdd3363f2d3d990c52d420dddc5ed854e1a7a9663aa52b21e169bf4352e662";
    pub const CSEAL: &str = "a7f77d90caad5fb8d844fc2c9f631e57dbd42c585267a2a3c8ba93389057acd3";
    pub const CONTRACT: &str = "01c4787ae97e430c2edc027e050be6c556fdbe2c3b0351f9bee42841dab3d8ac";
    pub const WITNESS: &str = "3069ae493d675e446476fca29b156857e355bd6bf5ac8f2c96cf4bcfd290f086";
    pub(super) const ROOT_RECEIPT: &str =
        "8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728";
}
#[cfg(epoch170_retry12)]
#[path = "retry12.rs"]
mod generation;
#[cfg(epoch170_retry13)]
#[path = "retry13.rs"]
mod generation;
#[cfg(any(epoch170_retry12, epoch170_retry13))]
pub use generation::funded_guard_floor;
pub use generation::{ATTEMPT, BASE, CONTRACT, CSEAL, GSEAL, GUARD_SHA, TIMER, UNIT, WITNESS};
use generation::{LOG_INODE, ROOT_INODE, ROOT_RECEIPT};

struct Index(&'static str, u64, u64, i64, i64, &'static str);
const INDEXES: &[Index] = &[
    Index(
        "169/epoch-169-bafyreibnyugrtsptq5qsj6tdweurgpzl55f75t7ku5r7wpxtia6e7gojbm-mainnet-slot-to-cid.index",
        114041069,
        15250890,
        1795159912717265981,
        1795159912727266030,
        "e8516d5682a15a53eeb978db80eb1a2542ec54720265a5f21c7fe43244068b4d",
    ),
    Index(
        "170/epoch-170-bafyreia7an3ku7nhc6mwpqygmsldmq25yli5urrrtf4j75u7k4zwx2psc4-mainnet-cid-to-offset-and-size.index",
        114041072,
        4334770962,
        1795159953596468664,
        1795159953759469473,
        "a11d1eae36a0db51a384b9e7d629305084ccb9d0f4f93038d075819357f10202",
    ),
    Index(
        "170/epoch-170-bafyreia7an3ku7nhc6mwpqygmsldmq25yli5urrrtf4j75u7k4zwx2psc4-mainnet-slot-to-cid.index",
        114041071,
        15077987,
        1795159916839286415,
        1795159916845286445,
        "ab98856c6b438c046f15b420516dac393af9c2f81875c0b78a59ef215c148e80",
    ),
];

include!("../horizon_epoch167_source_index_recovery_20261121_v1/cold_replay_inputs.rs");

mod retry11 {
    use super::*;
    pub(super) fn bootstrap() -> PathBuf {
        Path::new(LANE)
            .join("replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/private/destination-08b5a2ce51e5316cd6a0077cba0f7d6cda7ccfc6c7a8cc92df1e5eb7a49082da/work/root-cohort-170-170/run-3920059-1795265699573104685/scratch/.historical-runtime/jetstreamer-historical-parent-486Uxz/bound-bootstrap")
            .join(BOOT)
    }

    pub(super) fn snapshot(full: bool) -> Result<Value> {
        let path = bootstrap();
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let stamp = |m: fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.ctime(),
                m.ctime_nsec(),
                m.mtime(),
                m.mtime_nsec(),
            )
        };
        let expected = (
            64512, 113907443, 1001, 1003, 0o100600, 1, 2151049662, 1795265711, 833064444,
            1795265711, 833064444,
        );
        ensure!(
            path.canonicalize()? == path && stamp(f.metadata()?) == expected,
            "changed retained epoch 170 bank"
        );
        if full {
            let mut hash = Sha256::new();
            std::io::copy(&mut f, &mut hash)?;
            ensure!(
                format!("{:x}", hash.finalize()) == BOOT_SHA,
                "retained epoch 170 bank checksum differs"
            );
        }
        ensure!(
            stamp(f.metadata()?) == expected && stamp(path.symlink_metadata()?) == expected,
            "bank changed during verification"
        );
        Ok(
            json!({"path":path,"device":64512,"inode":113907443,"length":2151049662u64,"ctime":[1795265711,833064444],"sha256":BOOT_SHA,"generation":1634787467305970u64}),
        )
    }
}

#[cfg(any(epoch170_retry12, epoch170_retry13))]
fn previous_cold_attempt(
    root: &Value,
    directory: &str,
    unit_name: &str,
    timer_name: &str,
    invocation: &str,
    floor_file: &str,
) -> Result<Value> {
    let prior = rt(directory);
    let fr = &root["previous_start_failure"];
    let failure = bound(fr, &prior.join("START_FAILURE.json"))?;
    bound(&root["floor_reconstruction"], &prior.join(floor_file))?;
    let intent = bound(&failure["intent"], &prior.join("START_INTENT.json"))?;
    ensure!(
        failure["producer_invocation_id"] == invocation
            && failure["partial_retained"] == true
            && failure["cgroup"] == json!([])
            && intent["producer_unit"] == unit_name
            && !prior
                .join("ACTUAL_ADMISSION_AND_PROTECTION.json")
                .try_exists()?,
        "previous 170 attempt was admitted or its failure evidence changed"
    );
    for unit in [
        unit_name,
        timer_name,
        &timer_name.replace(".timer", ".service"),
    ] {
        let manager = native(unit)?;
        ensure!(
            manager["ActiveState"] == "inactive"
                && manager["Job"] == ""
                && (unit.ends_with(".timer")
                    || (manager["MainPID"] == "0" && members(unit)?.is_empty())),
            "previous 170 actor or guard remains active"
        );
    }
    Ok(fr.clone())
}

pub fn files() -> Result<Value> {
    let (root, rr) = doc(&base().join("SUCCESSOR_ROOT.json"), Some(ROOT_RECEIPT))?;
    let m = fs::symlink_metadata(run())?;
    ensure!(
        run().canonicalize()? == run()
            && root["root"] == json!(run())
            && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
                == (64512, ROOT_INODE, 1001, 1003, 0o40700)
            && root["prior"]["producer_invocation_id"] == PRIOR_IID
            && root["log"]["inode"] == LOG_INODE,
        "unexpected successor root or predecessor"
    );
    #[cfg(any(epoch170_retry12, epoch170_retry13))]
    let previous_failure = generation::previous_attempt(&root)?;
    let source = doc(
        &rt(PREDECESSOR).join("profile.json"),
        Some(ORIGINAL_PROFILE_SHA),
    )?
    .0;
    ensure!(
        source["epoch"] == EPOCH
            && source["bootstrap"]["sha256"] == BOOT_SHA
            && source["original_argv"]["sha256"] == ORIGINAL_ARGV_SHA,
        "original epoch 170 inputs differ"
    );
    let guard_dir = rt(PREDECESSOR).join("guard-receipts");
    let (stop, sr) = doc(
        &guard_dir.join("stop-completion.json"),
        Some("d670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a"),
    )?;
    let (intent, ir) = doc(
        &guard_dir.join("stop-intent.json"),
        Some("aec8d333e2cb8e6682a4d51304811d5d6407da7d8e118034176809e77abf1c9c"),
    )?;
    ensure!(
        stop["intent"] == ir["path"]
            && stop["producer_invocation_id"] == PRIOR_IID
            && intent["producer_invocation_id"] == PRIOR_IID
            && intent["reason"] == "filesystem-floor"
            && stop["terminal"]["pid"] == 0
            && stop["scratch_deleted"] == false,
        "predecessor stop incomplete"
    );
    for unit in [OLD_UNIT, PRIOR_UNIT] {
        let s = native(unit)?;
        ensure!(
            s["ActiveState"] == "inactive"
                && s["Job"] == ""
                && s["MainPID"] == "0"
                && members(unit)?.is_empty(),
            "previous 170 producer present"
        );
    }
    for (attempt, hash) in [
        (
            "local3retry9",
            "61d9c61e3b9f7a5c18646118929b401a7cf1f1e86b7377ab33d6a319ce9c0f3c",
        ),
        (
            "local3retry10",
            "935ce5e0fb8c6fe9b2373ed1bd2c63e92c30a9afeeae78de9363d5d1cbff2fb9",
        ),
    ] {
        let (v, _) = doc(
            &rt(CLEAN).join("state").join(attempt).join("COMPLETE.json"),
            Some(hash),
        )?;
        ensure!(
            v["attempt"] == attempt
                && v["scope_empty"] == true
                && v["archive_or_snapshot_removed"] == false
                && fs::read_dir(st(&v, "scope")?)?.next().is_none(),
            "charged 170 cleanup changed"
        );
    }
    let (_, manifest) = doc(
        &Path::new(PACKAGE).join("preflight-170-v4.json"),
        Some(MANIFEST_SHA),
    )?;
    let baseline = json!({"predecessor_stop":sr,"predecessor_intent":ir,"stable_roots":rr,"root":{"path":run(),"device":m.dev(),"inode":m.ino()},
        "snapshot":retry11::snapshot(false)?,"manifest":manifest,"profile":profile()?});
    #[cfg(any(epoch170_retry12, epoch170_retry13))]
    let baseline = {
        let mut baseline = baseline;
        baseline["previous_cold_failure"] = previous_failure;
        baseline
    };
    Ok(baseline)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn successor_uses_the_retained_bank_and_original_indexes() {
        let v = files().unwrap();
        let p = &v["profile"];
        assert_eq!(v["root"]["inode"], ROOT_INODE);
        assert_eq!(p["guard_worker_root"], LANE);
        assert_eq!(p["indexes"].as_array().unwrap().len(), 3);
        let argv = p["producer_argv"].as_array().unwrap();
        assert_eq!(argv[argv.len() - 8], node_arg());
        let mount = argv
            .iter()
            .filter_map(Value::as_str)
            .find(|s| s.starts_with("--property=BindReadOnlyPaths="))
            .unwrap();
        assert!(mount.contains(&format!(
            "{}:{INPUTS}/{BOOT}",
            retry11::bootstrap().display()
        )));
        for i in INDEXES {
            assert!(mount.contains(&format!(
                "{}:{}",
                source_index(i).display(),
                target_index(i).display()
            )));
        }
    }
}
