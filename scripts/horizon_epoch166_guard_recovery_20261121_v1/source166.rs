//! Original epoch 166 cold bootstrap, completed input caches, and stopped-generation evidence.
use super::*;

#[cfg(epoch166_retry11)]
#[path = "retry11.rs"]
mod retry11;
#[cfg(epoch166_retry11)]
use retry11::LOG_INODE;
#[cfg(all(test, epoch166_retry11))]
use retry11::ROOT_INODE;
#[cfg(epoch166_retry11)]
pub(crate) use retry11::{
    ATTEMPT, BASE, CONTRACT, CSEAL, GSEAL, GUARD_SHA, TIMER, UNIT, WITNESS, holding_complete,
};
#[cfg(not(epoch166_retry11))]
const ROOT_INODE: u64 = 93782017;
#[cfg(not(epoch166_retry11))]
const LOG_INODE: u64 = 93782020;
pub const EPOCH: u64 = 166;
#[cfg(not(epoch166_retry11))]
pub const BASE: &str = "epoch166-independent-cold-recovery-20261121-v1";
#[cfg(not(epoch166_retry11))]
pub const UNIT: &str = "horizon-qualify-166-independent-recovery-20261121-v1.service";
#[cfg(not(epoch166_retry11))]
pub const TIMER: &str = "horizon-guard-166-independent-recovery-20261121-v1.timer";
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
#[cfg(not(epoch166_retry11))]
pub const ATTEMPT: &str = "replacement-local3retry10-20261121-v1";
pub const OLD: &str = "epoch166-independent-cold-20261120-v1";
pub const CAP: u64 = 288 << 30;
pub const PREVIOUS_GUARD_ARGV: &str =
    "d9065f60a113cec3b3562aba6717cd0908673546c1c5864332cf6de39d1ef5f2";
const OLD_UNIT: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
#[cfg(not(epoch166_retry11))]
const OLD_IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
const PREVIOUS: &str = "replacement-local3retry9-20261110-v1";
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1";
const INPUTS: &str = "/usr/local/lib/jetstreamer/horizon-standard-local-input166-20261110-v1";
const BOOT: &str = "snapshot-71711708-73JLv83cyRgHUNxtajhwXimfDSH4GUmu6R8LHKPbxu76.tar.zst";
const BOOT_SHA: &str = "1e8fa388737b80a9e2218cd09f2fee43b064e19a65e26e466abda25d5e3688f4";
const MANIFEST_SHA: &str = "c632ae8d95748f563d8c47db587afa9139b165298004c3fa6820332c4d89b6b4";
const FINGERPRINT: &str = "sha256:08b441e89d7c9456aba5026ce206db8e08a14f96cb31cbad94a4a5c5e6e5622b";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const ORIGINAL_ARGV_SHA: &str = "4ef45e34b3a21f03eeda2115d371de1558e8e0e70574f64897f8d5b9be7ff893";
#[cfg(not(epoch166_retry11))]
const ROOTS_SHA: &str = "cc7d780afe3d0180de6785cdad4f1e38e70feb82df1c95d21ab342c5974782e2";

struct Index(&'static str, u64, u64, i64, i64, &'static str);
const INDEXES: &[Index] = &[
    Index(
        "165/epoch-165-bafyreibtqc7jzj5pyctcpa5a6cwqm5r3nzbx2nlhesvwau3merpsonx76i-mainnet-slot-to-cid.index",
        95882408,
        15490506,
        1795147200507752811,
        1795147200518752861,
        "ce8778e9da2f309ce9872a1db794b48ab5a31ff6fdf90ee42c657ea8ec29889a",
    ),
    Index(
        "166/epoch-166-bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe-mainnet-slot-to-cid.index",
        95882413,
        15281271,
        1795147205066773533,
        1795147205073773565,
        "230bffbd50eac3f7a45d5b60f6f3a260a3cc1e0eb0f9f9a14e7ffa564256658f",
    ),
    Index(
        "166/epoch-166-bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe-mainnet-cid-to-offset-and-size.index",
        95882417,
        4196268262,
        1795147238350924786,
        1795147239634930619,
        "faf457fe25a5fcef1451942a6118f91b39d0d352488257b01de8f80b8783b49b",
    ),
];

const BOOT_SLOT: u64 = 71711708;
const CHECKPOINT_SLOT: u64 = 72143703;
const CHECKPOINT_HASH: &str = "CJEQdfn6zGqx4da6wL7CqgDhNAEij9tCPz7CrY9ZWH1a";

include!("../horizon_epoch167_source_index_recovery_20261121_v1/cold_replay_inputs.rs");

#[cfg(epoch166_retry11)]
pub fn files() -> Result<Value> {
    retry11::files()
}
#[cfg(not(epoch166_retry11))]
pub fn files() -> Result<Value> {
    let (roots, rr) = doc(&base().join("ROOTS_BEFORE_WITNESS.json"), Some(ROOTS_SHA))?;
    let m = fs::symlink_metadata(run())?;
    ensure!(
        run().canonicalize()? == run()
            && m.dev() == 64512
            && m.ino() == ROOT_INODE
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700
            && roots["root"] == json!(run())
            && roots["replay_launch_authorized"] == false,
        "different permanent recovery root"
    );
    let p = rt(OLD).join("preparation/epoch166/local3retry9/guard-state/receipts");
    let (stop, sr) = doc(
        &p.join("stop-completion.json"),
        Some("21b336b726372a48993ac5d302671aad001f8d41791c29c75be4fd0e465ced04"),
    )?;
    let (intent, ir) = doc(
        &p.join("stop-intent.json"),
        Some("21bee05b4efba487e0005f608c53ccff356131a3b0d32d93eea9ca87221ae81a"),
    )?;
    ensure!(
        intent["producer_invocation_id"] == OLD_IID
            && stop["producer_invocation_id"] == OLD_IID
            && stop["terminal"]["sub"] == "dead"
            && stop["intent"] == ir["path"]
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && stop["scratch_deleted"] == false,
        "stopped generation differs"
    );
    let old = native(OLD_UNIT)?;
    ensure!(
        old["ActiveState"] == "inactive"
            && old["MainPID"] == "0"
            && old["Job"] == ""
            && members(OLD_UNIT)?.is_empty(),
        "old epoch 166 owner present"
    );
    let (_, manifest) = doc(
        &Path::new(PACKAGE).join("preflight-166-v4.json"),
        Some(MANIFEST_SHA),
    )?;
    let bootstrap = Path::new(INPUTS).join(BOOT);
    let bm = fs::symlink_metadata(&bootstrap)?;
    ensure!(
        bm.uid() == 0
            && bm.mode() & 0o222 == 0
            && bm.len() == 1968014870
            && bootstrap.canonicalize()? == bootstrap,
        "foreign snapshot"
    );
    Ok(
        json!({"predecessor_stop":sr,"predecessor_intent":ir,"stable_roots":rr,"root":{"path":run(),"device":m.dev(),"inode":m.ino()},
        "snapshot":{"path":bootstrap,"device":bm.dev(),"inode":bm.ino(),"length":bm.len(),"ctime":[bm.ctime(),bm.ctime_nsec()],"sha256":BOOT_SHA,"generation":1634787359098769u64},
        "manifest":manifest,"profile":profile()?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_epoch166_bound_inputs_and_closed_continuation() {
        let v = files().unwrap();
        assert_eq!(v["root"]["inode"], ROOT_INODE);
        assert_eq!(v["snapshot"]["length"], 1968014870);
        assert_eq!(v["profile"]["indexes"].as_array().unwrap().len(), 3);
        assert_eq!(v["profile"]["producer_argv"][0], "/usr/bin/systemd-run");
        assert_eq!(
            node_arg(),
            "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node"
        );
    }
}
