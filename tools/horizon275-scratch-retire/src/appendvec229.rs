//! Retire the RAM copy of epoch 229 v1 AccountsDb after checked disk staging.
use super::{
    appendvec288::{journal_event, lock_issuer},
    parked_accounts::{self, sealed},
    snapshot288::Stamp,
    *,
};

const RUN: &str = "/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v1/run";
const TARGET: &str = "output/.historical-runtime/jetstreamer-historical-parent-O7Clmc/jetstreamer-historical-v1.6.20-iXcpFP/accounts-state";
const PARTIAL: &str = "output/epoch-229-program-demotion-diagnostic.jet";
const PARTIAL_SHA: &str = "b8fac8f4d574226c520b9b6111fbbe937499d0291a5326e34ab8ec7f742b7d03";
const DONOR: &str = "/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v2/run/output/epoch-229-program-demotion-diagnostic.jet";
const DONOR_SHA: &str = "92ae7627d57e1c75d2be8898d146fd09c76947d4b06201d8b7fc52913f296359";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon229-called-program-demotion-v1/terminal.json";
const TERMINAL_SHA: &str = "cd8eb4a2ae2da0210ac54f954858be2b59f09304193d9383466c50f45f66c2b6";
const SUCCESSOR: &str = "/var/lib/jetstreamer/horizon229-called-program-demotion-v2/terminal.json";
const SUCCESSOR_SHA: &str = "7589e1bb05fac416d7694b5029e41115382afe18336e9edec8a1a4f9294a552b";
const STAGE: &str = "/var/lib/jetstreamer/horizon229-v1-accounts-custody-v1";
const STAGE_UNIT: &str = "foundation-229-closed-accounts-stage-v1.service";
const BUNDLE: &str = "epoch-229-closed-accounts.pax.zst";
const STATE: &str = "/var/lib/jetstreamer/horizon229-v1-accounts-retirement-v1";
const PRODUCER: &str = "horizon-qualify-229-called-program-demotion-v1.service";
const GUARD: &str = "horizon-229-called-program-demotion-protective-v1.service";
const TIMER: &str = "horizon-229-called-program-demotion-protective-v1.timer";
const CENSUS_SHA: &str = "1ba93110f4fc2228ff4d5112f3e6b6b4a3c9748569473c6bebceaa2fc00b6306";
const FILES: usize = 372_299;
const ALLOCATION: u64 = 153_204_084_736;
const DEVICE: u64 = 160;
const INODE: u64 = 406_824;

fn stage_invocation(receipt: &Binding, staged: &Value) -> Result<Binding> {
    let start_path = Path::new(STAGE).join("start.json");
    let start_ref = sealed(&start_path, JSON_LIMIT)?;
    let start: Value = read_bound(&start_path, &start_ref.sha256, JSON_LIMIT)?;
    let admission: Binding = serde_json::from_value(start["admission"].clone())?;
    let admission_json: Value = read_bound(&admission.path, &admission.sha256, JSON_LIMIT)?;
    let binary: Binding = serde_json::from_value(start["binary"].clone())?;
    let invocation = start["owner"]["InvocationID"]
        .as_str()
        .context("missing staging invocation")?;
    let pid = start["owner"]["MainPID"]
        .as_str()
        .context("missing staging PID")?;
    ensure!(
        start["schema"] == "foundation-epoch229-local-accounts-stage-start-v1"
            && start["owner"]["Id"] == STAGE_UNIT
            && start["owner"]["ControlGroup"] == format!("/system.slice/{STAGE_UNIT}")
            && start["retirement_authorized"] == false
            && start["remote_mutations"] == false
            && invocation.len() == 32
            && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
            && staged["invocation_id"] == invocation
            && staged["pid"].as_u64() == Some(pid.parse()?)
            && admission.path == Path::new(STAGE).join("admission.json")
            && staged["admission_sha256"] == admission.sha256
            && admission_json["admitted"] == true
            && admission_json["unit"] == STAGE_UNIT
            && admission_json["source_census_sha256"] == CENSUS_SHA
            && sealed(&binary.path, 128 << 20)?.sha256 == binary.sha256,
        "stage report, invocation, or admitted implementation differs"
    );
    terminal_unit(STAGE_UNIT)?;
    let binary_path = binary.path.to_str().context("non-UTF-8 stage image path")?;
    let started = journal_event(&[
        "_PID=1".into(),
        format!("UNIT={STAGE_UNIT}"),
        format!("INVOCATION_ID={invocation}"),
        format!("MESSAGE=Started {STAGE_UNIT} - [systemd-run] {binary_path} stage-229."),
    ])?;
    let manager = journal_event(&[
        "_PID=1".into(),
        format!("UNIT={STAGE_UNIT}"),
        format!("INVOCATION_ID={invocation}"),
        format!("MESSAGE={STAGE_UNIT}: Deactivated successfully."),
    ])?;
    let report = journal_event(&[
        format!("_PID={pid}"),
        format!("_SYSTEMD_UNIT={STAGE_UNIT}"),
        format!("_SYSTEMD_INVOCATION_ID={invocation}"),
        format!("MESSAGE={}", receipt.path.display()),
    ])?;
    ensure!(
        started["_SYSTEMD_UNIT"] == "init.scope"
            && manager["_SYSTEMD_UNIT"] == "init.scope"
            && report["_SYSTEMD_CGROUP"] == start["owner"]["ControlGroup"]
            && report["_UID"] == "0"
            && report["_TRANSPORT"] == "stdout"
            && (report["_EXE"].is_null() || report["_EXE"] == binary_path),
        "stage report did not come from the clean exact invocation"
    );
    Ok(start_ref)
}

fn checked_asset(path: &Path, sha: &str, rehash: bool) -> Result<(Metadata, Stamp)> {
    let mut file = open_regular(path)?;
    let metadata = file.metadata()?;
    let stamp = Stamp::of(&metadata)?;
    if rehash {
        ensure!(
            digest(&mut file)? == sha && stamp == Stamp::of(&file.metadata()?)?,
            "retained bytes changed: {path:?}"
        );
    }
    stamp.at(path)?;
    Ok((metadata, stamp))
}

pub(super) fn run(apply: bool, self_sha: &str, receipt: Binding) -> Result<()> {
    let run = Path::new(RUN);
    let target = run.join(TARGET);
    let partial = run.join(PARTIAL);
    let donor = Path::new(DONOR);
    let bundle = Path::new(STAGE).join(BUNDLE);
    ensure!(
        receipt.path == Path::new(STAGE).join("staged.json")
            && sealed(&receipt.path, JSON_LIMIT)?.sha256 == receipt.sha256,
        "require the exact sealed stage receipt"
    );
    let staged: Value = read_bound(&receipt.path, &receipt.sha256, JSON_LIMIT)?;
    ensure!(
        staged["schema"] == "foundation-epoch229-locally-checked-accounts-stage-v1"
            && staged["epoch"] == 229
            && staged["unit"] == STAGE_UNIT
            && staged["source"].as_str() == target.to_str()
            && staged["source_census_sha256"] == CENSUS_SHA
            && staged["members"] == FILES
            && staged["terminal_sha256"] == TERMINAL_SHA
            && staged["successor_terminal_sha256"] == SUCCESSOR_SHA
            && staged["bundle"].as_str() == bundle.to_str()
            && staged["full_sparse_comparison_matches"] == true
            && staged["partial"].as_str() == partial.to_str()
            && staged["partial_sha256"] == PARTIAL_SHA
            && staged["readers_before"]["references"] == json!([])
            && staged["readers_after"]["references"] == json!([])
            && staged["remote_mutations"] == false
            && staged["retirement_authorized"] == false,
        "stage proof does not match the closed source"
    );
    let start = stage_invocation(&receipt, &staged)?;
    let sha = staged["sha256"]
        .as_str()
        .context("missing bundle SHA-256")?;
    let (bundle_meta, bundle_stamp) = checked_asset(&bundle, sha, !apply)?;
    let (partial_meta, partial_stamp) = checked_asset(&partial, PARTIAL_SHA, !apply)?;
    let (donor_meta, donor_stamp) = checked_asset(donor, DONOR_SHA, !apply)?;
    ensure!(
        (partial_meta.dev(), partial_meta.ino(), partial_meta.len())
            == (DEVICE, 746_044, 2_510_240_156)
            && (donor_meta.dev(), donor_meta.ino(), donor_meta.len())
                == (162, 745_909, 3_667_632_797)
            && bundle_meta.dev() == Path::new("/").metadata()?.dev()
            && bundle_meta.uid() == 0
            && bundle_meta.mode() & 0o7777 == 0o400
            && bundle_meta.len() > 0
            && bundle_meta.len() < (96 << 30)
            && staged["length"] == bundle_meta.len(),
        "retained archive or disk bundle identity differs"
    );

    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    for unit in [PRODUCER, GUARD, TIMER, STAGE_UNIT] {
        terminal_unit(unit)?;
    }
    let original: Value = read_bound(Path::new(TERMINAL), TERMINAL_SHA, JSON_LIMIT)?;
    let successor: Value = read_bound(Path::new(SUCCESSOR), SUCCESSOR_SHA, JSON_LIMIT)?;
    ensure!(
        original["epoch"] == 229
            && original["partial"]["path"].as_str() == partial.to_str()
            && original["partial"]["complete"] == false
            && original["publication_authorized"] == false
            && successor["epoch"] == 229
            && successor["terminal_slot"] == 98_939_266
            && successor["terminal_accounts_root_verified"] == true
            && successor["archive"]["path"].as_str() == donor.to_str()
            && successor["archive"]["sha256"] == DONOR_SHA,
        "predecessor or successor evidence differs"
    );
    let check_preserved = || {
        bundle_stamp.at(&bundle)?;
        partial_stamp.at(&partial)?;
        donor_stamp.at(donor)
    };
    check_preserved()?;
    let state = Path::new(STATE);
    let meta = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o777 == 0o700,
        "unsafe retirement state"
    );
    let root = stopped_tree::open_root(&target, DEVICE, INODE)?;
    let mut mount: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(root.as_raw_fd(), &mut mount) } == 0
            && mount.f_type == libc::TMPFS_MAGIC,
        "retirement source is not tmpfs"
    );
    assert_no_nested_mount(&target)?;
    let mount_root = run.parent().context("missing epoch 229 tmpfs root")?;
    let scheduled = scheduled(mount_root, &target)?;
    let processes = process_references::scan(Path::new("/proc"), &target)?;
    ensure!(
        processes.inspected_processes > 0 && processes.references.is_empty(),
        "live epoch 229 source reference"
    );
    parked_accounts::run(
        apply,
        parked_accounts::Tree {
            epoch: 229,
            state,
            root: &root,
            target: &target,
            device: DEVICE,
            files: FILES,
            allocation: ALLOCATION,
            census_sha: CENSUS_SHA,
            anchors: json!({"self_sha256":self_sha,"stage_receipt":receipt,"stage_start":start,
            "target":target,"device":DEVICE,"inode":INODE,"disk_bundle":bundle_stamp,
            "original_partial":partial_stamp,"verified_donor":donor_stamp}),
            readers: json!({"scheduled":scheduled,"processes":processes}),
        },
        check_preserved,
    )
}
