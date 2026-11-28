//! Native finite DATA-selector receipt writer. No launch or R2 access.
#![deny(warnings)]
#[allow(dead_code)]
mod fsutil;
mod native;
mod selection_clock;
use anyhow::{Context, Result, ensure};
use horizon_original199_parent_memory as parent;
use horizon_terminal183_ended_data as data;
use model::Bound;
pub use parent::model;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-witness-ended183-DATA-selector-tools-20261107-v1/ended183-data";
const UNIT: &str = "horizon-epoch183-ended-DATA-select-20261105-v1.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    memory_selection: Bound,
    memory_original_completion: Bound,
    data_policy: Bound,
    data_policy_seal: Bound,
    output_directory: std::path::PathBuf,
}
fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root DATA selector required"
    );
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "loader overrides forbidden"
    );
    let av = env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        av.len() == 8
            && av[0] == "select"
            && av[2] == "--plan-sha256"
            && av[4] == "--self-sha256"
            && av[6] == "--output",
        "select PLAN --plan-sha256 SHA --self-sha256 SHA --output NEW_RECEIPT"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: av[5].clone(),
    };
    ensure!(
        image.path == Path::new(IMAGE),
        "DATA selector normal namespace differs"
    );
    let raw = fsutil::bytes(&image, 128 << 20, true)?;
    let mut mapped = File::open("/proc/self/exe")?;
    let m = mapped.metadata()?;
    let n = fsutil::open(&image.path)?.metadata()?;
    let mut actual = Vec::new();
    Read::by_ref(&mut mapped)
        .take((128 << 20) + 1)
        .read_to_end(&mut actual)?;
    ensure!(
        raw.starts_with(b"\x7fELF") && actual == raw && (m.dev(), m.ino()) == (n.dev(), n.ino()),
        "DATA mapped/canonical bytes or inode differs"
    );
    let plan = Bound {
        path: av[1].clone().into(),
        sha256: av[3].clone(),
    };
    let p: Plan = serde_json::from_value(fsutil::immutable(&plan)?)?;
    ensure!(
        p.schema == "epoch183-native-current-ended-DATA-selection-plan-v1",
        "DATA selector plan schema"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        fsutil::hex(&iid, 32),
        "DATA selector actual invocation absent"
    );
    let before = native::native(&iid)?;
    let original = fsutil::immutable(&p.memory_selection)?;
    let completion = fsutil::immutable(&p.memory_original_completion)?;
    ensure!(
        original["schema"] == "terminal199-parent-memory-selector-original-execution-v1"
            && original["capability_only"] == false
            && completion["schema"] == "epoch163-parent-memory-selector-original-completion-v1"
            && completion["receipt"] == json!(p.memory_selection)
            && completion["invocation_id"] == original["invocation_id"]
            && completion["result"] == "success"
            && completion["exec_main_status"] == 0
            && completion["original_outer_reaped"] == true
            && completion["original_cgroup_empty"] == true
            && completion["original_descriptors_drained"] == true,
        "genuine completed memory selector required"
    );
    let request: parent::model::Request =
        serde_json::from_value(original["selection"]["request"].clone())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let view = parent::admission_bridge::from_current_reader(&request, now)?;
    selection_clock::validate(&original["selection"], view.evidence(), now)?;
    let selected = data::select(&view, &p.data_policy, &p.data_policy_seal, now)?;
    let after = native::native(&iid)?;
    ensure!(before == after, "DATA selector invocation changed");
    let output = Path::new(&av[7]);
    let parent = output.parent().context("DATA output parent")?;
    let expected =
        std::path::PathBuf::from("/var/lib/jetstreamer/horizon-ended183-DATA-selection-v1")
            .join(&request.current.observer.sha256);
    ensure!(
        p.output_directory == expected
            && parent == expected
            && output == expected.join("selection.json"),
        "DATA selector exact current output namespace differs"
    );
    let dir = fsutil::open(parent)?;
    let dm = dir.metadata()?;
    ensure!(
        dm.is_dir() && dm.uid() == 0 && dm.mode() & 0o777 == 0o700,
        "DATA output parent is not root0700"
    );
    let proof = json!({"schema":"epoch183-native-ended-DATA-selector-original-execution-v1","program":image,"plan":plan,"unit":UNIT,"invocation_id":iid,
        "native_before":before,"native_after":after,"recorded_unix_seconds":now,"memory_selection":p.memory_selection,"data_selection":selected.evidence(),
        "raw_protected_DATA_bytes":selected.raw_protected_bytes(),"effective_protected_DATA_bytes":selected.effective_protected_bytes(),
        "memory_effective_total_bytes":view.effective_total_bytes(),"actual_native_capability_passed":true,"physical_credit_bytes":0,"memory_credit_bytes":0,
        "replay_launch_authorized":false,"admission_authorized":false,"archive_retirement_authorized":false,"r2_mutations":false});
    let mut bytes = serde_json::to_vec_pretty(&proof)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 32 << 20, "DATA receipt size bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    dir.sync_all()?;
    println!(
        "{}",
        json!({"receipt":{"path":output,"sha256":fsutil::sha(&bytes)},"effective_protected_DATA_bytes":selected.effective_protected_bytes(),"replay_admission":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ended183 DATA selector rejected evidence: {e:#}");
        std::process::exit(1);
    }
}
