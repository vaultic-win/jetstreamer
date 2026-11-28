//! Local qualification metadata and normal deployment sealing; no replay or R2 authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, process::Command};

const STATE: &str = "/var/lib/jetstreamer/epoch167-retry6-live166retry7-prepare-20261118-v3";
const SOURCE: &str = "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-prepare-source-20261118-v3";
const RUNTIME: &str = "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-prepare-20261118-v3";
const TARGET: &str = "/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v2/cargo-target/release/prepare";
const REPO: &str = "/home/sol/workspace/jetstreamer";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn bind(path: &str) -> Result<Value> { Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)})) }
fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd.output()?;
    ensure!(out.status.success(), "command failed: {:?}: {}",cmd,String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?)
}
fn write(name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(!name.contains('/'), "leaf only");
    let path = format!("{STATE}/{name}");
    let mut f = OpenOptions::new().create_new(true).write(true).custom_flags(libc::O_NOFOLLOW).mode(0o400).open(&path)?;
    f.write_all(bytes)?; f.sync_all()?; File::open(STATE)?.sync_all()?; bind(&path)
}
fn json_file(name: &str, value: &Value) -> Result<Value> { write(name,&serde_json::to_vec_pretty(value)?) }
fn member(path: &str, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"sha256":sha(&fs::read(path)?),"mode":mode}))
}
fn seal(name: &str, destination: &str, members: Value) -> Result<Value> {
    let plan=json_file(name,&json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members}))?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA,"sealer changed");
    output(Command::new(SEALER).arg(plan["path"].as_str().unwrap()).args(["--plan-sha256",plan["sha256"].as_str().unwrap(),"--self-sha256",SEALER_SHA]))?;
    bind(&format!("{destination}/deployment-seal-receipt.json"))
}
fn native(unit: &str, leaf: &str) -> Result<Value> {
    let raw=output(Command::new("/usr/bin/systemctl").args(["show",unit,"--all"]))?;
    for required in ["Result=success","ExecMainStatus=0","ActiveState=active","SubState=exited"] {
        ensure!(raw.lines().any(|s|s==required),"unit {unit} missing terminal success: {required}");
    }
    write(leaf,raw.as_bytes())
}
fn git(args: &[&str]) -> Result<String> { output(Command::new("git").arg("-C").arg(REPO).args(args)) }
fn run() -> Result<()> {
    ensure!(unsafe {libc::geteuid()} == 0,"Root required");
    let args:Vec<_>=std::env::args().collect();
    ensure!((args.len()==2 && matches!(args[1].as_str(),"source"|"runtime"|"stage"|"cycle"|"close-hash141"|"holding141"))
        || (args.len()==6 && args[1]=="measure") || (args.len()==7 && args[1]=="prepare"),
        "qualify source|runtime|stage|cycle|measure HHMM OBSERVER STATUS NEXT_OBSERVER|prepare HHMM OBSERVER STATUS NEXT_OBSERVER MEASUREMENT");
    let commit=git(&["rev-parse","HEAD"])? .trim().to_owned();
    git(&["merge-base","--is-ancestor",&commit,"origin/account-updates"])?;
    ensure!(git(&["status","--porcelain","--untracked-files=no"])?.is_empty(),"tracked tree changed");
    if args[1]=="source" {
        fs::create_dir(STATE)?; fs::set_permissions(STATE,fs::Permissions::from_mode(0o700))?;
        let old:Value=serde_json::from_slice(&fs::read("/var/lib/jetstreamer/epoch167-retry6-live166retry7-prepare-20261118-v2/source-seal-plan.json")?)?;
        let mut members=Vec::new();
        for m in old["members"].as_array().context("source members")? {
            members.push(member(m["source"].as_str().context("source path")?,m["name"].as_str().context("source name")?,292)?);
        }
        println!("{}",seal("source-seal-plan.json",SOURCE,json!(members))?);
    } else if args[1]=="runtime" {
        let build=native("horizon-167-live166retry7-prepare-build-20261118-v3.service","build-native.txt")?;
        let tests=native("horizon-167-live166retry7-prepare-tests-20261118-v3.service","tests-native.txt")?;
        let log=output(Command::new("/usr/bin/journalctl").args(["-u","horizon-167-live166retry7-prepare-tests-20261118-v3.service","--no-pager","--all","-o","cat"]))?;
        ensure!(log.contains("test result: ok. 298 passed; 0 failed;"),"full test result missing");
        let test_log=write("tests.log",log.as_bytes())?;
        let proof=json!({"schema":"horizon-live166retry7-preparer-build-proof-v1","owner":"/root",
            "primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":167,"attempt":"local3retry6",
            "source_commit":commit,"source_commit_verified_on_origin_account_updates":true,
            "source_seal":bind(&format!("{SOURCE}/deployment-seal-receipt.json"))?,"production":bind(TARGET)?,
            "native":{"build":build,"tests":tests},"tests_passed":298,"tests_failed":0,"test_output":test_log,
            "features":["preparation"],"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false});
        let p=json_file("artifact-proof.json",&proof)?;
        println!("{}",seal("runtime-seal-plan.json",RUNTIME,json!([member(TARGET,"prepare",365)?,member(p["path"].as_str().unwrap(),"artifact-proof.json",292)?]))?);
    } else if args[1]=="stage" {
        let binary=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/target/release/horizon-retry6-167-live166-stage");
        let source=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/src/main.rs");
        let manifest=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml");
        let lock=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.lock");
        let p=json_file("stage-artifact-proof.json",&json!({"source_commit":commit,
            "source_commit_verified_on_origin_account_updates":true,"production":bind(&binary)?,
            "source":bind(&source)?,"manifest":bind(&manifest)?,"lock":bind(&lock)?,
            "replay_launch_authorized":false}))?;
        println!("{}",seal("stage-runtime-seal-plan.json","/usr/local/lib/jetstreamer/horizon-epoch167-live166-stage-20261118-v3",
            json!([member(&binary,"stage",365)?,member(&source,"main.rs",292)?,member(&manifest,"Cargo.toml",292)?,member(&lock,"Cargo.lock",292)?,member(p["path"].as_str().unwrap(),"artifact-proof.json",292)?]))?);
    } else if args[1]=="cycle" {
        let observer="/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root2049-live166-20261118-v1.json";
        let status="/home/sol/.jetstreamer-private/r2-status-receipts/cycle2049-live166-19-20261118-v1/COMPLETED.json";
        let sample:Value=serde_json::from_slice(&fs::read(observer)?)?;
        let audit:Value=serde_json::from_slice(&fs::read(status)?)?;
        ensure!(sample["recorded_at_utc"]=="2026-11-18T20:49:25Z"
            && sample["cadence"]["next_routine_observation_not_before_utc"]=="2026-11-18T21:19:25Z"
            && audit["observer"]==bind(observer)? && audit["authenticated_readback"]==true,
            "exact accepted next cycle required");
        let mut next:Value=serde_json::from_slice(&fs::read("/usr/local/lib/jetstreamer/horizon-live166-observer-config-20261118-v3/next-observer.json")?)?;
        next["previous_sample"]=json!(observer);
        next["not_before_utc"]=sample["cadence"]["next_routine_observation_not_before_utc"].clone();
        next["output"]=json!("/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root2119-live166-20261118-v1.json");
        let next_source=json_file("next-observer.json",&next)?;
        let next_package="/usr/local/lib/jetstreamer/horizon-live166-observer-config-20261118-v4";
        seal("next-observer-seal-plan.json",next_package,json!([member(next_source["path"].as_str().unwrap(),"next-observer.json",292)?]))?;
        let mut cfg:Value=serde_json::from_slice(&fs::read("/var/lib/jetstreamer/epoch167-live166-stage-20261118-v1/stage-config2033.json")?)?;
        let root="/var/lib/jetstreamer/root2054-live166-prepare167-20261118-v1";
        fs::create_dir(root)?;fs::set_permissions(root,fs::Permissions::from_mode(0o700))?;
        cfg["output_root"]=json!(root);
        cfg["observer"]=bind(observer)?;cfg["status_audit"]=bind(status)?;
        cfg["next_observer"]=bind(&format!("{next_package}/next-observer.json"))?;
        cfg["booking_path"]=json!("/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1/ROOT_DATA_BOOKING-20261118T2054Z.json");
        cfg["measurement"]=bind("/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry6/physical-1795035019-1492131.json")?;
        cfg["preparer_image"]=json!(format!("{RUNTIME}/prepare"));
        cfg["preparer_qualification"]=bind(&format!("{STATE}/artifact-proof.json"))?;
        println!("{}",json_file("stage-config2054.json",&cfg)?);
    } else if args[1]=="prepare" || args[1]=="measure" {
        let measure=args[1]=="measure";
        let tag=&args[2];
        ensure!(tag.len()==4 && tag.bytes().all(|b|b.is_ascii_digit()),"four-digit attempt label");
        let root=format!("/var/lib/jetstreamer/root{tag}-live166-prepare167-20261118-v1");
        fs::create_dir(&root)?;fs::set_permissions(&root,fs::Permissions::from_mode(0o700))?;
        let witness_root=format!("{STATE}/native-witness-{tag}");
        fs::create_dir(&witness_root)?;fs::set_permissions(&witness_root,fs::Permissions::from_mode(0o700))?;
        let witness_path=format!("{witness_root}/NATIVE_WITNESS.json");
        let witness_unit=format!("horizon-167-live166retry7-data-witness-{tag}-20261118-v1");
        let mut cfg:Value=serde_json::from_slice(&fs::read(format!("{STATE}/stage-config2054.json"))?)?;
        cfg["observer"]=bind(&args[3])?;
        cfg["status_audit"]=bind(&args[4])?;
        cfg["next_observer"]=bind(&args[5])?;
        cfg["measurement"]=if measure {Value::Null} else {bind(&args[6])?};
        // A measurement cannot launch and does not consume a fresh witness.
        // The preparation route obtains its own short-lived native witness only
        // after the caller supplies the completed physical measurement.
        if !measure {
        let guard=cfg["data_fulfillment"]["runtime"]["path"].as_str().context("guard path")?;
        let guard_sha=cfg["data_fulfillment"]["runtime"]["sha256"].as_str().context("guard SHA")?;
        ensure!(sha(&fs::read(guard)?)==guard_sha,"guard runtime changed");
        output(Command::new("/usr/bin/systemd-run").args(["--wait","--collect","--unit",&witness_unit,
            "--property=Type=oneshot","--property=CPUQuota=200%","--property=MemoryMax=4G","--property=TasksMax=128",
            "--property=LimitNOFILE=1048576",guard,"--qualify-data-witness",
            "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json",
            "--seed-sha256","8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee","--seal",
            "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/deployment-seal-receipt.json",
            "--seal-sha256","611c29b18c52e02fce0be67314cdaae4ff780bea72b0e8e6c22a7dd248dfc24f",
            "--output",&witness_path,"--self-sha256",guard_sha]))?;
        let original_contract=cfg["data_fulfillment"]["contract"]["contract"]["path"].as_str().context("contract path")?;
        let mut contract:Value=serde_json::from_slice(&fs::read(original_contract)?)?;
        contract["qualified_native_witness"]=bind(&witness_path)?;
        let contract_source=json_file(&format!("contract-{tag}.json"),&contract)?;
        let contract_runtime=format!("/usr/local/lib/jetstreamer/horizon-epoch167-live166-data-contract-{tag}-20261118-v1");
        let contract_seal=seal(&format!("contract-seal-plan-{tag}.json"),&contract_runtime,
            json!([member(contract_source["path"].as_str().unwrap(),"contract.json",292)?]))?;
        cfg["data_fulfillment"]["contract"]=json!({"contract":bind(&format!("{contract_runtime}/contract.json"))?,"deployment_seal":contract_seal});
        }
        cfg["output_root"]=json!(root);
        cfg["booking_path"]=json!(format!("/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1/ROOT_DATA_BOOKING-20261118T{tag}Z.json"));
        let c=json_file(&format!("stage-config{tag}.json"),&cfg)?;
        let stage="/usr/local/lib/jetstreamer/horizon-epoch167-live166-stage-20261118-v3/stage";
        let stage_result=output(Command::new(stage).args([c["path"].as_str().unwrap(),"--plan-sha256",c["sha256"].as_str().unwrap(),
            "--self-sha256","52044dca4abdd49a153f7998af0e6197171390c241bd05950cb2a7cc43d2a445"]))?;
        let generated:Value=serde_json::from_str(&stage_result)?;
        let p=&generated["plan"];
        println!("{stage_result}");
        let operation=if measure {"measure"} else {"prepare"};
        let prepare_unit=format!("horizon-167-live166retry7-{operation}-operation-{tag}-20261118-v1");
        let prepare_image=format!("{RUNTIME}/prepare");
        let prepare_sha=sha(&fs::read(&prepare_image)?);
        output(Command::new("/usr/bin/systemd-run").args(["--unit",&prepare_unit,
            "--property=Type=oneshot","--property=RemainAfterExit=yes","--property=CPUQuota=200%",
            "--property=MemoryMax=4G","--property=TasksMax=128","--property=LimitNOFILE=1048576",
            &prepare_image,p["path"].as_str().context("prepare plan")?,"--plan-sha256",p["sha256"].as_str().context("prepare plan SHA")?,
            "--self-sha256",&prepare_sha,if measure {"--measure-only"} else {"--prepare"}]))?;
    } else if args[1]=="close-hash141" {
        let unit="horizon-epoch141-closed-input-hash-20261118-v1.service";
        let iid="24688356ca3f4f5c91ee225680f4d596";
        let captured=native(unit,"hash141-terminal-before-close.txt")?;
        let raw=fs::read_to_string(captured["path"].as_str().unwrap())?;
        ensure!(raw.lines().any(|l|l==format!("InvocationID={iid}"))
            && raw.lines().any(|l|l=="MainPID=0") && raw.lines().any(|l|l=="ControlPID=0")
            && raw.lines().any(|l|l=="Job="),"hash141 exact terminal invocation required");
        let fragment=format!("/run/systemd/transient/{unit}");
        let definition=write("hash141-terminal-fragment.service",&fs::read(&fragment)?)?;
        let journal=output(Command::new("/usr/bin/journalctl").args(["--no-pager","--all","-o","json",&format!("_SYSTEMD_INVOCATION_ID={iid}")]))?;
        let journal=write("hash141-terminal-journal.jsonl",journal.as_bytes())?;
        json_file("hash141-close-intent.json",&json!({"unit":unit,"invocation_id":iid,"before":captured,
            "fragment":definition,"journal":journal,"source_hash_native_history_preserved":true,
            "only_completed_hash_control_stopped":true,"replay_mutations":false,"r2_mutations":false}))?;
        output(Command::new("/usr/bin/systemctl").args(["stop",unit]))?;
        let after=output(Command::new("/usr/bin/systemctl").args(["show",unit,"-p","Id,LoadState,ActiveState,SubState,MainPID,ControlPID"]))?;
        ensure!(after.lines().any(|l|l=="ActiveState=inactive") && after.lines().any(|l|l=="MainPID=0")
            && after.lines().any(|l|l=="ControlPID=0"),"hash141 did not close");
        let after=write("hash141-terminal-after-close.txt",after.as_bytes())?;
        println!("{}",json_file("hash141-close-completion.json",&json!({"unit":unit,"original_invocation_id":iid,
            "after":after,"data_removed":false,"replay_mutations":false,"r2_mutations":false}))?);
    } else if args[1]=="holding141" {
        let source="/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2";
        let hash="7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b";
        let hash_output="/var/lib/jetstreamer/epoch167-disk-fit-recovery-20261118-v1/epoch141-source-sha256.txt";
        ensure!(fs::read_to_string(hash_output)?.trim()==format!("{hash}  {source}"),"completed source digest missing");
        let hash_native=native("horizon-epoch141-closed-input-hash-20261118-v1.service","holding141-hash-native.txt")?;
        use std::os::unix::fs::MetadataExt;
        let m=fs::symlink_metadata(source)?;
        ensure!(m.is_file() && m.dev()==64512 && m.ino()==105526093 && m.uid()==0 && m.gid()==0
            && m.mode()&0o7777==0o444 && m.nlink()==1 && m.len()==189_943_475_031,"closed source identity changed");
        let destination="/usr/local/lib/jetstreamer/horizon-closed141-input-holding-plan-20261118-v1";
        let eligibility=json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":"dev-samjohnson",
            "source":source,"length":m.len(),"sha256":hash,"closed":true,"content_class":"public-chain-artifact",
            "credentials_config_and_logs_excluded":true,"canonical_archive":false,"local_retirement_authorized":false,
            "purpose":"Park the closed compressed epoch141 ledger source while its extracted input remains local, to recover capacity for epoch167 replay. The Rust parker independently rejects live process references and rehashes the source before and after remote readback.",
            "source_hash_native":hash_native,"source_hash_output":bind(hash_output)?,
            "identity":{"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"length":m.len(),"allocated_bytes":m.blocks()*512},
            "restore_route":"Authenticated holding-restore into private staging with a freshly qualified restore admission before epoch141 needs this compressed source again.",
            "rotation_budget":{"candidate_epoch":167,"native_free_bytes":7_261_548_232_704u64,"required_bytes":7_493_617_796_914u64,
                "deficit_bytes":232_069_564_210u64,"potential_reclaim_bytes":m.blocks()*512,"credited_reclaim_bytes":0,
                "restore_overlap_bytes":m.len(),"upload_local_growth_bytes":0,"readback_streamed":true,
                "additional_recovery_required":"Qualify at least 43 GB of duplicate snapshot-cache cleanup; no capacity credit until actual retirement.",
                "transfer_readback_planning_seconds":10800,"restore_planning_seconds":7200},
            "runtime_checkpoint_qualified":false,"replay_launch_authorized":false});
        let e=json_file("holding141-eligibility.json",&eligibility)?;
        let p=json_file("holding141-plan.json",&json!({"schema":"jetstreamer-horizon-holding-park-plan-v2",
            "mapping":bind("/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json")?,
            "eligibility":{"path":format!("{destination}/eligibility.json"),"sha256":e["sha256"]},
            "source":source,"length":m.len(),"sha256":hash}))?;
        seal("holding141-seal-plan.json",destination,json!([member(e["path"].as_str().unwrap(),"eligibility.json",256)?,member(p["path"].as_str().unwrap(),"plan.json",256)?]))?;
        println!("{}",bind(&format!("{destination}/plan.json"))?);
    } else { anyhow::bail!("unknown operation"); }
    Ok(())
}
fn main() { if let Err(e)=run(){ eprintln!("{e:#}"); std::process::exit(1); } }
