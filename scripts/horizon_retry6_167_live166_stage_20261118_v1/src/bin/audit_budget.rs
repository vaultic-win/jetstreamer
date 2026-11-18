//! Tighten the audit-only memory limit and retain its complete additive booking.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, process::Command};
const ROOT:&str="/var/lib/jetstreamer/r2-audit-additive-budget-20261118-v1";
const UNIT:&str="horizon-r2-chronological-plugin-audit-20261118-v1.service";
const IID:&str="6de50b080c4e48f79dc095d03255d493";
const FLEET:&str="/var/lib/jetstreamer/root2149-live166-observation-20261118-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const ORIGINAL_MEMORY:u64=761_131_708_416;
const RESERVE:u64=17_179_869_184;
const AUDIT_MEMORY:u64=24<<30;
fn sha(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn run(c:&mut Command)->Result<String>{let o=c.output()?;ensure!(o.status.success(),"{c:?}: {}",String::from_utf8_lossy(&o.stderr));Ok(String::from_utf8(o.stdout)?)}
fn save(name:&str,v:&Value)->Result<Value>{let path=format!("{ROOT}/{name}");let bytes=serde_json::to_vec_pretty(v)?;let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(&path)?;f.write_all(&bytes)?;f.sync_all()?;File::open(ROOT)?.sync_all()?;Ok(json!({"path":path,"sha256":sha(&bytes)}))}
fn native()->Result<Value>{let raw=run(Command::new("/usr/bin/systemctl").args(["show",UNIT,"-pId,InvocationID,MainPID,NRestarts,ActiveState,SubState,MemoryCurrent,MemoryPeak,MemoryHigh,MemoryMax,CPUQuotaPerSecUSec,ExecStart,ControlGroup,DropInPaths"]))?;let mut row=serde_json::Map::new();for line in raw.lines(){let(k,v)=line.split_once('=').context("native row")?;ensure!(row.insert(k.into(),json!(v)).is_none(),"duplicate native property");}Ok(json!({"raw":raw,"properties":row}))}
fn main()->Result<()> {
 ensure!(unsafe{libc::geteuid()}==0,"Root required");
 let git=|a:&[&str]|run(Command::new("git").arg("-C").arg("/home/sol/workspace/jetstreamer").args(a));
 let commit=git(&["rev-parse","HEAD"])?;git(&["merge-base","--is-ancestor",commit.trim(),"origin/account-updates"])?;
 ensure!(git(&["status","--porcelain","--untracked-files=no","--","scripts/horizon_retry6_167_live166_stage_20261118_v1"])?.is_empty(),"operator source changed");
 let fleet_bytes=fs::read(FLEET)?;let fleet:Value=serde_json::from_slice(&fleet_bytes)?;
 ensure!(fleet["complete_projected_memory_bytes"]==ORIGINAL_MEMORY,"original promises differ");
 let total=fs::read_to_string("/proc/meminfo")?.lines().find_map(|l|l.strip_prefix("MemTotal:").map(str::to_owned)).context("MemTotal")?.split_whitespace().next().context("memory value")?.parse::<u64>()?.checked_mul(1024).context("memory overflow")?;
 let full=ORIGINAL_MEMORY.checked_add(AUDIT_MEMORY).and_then(|v|v.checked_add(RESERVE)).context("booking overflow")?;
 ensure!(full<=total,"full additive audit memory does not fit");
 let before=native()?;let p=&before["properties"];
 ensure!(p["Id"]==UNIT && p["InvocationID"]==IID && p["MainPID"]=="1568376" && p["ActiveState"]=="active" && p["SubState"]=="running" && p["NRestarts"]=="0"
    && p["MemoryMax"]=="34359738368" && p["MemoryHigh"]=="25769803776" && p["CPUQuotaPerSecUSec"]=="4s","audit predecessor differs");
 ensure!(p["MemoryCurrent"].as_str().context("current memory")?.parse::<u64>()?<8<<30
    && p["MemoryPeak"].as_str().context("peak memory")?.parse::<u64>()?<8<<30,"audit current/peak too close to new cap");
 fs::create_dir(ROOT)?;fs::set_permissions(ROOT,fs::Permissions::from_mode(0o700))?;
 let before=save("before.json",&before)?;
 let intent=save("intent.json",&json!({"schema":"horizon-r2-audit-memory-limit-intent-v1","unit":UNIT,"invocation_id":IID,"before":before,"old_memory_max_bytes":32u64<<30,"new_memory_max_bytes":AUDIT_MEMORY,"new_memory_high_bytes":20u64<<30,"source_commit":commit.trim(),"replay_mutations":false}))?;
 run(Command::new("/usr/bin/systemctl").args(["set-property",UNIT,"MemoryMax=24G","MemoryHigh=20G"]))?;
 let after=native()?;let p=&after["properties"];
 ensure!(p["InvocationID"]==IID && p["MainPID"]=="1568376" && p["ActiveState"]=="active" && p["SubState"]=="running" && p["NRestarts"]=="0"
    && p["MemoryMax"]=="25769803776" && p["MemoryHigh"]=="21474836480" && p["CPUQuotaPerSecUSec"]=="4s","audit limit change failed or identity changed");
 let after=save("after.json",&after)?;
 let allocation=save("allocation.json",&json!({"schema":"horizon-r2-audit-additive-allocation-v1","unit":UNIT,"invocation_id":IID,"source_commit":commit.trim(),"intent":intent,"after":after,
    "original_fleet":{"path":FLEET,"sha256":sha(&fleet_bytes)},"original_complete_projected_memory_bytes":ORIGINAL_MEMORY,
    "additional_audit_memory_bytes":AUDIT_MEMORY,"effective_complete_projected_memory_bytes":ORIGINAL_MEMORY+AUDIT_MEMORY,"memory_reserve_bytes":RESERVE,"effective_memory_plus_reserve_bytes":full,"actual_total_memory_bytes":total,
    "additional_audit_cpu_quota_micros":4_000_000,"audit_root_working_budget_bytes":16u64<<30,"audit_root_archive_cap_bytes":16u64<<30,"audit_root_free_reserve_bytes":32u64<<30,
    "audit_DATA_reservation_bytes":0,"resource_credit_bytes":0,"original_promises_ended":false,"replay_admission_authorized":false,"replay_mutations":false,"r2_mutations":false}))?;
 println!("{allocation}");Ok(())
}
