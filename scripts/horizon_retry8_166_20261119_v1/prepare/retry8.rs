//! Exact stopped retry7 recovery. No checkpoint reuse, promise ending or deletion.
use super::*;
const STOP166: &str="/var/lib/jetstreamer/retry7-preparation-20261118-v1/epoch166/local3retry7/guard-state-recovery-v2/receipts/stop-completion.json";
const STOP166_SHA:&str="846c5f57fa2600a1aec5ee9ac0d3a32590b97d6982a66cc5db091f2fadda390e";
const INTENT166:&str="/var/lib/jetstreamer/retry7-preparation-20261118-v1/epoch166/local3retry7/guard-state-recovery-v2/receipts/stop-intent.json";
const INTENT166_SHA:&str="68ca26b67441deed9931c84b08d864aadf252613662fac65ee91711df9f1d97d";
const STOP167:&str="/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry6/guard-state/receipts/stop-completion.json";
const STOP167_SHA:&str="7982bdde1db49f77d1fe3bcfd41dc2f8be91ccdd0ed22ee451beac765e48f3ac";
const INTENT167:&str="/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry6/guard-state/receipts/stop-intent.json";
const INTENT167_SHA:&str="f7215f2ca0a510a9468bc9c9b427639e1339bb1fb2e9099a745babe9158f0ee4";
fn exact(path:&str,sha:&str)->Bound{Bound{path:path.into(),sha256:sha.into()}}
fn stopped(c:&Value,i:&Value,iid:&str,intent:&str)->Result<()> {
 ensure!(c["schema"]=="jetstreamer-horizon-standalone-stop-completion-v1"
 && c["producer_invocation_id"]==iid && c["intent"]==intent && c["scratch_deleted"]==false
 && c["terminal"]["invocation_id"]==iid && c["terminal"]["pid"]==0 && c["terminal"]["active"]=="inactive"
 && c["terminal"]["sub"]=="dead" && c["terminal"]["restarts"]==0
 && c["remote_mutations"]==false && c["r2_mutations"]==false
 && i["producer_invocation_id"]==iid && i["reason"]=="DATA-fulfillment-observation-failed"
 && i["sample"]["producer_stop_enabled"]==true,"exact retained terminal predecessor required");Ok(())
}
pub(super) fn shape(p:&Plan)->Result<()> {
 ensure!(p.epoch==166 && p.attempt=="local3retry8" && p.resident_memory.as_ref().is_some_and(|r|r.owners.is_empty()),"retry8 is exact zero-replay recovery");
 for (e,attempt,cp,cs,ip,is,iid) in [
 (166,"local3retry7",STOP166,STOP166_SHA,INTENT166,INTENT166_SHA,"03fa3ce80d8c4769a1e9dec548cdbeca"),
 (167,"local3retry6",STOP167,STOP167_SHA,INTENT167,INTENT167_SHA,"fdfadeb7b76d4760a37983b402fd2771")] {
 stopped(&bound(&exact(cp,cs))?,&bound(&exact(ip,is))?,iid,ip)?;
 for unit in [format!("horizon-qualify-{e}-replacement-{attempt}-20261110-v1.service"),format!("horizon-guard-replacement-{e}-{attempt}-20261110-v1.service"),format!("horizon-guard-replacement-{e}-{attempt}-20261110-v1.timer")] {
 ensure!(p.closed_units.contains(&unit),"terminal producer/guard omitted");
 }
 }
 let proof=bound(p.retry8_precreated_roots.as_ref().context("all next roots must be created before DATA witness")?)?;
 ensure!(proof["schema"]=="horizon-three-next-roots-before-witness-v1" && proof["owner"]=="/root"
 && proof["primary_thread"]==THREAD && proof["remote_mutations"]==false,"wrong precreated roots proof");
 let rows=proof["roots"].as_array().context("precreated roots")?;ensure!(rows.len()==3,"three next lane roots required");
 for (epoch,attempt) in [(166,"local3retry8"),(167,"local3retry7"),(170,"local3retry6")] {
 let path=PathBuf::from(format!("/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1/replacement-{attempt}-20261110-v1"));
 let hits:Vec<_>=rows.iter().filter(|r|r["path"]==path.to_str().unwrap()).collect();ensure!(hits.len()==1,"missing or duplicate next root");
 let m=fs::symlink_metadata(&path)?;ensure!(m.is_dir()&&!m.file_type().is_symlink() && m.uid()==1001 && m.mode()&0o777==0o700
 && hits[0]["device"]==m.dev() && hits[0]["inode"]==m.ino(),"next root identity differs");
 }
 let contract=bound(&Bound{path:p.data_fulfillment.as_ref().context("DATA")?.contract.contract.path.clone(),sha256:p.data_fulfillment.as_ref().unwrap().contract.contract.sha256.clone()})?;
 let witness=bound(&serde_json::from_value(contract["qualified_native_witness"].clone())?)?;
 ensure!(proof["recorded_unix_seconds"].as_u64().context("root time")? <= witness["recorded_unix_seconds"].as_u64().context("native witness time")?,"DATA witness predates next-root creation");
 Ok(())
}
#[cfg(test)]mod tests{use super::*;#[test]fn genuine_stopped_pair_is_bound(){for(cp,cs,ip,is,iid)in[(STOP166,STOP166_SHA,INTENT166,INTENT166_SHA,"03fa3ce80d8c4769a1e9dec548cdbeca"),(STOP167,STOP167_SHA,INTENT167,INTENT167_SHA,"fdfadeb7b76d4760a37983b402fd2771")]{let c=bound(&exact(cp,cs)).unwrap();let i=bound(&exact(ip,is)).unwrap();stopped(&c,&i,iid,ip).unwrap();let mut bad=c;bad["terminal"]["pid"]=json!(1);assert!(stopped(&bad,&i,iid,ip).is_err());}}}
