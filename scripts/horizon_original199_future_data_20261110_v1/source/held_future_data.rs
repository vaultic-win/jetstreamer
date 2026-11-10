//! Scoped auxiliary census of the unchanged held original199 family.
//! Never a current Frame/Reader, physical retirement, or admission constructor.
use crate::{ContextInputs,census_capture,fsutil as f,model::*,original_discovery,registration,validate};
use anyhow::{Result,ensure};
use serde_json::{Value,json};
use std::{path::Path,time::{SystemTime,UNIX_EPOCH}};
pub fn held_future_data_census(held:&Bound,accounting:&Bound)->Result<Value>{
 ensure!(held.path==Path::new("/var/lib/jetstreamer/horizon-original199-parent-memory-selection-v1/e6a0713f158869752e84560f11f52d52a7f9dfb405038e5ee2d4af031e6b2334/select-1/selection.json")&&held.sha256=="04a6c68f71a4a3a763a2a529b72b3eaa14b82728bfa46919073eb12098074b92","exact held original199 parent selection required");
 ensure!(accounting.path==Path::new("/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/e6a0713f158869752e84560f11f52d52a7f9dfb405038e5ee2d4af031e6b2334-cold185-722adc397ae24bb4b96d452783599f57/raw-accounting.json")&&accounting.sha256=="d783309cf31a26a572b0ad9113c154e4c86604fe1c8a8f882b17f3a6285f7274","exact unchanged held raw accounting required");
 let h=f::immutable(held)?;let raw=f::json(accounting)?;ensure!(h["schema"]=="terminal199-parent-memory-selector-original-execution-v1"&&h["actual_native_capability_passed"]==true,"genuine old parent acceptance required");let s=&h["selection"];
 ensure!(s["raw_accounting_serde_json_sha256"]==f::sha(&serde_json::to_vec(&raw)?)&&s["retained_original199_DATA_bytes"]==DATA&&s["DATA_credit_bytes"]==0&&s["all_DATA_promises_preserved"]==true,"held raw DATA already reduced or crossed");
 let request:Request=serde_json::from_value(s["request"].clone())?;let policy=registration(&request)?;let inputs=ContextInputs::for_current(&policy,&request.current)?;
 let original_row=validate::terminal_raw_row_for_context(&raw,&inputs)?;let reader=f::json(&request.current_reader)?;let discovery=original_discovery::OriginalDiscovery::from_reader(&reader)?;
 validate::failed_state(&inputs.state(&policy.quarantined_state)?)?;
 census_capture::recheck(&policy,&raw,&inputs,discovery.as_ref())?;
 Ok(json!({"schema":"original199-held-family-future-DATA-auxiliary-census-v1","recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"held_parent_selection":held,"held_raw_accounting":accounting,"original_row":original_row,"policy":policy,"original_held_tuple":request.current,"current_scoped_source_state_native_queue_process_and_directory_anchor_checks_passed":true,"all_existing_raw_memory_and_DATA_preserved":true,"historical_tuple_is_not_fresh_resource_evidence":true,"native_Frame_or_full_Reader_acceptance_claimed":false,"physical_credit_bytes":0,"DATA_credit_bytes":0,"replay_launch_authorized":false}))
}
