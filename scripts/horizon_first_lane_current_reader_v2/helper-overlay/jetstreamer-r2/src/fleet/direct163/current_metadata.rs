//! Exact versioned post-custody epoch163 metadata binding. No authentication or mutation.
use super::{Bound, Spec, protected};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

pub(super) const LEGACY_PATH: &str = "/home/sol/.jetstreamer-private/epoch163-authenticated-input-metadata-20261105-v1/ROOT_BOTH163_ISOLATED_GENERATIONS_AUTHENTICATED_NOT_REPLAY_ADMISSION.json";
pub(super) const CURRENT_PATH: &str = "/home/sol/.jetstreamer-private/epoch163-authenticated-input-metadata-20261106-post-custody-v5/ROOT_BOTH163_ISOLATED_GENERATIONS_AUTHENTICATED_NOT_REPLAY_ADMISSION.json";
const SCHEMA: &str = "horizon-direct163-current-post-custody-isolated-generations-v1";
const AUTH: &str = "/home/sol/.jetstreamer-private/epoch163-direct-parent-20261104-v1/credential-refresh-20261106-v5";
const CONFIG: &str = "/home/sol/.jetstreamer-private/epoch163-direct-parent-20261104-v1/gcloud";
const ACCOUNT: &str = "sam.johnson@anza.xyz";
const PROJECT: &str = "principal-lane-200702";
const BOOT: u64 = 1634787272998262;
const TAIL: u64 = 1634787310547338;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    schema: String,
    bootstrap_generation: u64,
    terminal_generation: u64,
    config: String,
    current_account: String,
    current_project: String,
    read_only_remote_metadata: bool,
    no_replay_or_full_admission_authority: bool,
    actual_executions: Vec<Bound>,
    root_refreshed_credential_acceptance: Bound,
    actual_generation_acceptances: Vec<Bound>,
    isolated_active_config: Bound,
    isolated_configuration: Bound,
    login_source_fallback_blocked_in_both_auth_sandboxes: bool,
}
struct Evidence {
    root: Value,
    executions: [Value; 2],
    acceptances: [Value; 2],
}
fn binding(name: &str, digest: &str) -> Bound {
    Bound { path: Path::new(AUTH).join(name), sha256: digest.into() }
}
fn root_binding() -> Bound {
    binding("ROOT_ISOLATED_CREDENTIAL_REFRESH_AND_BOTH_GENERATIONS_ACCEPTED.json", "b158f98891ddc6f76b8462f853f59a2b84a1ea05306e7e6b6d8f80a3a378b577")
}
fn execution_bindings() -> Vec<Bound> {
    vec![binding("ROOT_BOOTSTRAP_ISOLATED_AUTH_ORIGINAL_EXECUTION.json", "5361701f51b6c94d59624584dda29d4288a9359a6dad8afce1026d9a0653e5f9"), binding("ROOT_TERMINAL_ISOLATED_AUTH_ORIGINAL_EXECUTION.json", "28664493549d7b4dbe07f2a943edc3574c878f0dea64163012d94738ee0f3c7a")]
}
fn acceptance_bindings() -> Vec<Bound> {
    vec![binding("ROOT_BOOTSTRAP_ISOLATED_AUTH_EXACT_METADATA_ACCEPTED.json", "bda241ce773a329fa071d86558e1ad5347864fe59e588d8984eb393faaaf0886"), binding("ROOT_TERMINAL_ISOLATED_AUTH_EXACT_METADATA_ACCEPTED.json", "2615f9b2d657991441ed450ce7b903c409f7c881f189301a145730415ac7a20b")]
}
fn active_binding() -> Bound {
    Bound { path: Path::new(CONFIG).join("active_config"), sha256: "37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f".into() }
}
fn configuration_binding() -> Bound {
    Bound { path: Path::new(CONFIG).join("configurations/config_default"), sha256: "687008962a16f16c4863684b87070eccfd0edc8e3092adb52dd0c4ce05271f1c".into() }
}
fn same(a: &Bound, b: &Bound) -> bool { json!(a) == json!(b) }
pub(super) fn input_path_allowed(path: &Path) -> bool {
    path == Path::new(LEGACY_PATH) || path == Path::new(CURRENT_PATH)
}
fn current_route(path: &Path, inputs: &Value) -> Result<bool> {
    ensure!(input_path_allowed(path), "direct163 metadata path scope");
    if path == Path::new(LEGACY_PATH) {
        ensure!(inputs["schema"] != SCHEMA, "current163 projection cannot impersonate legacy metadata path");
        return Ok(false);
    }
    Ok(true)
}
fn projection(path: &Path, raw: &Value, active: &Bound, config: &Bound) -> Result<Projection> {
    ensure!(path == Path::new(CURRENT_PATH), "current163 projection path/version");
    let p: Projection = serde_json::from_value(raw.clone()).context("current163 exact projection schema")?;
    ensure!(p.schema == SCHEMA && p.bootstrap_generation == BOOT && p.terminal_generation == TAIL
        && p.config == CONFIG && p.current_account == ACCOUNT && p.current_project == PROJECT
        && p.read_only_remote_metadata && p.no_replay_or_full_admission_authority
        && p.login_source_fallback_blocked_in_both_auth_sandboxes,
        "current163 generation/account/project/authority scope");
    ensure!(same(&p.root_refreshed_credential_acceptance, &root_binding())
        && json!(p.actual_executions) == json!(execution_bindings())
        && json!(p.actual_generation_acceptances) == json!(acceptance_bindings())
        && same(&p.isolated_active_config, &active_binding())
        && same(&p.isolated_configuration, &configuration_binding())
        && same(active, &p.isolated_active_config) && same(config, &p.isolated_configuration),
        "current163 actual Root/execution/config bindings");
    Ok(p)
}
fn versioned_uri(role: usize) -> &'static str {
    if role == 0 { "gs://mainnet-beta-ledger-us-ny5/70415741/snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst#1634787272998262" }
    else { "gs://mainnet-beta-ledger-us-ny5/70847738/snapshot-70847738-H5pk5Ew133pHrsEXH6VATUzeyAwbmHWBmANLvVdiYRnS.tar.zst#1634787310547338" }
}
fn expected_probe_argv(role: usize) -> Vec<String> {
    let label = if role == 0 { "bootstrap" } else { "terminal" };
    let mut args = vec!["/usr/bin/systemd-run".into(), "--wait".into(), "--pipe".into(), format!("--unit=horizon-epoch163-isolated-input-metadata-{label}-20261106-post-custody-v5"), "--service-type=exec".into()];
    for property in ["User=sol", "Group=horizon", "Restart=no", "MemoryAccounting=yes", "MemoryHigh=384M", "MemoryMax=512M", "MemorySwapMax=0", "CPUQuota=100%", "TasksMax=512", "RuntimeMaxSec=90", "TimeoutStopSec=15", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only"] {
        args.extend(["-p".into(), property.into()]);
    }
    args.extend(["-p".into(), format!("ReadWritePaths={CONFIG}"), "-p".into(), format!("Environment=CLOUDSDK_CONFIG={CONFIG} CLOUDSDK_CORE_DISABLE_PROMPTS=1 CLOUDSDK_CORE_DISABLE_FILE_LOGGING=1"), format!("--setenv=CLOUDSDK_CORE_ACCOUNT={ACCOUNT}"), format!("--setenv=CLOUDSDK_CORE_PROJECT={PROJECT}"), "-p".into(), "InaccessiblePaths=/home/sol/.config/gcloud".into()]);
    args.extend(["/usr/lib/google-cloud-sdk/bin/gcloud", "storage", "objects", "describe", versioned_uri(role), "--format=json"].map(str::to_owned));
    args
}
fn expected_metadata(role: usize) -> (u64, u64, &'static str, &'static str) {
    if role == 0 { (BOOT, 1901405026, "GIvvcL0yXKjY2dumxRsJrg==", "bpbuVg==") }
    else { (TAIL, 1906864490, "Yqr/rEuqd9JnU5a7M1EzGA==", "yrN75Q==") }
}
fn check_evidence(p: &Projection, e: &Evidence) -> Result<()> {
    ensure!(e.root["schema"] == "horizon-root-direct163-refreshed-isolated-credential-and-exact-GCS-acceptance-v1"
        && e.root["epoch"] == 163 && e.root["login_source_fallback_blocked_in_both_auth_sandboxes"] == true
        && e.root["current_credential_or_auth_actors_drained_after_wait"] == true
        && e.root["no_new_replay_input_download_or_resource_credit"] == true
        && e.root["both_exact_generation_authentication_proofs"] == json!(p.actual_generation_acceptances)
        && e.root["actual_isolated_active_configuration_bindings"] == json!([p.isolated_active_config, p.isolated_configuration]),
        "current163 genuine post-custody acceptance scope");
    for role in 0..2 {
        let (generation, size, md5, crc) = expected_metadata(role);
        let generation_text = generation.to_string();
        let execution = &e.executions[role];
        ensure!(execution["code"] == 0 && execution["argv"] == json!(expected_probe_argv(role)), "current163 actual isolated probe invocation");
        let raw = execution["stdout"].as_str().context("current163 probe metadata stdout")?;
        ensure!(raw.len() <= 1 << 20, "current163 metadata response bound");
        let metadata: Value = serde_json::from_str(raw).context("current163 actual generation metadata JSON")?;
        ensure!(metadata["generation"].as_str() == Some(generation_text.as_str()) && metadata["size"] == size
            && metadata["md5_hash"] == md5 && metadata["crc32c_hash"] == crc
            && metadata["storage_url"] == versioned_uri(role), "current163 exact GCS generation/size/digests");
        let accepted = &e.acceptances[role];
        let name = if role == 0 { "BOOTSTRAP" } else { "TERMINAL" };
        ensure!(accepted["epoch"] == 163 && accepted["role"] == name && accepted["generation"].as_str() == Some(generation_text.as_str())
            && accepted["size"] == size && accepted["md5"] == md5 && accepted["crc32c"] == crc
            && accepted["isolated_config_authenticated"] == true && accepted["login_config_inaccessible"] == true
            && accepted["no_download_or_replay_authority"] == true
            && accepted["original_execution"] == format!("ROOT_{name}_ISOLATED_AUTH_ORIGINAL_EXECUTION.json"),
            "current163 original metadata acceptance mismatch");
    }
    Ok(())
}
pub(super) fn validate_if_current(s: &Spec, inputs: &Value) -> Result<()> {
    validate_selected(&s.input_metadata, &s.isolated_active_config, &s.isolated_configuration, inputs)
}
pub(super) fn validate_selected(input: &Bound, active: &Bound, config: &Bound, inputs: &Value) -> Result<()> {
    if !current_route(&input.path, inputs)? { return Ok(()); }
    let p = projection(&input.path, inputs, active, config)?;
    let e = Evidence { root: protected(&p.root_refreshed_credential_acceptance)?,
        executions: [protected(&p.actual_executions[0])?, protected(&p.actual_executions[1])?],
        acceptances: [protected(&p.actual_generation_acceptances[0])?, protected(&p.actual_generation_acceptances[1])?] };
    check_evidence(&p, &e)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_projection() -> Value {
        json!({"schema":SCHEMA,"bootstrap_generation":BOOT,"terminal_generation":TAIL,"config":CONFIG,
            "current_account":ACCOUNT,"current_project":PROJECT,"read_only_remote_metadata":true,"no_replay_or_full_admission_authority":true,
            "actual_executions":execution_bindings(),"root_refreshed_credential_acceptance":root_binding(),"actual_generation_acceptances":acceptance_bindings(),
            "isolated_active_config":active_binding(),"isolated_configuration":configuration_binding(),"login_source_fallback_blocked_in_both_auth_sandboxes":true})
    }
    fn parse(v: &Value) -> Result<Projection> { projection(Path::new(CURRENT_PATH),v,&active_binding(),&configuration_binding()) }
    fn fixture_evidence(p: &Projection) -> Evidence {
        let executions=std::array::from_fn(|role| {let (generation,size,md5,crc)=expected_metadata(role);
            json!({"code":0,"argv":expected_probe_argv(role),"stdout":json!({"generation":generation.to_string(),"size":size,"md5_hash":md5,"crc32c_hash":crc,"storage_url":versioned_uri(role)}).to_string()})});
        let acceptances=std::array::from_fn(|role| {let (generation,size,md5,crc)=expected_metadata(role);let name=if role==0{"BOOTSTRAP"}else{"TERMINAL"};
            json!({"epoch":163,"role":name,"generation":generation.to_string(),"size":size,"md5":md5,"crc32c":crc,"isolated_config_authenticated":true,"login_config_inaccessible":true,"no_download_or_replay_authority":true,"original_execution":format!("ROOT_{name}_ISOLATED_AUTH_ORIGINAL_EXECUTION.json")})});
        Evidence{root:json!({"schema":"horizon-root-direct163-refreshed-isolated-credential-and-exact-GCS-acceptance-v1","epoch":163,"login_source_fallback_blocked_in_both_auth_sandboxes":true,"current_credential_or_auth_actors_drained_after_wait":true,"no_new_replay_input_download_or_resource_credit":true,"both_exact_generation_authentication_proofs":p.actual_generation_acceptances,"actual_isolated_active_configuration_bindings":[p.isolated_active_config,p.isolated_configuration]}),executions,acceptances}
    }
    #[test] fn exact_current_projection_and_both_real_probe_shapes_pass() {let p=parse(&fixture_projection()).unwrap();assert!(check_evidence(&p,&fixture_evidence(&p)).is_ok());}
    #[test] fn legacy_and_exact_current_paths_only_are_allowed() {assert!(input_path_allowed(Path::new(LEGACY_PATH)));assert!(input_path_allowed(Path::new(CURRENT_PATH)));for path in [format!("{CURRENT_PATH}.alias"),CURRENT_PATH.replace("v5","v6"),"/tmp/current.json".into()]{assert!(!input_path_allowed(Path::new(&path)));}}
    #[test] fn legacy_or_crossed_path_cannot_deserialize_as_current() {for path in [LEGACY_PATH,"/tmp/current.json"]{assert!(projection(Path::new(path),&fixture_projection(),&active_binding(),&configuration_binding()).is_err());}}
    #[test] fn wrong_schema_or_generation_or_authority_is_rejected() {for (key,value) in [("schema",json!("old")),("bootstrap_generation",json!(BOOT+1)),("terminal_generation",json!(TAIL+1)),("no_replay_or_full_admission_authority",json!(false)),("login_source_fallback_blocked_in_both_auth_sandboxes",json!(false))]{let mut v=fixture_projection();v[key]=value;assert!(parse(&v).is_err());}}
    #[test] fn current_account_project_and_config_scope_cannot_drift() {for key in ["config","current_account","current_project"]{let mut v=fixture_projection();v[key]=json!("foreign");assert!(parse(&v).is_err());}}
    #[test] fn root_acceptance_and_actual_execution_receipt_digests_are_exact() {for pointer in ["/root_refreshed_credential_acceptance/sha256","/actual_executions/0/sha256","/actual_generation_acceptances/1/sha256"]{let mut v=fixture_projection();*v.pointer_mut(pointer).unwrap()=json!("0".repeat(64));assert!(parse(&v).is_err());}}
    #[test] fn swapped_probe_receipts_and_old_receipt_path_are_rejected() {let mut v=fixture_projection();v["actual_executions"].as_array_mut().unwrap().swap(0,1);assert!(parse(&v).is_err());let mut v=fixture_projection();v["actual_executions"][0]["path"]=json!(LEGACY_PATH);assert!(parse(&v).is_err());}
    #[test] fn actual_spec_config_must_match_exact_accepted_configuration() {let mut wrong=configuration_binding();wrong.sha256="0".repeat(64);assert!(projection(Path::new(CURRENT_PATH),&fixture_projection(),&active_binding(),&wrong).is_err());}
    #[test] fn unknown_projection_fields_do_not_grant_extra_authority() {let mut v=fixture_projection();v["publication_authorized"]=json!(true);assert!(parse(&v).is_err());}
    #[test] fn failed_probe_login_fallback_or_changed_probe_argv_is_rejected() {let p=parse(&fixture_projection()).unwrap();for role in 0..2{let mut e=fixture_evidence(&p);e.executions[role]["code"]=json!(1);assert!(check_evidence(&p,&e).is_err());let mut e=fixture_evidence(&p);e.executions[role]["argv"].as_array_mut().unwrap().pop();assert!(check_evidence(&p,&e).is_err());}}
    #[test] fn actual_gcs_generation_size_md5_and_crc_must_match() {let p=parse(&fixture_projection()).unwrap();for role in 0..2{for (key,value) in [("generation",json!("1")),("size",json!(1)),("md5_hash",json!("bad")),("crc32c_hash",json!("bad")),("storage_url",json!("gs://foreign"))]{let mut e=fixture_evidence(&p);let mut m:Value=serde_json::from_str(e.executions[role]["stdout"].as_str().unwrap()).unwrap();m[key]=value;e.executions[role]["stdout"]=json!(m.to_string());assert!(check_evidence(&p,&e).is_err());}}}
    #[test] fn genuine_root_acceptance_and_role_specific_original_proof_are_required() {let p=parse(&fixture_projection()).unwrap();let mut e=fixture_evidence(&p);e.root["epoch"]=json!(164);assert!(check_evidence(&p,&e).is_err());for role in 0..2{let mut e=fixture_evidence(&p);e.acceptances[role]["original_execution"]=json!("old.json");assert!(check_evidence(&p,&e).is_err());let mut e=fixture_evidence(&p);e.acceptances[role]["login_config_inaccessible"]=json!(false);assert!(check_evidence(&p,&e).is_err());}}
    #[test] fn legacy_shape_is_preserved_but_cannot_impersonate_current_projection() {assert!(!current_route(Path::new(LEGACY_PATH),&json!({"bootstrap_generation":BOOT,"terminal_generation":TAIL})).unwrap());assert!(current_route(Path::new(LEGACY_PATH),&fixture_projection()).is_err());assert!(current_route(Path::new(CURRENT_PATH),&fixture_projection()).unwrap());}
}
