//! Complete pure CLI consumer validation of genuine0728 metadata at its original clock.
//! The candidate current-image field is a test value; all original bindings/censuses stay raw.
//! This performs no native census, writes, observation, admission or publication.
use super::*;
struct Actual {
    before: Vec<Value>,
    cohort: Option<Value>,
    cohort_sources: BTreeMap<String, Value>,
    native: Option<Value>,
    native_sources: BTreeMap<String, Value>,
    prior: Option<Value>,
    fleet_transition: Option<Value>,
    frame: Value,
    bindings: Value,
    clock: u64,
    current_image: String,
}
impl Actual {
    fn load() -> Self {
        let plan = Bound { path: "/usr/local/lib/jetstreamer/horizon-retained145-terminal-Frame-current0728-plan-20261107-v1/plan.json".into(), sha256: "2db00cbf06357a20d0193c44e430d8dc1ae27642dcfe486f54eb3eb23aa1e1ae".into() };
        let p: Plan = serde_json::from_value(json_read(&plan).unwrap()).unwrap();
        let frame_bound = Bound { path: "/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261107T072809-cached145-original-terminal-reload-native-v1.json".into(), sha256: "47023f0884c3cfd0a34fabc15e164148a041e4af530fbf16f6e4f3af62514633".into() };
        let mut frame = json_read(&frame_bound).unwrap();
        assert_eq!(frame["self_sha256"], "b692189704ed9001c016b1931ec6e54210104d36a5fbf787dfdd9d2505ae75eb");
        let current_image = "c".repeat(64);
        frame["self_sha256"] = json!(current_image);
        let bindings = frame["bindings"].clone();
        let clock = frame["recorded_unix_seconds"].as_u64().unwrap();
        let cohort = p.cohort183_transition.as_ref().map(json_read).transpose().unwrap();
        let cohort_sources = cohort183_sources(cohort.as_ref()).unwrap();
        let native = p.native154_transition.as_ref().map(json_read).transpose().unwrap();
        let native_sources = native154_sources(native.as_ref()).unwrap();
        let prior = p.prior_recovery.as_ref().map(json_read).transpose().unwrap();
        let fleet_transition = p.fleet_transition.as_ref().map(json_read).transpose().unwrap();
        let before = [&p.observer, &p.fleet, &p.fleet_plan, &p.prior_parent,
            &p.prior_completion, &p.prior_fleet_plan, &p.correction191, &p.transition]
            .into_iter().map(json_read).collect::<Result<Vec<_>>>().unwrap();
        Self { before, cohort, cohort_sources, native, native_sources, prior,
            fleet_transition, frame, bindings, clock, current_image }
    }
    fn check(&self) -> Result<()> {
        let e = Evidence {
            observer: &self.before[0], fleet: &self.before[1], fleet_plan: &self.before[2],
            prior_parent: &self.before[3], prior_completion: &self.before[4],
            prior_fleet_plan: &self.before[5], transition: &self.before[7],
            prior_recovery: self.prior.as_ref(), fleet_transition: self.fleet_transition.as_ref(),
            capture_tool_sha: &self.current_image, cohort183_transition: self.cohort.as_ref(),
            cohort183_sources: &self.cohort_sources, native154_transition: self.native.as_ref(),
            native154_sources: &self.native_sources,
        };
        assert!(horizon_recovered_resource_frame_recovery199::cached145_frame::selected(&e));
        validate_frame(&self.frame, &e, &self.bindings, self.clock)
    }
}
#[test]
fn genuine0728_complete_validator_accepts_distinct_current_image_and_proven_cached_predecessor() {
    let a = Actual::load();
    let before = serde_json::to_value((&a.frame, &a.prior, &a.before, &a.cohort_sources)).unwrap();
    a.check().unwrap();
    assert_eq!(before, serde_json::to_value((&a.frame, &a.prior, &a.before, &a.cohort_sources)).unwrap());
}
#[test]
fn genuine0728_complete_validator_rejects_unknown_predecessor_and_changed_native_envelopes() {
    let mut a = Actual::load();
    a.check().unwrap();
    let original = a.prior.clone();
    a.prior.as_mut().unwrap()["self_sha256"] = json!("d".repeat(64));
    assert!(a.check().is_err());
    a.prior = original.clone();
    a.prior.as_mut().unwrap()["native_census_after"] = json!({"foreign":true});
    assert!(a.check().is_err());
    a.prior = original;
    let native = a.frame["native_census_after"].clone();
    a.frame["native_census_after"] = json!({"foreign":true});
    assert!(a.check().is_err());
    a.frame["native_census_after"] = native;
    a.check().unwrap();
}
