#[cfg(test)]
mod preparation_tests {
    use super::*;
    #[test]
    fn only_the_registered_inert_preparation_can_transfer() {
        let old = Bound::new(PRIOR_LAUNCHER.0, PRIOR_LAUNCHER.1);
        let new = Bound::new(LAUNCHER, "c".repeat(64));
        let reference = Bound::new(PRIOR_PREPARATION.0, PRIOR_PREPARATION.1);
        let roles = |launcher: &Bound, commit: &str| json!({"artifacts":[{"role":"launcher","artifact":launcher,"source_commit":commit},{"role":"harness","artifact":Bound::new(HARNESS,HARNESS_SHA),"source_commit":"a".repeat(40)},{"role":"guard","artifact":Bound::new(GUARD,GUARD_SHA),"source_commit":"b".repeat(40)}]});
        let previous = roles(&old, PRIOR_LAUNCHER_COMMIT);
        let current = roles(&new, &"c".repeat(40));
        prepared_transition(&reference, &old, &new, &previous, &current).unwrap();
        let different = Bound::new(PRIOR_PREPARATION.0, "f".repeat(64));
        prepared_transition(&different, &new, &new, &current, &current).unwrap();
        assert!(prepared_transition(&different, &old, &new, &previous, &current).is_err());
        let wrong_old = roles(&old, &"d".repeat(40));
        assert!(prepared_transition(&reference, &old, &new, &wrong_old, &current).is_err());
        let other = Bound::new("/other-launcher", &new.sha256);
        let wrong_path = roles(&other, &"c".repeat(40));
        assert!(prepared_transition(&reference, &old, &other, &previous, &wrong_path).is_err());
        for index in [1, 2] {
            let mut changed = current.clone();
            changed["artifacts"][index]["source_commit"] = json!("f".repeat(40));
            assert!(prepared_transition(&reference, &old, &new, &previous, &changed).is_err());
        }
    }
}
