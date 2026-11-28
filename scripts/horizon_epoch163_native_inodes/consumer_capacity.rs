//! Keep the price of a serial compiler separate from the restored bank's later admission.
use super::*;

pub(super) fn reserve(review: &Value, fleet: &Value) -> Result<(File, File, u64)> {
    let fit = checked_json(&review["complete_native_fit"])?;
    let grant = checked_json(&review["compiler_loan"])?;
    let general = &fleet["retry9_auxiliary_commitments"];
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["owner"] == "/root"
            && fit["schema"] == "horizon-incident-replay-fit-v1"
            && fit["fleet"] == review["current_complete_fleet"]
            && fit["fits"] == true
            && fit["resource_credit_bytes"] == 0
            && fit["replay_launch_authorized"] == false
            && fit["complete_cpu_quota_micros"] == 64_000_000
            && fit["complete_memory_plus_reserve_bytes"] == 810_658_050_048u64
            && fit["complete_memory_plus_reserve_bytes"] == review["complete_projected_memory_bytes"]
            && fit["complete_required_HOME_bytes"] == review["complete_DATA_bytes"]
            && general["build_and_native_qualification_serial"] == true
            && general["build_cpu_quota_micros"] == 1_000_000
            && general["build_memory_bytes"] == 2u64 << 30,
        "different complete fleet or serial compiler booking"
    );
    let at = now()?;
    ensure!(
        at.checked_sub(n(&fit, "recorded_unix_seconds")?).is_some_and(|age| age <= 120)
            && grant["owner"] == "/root"
            && grant["schema"] == "horizon-native163-consumer-compiler-loan-v1"
            && grant["native"] == review["complete_native_fit"]
            && grant["original_authority_retained"] == true
            && grant["paid_phase"] == review["phase"]
            && grant["expires_unix_seconds"] == review["absolute_completion_deadline_unix_seconds"]
            && grant["consumer_compilation_only"] == true
            && grant["producer_authorized"] == false
            && grant["resource_credit_bytes"] == 0
            && fit["candidate136"]["occupied"] == false
            && fit["candidate136"]["loan_micros"] == 0,
        "missing current exclusive focused-169 loan"
    );
    let quote = checked_json(&grant["build_fit"])?;
    ensure!(
        quote["schema"] == "horizon-native48-build-resource-quote-v1"
            && quote["fit"] == review["complete_native_fit"]
            && quote["fleet"] == fit["fleet"]
            && quote["conditional_arithmetic_fits"] == true
            && quote["home_build_and_control_charge_bytes"] == (10u64 << 30) + (512u64 << 20)
            && quote["original_focused_guard_reserved"]["cpu_micros"] == 1_000_000
            && quote["original_focused_guard_reserved"]["memory_bytes"] == 1u64 << 30
            && quote["paid_donor"]["producer_cpu_micros"] == 3_000_000
            && quote["paid_donor"]["producer_memory"] == 68u64 << 30
            && quote["resource_credit_bytes"] == 0,
        "different original phase price"
    );
    // The immutable V5m census cannot enroll these replay-named compiler fixtures.
    // Never start one while its original guarded verifier cgroup exists.
    drained("horizon-holding-export145-20261121-v1.service")?;
    let phase = &fit["phase145"];
    ensure!(phase["retry_worker"].is_null() && phase["MainPID"] == "0"
            && (phase["ActiveState"] == "inactive" || phase["ActiveState"] == "failed"),
            "epoch 145 still owns a live verification");
    let locks = [
        ("/run/horizon-epoch171-to136-g1.operation.lock", 26u64, 3_453_440u64),
        ("/run/lock/horizon-epoch140-suffix-compiler.lock", 29u64, 1048u64),
    ];
    let acquire = |(path,dev,ino): (&str,u64,u64)| -> Result<File> {
        let f = OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
        let meta = f.metadata()?;
        let named = fs::symlink_metadata(path)?;
        ensure!(meta.is_file() && meta.dev() == dev && meta.ino() == ino && meta.nlink() == 1
                && named.dev() == dev && named.ino() == ino
                && unsafe { libc::flock(f.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB) } == 0,
                "original compiler/donor lock occupied or replaced");
        Ok(f)
    };
    let floor = n(&quote["paid_donor"], "protected_HOME")?
        .checked_add(n(&quote["paid_donor"],"future_staging")?).context("source staging")?
        .checked_add(n(&quote["paid_donor"],"private_workspace")?).context("hourly reserve")?
        .checked_add(n(&quote, "home_build_and_control_charge_bytes")?).context("compiler work")?;
    ensure!(n(review,"raw_guard_floor_bytes")? == floor, "different paid disk floor");
    let donor = acquire(locks[0])?;
    let compiler = acquire(locks[1])?;
    current_floor(floor)?;
    Ok((donor, compiler, floor))
}

pub(super) fn current_floor(floor: u64) -> Result<()> {
    let mut out = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(unsafe { libc::statvfs(c"/home/sol".as_ptr(),out.as_mut_ptr()) } == 0, "home statvfs");
    let stat = unsafe { out.assume_init() };
    ensure!(stat.f_bavail.checked_mul(stat.f_frsize).is_some_and(|free| free >= floor)
            && stat.f_favail > 0, "current combined HOME floor crossed");
    Ok(())
}
