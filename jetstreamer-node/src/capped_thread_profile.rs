//! Explicit thread and inherited CPU-affinity contract for new capped attempts.
//! Quota is independent of this contract and remains separately enforced.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs};

pub const THREADS: usize = 8;
pub const VARIABLES: [&str; 6] = [
    "TOKIO_WORKER_THREADS",
    "SOLANA_RAYON_THREADS",
    "RAYON_NUM_THREADS",
    "JETSTREAMER_REPLAY_THREADS",
    "JETSTREAMER_RIPGET_THREADS",
    "JETSTREAMER_THREADS",
];

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ThreadProfile {
    pub schema: String,
    /// Sorted exact Linux logical CPU IDs, chosen from the admitted host mask.
    pub cpu_ids: Vec<u32>,
}
impl ThreadProfile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "jetstreamer-capped204205-eight-thread-profile-v1"
                && self.cpu_ids.len() == THREADS
                && self.cpu_ids.windows(2).all(|v| v[0] < v[1])
                && self.cpu_ids.iter().all(|&v| v < libc::CPU_SETSIZE as u32),
            "invalid exact eight-CPU thread profile"
        );
        Ok(())
    }
    pub fn affinity_property(&self) -> Result<String> {
        self.validate()?;
        Ok(self
            .cpu_ids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" "))
    }
    pub fn check_manager(&self, manager: &BTreeMap<String, String>) -> Result<()> {
        self.validate()?;
        ensure!(
            parse_cpu_list(
                manager
                    .get("CPUAffinity")
                    .context("missing manager CPU affinity")?
            )? == self.cpu_ids,
            "manager CPU affinity differs from admitted eight-CPU profile"
        );
        let fields: Vec<_> = manager
            .get("Environment")
            .context("missing manager environment")?
            .split_whitespace()
            .collect();
        for key in VARIABLES {
            let prefix = format!("{key}=");
            let values: Vec<_> = fields
                .iter()
                .filter_map(|v| v.strip_prefix(&prefix))
                .collect();
            ensure!(
                values == ["8"],
                "missing, duplicate or unbounded manager thread variable {key}"
            );
        }
        Ok(())
    }
    pub fn check_process(&self, pid: u32) -> Result<()> {
        self.validate()?;
        let env = fs::read(format!("/proc/{pid}/environ"))?;
        ensure!(env.len() <= 1 << 20, "oversized process environment");
        for key in VARIABLES {
            let prefix = format!("{key}=");
            let values: Vec<_> = env
                .split(|b| *b == 0)
                .filter_map(|v| v.strip_prefix(prefix.as_bytes()))
                .collect();
            ensure!(
                values == [b"8".as_slice()],
                "process thread variable differs: {key}"
            );
        }
        // Check every actual thread: a main-thread mask alone does not bind pools.
        let mut count = 0usize;
        for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
            let tid = entry?
                .file_name()
                .to_str()
                .context("non-UTF8 TID")?
                .parse::<i32>()?;
            ensure!(
                affinity(tid)? == self.cpu_ids,
                "actual thread CPU affinity differs from admitted mask"
            );
            count += 1;
            ensure!(count <= 512, "thread profile exceeds retained task ceiling");
        }
        ensure!(count > 0, "empty process thread census");
        Ok(())
    }
}

pub fn parse_cpu_list(text: &str) -> Result<Vec<u32>> {
    ensure!(text.len() <= 8192, "oversized CPU list");
    let mut cpus = Vec::new();
    for part in text
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
    {
        let (first, last) = match part.split_once('-') {
            Some((a, b)) => (a.parse::<u32>()?, b.parse::<u32>()?),
            None => {
                let n = part.parse::<u32>()?;
                (n, n)
            }
        };
        ensure!(
            first <= last && last < libc::CPU_SETSIZE as u32,
            "invalid CPU range"
        );
        cpus.extend(first..=last);
        ensure!(
            cpus.len() <= libc::CPU_SETSIZE as usize,
            "oversized CPU mask"
        );
    }
    cpus.sort_unstable();
    ensure!(
        !cpus.is_empty() && cpus.windows(2).all(|v| v[0] != v[1]),
        "empty or duplicate CPU mask"
    );
    Ok(cpus)
}

pub fn affinity(tid: i32) -> Result<Vec<u32>> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(tid, std::mem::size_of_val(&set), &mut set) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .map(|v| v as u32)
        .collect())
}

/// Before Tokio creates any pool. Exact CPU identities are bound to admission
/// later, before native initialization; this initial gate requires exactly eight.
pub fn check_entrypoint() -> Result<()> {
    for key in VARIABLES {
        ensure!(
            std::env::var(key).as_deref() == Ok("8"),
            "capped entrypoint requires {key}=8"
        );
    }
    ensure!(
        affinity(0)?.len() == THREADS,
        "capped entrypoint requires exactly eight inherited CPUs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> ThreadProfile {
        ThreadProfile {
            schema: "jetstreamer-capped204205-eight-thread-profile-v1".into(),
            cpu_ids: (0..8).collect(),
        }
    }
    #[test]
    fn exact_profile_rejects_unbounded_and_ambiguous_masks() {
        assert!(profile().validate().is_ok());
        for ids in [
            vec![],
            (0..7).collect(),
            (0..9).collect(),
            vec![0; 8],
            vec![7, 6, 5, 4, 3, 2, 1, 0],
        ] {
            assert!(
                ThreadProfile {
                    cpu_ids: ids,
                    ..profile()
                }
                .validate()
                .is_err()
            );
        }
        assert_eq!(parse_cpu_list("0-3, 4 5 6 7").unwrap(), profile().cpu_ids);
        for text in ["", "0-7,7", "7-0", "0-1024", "0--1"] {
            assert!(parse_cpu_list(text).is_err());
        }
    }
    #[test]
    fn manager_requires_affinity_and_each_exact_environment_value() {
        let env = VARIABLES.map(|k| format!("{k}=8")).join(" ");
        let manager = BTreeMap::from([
            ("Environment".into(), env.clone()),
            ("CPUAffinity".into(), "0-7".into()),
        ]);
        assert!(profile().check_manager(&manager).is_ok());
        for key in VARIABLES {
            let mut bad = manager.clone();
            bad.insert(
                "Environment".into(),
                env.replace(&format!("{key}=8"), &format!("{key}=255")),
            );
            assert!(profile().check_manager(&bad).is_err());
            bad.insert("Environment".into(), format!("{env} {key}=8"));
            assert!(profile().check_manager(&bad).is_err());
        }
        let mut bad = manager;
        bad.insert("CPUAffinity".into(), "0-8".into());
        assert!(profile().check_manager(&bad).is_err());
    }
}
