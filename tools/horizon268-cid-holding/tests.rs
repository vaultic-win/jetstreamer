use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};
const SAMPLE: &[u8] = b"AAAABBBBCC";
const UNIT: usize = 4;
const PROFILE: &str = "offline artifact specimen";
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let d = env::temp_dir().join(format!(
            "cid268-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&d).unwrap();
        Self(d)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[derive(Default)]
struct Fake {
    data: RefCell<BTreeMap<String, Vec<u8>>>,
    puts: Cell<u32>,
    race: Cell<bool>,
    corrupt_race: Cell<bool>,
}
impl Transport for Fake {
    fn request(&self, k: &str, put: Option<&Path>, max: u64) -> R<(u16, Vec<u8>)> {
        assert!(k.starts_with(&format!("{PREFIX}/")));
        let mut map = self.data.borrow_mut();
        if let Some(p) = put {
            self.puts.set(self.puts.get() + 1);
            if map.contains_key(k) {
                return Ok((412, vec![]));
            }
            let bytes = fs::read(p).unwrap();
            map.insert(
                k.into(),
                if self.corrupt_race.get() {
                    vec![0; bytes.len()]
                } else {
                    bytes
                },
            );
            return Ok((
                if self.race.get() || self.corrupt_race.get() {
                    412
                } else {
                    200
                },
                vec![],
            ));
        }
        match map.get(k) {
            None => Ok((404, vec![])),
            Some(v) if v.len() as u64 <= max => Ok((200, v.clone())),
            _ => Err("response too large".into()),
        }
    }
}
fn sha() -> String {
    hash_bytes(SAMPLE).unwrap()
}
fn parts(f: &Fake, d: &Path) -> R<Vec<String>> {
    parked(f, &mut &SAMPLE[..], SAMPLE.len() as u64, UNIT, &sha(), d)
}
fn publish_fixture(f: &Fake, d: &Path, hashes: &[String]) -> R<()> {
    let m = manifest(PROFILE, hashes);
    let length = m.len() as u64;
    let scratch = Scratch::new(d, "manifest", &m)?;
    f.small(
        &format!("{PREFIX}/manifests/{}.manifest", hash_bytes(&m)?),
        &scratch.0,
        length,
    )?;
    f.small(&fixed(), &scratch.0, length)
}
#[test]
fn archived_epoch_geometry_round_trips_both_manifests() {
    let size = 185_599_540_324u64;
    let digest = "ab".repeat(32);
    let parts = vec![digest; size.div_ceil(PART as u64) as usize];
    let length = manifest_length(PROFILE, size, PART).unwrap();
    assert!(length > 65536);
    let f = Fake::default();
    let d = Dir::new();
    publish_fixture(&f, &d.0, &parts).unwrap();
    assert_eq!(remote_manifest(&f, PROFILE, size, PART).unwrap().0, parts);
    let malformed = Scratch::new(&d.0, "oversize", &vec![0; length as usize + 1]).unwrap();
    assert!(f.small(&fixed(), &malformed.0, length).is_err());
    f.data.borrow_mut().get_mut(&fixed()).unwrap().push(b'\n');
    assert!(remote_manifest(&f, PROFILE, size, PART).is_err());
    assert!(manifest_length(PROFILE, size, 0).is_err());
    assert!(manifest_length(PROFILE, 0, 1).is_err());
    assert!(manifest_length(PROFILE, u64::MAX, 1).is_err());
}
#[test]
fn exact_geometry() {
    let (parts, tail) = if EPOCH == 267 {
        (310, 24474758)
    } else {
        (363, 14_791_482)
    };
    assert_eq!(SIZE.div_ceil(PART as u64), parts);
    assert_eq!(SIZE % (PART as u64), tail);
    assert!(header().contains(REC_SHA));
    assert_eq!(
        fs::read_link("/usr/bin/sha256sum").unwrap(),
        PathBuf::from("../lib/cargo/bin/coreutils/sha256sum")
    );
}
#[test]
fn successful_two_pass_and_reuse() {
    let d = Dir::new();
    let f = Fake::default();
    let l = parts(&f, &d.0).unwrap();
    publish_fixture(&f, &d.0, &l).unwrap();
    let (l2, _) = remote_manifest(&f, PROFILE, 10, UNIT).unwrap();
    let mut body = vec![];
    recover(&f, &l2, 10, UNIT, &sha(), &mut body).unwrap();
    assert_eq!(body, SAMPLE);
    assert_eq!(parts(&f, &d.0).unwrap(), l);
    publish_fixture(&f, &d.0, &l).unwrap();
    assert_eq!(f.puts.get(), 5);
}
#[test]
fn conditional_races_read_back_and_conflicts_stop() {
    let d = Dir::new();
    let f = Fake::default();
    f.race.set(true);
    let l = parts(&f, &d.0).unwrap();
    publish_fixture(&f, &d.0, &l).unwrap();
    let bad = Fake::default();
    bad.corrupt_race.set(true);
    assert!(parts(&bad, &d.0).is_err());
    assert!(!bad.data.borrow().contains_key(&fixed()));
    f.data.borrow_mut().insert(fixed(), b"other".to_vec());
    assert!(publish_fixture(&f, &d.0, &l).is_err());
    assert_eq!(f.data.borrow()[&fixed()], b"other");
}
#[test]
fn source_truncation_drift_or_wrong_whole() {
    let d = Dir::new();
    for input in [&SAMPLE[..9], &b"AAAABBBBCCC"[..], &b"AAAABBBBCD"[..]] {
        let f = Fake::default();
        assert!(parked(&f, &mut &input[..], 10, UNIT, &sha(), &d.0).is_err());
        assert!(!f.data.borrow().contains_key(&fixed()));
    }
}
#[test]
fn missing_or_mismatched_manifests_rejected() {
    let d = Dir::new();
    let f = Fake::default();
    let l = parts(&f, &d.0).unwrap();
    assert!(remote_manifest(&f, PROFILE, 10, 4).is_err());
    publish_fixture(&f, &d.0, &l).unwrap();
    assert!(remote_manifest(&f, "other source", 10, 4).is_err());
    let m = manifest(PROFILE, &l);
    let k = format!("{PREFIX}/manifests/{}.manifest", hash_bytes(&m).unwrap());
    f.data.borrow_mut().remove(&k);
    assert!(remote_manifest(&f, PROFILE, 10, 4).is_err());
    f.data.borrow_mut().insert(k, b"other".to_vec());
    assert!(remote_manifest(&f, PROFILE, 10, 4).is_err());
    assert!(parse(&m[..m.len() - 1], PROFILE, 10, 4).is_err());
}
#[test]
fn short_oversize_corrupt_missing_and_reordered_chunks() {
    let d = Dir::new();
    let f = Fake::default();
    let mut l = parts(&f, &d.0).unwrap();
    l.swap(0, 1);
    assert!(recover(&f, &l, 10, 4, &sha(), &mut io::sink()).is_err());
    l.swap(0, 1);
    for bytes in [vec![0], vec![1; 5], vec![1; 4]] {
        f.data.borrow_mut().insert(key(&l[0]), bytes);
        assert!(recover(&f, &l, 10, 4, &sha(), &mut io::sink()).is_err());
    }
    f.data.borrow_mut().remove(&key(&l[0]));
    assert!(recover(&f, &l, 10, 4, &sha(), &mut io::sink()).is_err());
}
fn partial(d: &Path, data: &[u8]) {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(d.join(".index.partial"))
        .unwrap();
    f.write_all(data).unwrap();
}
#[test]
fn interrupted_restore_resumes_and_reopens_existing_output() {
    let d = Dir::new();
    let f = Fake::default();
    let l = parts(&f, &d.0).unwrap();
    partial(&d.0, &SAMPLE[..5]);
    restore(&f, &l, 10, 4, &sha(), &d.0).unwrap();
    let o = d.0.join("index.body");
    let m = o.metadata().unwrap();
    assert_eq!(m.mode() & 0o7777, 0o400);
    assert_eq!(fs::read(&o).unwrap(), SAMPLE);
    restore(&f, &l, 10, 4, &sha(), &d.0).unwrap();
    assert_eq!(m.ino(), o.metadata().unwrap().ino());
    f.data.borrow_mut().remove(&key(&l[2]));
    assert!(restore(&f, &l, 10, 4, &sha(), &d.0).is_err());
    assert_eq!(fs::read(&o).unwrap(), SAMPLE);
}
#[test]
fn conflicting_or_aliased_partial_and_existing_destination_preserved() {
    let d = Dir::new();
    let f = Fake::default();
    let l = parts(&f, &d.0).unwrap();
    partial(&d.0, b"AAAAX");
    assert!(restore(&f, &l, 10, 4, &sha(), &d.0).is_err());
    assert_eq!(fs::read(d.0.join(".index.partial")).unwrap(), b"AAAAX");
    let other = d.0.join("neighbor");
    fs::write(&other, b"secret").unwrap();
    fs::remove_file(d.0.join(".index.partial")).unwrap();
    std::os::unix::fs::symlink(&other, d.0.join(".index.partial")).unwrap();
    assert!(restore(&f, &l, 10, 4, &sha(), &d.0).is_err());
    assert_eq!(fs::read(&other).unwrap(), b"secret");
    let o = d.0.join("index.body");
    fs::write(&o, b"conflict").unwrap();
    assert!(restore(&f, &l, 10, 4, &sha(), &d.0).is_err());
    assert!(publish(&other, &o).is_err());
    assert_eq!(fs::read(o).unwrap(), b"conflict");
    assert_eq!(fs::read(other).unwrap(), b"secret");
}

#[test]
fn owner_and_profile_do_not_accept_another_namespace() {
    assert!(approved_owner(200, OWNER).is_ok());
    assert!(approved_owner(404, OWNER).is_err());
    let foreign = String::from_utf8(OWNER.to_vec())
        .unwrap()
        .replace("node_01", "node_02");
    assert!(approved_owner(200, foreign.as_bytes()).is_err());
    assert!(fixed().starts_with(&format!(
        "foundation_node_01/closed-private-v1/epoch{EPOCH}-cid-index-v1/"
    )));
    assert!(!key(&"0".repeat(64)).ends_with(".jet"));
}
