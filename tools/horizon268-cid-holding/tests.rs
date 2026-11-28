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
    let (parts, tail) = match EPOCH {
        249 => (5_392, 32_834_908),
        250 => (5_532, 9_976_932),
        251 => (5_391, 11_267_104),
        267 => (310, 24_474_758),
        268 => (363, 14_791_482),
        _ => panic!("unknown source profile"),
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
    let o = d.0.join(RESTORE_FILE);
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
    let o = d.0.join(RESTORE_FILE);
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
    let source_kind = if matches!(EPOCH, 249..=251) {
        "closed-archive"
    } else {
        "cid-index"
    };
    assert!(fixed().starts_with(&format!(
        "foundation_node_01/closed-private-v1/epoch{EPOCH}-{source_kind}-v1/"
    )));
    assert!(!key(&"0".repeat(64)).ends_with(".jet"));
}

#[test]
#[cfg(any(epoch249, epoch250, epoch251))]
fn refills_only_the_quarantined_original_and_resumes_a_partial_part() {
    use std::time::{Duration, UNIX_EPOCH};
    let d = Dir::new();
    let f = Fake::default();
    let parts = parts(&f, &d.0).unwrap();
    let path = d.0.join("held");
    fs::write(&path, &SAMPLE[..5]).unwrap();
    let m = path.metadata().unwrap();
    let target = HeldInode {
        device: m.dev(),
        inode: m.ino(),
        owner_mode: (m.uid(), m.gid(), m.mode() & 0o7777),
        modified: UNIX_EPOCH + Duration::new(100, 512),
    };
    let refill = |path: &Path| target.refill(path, &f, &parts, 10, UNIT, &sha());
    let pin = File::open(&path).unwrap();
    pin.try_lock().unwrap();
    assert!(refill(&path).is_err());
    drop(pin);
    let replacement = d.0.join("other");
    fs::write(&replacement, &SAMPLE[..5]).unwrap();
    assert!(refill(&replacement).is_err());
    fs::hard_link(&path, d.0.join("link")).unwrap();
    assert!(refill(&path).is_err());
    fs::remove_file(d.0.join("link")).unwrap();
    fs::write(&path, b"AAAAX").unwrap();
    assert!(refill(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"AAAAX");
    fs::write(&path, &SAMPLE[..5]).unwrap();
    let last = f.data.borrow_mut().remove(&key(&parts[2])).unwrap();
    assert!(refill(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), &SAMPLE[..8]);
    f.data.borrow_mut().insert(key(&parts[2]), last);
    for _ in 0..2 {
        refill(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), SAMPLE);
        let m = path.metadata().unwrap();
        assert_eq!(m.ino(), target.inode);
        assert_eq!(m.modified().unwrap(), target.modified);
    }
    assert_eq!(fs::read(replacement).unwrap(), &SAMPLE[..5]);
}

#[test]
#[cfg(any(epoch249, epoch250, epoch251))]
fn returns_the_verified_original_without_overwriting_a_delivery_candidate() {
    let d = Dir::new();
    let holding = d.0.join("holding");
    fs::create_dir(&holding).unwrap();
    fs::set_permissions(&holding, fs::Permissions::from_mode(0o700)).unwrap();
    let src = holding.join("original-inode");
    let dest = d.0.join("epoch.jet");
    fs::write(&src, SAMPLE).unwrap();
    let m = src.metadata().unwrap();
    let held = HeldInode {
        device: m.dev(),
        inode: m.ino(),
        owner_mode: (m.uid(), m.gid(), m.mode() & 0o7777),
        modified: m.modified().unwrap(),
    };
    let restore = |digest: &str| {
        held.return_to_delivery(
            &holding,
            &dest,
            SAMPLE.len() as u64,
            digest,
            &d.0.metadata().unwrap(),
        )
    };
    assert!(restore(&"0".repeat(64)).is_err());
    let lock = File::open(&src).unwrap();
    lock.try_lock().unwrap();
    assert!(restore(&sha()).is_err());
    drop(lock);
    std::os::unix::fs::symlink("absent", &dest).unwrap();
    assert!(restore(&sha()).is_err());
    assert!(dest.is_symlink());
    fs::remove_file(&dest).unwrap();
    fs::write(&dest, SAMPLE).unwrap();
    assert!(restore(&sha()).is_err());
    assert!(src.exists());
    fs::remove_file(&dest).unwrap();
    restore(&sha()).unwrap();
    restore(&sha()).unwrap();
    assert!(!src.exists());
    assert_eq!(dest.metadata().unwrap().ino(), m.ino());
    fs::rename(&dest, d.0.join("keep")).unwrap();
    fs::write(&dest, SAMPLE).unwrap();
    assert!(restore(&sha()).is_err());
}
