use super::*;

#[test]
fn actual_ext4_mount_requires_exact_descriptor_mount_and_device() {
    let valid = b"42 1 259:3 / / rw,relatime - ext4 /dev/nvme0n1p3 rw\n";
    validate_ext4_mount(valid, 42, 259, 3).unwrap();
    assert!(validate_ext4_mount(valid, 43, 259, 3).is_err());
    assert!(validate_ext4_mount(valid, 42, 259, 4).is_err());
    for kind in ["ext2", "ext3", "tmpfs", "overlay"] {
        let changed = String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("ext4", kind);
        assert!(validate_ext4_mount(changed.as_bytes(), 42, 259, 3).is_err());
    }
    let duplicated = [valid.as_slice(), valid.as_slice()].concat();
    assert!(validate_ext4_mount(&duplicated, 42, 259, 3).is_err());
    assert!(validate_ext4_mount(b"42 1 259:3 / / rw ext4\n", 42, 259, 3).is_err());
    assert!(validate_ext4_mount(&vec![b'x'; 1_048_577], 42, 259, 3).is_err());
}

fn stable(kind: Kind) -> Stable {
    Stable {
        device: 1,
        inode: 2,
        mode: match kind {
            Kind::Regular => libc::S_IFREG | 0o600,
            Kind::Directory => libc::S_IFDIR | 0o700,
        },
        nlink: if kind == Kind::Regular { 1 } else { 2 },
        uid: 0,
        gid: 0,
        rdev: 0,
        length: BLOCK,
        blocks: 8,
        block_size: BLOCK,
        mtime: 1,
        mtime_nsec: 2,
        ctime: 3,
        ctime_nsec: 4,
    }
}
fn extent(logical: u64, physical: u64, flags: u32) -> Extent {
    Extent {
        logical,
        physical,
        length: BLOCK,
        flags,
        ..Extent::default()
    }
}
fn map(start: u64, limit: u64, extents: &[Extent]) -> Fiemap {
    let mut m = Fiemap {
        start,
        length: limit - start,
        flags: 0,
        mapped: extents.len() as u32,
        count: CHUNK as u32,
        reserved: 0,
        extents: [Extent::default(); CHUNK],
    };
    m.extents[..extents.len()].copy_from_slice(extents);
    m
}
fn dirent(name: &[u8], ino: u64, dtype: u8) -> Vec<u8> {
    let length = (19 + name.len() + 1 + 7) / 8 * 8;
    let mut b = vec![0u8; length];
    b[..8].copy_from_slice(&ino.to_ne_bytes());
    b[16..18].copy_from_slice(&(length as u16).to_ne_bytes());
    b[18] = dtype;
    b[19..19 + name.len()].copy_from_slice(name);
    b
}

#[test]
fn kernel_abi_layouts_and_closed_case_namespace() {
    assert_eq!(std::mem::size_of::<OpenHow>(), 24);
    assert_eq!(std::mem::size_of::<Extent>(), 56);
    assert_eq!(std::mem::size_of::<Fiemap>(), 32 + CHUNK * 56);
    for name in [
        "stable",
        "symlink",
        "hardlink",
        "fifo",
        "bind-mount",
        "pin-mutation",
    ] {
        assert_eq!(Case::parse(name).unwrap().name(), name);
        assert!(
            Case::parse(name)
                .unwrap()
                .relative()
                .starts_with(ROOT.trim_start_matches('/').as_bytes())
        );
    }
    for name in [
        "/home/ubuntu/horizon",
        "../qualification-236",
        "stable/../other",
        "",
        "replay",
        "allocation-freeze-fixture925-v1",
    ] {
        assert!(Case::parse(name).is_err());
    }
}

#[test]
fn metadata_gate_rejects_hardlinks_ownership_modes_special_files_and_foreign_devices() {
    for kind in [Kind::Regular, Kind::Directory] {
        let good = stable(kind);
        good.validate(1).unwrap();
        let mut bad = good.clone();
        bad.device = 2;
        assert!(bad.validate(1).is_err());
        bad = good.clone();
        bad.uid = 1000;
        assert!(bad.validate(1).is_err());
        bad = good.clone();
        bad.gid = 1000;
        assert!(bad.validate(1).is_err());
        bad = good.clone();
        bad.mode |= 0o020;
        assert!(bad.validate(1).is_err());
        bad = good.clone();
        bad.mode |= 0o4000;
        assert!(bad.validate(1).is_err());
        bad = good.clone();
        bad.rdev = 1;
        assert!(bad.validate(1).is_err());
    }
    let mut bad = stable(Kind::Regular);
    bad.nlink = 2;
    assert!(bad.validate(1).is_err());
    bad = stable(Kind::Regular);
    bad.length = MAX_FILE_LENGTH + 1;
    assert!(bad.validate(1).is_err());
    for kind in [
        libc::S_IFIFO,
        libc::S_IFLNK,
        libc::S_IFCHR,
        libc::S_IFBLK,
        libc::S_IFSOCK,
    ] {
        bad = stable(Kind::Regular);
        bad.mode = kind | 0o600;
        assert!(bad.validate(1).is_err());
    }
}

#[test]
fn dirent_parser_handles_raw_names_dot_entries_and_multiple_records() {
    let mut b = dirent(b".", 1, libc::DT_DIR);
    b.extend(dirent(b"..", 1, libc::DT_DIR));
    b.extend(dirent(b"name with spaces", 8, libc::DT_REG));
    b.extend(dirent(&[b'x', 0xff], 9, libc::DT_UNKNOWN));
    let entries = parse_dirents(&b).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, b"name with spaces");
    assert_eq!(entries[1].name, [b'x', 0xff]);
    assert_eq!(entries[1].inode, 9);
}

#[test]
fn dirent_parser_rejects_truncated_length_escape_inode_and_missing_terminator() {
    let good = dirent(b"entry", 7, libc::DT_REG);
    for n in 1..good.len() {
        assert!(
            parse_dirents(&good[..n]).is_err(),
            "accepted truncation {n}"
        );
    }
    for bad_len in [0u16, 8, 19, 23, 25, 65528] {
        let mut b = good.clone();
        b[16..18].copy_from_slice(&bad_len.to_ne_bytes());
        assert!(parse_dirents(&b).is_err());
    }
    let mut b = good.clone();
    b[19..].fill(b'x');
    assert!(parse_dirents(&b).is_err());
    assert!(parse_dirents(&dirent(b"a/b", 7, libc::DT_REG)).is_err());
    assert!(parse_dirents(&dirent(b"", 7, libc::DT_REG)).is_err());
    assert!(parse_dirents(&dirent(b"a", 0, libc::DT_REG)).is_err());
}

#[test]
fn fiemap_continues_across_full_chunks_then_honors_last() {
    let limit = (CHUNK as u64 + 1) * BLOCK;
    let first: Vec<_> = (0..CHUNK as u64)
        .map(|i| extent(i * BLOCK, (100 + i * 2) * BLOCK, 0))
        .collect();
    let mut all = Physical::default();
    let (next, done, _) =
        accept_chunk(&map(0, limit, &first), 0, limit, 1000 * BLOCK, &mut all).unwrap();
    assert_eq!(next, CHUNK as u64 * BLOCK);
    assert!(!done);
    let (end, done, _) = accept_chunk(
        &map(next, limit, &[extent(next, 500 * BLOCK, EXTENT_LAST)]),
        next,
        limit,
        1000 * BLOCK,
        &mut all,
    )
    .unwrap();
    assert_eq!(end, limit);
    assert!(done);
    assert_eq!(all.bytes, limit);
    assert_eq!(all.count, CHUNK + 1);
}

#[test]
fn sparse_tail_and_short_nonlast_chunk_have_explicit_termination() {
    let mut all = Physical::default();
    let limit = 10 * BLOCK;
    let (next, done, _) = accept_chunk(
        &map(0, limit, &[extent(2 * BLOCK, 100 * BLOCK, 0)]),
        0,
        limit,
        1000 * BLOCK,
        &mut all,
    )
    .unwrap();
    assert_eq!(next, 3 * BLOCK);
    assert!(!done);
    let (next, done, empty) =
        accept_chunk(&map(next, limit, &[]), next, limit, 1000 * BLOCK, &mut all).unwrap();
    assert_eq!(next, limit);
    assert!(done);
    assert!(empty.is_empty());
    assert_eq!(all.bytes, BLOCK);
    assert_eq!(rounded_length(0).unwrap(), 0);
    assert_eq!(rounded_length(1).unwrap(), BLOCK);
    assert!(rounded_length(MAX_FILE_LENGTH + 1).is_err());
}

#[test]
fn fiemap_rejects_unknown_delalloc_shared_encoded_inline_and_unaligned_flags() {
    // LAST and ext4 unwritten physical allocation are the entire allowed set.
    for flag in [
        0x2, 0x4, 0x8, 0x80, 0x100, 0x200, 0x400, 0x1000, 0x2000, 0x80000000,
    ] {
        assert!(
            accept_chunk(
                &map(0, BLOCK, &[extent(0, 100 * BLOCK, flag)]),
                0,
                BLOCK,
                1000 * BLOCK,
                &mut Physical::default()
            )
            .is_err(),
            "accepted {flag:x}"
        );
    }
    accept_chunk(
        &map(
            0,
            BLOCK,
            &[extent(0, 100 * BLOCK, EXTENT_LAST | EXTENT_UNWRITTEN)],
        ),
        0,
        BLOCK,
        1000 * BLOCK,
        &mut Physical::default(),
    )
    .unwrap();
    for e in [
        Extent {
            logical: 1,
            ..extent(0, 100 * BLOCK, 0)
        },
        Extent {
            physical: 100 * BLOCK + 1,
            ..extent(0, 100 * BLOCK, 0)
        },
        Extent {
            length: 1,
            ..extent(0, 100 * BLOCK, 0)
        },
        Extent {
            length: 0,
            ..extent(0, 100 * BLOCK, 0)
        },
        Extent {
            physical: 0,
            ..extent(0, 100 * BLOCK, 0)
        },
    ] {
        assert!(
            accept_chunk(
                &map(0, 2 * BLOCK, &[e]),
                0,
                2 * BLOCK,
                1000 * BLOCK,
                &mut Physical::default()
            )
            .is_err()
        );
    }
}

#[test]
fn fiemap_rejects_header_mutation_reserved_fields_and_premature_last() {
    for bad in 0..6 {
        let mut m = map(0, 2 * BLOCK, &[extent(0, 100 * BLOCK, 0)]);
        match bad {
            0 => m.start = 1,
            1 => m.length += 1,
            2 => m.flags = 1,
            3 => m.count += 1,
            4 => m.mapped = CHUNK as u32 + 1,
            _ => m.reserved = 1,
        };
        assert!(accept_chunk(&m, 0, 2 * BLOCK, 1000 * BLOCK, &mut Physical::default()).is_err());
    }
    let mut e = extent(0, 100 * BLOCK, 0);
    e.reserved64[0] = 1;
    assert!(
        accept_chunk(
            &map(0, BLOCK, &[e]),
            0,
            BLOCK,
            1000 * BLOCK,
            &mut Physical::default()
        )
        .is_err()
    );
    e.reserved64 = [0; 2];
    e.reserved[2] = 1;
    assert!(
        accept_chunk(
            &map(0, BLOCK, &[e]),
            0,
            BLOCK,
            1000 * BLOCK,
            &mut Physical::default()
        )
        .is_err()
    );
    let m = map(
        0,
        2 * BLOCK,
        &[
            extent(0, 100 * BLOCK, EXTENT_LAST),
            extent(BLOCK, 200 * BLOCK, EXTENT_LAST),
        ],
    );
    assert!(accept_chunk(&m, 0, 2 * BLOCK, 1000 * BLOCK, &mut Physical::default()).is_err());
}

#[test]
fn physical_overlap_is_global_across_files_and_adjacent_intervals_are_distinct() {
    let mut all = Physical::default();
    for start in [3 * BLOCK, BLOCK, 2 * BLOCK] {
        all.add(start, start + BLOCK).unwrap();
    }
    assert_eq!(all.bytes, 3 * BLOCK);
    for (a, b) in [
        (BLOCK, 2 * BLOCK),
        (BLOCK + 1, 2 * BLOCK),
        (0, 2 * BLOCK),
        (BLOCK, 5 * BLOCK),
        (2 * BLOCK, 3 * BLOCK + 1),
    ] {
        assert!(all.add(a, b).is_err());
    }
    let mut all = Physical::default();
    accept_chunk(
        &map(0, BLOCK, &[extent(0, 100 * BLOCK, EXTENT_LAST)]),
        0,
        BLOCK,
        1000 * BLOCK,
        &mut all,
    )
    .unwrap();
    // A second file resets its logical cursor, never the physical registry.
    assert!(
        accept_chunk(
            &map(0, BLOCK, &[extent(0, 100 * BLOCK, EXTENT_LAST)]),
            0,
            BLOCK,
            1000 * BLOCK,
            &mut all
        )
        .is_err()
    );
}

#[test]
fn fiemap_checked_ends_reject_logical_physical_and_filesystem_overflow() {
    let e = extent(u64::MAX - (BLOCK - 1), BLOCK, 0);
    assert!(
        accept_chunk(
            &map(0, u64::MAX, &[e]),
            0,
            u64::MAX,
            u64::MAX,
            &mut Physical::default()
        )
        .is_err()
    );
    let e = extent(0, u64::MAX - (BLOCK - 1), 0);
    assert!(
        accept_chunk(
            &map(0, BLOCK, &[e]),
            0,
            BLOCK,
            u64::MAX,
            &mut Physical::default()
        )
        .is_err()
    );
    assert!(
        accept_chunk(
            &map(0, BLOCK, &[extent(0, 100 * BLOCK, 0)]),
            0,
            BLOCK,
            100 * BLOCK,
            &mut Physical::default()
        )
        .is_err()
    );
    assert!(
        accept_chunk(
            &map(
                0,
                BLOCK,
                &[Extent {
                    length: 2 * BLOCK,
                    ..extent(0, 100 * BLOCK, 0)
                }]
            ),
            0,
            BLOCK,
            1000 * BLOCK,
            &mut Physical::default()
        )
        .is_err()
    );
}

#[test]
fn bounded_physical_registry_and_monotonic_deadline_fail_closed() {
    let mut all = Physical::default();
    for i in 0..MAX_EXTENTS as u64 {
        all.add((i + 1) * BLOCK, (i + 2) * BLOCK).unwrap();
    }
    assert!(
        all.add(
            (MAX_EXTENTS as u64 + 1) * BLOCK,
            (MAX_EXTENTS as u64 + 2) * BLOCK
        )
        .is_err()
    );
    let mut b = Budget::new();
    b.deadline = Instant::now() - Duration::from_millis(1);
    assert!(b.check().is_err());
    let mut b = Budget::new();
    b.checks = MAX_SYSCALL_CHECKS;
    assert!(b.check().is_err());
    let mut b = Budget::new();
    b.map_calls = MAX_MAP_CALLS;
    assert!(b.map_call().is_err());
}

// Native controls are deliberately ignored by the ordinary suite. They create
// unique fixed-case directories with no-clobber mkdir/create and retain them on
// failure. They never remove or reuse prior cases or touch the925 fixture.
fn mkdir_at(fd: RawFd, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    ensure!(
        unsafe { libc::mkdirat(fd, name.as_ptr(), 0o700) } == 0,
        "fixture case already exists or mkdir failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn native_case(case: Case) -> Result<File> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native fixture requires Root"
    );
    let anchor = File::open("/")?;
    let mut budget = Budget::new();
    let parent = open_beneath(
        anchor.as_raw_fd(),
        b"home/ubuntu/.jetstreamer-private",
        libc::O_RDONLY | libc::O_DIRECTORY,
        &mut budget,
    )?;
    let name = c"allocation-tree-fixture927-v1";
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result != 0 {
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST),
            "cannot prepare fixed fixture root"
        );
    }
    parent.sync_all()?;
    let root = open_beneath(
        parent.as_raw_fd(),
        name.to_bytes(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        &mut budget,
    )?;
    let s = Stable::of(&root.metadata()?);
    ensure!(
        s.validate(s.device)? == Kind::Directory,
        "unsafe existing fixture root"
    );
    ext4_capacity(root.as_raw_fd(), &mut budget)?;
    mkdir_at(root.as_raw_fd(), case.name())?;
    root.sync_all()?;
    open_beneath(
        root.as_raw_fd(),
        case.name().as_bytes(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        &mut budget,
    )
}
fn create_file(dir: &File, name: &str) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    ensure!(fd >= 0, "fixture file exists or create failed");
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn write_block(file: &File, offset: u64) -> Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(&[0x5a; BLOCK as usize], offset)?;
    Ok(())
}

#[test]
#[ignore = "native disposable ext4 fixture; separate Main admission required"]
fn native_stable_sparse_tree_exercises_more_than_one_fiemap_chunk() {
    let dir = native_case(Case::Stable).unwrap();
    mkdir_at(dir.as_raw_fd(), "nested").unwrap();
    let mut b = Budget::new();
    let nested = open_beneath(
        dir.as_raw_fd(),
        b"nested",
        libc::O_RDONLY | libc::O_DIRECTORY,
        &mut b,
    )
    .unwrap();
    let fragmented = create_file(&nested, "sparse-fragmented").unwrap();
    for i in 0..(CHUNK as u64 + 3) {
        write_block(&fragmented, i * 2 * BLOCK).unwrap();
    }
    fragmented.sync_all().unwrap();
    create_file(&dir, "empty").unwrap().sync_all().unwrap();
    nested.sync_all().unwrap();
    dir.sync_all().unwrap();
    let r = scan(Case::Stable).unwrap();
    assert_eq!(r.files, 2);
    assert_eq!(r.directories, 2);
    assert!(r.fiemap_calls >= 2);
    assert!(r.extent_count > CHUNK);
    assert!(r.unique_physical_extent_bytes_observed > CHUNK as u64 * BLOCK);
    assert_eq!(r.capacity_credit_bytes, 0);
    assert!(!r.quiescence_proven && !r.admission_authorized && !r.live_replay_authorized);
}

#[test]
#[ignore = "native disposable symlink negative control; separate Main admission required"]
fn native_symlink_cannot_escape_to_outside_fixture() {
    let dir = native_case(Case::Symlink).unwrap();
    let name = c"outside";
    assert_eq!(
        unsafe { libc::symlinkat(c"/etc/passwd".as_ptr(), dir.as_raw_fd(), name.as_ptr()) },
        0
    );
    Tree::root(Case::Symlink, &mut Budget::new()).unwrap();
    let error = scan(Case::Symlink)
        .err()
        .expect("symlink was accepted")
        .to_string();
    assert!(
        error.contains("symlink or nonregular fixture entry")
            || (error.contains("openat2 refused fixture path") && error.contains("os error 40")),
        "{error}"
    );
}

#[test]
#[ignore = "native disposable hardlink negative control; separate Main admission required"]
fn native_hardlink_alias_is_rejected() {
    let dir = native_case(Case::Hardlink).unwrap();
    let f = create_file(&dir, "data").unwrap();
    write_block(&f, 0).unwrap();
    f.sync_all().unwrap();
    assert_eq!(
        unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                c"data".as_ptr(),
                dir.as_raw_fd(),
                c"alias".as_ptr(),
                0,
            )
        },
        0
    );
    let error = scan(Case::Hardlink)
        .err()
        .expect("hardlink was accepted")
        .to_string();
    assert!(
        error.contains("hardlink or oversized fixture file"),
        "{error}"
    );
}

#[test]
#[ignore = "native disposable FIFO negative control; separate Main admission required"]
fn native_fifo_is_rejected_without_blocking_data_open() {
    let dir = native_case(Case::Fifo).unwrap();
    assert_eq!(
        unsafe { libc::mkfifoat(dir.as_raw_fd(), c"pipe".as_ptr(), 0o600) },
        0
    );
    let error = scan(Case::Fifo)
        .err()
        .expect("FIFO was accepted")
        .to_string();
    assert!(
        error.contains("symlink or nonregular fixture entry"),
        "{error}"
    );
}

#[test]
#[ignore = "native disposable bind mount; requires separate CAP_SYS_ADMIN and namespace admission"]
fn native_same_filesystem_bind_mount_is_rejected() {
    let dir = native_case(Case::BindMount).unwrap();
    Tree::root(Case::BindMount, &mut Budget::new()).unwrap();
    mkdir_at(dir.as_raw_fd(), "source").unwrap();
    mkdir_at(dir.as_raw_fd(), "target").unwrap();
    let source = CString::new(format!("/proc/self/fd/{}/source", dir.as_raw_fd())).unwrap();
    let target = CString::new(format!("/proc/self/fd/{}/target", dir.as_raw_fd())).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0
    );
    struct Mounted {
        target: CString,
        active: bool,
    }
    impl Drop for Mounted {
        fn drop(&mut self) {
            if self.active {
                let r = unsafe { libc::umount2(self.target.as_ptr(), libc::MNT_DETACH) };
                eprintln!("fixture-only emergency bind unmount result={r}");
            }
        }
    }
    let mut mount = Mounted {
        target,
        active: true,
    };
    let result = scan(Case::BindMount);
    assert_eq!(unsafe { libc::umount2(mount.target.as_ptr(), 0) }, 0);
    mount.active = false;
    let error = result.err().expect("bind mount was accepted").to_string();
    assert!(
        error.contains("openat2 refused fixture path") && error.contains("os error 18"),
        "{error}"
    );
}

#[test]
#[ignore = "native disposable truncate/punch demonstration; separate Main admission required"]
fn native_open_descriptors_do_not_prevent_truncate_or_hole_punch() {
    let dir = native_case(Case::PinMutation).unwrap();
    let pinned = create_file(&dir, "truncate").unwrap();
    for i in 0..8 {
        write_block(&pinned, i * BLOCK).unwrap();
    }
    pinned.sync_all().unwrap();
    let before = Stable::of(&pinned.metadata().unwrap());
    let mut b = Budget::new();
    let mut tree = Tree::root(Case::PinMutation, &mut b).unwrap();
    tree.walk(0, 0, &mut b).unwrap();
    let mutator = open_beneath(dir.as_raw_fd(), b"truncate", libc::O_RDWR, &mut b).unwrap();
    mutator.set_len(0).unwrap();
    mutator.sync_all().unwrap();
    assert_ne!(before, Stable::of(&pinned.metadata().unwrap()));
    assert_eq!(pinned.metadata().unwrap().len(), 0);
    assert!(tree.validate_all(&mut b).is_err());
    drop(tree);
    let pinned = create_file(&dir, "punch").unwrap();
    for i in 0..8 {
        write_block(&pinned, i * BLOCK).unwrap();
    }
    pinned.sync_all().unwrap();
    let before = Stable::of(&pinned.metadata().unwrap());
    let mut b = Budget::new();
    let mut tree = Tree::root(Case::PinMutation, &mut b).unwrap();
    tree.walk(0, 0, &mut b).unwrap();
    let mutator = open_beneath(dir.as_raw_fd(), b"punch", libc::O_RDWR, &mut b).unwrap();
    assert_eq!(
        unsafe {
            libc::fallocate(
                mutator.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                BLOCK as i64,
                BLOCK as i64,
            )
        },
        0
    );
    mutator.sync_all().unwrap();
    let after = Stable::of(&pinned.metadata().unwrap());
    assert_eq!(before.length, after.length);
    assert_ne!(before, after);
    assert!(tree.validate_all(&mut b).is_err());
}
