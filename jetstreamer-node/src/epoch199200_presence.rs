//! Reconcile approximate legacy compact membership with root-verified local indexes.
use jetstreamer_firehose::index::{
    SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url, slot_to_range,
};
use sha2::{Digest, Sha256};
use std::{env, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

// Every listed legacy false positive lies strictly between CID-rooted, consecutive
// physical parent and child blocks in the qualified CAR windows.
const MANIFEST_SHA: &str = "cc4250c62eee9136933a87909891041c40bf5f2bc28fde36906e071a1b7156d0";
const COHORT_267_268_MANIFEST_SHA: &str =
    "80245e30eb7dbe2ccfdac4b17110799100f6ffd2356b455751735cd93a3f4802";
const COHORT_267_270_SHA: &str = "3e0bfe7153bb17f13dc75caac88b8e4f6ff06760520d48b7f92b5d66e6c5027d";
const COHORT_270_274_SHA: &str = "a1ddfbf5ad7f7a8932895d0c2e8b6a61e5f597fbaae3790e9a719e928df2395f";
const SLOTS: u64 = 432_000;
const TABLE_BYTES: usize = SLOTS as usize * 12;

struct Profile {
    epoch: u64,
    raw_sha: &'static str,
    compact_sha: &'static str,
    proven_skips: &'static [u64],
}

const EPOCH_199: Profile = Profile {
    epoch: 199,
    raw_sha: "ebabf661a7608e72169e85d3be3129a575ab8f5b1d2e67d2f10c95a8de79a1ae",
    compact_sha: "ed0005ecf731c6716d52f0f67aea2ca98d1b1a31771dc1d319fb6c873c136958",
    proven_skips: &[
        85975214, 85975920, 85981443, 85984461, 85988546, 85990752, 85994522, 86016034, 86016440,
        86028032, 86032179, 86033071, 86034674, 86044661, 86057311, 86060695, 86064504, 86080868,
        86084404, 86087238, 86090573, 86097404, 86099952, 86104351, 86109815, 86125477, 86136437,
        86137036, 86142926, 86154409, 86160443, 86162129, 86166456, 86172933, 86178710, 86184359,
        86208574, 86208665, 86219603, 86233439, 86233938, 86240738, 86250434, 86263995, 86273695,
        86276159, 86284661, 86285926, 86287064, 86287945, 86288643, 86288751, 86295448, 86303362,
        86307362, 86307481, 86314226, 86321218, 86322051, 86325077, 86329026, 86330689, 86339356,
        86343053, 86346075, 86349977, 86360891, 86361771, 86363201, 86373195, 86382484, 86396856,
    ],
};

const EPOCH_200: Profile = Profile {
    epoch: 200,
    raw_sha: "d37e594b89638dac4fb8ca094bccce5c388f5c583472a592dec1ed811c749cd7",
    compact_sha: "53b10b76265b4feff785c1f60c4dff4e70f4c932ab2b295237b5d7a1ace3484a",
    proven_skips: &[
        86400353, 86406549, 86417873, 86419017, 86424896, 86436299, 86439971, 86443638, 86468330,
        86476229, 86483862, 86487972, 86490504, 86490717, 86504382, 86505284, 86526623, 86530309,
        86539355, 86541582, 86543974, 86547683, 86552347, 86555877, 86570563, 86579825, 86586536,
        86592985, 86593737, 86602561, 86624468, 86634730, 86644911, 86646879, 86649599, 86654001,
        86670583, 86672779, 86676098, 86677360, 86680425, 86684353, 86691072, 86696527, 86702807,
        86704203, 86710204, 86718937, 86732704, 86746235, 86749070, 86756339, 86777659, 86782335,
        86786206, 86787008, 86787077, 86798396, 86805965, 86816583, 86823620, 86827774, 86829880,
    ],
};

const EPOCH_268: Profile = Profile {
    epoch: 268,
    raw_sha: "97a0e4ad0cbf5b99c81f1e5097625ef90b3e03364aee567c7679ba59ff4417af",
    compact_sha: "55c5d4895b620afb57afacdb7284df709217443b0fcd986849ca68a3d73eef8f",
    proven_skips: &[
        115785300, 115796349, 115800679, 115885020, 115890547, 115892696, 115932365, 115958926,
        115971936, 115977892, 116025892, 116028176, 116032670, 116071938, 116087494, 116094316,
        116105761, 116113001, 116125872,
    ],
};

const EPOCH_269: Profile = Profile {
    epoch: 269,
    raw_sha: "c36b80da05b7b8f1c7ceb0eb4eb493c5c6c71a7a6d39c26013ed6d57bef146b1",
    compact_sha: "760af23b1f4ce08bfbb82d320846c49a18fe53a6550b3e2b6f403d8633280447",
    proven_skips: &[
        116260388, 116261511, 116271319, 116282125, 116311334, 116348641, 116383321, 116419950,
        116423577, 116448001, 116457771, 116473569, 116493388, 116562945,
    ],
};
const EPOCH_270: Profile = Profile {
    epoch: 270,
    raw_sha: "8bf3e296ee3a944cb6fcd1c9ff70eaa6a59f5269a9009eaa1649cc19608434b9",
    compact_sha: "a40fecc69aef805155d276acf93c680f5628dd7eb089dad68bb6bd21fdc6e167",
    proven_skips: &[
        116667934, 116682966, 116715243, 116761379, 116807097, 116836992, 116846916, 116990228,
        117008024, 117010075, 117037937,
    ],
};
const EPOCH_267: Profile = Profile {
    epoch: 267,
    raw_sha: "b60ac1831d3f8850e426a6b47ee393e8260e67a9c7c473f1aea370fedd92c5e0",
    compact_sha: "f4e7038ddc675f1a232da98aedce805c30f73297d556ebe61e5ea5b2b9a1496a",
    proven_skips: &[
        115346704, 115347368, 115363157, 115372859, 115378566, 115385019, 115425045, 115473625,
        115475380, 115488514, 115489756, 115506558, 115535754, 115558078, 115578563, 115581456,
        115583627, 115610728, 115612956, 115613553, 115615519, 115620615, 115629720, 115640040,
        115662050, 115668148, 115721933, 115722433, 115747564, 115760672,
    ],
};

const EPOCH_271: Profile = Profile {
    epoch: 271,
    raw_sha: "4426d157519b8c2d985ec990f14d2b9c9537c9a61040646c1c3587189d670eff",
    compact_sha: "18d79a95d89542f77ca5095c2ca66601662da49dbfd9d2bd461240f8f785aeb2",
    proven_skips: &[
        117076328, 117096977, 117105768, 117121048, 117121725, 117122283, 117125893, 117150455,
        117159624, 117188844, 117191616, 117204356, 117235564, 117251099, 117256141, 117260365,
        117280264, 117292001, 117293330, 117307320, 117309749, 117316604, 117319663, 117329315,
        117330026, 117341517, 117342879, 117363244, 117366324, 117428878,
    ],
};

const EPOCH_272: Profile = Profile {
    epoch: 272,
    raw_sha: "80c214ab627eab724de597a1487aaadea2af11178f0290de7bc0ef22c0b51b48",
    compact_sha: "5cd681b9c2f1efa9c91134826e35dcdf32960fbeac01998559af19bed4c9959b",
    proven_skips: &[
        117564996, 117576770, 117596300, 117639544, 117650880, 117672388, 117710963, 117720819,
        117762256, 117763081, 117774647, 117833088, 117889903, 117908261, 117918075,
    ],
};

const EPOCH_273: Profile = Profile {
    epoch: 273,
    raw_sha: "222e533f4e85885bfb5e87c9733f81e0ee9657a4b2059f8e1394db1a161386f5",
    compact_sha: "2a86d4e959b2c829e04d05dd154aa31cb205e0e0e97ffd0d5556c1fc23727db9",
    proven_skips: &[
        117983227, 118127610, 118158232, 118198186, 118208016, 118240075, 118260349, 118366472,
        118366758,
    ],
};

const EPOCH_274: Profile = Profile {
    epoch: 274,
    raw_sha: "ba0ced24ed639dd354e4799c5c87c1cb9dadd43ac3e245ac9f2e6bdbda6221e0",
    compact_sha: "6984406cef13898010d9163638590fa79291bfcca650aa8c3a31e19ea667a9bb",
    proven_skips: &[
        118453640, 118590656, 118624580, 118639077, 118667452, 118756132, 118764536,
    ],
};

pub(super) struct RootedSlotPresence {
    profile: &'static Profile,
    raw: Vec<u8>,
}

impl RootedSlotPresence {
    /// An ordinary replay keeps its existing sources and trust assumptions.
    pub(super) async fn configured(epoch: u64) -> Result<Option<Self>, String> {
        let (profile, manifest_sha) = match epoch {
            199 => (&EPOCH_199, MANIFEST_SHA),
            200 => (&EPOCH_200, MANIFEST_SHA),
            267 => (
                &EPOCH_267,
                "e6f765e4fdca3f5e2c7c8bb1cda38b8ad9ff0e801dcb6df75799f74ce9e47f6f",
            ),
            268 => (
                &EPOCH_268,
                "92a805a982c8edfc24f0f4c02192c26e2ad2ab57db6a4bd9355f36eca7d26642",
            ),
            269 => (
                &EPOCH_269,
                "7428b7e662df64fdab109021fdf38fa464650744270b34ee66f4b2e630e27a1c",
            ),
            270 => (
                &EPOCH_270,
                "930dd2337cfa4abf31ca4423e9f3a3b3825c3dfae271db6ddaaccb1fbc446fb3",
            ),
            271 => (
                &EPOCH_271,
                "dfd5ea092855246ec440d5dda30c4188335b0736d8fea34bec762118621eb678",
            ),
            272 => (
                &EPOCH_272,
                "a3144eb683a7d48634b1f0838cc9ffab2d526e8d5681bf1173b386c645903fba",
            ),
            273 => (
                &EPOCH_273,
                "2227c249ea8e5cd9e87d202314e41291a87ab4d759eef26f431ebbd0e9303219",
            ),
            274 => (
                &EPOCH_274,
                "74c2a4634f067787a0fadd11a56fb6a0d40e4d848fac9eff61dc22ade0c66014",
            ),
            _ => return Ok(None),
        };
        let configured = env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").ok();
        let combined = matches!(epoch, 267 | 268)
            && configured.as_deref() == Some(COHORT_267_268_MANIFEST_SHA);
        let four = matches!(epoch, 267..=270) && configured.as_deref() == Some(COHORT_267_270_SHA);
        let next_cohort =
            matches!(epoch, 270..=274) && configured.as_deref() == Some(COHORT_270_274_SHA);
        if configured.as_deref() != Some(manifest_sha) && !combined && !four && !next_cohort {
            return Ok(None);
        }
        if env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").is_none() {
            return Err("missing qualified slot-ranges manifest".into());
        }
        // Resolve this through the same authenticated manifest and global index used by the
        // CAR reader. Only a missing slot from the local table identifies the acting source.
        SlotOffsetIndex::new(get_index_base_url().map_err(|err| err.to_string())?)
            .map_err(|err| err.to_string())?;
        let sentinel = profile.proven_skips[0];
        let path = match slot_to_range(sentinel).await {
            Err(SlotOffsetIndexError::SlotNotFound(slot, url))
                if slot == sentinel && url.scheme() == "file" =>
            {
                url.to_file_path()
                    .map_err(|_| "invalid local slot-ranges file URL".to_string())?
            }
            other => {
                return Err(format!(
                    "epoch {epoch} qualified slot-ranges source disagrees at {sentinel}: {other:?}"
                ));
            }
        };
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        let m = f.metadata().map_err(|e| e.to_string())?;
        if !m.is_file() || m.len() != TABLE_BYTES as u64 {
            return Err(format!(
                "epoch {epoch} invalid local slot-ranges length or type"
            ));
        }
        let mut raw = Vec::with_capacity(TABLE_BYTES);
        f.take(TABLE_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() != TABLE_BYTES || format!("{:x}", Sha256::digest(&raw)) != profile.raw_sha {
            return Err(format!(
                "epoch {epoch} qualified slot-ranges content changed"
            ));
        }
        Ok(Some(Self { profile, raw }))
    }

    pub(super) fn verify_compact(&self, bytes: &[u8]) -> Result<(), String> {
        if format!("{:x}", Sha256::digest(bytes)) != self.profile.compact_sha {
            return Err(format!(
                "epoch {} independent slot-to-CID identity changed",
                self.profile.epoch
            ));
        }
        Ok(())
    }

    pub(super) fn present(&self, slot: u64, legacy: bool) -> Result<bool, String> {
        let row = slot
            .checked_sub(self.profile.epoch * SLOTS)
            .filter(|i| *i < SLOTS)
            .ok_or_else(|| format!("slot {slot} outside qualified epoch {}", self.profile.epoch))?
            as usize;
        let p = &self.raw[row * 12..(row + 1) * 12];
        let present = u32::from_le_bytes(p[8..12].try_into().unwrap()) != 0;
        let known_skip = self.profile.proven_skips.binary_search(&slot).is_ok();
        if known_skip && legacy && !present {
            return Ok(false);
        }
        if !known_skip && legacy == present {
            return Ok(present);
        }
        Err(format!(
            "unexpected legacy and rooted slot presence at slot {slot}: legacy={legacy} rooted={present} known_skip={known_skip}"
        ))
    }
}

// Uses the actual scheduler/recorder path and compact index reader. This exact
// ignored test runs under the funded offline fixture with the sealed map projected.
#[cfg(test)]
mod qualified_epoch268 {
    use super::super::{LocalSlotIndex, SlotPresenceState, build_slot_presence_map};
    use super::{Profile, RootedSlotPresence, SLOTS};
    use std::{
        env, fs,
        path::PathBuf,
        sync::{Arc, atomic::AtomicBool},
    };
    #[tokio::test]
    #[ignore = "requires sealed epoch 268 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_rooted_map() {
        check(
            &super::EPOCH_268,
            "bafyreiadrsuockl4wyx2s2nu247atdi7xhc6pc7ynhmetagg7mdkjdktgu",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 267 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch267_map() {
        check(
            &super::EPOCH_267,
            "bafyreifn4ykgns5ih2lzfzrvky2u5vfh4jvqcqy7tdylujrbvl6pqavi4m",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 269 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch269_map() {
        check(
            &super::EPOCH_269,
            "bafyreihyxzt42dpkxrmluxqvkxqfnkas7czh5igcvorg5a7fr4ckvewxzm",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 270 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch270_map() {
        check(
            &super::EPOCH_270,
            "bafyreiewpp2gte55lvp5ml7labmgudq72juwvj5o5j3jd6xyjjbaxpudcu",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 271 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch271_map() {
        check(
            &super::EPOCH_271,
            "bafyreievtg2mp5c7prfzuntr3hhljck6hbhrmkb65jmswlke6norpck4my",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 272 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch272_map() {
        check(
            &super::EPOCH_272,
            "bafyreibyphy25qwppk5bm2uum2kp3dbqrjtjljqhdulhbqxesjj5encc3a",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 273 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch273_map() {
        check(
            &super::EPOCH_273,
            "bafyreiad53lhdnph2etnrbwslfirrx7rb6r2dma2aazgm4bs5dvfw4hax4",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 274 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch274_map() {
        check(
            &super::EPOCH_274,
            "bafyreid47yanxmkgrltqmsa3lbjwnbphm6fgwj7lvvwdoait7yv2zfwglq",
        )
        .await;
    }

    async fn check(profile: &Profile, car_root: &str) {
        let epoch = profile.epoch;
        let first = epoch * SLOTS;
        let last = first + SLOTS - 1;
        let ledger =
            PathBuf::from(env::var_os(format!("HORIZON{epoch}_QUALIFIED_LEDGER")).unwrap());
        let compact = ledger.join(format!(
            "compact-indexes/{epoch}/epoch-{epoch}-{car_root}-mainnet-slot-to-cid.index"
        ));
        let bytes = fs::read(compact).unwrap();
        let raw = fs::read(format!("/var/lib/jetstreamer/horizon{epoch}-rooted-slot-ranges-v1/epoch-{epoch}-slot-ranges.raw")).unwrap();
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_267_270_SHA)
        {
            for sibling in 267..=270 {
                assert!(
                    RootedSlotPresence::configured(sibling)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_267_268_MANIFEST_SHA)
        {
            let previous = RootedSlotPresence::configured(267).await.unwrap().unwrap();
            let skip = super::EPOCH_267.proven_skips[0];
            assert!(!previous.present(skip, true).unwrap());
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_270_274_SHA)
        {
            for sibling in 270..=274 {
                assert!(
                    RootedSlotPresence::configured(sibling)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
        let source = RootedSlotPresence::configured(epoch)
            .await
            .unwrap()
            .unwrap();
        source.verify_compact(&bytes).unwrap();
        assert!(source.verify_compact(&bytes[..bytes.len() - 1]).is_err());
        let legacy = LocalSlotIndex::from_bytes(bytes).unwrap();
        assert_eq!(legacy.header.metadata_epoch(), Some(epoch));
        let m = build_slot_presence_map(
            first,
            last,
            Arc::new(AtomicBool::new(false)),
            &ledger,
            epoch,
        )
        .await
        .unwrap();
        let mut next = None;
        let mut false_positives = Vec::new();
        for i in (0..SLOTS as usize).rev() {
            let slot = first + i as u64;
            let offset = i * 12;
            let expected =
                u32::from_le_bytes(raw[offset + 8..offset + 12].try_into().unwrap()) != 0;
            let h = legacy.contains_slot(slot).unwrap();
            assert_eq!(source.present(slot, h).unwrap(), expected);
            assert!(source.present(slot, !h).is_err());
            assert_eq!(
                m.state(slot),
                Some(if expected {
                    SlotPresenceState::Present
                } else {
                    SlotPresenceState::Missing
                })
            );
            assert_eq!(m.next_present_after(slot), next);
            if expected {
                next = Some(slot)
            } else if h {
                false_positives.push(slot)
            }
        }
        false_positives.reverse();
        assert_eq!(false_positives.as_slice(), profile.proven_skips);
        assert!(source.present(first - 1, false).is_err());
        assert!(source.present(last + 1, false).is_err());
    }
}
