//! Reconcile approximate legacy compact membership with the two root-verified local indexes.
use jetstreamer_firehose::index::{
    SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url, slot_to_range,
};
use sha2::{Digest, Sha256};
use std::{env, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

// Every listed legacy false positive lies strictly between CID-rooted, consecutive
// physical parent and child blocks in the qualified CAR windows.
const MANIFEST_SHA: &str = "cc4250c62eee9136933a87909891041c40bf5f2bc28fde36906e071a1b7156d0";
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

pub(super) struct RootedSlotPresence {
    profile: &'static Profile,
    raw: Vec<u8>,
}

impl RootedSlotPresence {
    /// An ordinary replay keeps its existing sources and trust assumptions.
    pub(super) async fn configured(epoch: u64) -> Result<Option<Self>, String> {
        let profile = match epoch {
            199 => &EPOCH_199,
            200 => &EPOCH_200,
            _ => return Ok(None),
        };
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            != Ok(MANIFEST_SHA)
        {
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
