//! Exact retained object profiles shared by preparation and the private node.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Snapshot {
    pub slot: u64,
    pub hash: &'static str,
    pub generation: u64,
    pub size: u64,
    pub crc: &'static str,
    pub md5: &'static str,
}
impl Snapshot {
    pub fn filename(self) -> String {
        format!("snapshot-{}-{}.tar.zst", self.slot, self.hash)
    }
    pub fn uri(self) -> String {
        format!(
            "gs://mainnet-beta-ledger-us-ny5/{}/{}",
            self.slot,
            self.filename()
        )
    }
    pub fn versioned_uri(self) -> String {
        format!("{}#{}", self.uri(), self.generation)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Profile {
    pub epoch: u64,
    pub package: &'static str,
    pub bindings_sha: &'static str,
    pub bootstrap: Snapshot,
    pub root: Snapshot,
}
impl Profile {
    pub fn start(self) -> u64 {
        self.epoch * 432000
    }
    pub fn end(self) -> u64 {
        (self.epoch + 1) * 432000
    }
    pub fn root_prefix(self) -> String {
        format!("qualification-{}-singleton-", self.epoch)
    }
}
const S209: Snapshot = Snapshot {
    slot: 90287519,
    hash: "6hSbTbwcGhgRGtxQ6iH2aWBhqRzGwhNBPCVDCBZ1fAxp",
    generation: 1628496316031397,
    size: 8543246873,
    crc: "nje1nQ==",
    md5: "TlPye07dj4vjbpuxWY1VJQ==",
};
const S210: Snapshot = Snapshot {
    slot: 90719638,
    hash: "3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ",
    generation: 1628731675837475,
    size: 8579041139,
    crc: "rBQmbQ==",
    md5: "pBPdxBtyTOt6A7LhXryC8Q==",
};
const S211: Snapshot = Snapshot {
    slot: 91151575,
    hash: "xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx",
    generation: 1628983801891966,
    size: 8731506223,
    crc: "4Sr/GA==",
    md5: "mMBeym4d6L8xRT8awzc+Kg==",
};
const S212: Snapshot = Snapshot {
    slot: 91583512,
    hash: "548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV",
    generation: 1629232341551900,
    size: 8715614412,
    crc: "Ve4m1Q==",
    md5: "HME5fA/Y1I3O4MhAh4O8Lg==",
};
const S213: Snapshot = Snapshot {
    slot: 92015419,
    hash: "VkTNdojvP5U4pPTSUQfK997eJsxMVfwt8HYxhgcV4nU",
    generation: 1629495308790561,
    size: 8981889115,
    crc: "iU3mfg==",
    md5: "KGpeDBOVBqyEI/gcezbhzw==",
};
pub(crate) const PROFILES: [Profile; 4] = [
    Profile {
        epoch: 209,
        package: "/var/lib/jetstreamer/horizon-focused-209-complete-span-store8-ca2e38b-v2",
        bindings_sha: "62fdbca7cfe8642c3e6d6bffab3161bf0dbd558a9eca3be6193ac1cc14ce9be0",
        bootstrap: S209,
        root: S210,
    },
    Profile {
        epoch: 210,
        package: "/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1",
        bindings_sha: "877aeb63674523f1d4cc6937f993a57204bc39999e8e378ea84a6ac1ae5409a8",
        bootstrap: S210,
        root: S211,
    },
    Profile {
        epoch: 211,
        package: "/var/lib/jetstreamer/horizon-focused-211-complete-span-store8-ca2e38b-v1",
        bindings_sha: "f48751ee91ab153ab185b5e14967d1adfc4681b2a3c46402bce9339e1e60d681",
        bootstrap: S211,
        root: S212,
    },
    Profile {
        epoch: 212,
        package: "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1",
        bindings_sha: "80cb65fdabb9f15cb68e14a7c905b6568be9ecda10f4950c6cd58305f847ac76",
        bootstrap: S212,
        root: S213,
    },
];
pub(crate) fn profile(epoch: u64) -> Result<Profile, String> {
    PROFILES
        .iter()
        .find(|p| p.epoch == epoch)
        .copied()
        .ok_or_else(|| "private singleton profile must be209,210,211or212".into())
}
