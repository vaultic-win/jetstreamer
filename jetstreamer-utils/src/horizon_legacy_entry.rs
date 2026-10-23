//! Diagnostic-only fixed-integer bincode entry decoding for Solana v1.4.25.
//!
//! Pinned revision: 893cc7647248a3536fb6e6d0b5e51c71446b862d. Entry layout and
//! signature Merkle hashing follow ledger/src/entry.rs (SHA-256
//! 8ba2b21314b85f709dc9b398705ce340250e1419ab13f4e5a7dd5f44322d711f) and
//! merkle-tree/src/merkle_tree.rs (SHA-256
//! 055a9d96aa098f58dcfd83de6f0ddc8c8aeb08a93dab1c9b1e28a44a2225a6b0).
//! This is not ledger completeness, signature authentication, PoH verification,
//! runtime qualification, or publication evidence. No production caller exists.

use sha2::{Digest, Sha256};

const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536;
const MAX_TRANSACTIONS: usize = 65_536;
const MAX_SIGNATURES: usize = 65_536;
const MAX_TRANSACTION_BYTES: usize = 1232;

/// One decoded entry's claimed hash and independently derived signature mixin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticEntry {
    /// Claimed hash work; not yet executed or verified by this decoder.
    pub num_hashes: u64,
    /// Claimed entry hash, still requiring chained PoH verification.
    pub hash: [u8; 32],
    /// Number of structurally decoded legacy transactions.
    pub transaction_count: usize,
    /// None for ticks; Some(zero hash) for nonempty, signature-free transactions.
    /// Otherwise the pinned Merkle root over signatures in transaction order.
    pub signature_mixin: Option<[u8; 32]>,
}

/// Diagnostic entry-vector decoding result; it confers no integrity authority.
#[derive(Debug, Eq, PartialEq)]
pub struct DiagnosticEntryBatch {
    /// Entries in their original serialized order.
    pub entries: Vec<DiagnosticEntry>,
    /// Exact serialized-vector length, excluding verified zero padding.
    pub serialized_bytes: usize,
}

/// Lossless, borrowed legacy transactions for a separately qualified source adapter.
/// These bytes have passed only structural decoding, not runtime or signature gates.
#[derive(Debug, Eq, PartialEq)]
pub struct DiagnosticWireEntry<'a> {
    /// Structurally decoded hash-work claim, entry hash, count, and signature mixin.
    pub metadata: DiagnosticEntry,
    /// Original legacy Transaction encodings in their original entry order.
    pub transactions: Vec<&'a [u8]>,
}

/// A bounded, lossless entry-vector view with verified zero padding excluded.
#[derive(Debug, Eq, PartialEq)]
pub struct DiagnosticWireEntryBatch<'a> {
    /// Entries and borrowed transaction bytes, without reordering or normalization.
    pub entries: Vec<DiagnosticWireEntry<'a>>,
    /// Original serialized-vector length before its verified zero padding.
    pub serialized_bytes: usize,
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(count)
            .ok_or("entry offset overflow")?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated legacy entry batch")?;
        self.position = end;
        Ok(result)
    }

    fn integer(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn length(&mut self, maximum: usize) -> Result<usize, String> {
        let count =
            usize::try_from(self.integer()?).map_err(|_| "legacy vector length overflow")?;
        if count > maximum {
            return Err("legacy vector exceeds diagnostic work bound".into());
        }
        Ok(count)
    }

    fn short_length(&mut self) -> Result<usize, String> {
        // Canonical ShortU16: reject aliases, a fourth byte, and overflow bits.
        let mut value = 0_usize;
        for index in 0..3 {
            let byte = self.take(1)?[0];
            let bits = usize::from(byte & 0x7f);
            if (index > 0 && bits == 0 && byte & 0x80 == 0) || (index == 2 && byte > 3) {
                return Err("noncanonical or overflowing legacy ShortU16".into());
            }
            value |= bits << (7 * index);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("unterminated legacy ShortU16".into())
    }

    fn transaction(
        &mut self,
        leaves: &mut Vec<[u8; 32]>,
        remaining_signature_budget: usize,
    ) -> Result<(), String> {
        let start = self.position;
        let signatures = self.short_length()?;
        if signatures > MAX_TRANSACTION_BYTES / 64
            || leaves
                .len()
                .checked_add(signatures)
                .is_none_or(|n| n > remaining_signature_budget)
        {
            return Err("legacy signature work bound exceeded".into());
        }
        for _ in 0..signatures {
            let signature = self.take(64)?;
            let mut hash = Sha256::new();
            hash.update([0]);
            hash.update(signature);
            leaves.push(hash.finalize().into());
        }
        let header = self.take(3)?;
        if header[0] & 0x80 != 0 {
            return Err("versioned message is outside pinned legacy layout".into());
        }
        let accounts = self.short_length()?;
        self.take(accounts.checked_mul(32).ok_or("account length overflow")?)?;
        self.take(32)?; // Recent blockhash.
        let instructions = self.short_length()?;
        // Every instruction consumes at least program index + two short lengths.
        if instructions > MAX_TRANSACTION_BYTES / 3 {
            return Err("legacy instruction work bound exceeded".into());
        }
        for _ in 0..instructions {
            self.take(1)?;
            let accounts = self.short_length()?;
            self.take(accounts)?;
            let data = self.short_length()?;
            self.take(data)?;
        }
        if self.position - start > MAX_TRANSACTION_BYTES {
            return Err("legacy transaction exceeds pinned packet bound".into());
        }
        Ok(())
    }
}

fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0; 32];
    }
    while leaves.len() > 1 {
        let count = leaves.len();
        for index in 0..count.div_ceil(2) {
            let left = leaves[2 * index];
            let right = leaves[(2 * index + 1).min(count - 1)];
            let mut hash = Sha256::new();
            hash.update([1]);
            hash.update(left);
            hash.update(right);
            leaves[index] = hash.finalize().into();
        }
        leaves.truncate(count.div_ceil(2));
    }
    leaves[0]
}

/// Decode one assembled padded entry-vector batch without trusting its hashes.
///
/// Input must first pass complete-slot shred assembly and independent generation,
/// live-state and SlotMeta gates. This function imposes separate byte, entry,
/// transaction and signature limits. It parses every transaction's complete wire
/// shape, without allocating account/instruction data, and rejects nonzero trailing
/// padding. It does not execute num_hashes or validate transaction signatures,
/// message sanitization, tick counts, canonical boundaries or final blockhashes.
pub fn decode_v1_4_25_padded_entries(bytes: &[u8]) -> Result<DiagnosticEntryBatch, String> {
    decode_entries(bytes, false).map(|parsed| parsed.metadata)
}

/// Preserve exact canonical bincode transaction slices without reserialization.
/// All original decoder bounds and rejection rules still apply. This is not a
/// production recovery route or permission to replace source entries.
pub fn decode_v1_4_25_padded_wire_entries(
    bytes: &[u8],
) -> Result<DiagnosticWireEntryBatch<'_>, String> {
    let ParsedEntries {
        metadata: batch,
        transactions,
    } = decode_entries(bytes, true)?;
    Ok(DiagnosticWireEntryBatch {
        serialized_bytes: batch.serialized_bytes,
        entries: batch
            .entries
            .into_iter()
            .zip(transactions)
            .map(|(metadata, transactions)| DiagnosticWireEntry {
                metadata,
                transactions,
            })
            .collect(),
    })
}

struct ParsedEntries<'a> {
    metadata: DiagnosticEntryBatch,
    transactions: Vec<Vec<&'a [u8]>>,
}

fn decode_entries(bytes: &[u8], retain_wire: bool) -> Result<ParsedEntries<'_>, String> {
    if bytes.len() > MAX_BATCH_BYTES {
        return Err("legacy entry batch exceeds byte bound".into());
    }
    let mut reader = Reader { bytes, position: 0 };
    let count = reader.length(MAX_ENTRIES)?;
    if count == 0 || count > bytes.len().saturating_sub(8) / 48 {
        return Err("empty or impossible legacy entry-vector length".into());
    }
    let mut entries = Vec::with_capacity(count);
    let mut wire_entries = Vec::new();
    let mut total_transactions = 0;
    let mut total_signatures = 0;
    for _ in 0..count {
        let num_hashes = reader.integer()?;
        let hash = reader.take(32)?.try_into().unwrap();
        let transaction_count = reader.length(MAX_TRANSACTIONS - total_transactions)?;
        total_transactions += transaction_count;
        let mut leaves = Vec::new();
        let mut wire_transactions = Vec::new();
        for _ in 0..transaction_count {
            let start = reader.position;
            reader.transaction(&mut leaves, MAX_SIGNATURES - total_signatures)?;
            if retain_wire {
                wire_transactions.push(&bytes[start..reader.position]);
            }
        }
        if retain_wire {
            wire_entries.push(wire_transactions);
        }
        total_signatures += leaves.len();
        if total_signatures > MAX_SIGNATURES {
            return Err("legacy batch signature work bound exceeded".into());
        }
        entries.push(DiagnosticEntry {
            num_hashes,
            hash,
            transaction_count,
            signature_mixin: (transaction_count != 0).then(|| merkle_root(leaves)),
        });
    }
    let serialized_bytes = reader.position;
    if bytes[serialized_bytes..].iter().any(|byte| *byte != 0) {
        return Err("nonzero legacy entry-batch padding".into());
    }
    Ok(ParsedEntries {
        metadata: DiagnosticEntryBatch {
            entries,
            serialized_bytes,
        },
        transactions: wire_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossless_wire_matches_pinned_sdk_golden_and_diagnostic_metadata() {
        let transactions = vec![
            transaction(Some(1)),
            transaction(Some(2)),
            transaction(Some(3)),
        ];
        let raw = batch(&transactions);
        assert_eq!(
            format!("{:x}", Sha256::digest(&raw)),
            "b3d19c5653173ed4150e6806bce35848b044a734058acaeff645064a8e06f773"
        );
        let mut padded = raw.clone();
        padded.resize(1051, 0);
        let decoded = decode_v1_4_25_padded_wire_entries(&padded).unwrap();
        let metadata = decode_v1_4_25_padded_entries(&padded).unwrap();
        assert_eq!(decoded.serialized_bytes, raw.len());
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].metadata, metadata.entries[0]);
        assert_eq!(
            decoded.entries[0].transactions,
            transactions.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
        let mut roundtrip = 1_u64.to_le_bytes().to_vec();
        for entry in decoded.entries {
            roundtrip.extend_from_slice(&entry.metadata.num_hashes.to_le_bytes());
            roundtrip.extend_from_slice(&entry.metadata.hash);
            roundtrip.extend_from_slice(&(entry.transactions.len() as u64).to_le_bytes());
            for transaction in entry.transactions {
                roundtrip.extend_from_slice(transaction);
            }
        }
        assert_eq!(roundtrip, raw);
    }

    #[test]
    fn wire_decoder_keeps_tick_unsigned_and_rejection_semantics() {
        for transactions in [vec![], vec![transaction(None)]] {
            let raw = batch(&transactions);
            let wire = decode_v1_4_25_padded_wire_entries(&raw).unwrap();
            assert_eq!(wire.entries[0].transactions.len(), transactions.len());
            assert_eq!(
                wire.entries[0].metadata.signature_mixin.is_some(),
                !transactions.is_empty()
            );
            for malformed in [
                raw[..raw.len() - 1].to_vec(),
                [raw.clone(), vec![1]].concat(),
            ] {
                assert!(decode_v1_4_25_padded_entries(&malformed).is_err());
                assert!(decode_v1_4_25_padded_wire_entries(&malformed).is_err());
            }
        }
    }

    fn batch(transactions: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = 1_u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&7_u64.to_le_bytes());
        bytes.extend_from_slice(&[9; 32]);
        bytes.extend_from_slice(&(transactions.len() as u64).to_le_bytes());
        for transaction in transactions {
            bytes.extend_from_slice(transaction);
        }
        bytes
    }

    fn transaction(signature: Option<u8>) -> Vec<u8> {
        let mut bytes = vec![u8::from(signature.is_some())];
        if let Some(value) = signature {
            bytes.extend_from_slice(&[value; 64]);
        }
        bytes.extend_from_slice(&[u8::from(signature.is_some()), 0, 0]);
        bytes.push(1);
        bytes.extend_from_slice(&[42; 32]);
        bytes.extend_from_slice(&[43; 32]);
        bytes.extend_from_slice(&[1, 0, 1, 0, 2, 44, 45]);
        bytes
    }

    #[test]
    fn ticks_and_unsigned_transactions_remain_distinct() {
        let mut tick = batch(&[]);
        let length = tick.len();
        tick.resize(1051, 0);
        let decoded = decode_v1_4_25_padded_entries(&tick).unwrap();
        assert_eq!(decoded.serialized_bytes, length);
        assert_eq!(decoded.entries[0].num_hashes, 7);
        assert_eq!(decoded.entries[0].hash, [9; 32]);
        assert_eq!(decoded.entries[0].signature_mixin, None);
        let decoded = decode_v1_4_25_padded_entries(&batch(&[transaction(None)])).unwrap();
        assert_eq!(decoded.entries[0].signature_mixin, Some([0; 32]));
    }

    #[test]
    fn signature_merkle_tree_uses_prefixes_and_duplicates_odd_leaf() {
        let bytes = batch(&[
            transaction(Some(1)),
            transaction(Some(2)),
            transaction(Some(3)),
        ]);
        let decoded = decode_v1_4_25_padded_entries(&bytes).unwrap();
        // Independently reproduced by the pinned v1.4.25 SDK test fixture.
        assert_eq!(bytes.len(), 476);
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "b3d19c5653173ed4150e6806bce35848b044a734058acaeff645064a8e06f773"
        );
        let leaf = |v| Sha256::digest([vec![0], vec![v; 64]].concat()).to_vec();
        let node = |a: Vec<u8>, b: Vec<u8>| Sha256::digest([vec![1], a, b].concat()).to_vec();
        let expected: [u8; 32] = node(node(leaf(1), leaf(2)), node(leaf(3), leaf(3)))
            .try_into()
            .unwrap();
        assert_eq!(decoded.entries[0].signature_mixin, Some(expected));
        assert_eq!(
            expected,
            [
                16, 250, 232, 52, 23, 235, 40, 179, 214, 126, 89, 164, 243, 253, 102, 204, 104,
                211, 74, 173, 103, 114, 77, 91, 158, 125, 109, 78, 15, 36, 25, 101
            ]
        );
        assert_eq!(decoded.entries[0].transaction_count, 3);
        let mut changed = bytes;
        changed[57] ^= 1; // First signature, not message/header bytes.
        assert_ne!(
            decode_v1_4_25_padded_entries(&changed).unwrap().entries[0].signature_mixin,
            Some(expected)
        );
    }

    #[test]
    fn truncation_aliases_overflow_and_nonzero_padding_fail_closed() {
        let bytes = batch(&[transaction(Some(1))]);
        for end in 0..bytes.len() {
            assert!(
                decode_v1_4_25_padded_entries(&bytes[..end]).is_err(),
                "accepted truncation {end}"
            );
        }
        let mut padding = bytes.clone();
        padding.push(1);
        assert!(decode_v1_4_25_padded_entries(&padding).is_err());
        for encoded in [
            vec![0x80, 0],
            vec![0xff, 0xff, 4],
            vec![0x80, 0x80, 0x80, 0],
        ] {
            let mut malformed = batch(&[]);
            malformed[48..56].copy_from_slice(&1_u64.to_le_bytes());
            malformed.extend_from_slice(&encoded);
            assert!(decode_v1_4_25_padded_entries(&malformed).is_err());
        }
        let mut oversized = bytes;
        oversized[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_v1_4_25_padded_entries(&oversized).is_err());
    }

    #[test]
    fn short_lengths_are_canonical_and_bounded() {
        for (bytes, expected) in [
            (vec![0], 0),
            (vec![127], 127),
            (vec![128, 1], 128),
            (vec![255, 255, 3], 65535),
        ] {
            assert_eq!(
                Reader {
                    bytes: &bytes,
                    position: 0
                }
                .short_length()
                .unwrap(),
                expected
            );
        }
        for bytes in [
            vec![128],
            vec![128, 0],
            vec![129, 128, 0],
            vec![255, 255, 4],
        ] {
            assert!(
                Reader {
                    bytes: &bytes,
                    position: 0
                }
                .short_length()
                .is_err()
            );
        }
    }

    #[test]
    fn fixed_integer_tick_vectors_match_bincode_layout() {
        use bincode::Options;
        let entries = vec![(0_u64, [8_u8; 32], Vec::<u8>::new()), (99, [7; 32], vec![])];
        let mut bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&entries)
            .unwrap();
        let length = bytes.len();
        bytes.resize(1051, 0);
        let decoded = decode_v1_4_25_padded_entries(&bytes).unwrap();
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.serialized_bytes, length);
        assert_eq!(decoded.entries[0].num_hashes, 0);
        assert_eq!(decoded.entries[1].num_hashes, 99);
        assert_eq!(decoded.entries[1].hash, [7; 32]);
    }

    #[test]
    fn rejects_oversized_transactions_instructions_and_transaction_counts() {
        let mut oversized_tx = transaction(Some(1));
        // A second instruction whose data length forces the full transaction
        // beyond the packet bound, while every wire length remains canonical.
        let instruction_count_offset = 1 + 64 + 3 + 1 + 32 + 32;
        oversized_tx[instruction_count_offset] = 2;
        oversized_tx.extend_from_slice(&[0, 0, 0x80, 0x10]);
        oversized_tx.resize(oversized_tx.len() + 2048, 0);
        assert!(decode_v1_4_25_padded_entries(&batch(&[oversized_tx])).is_err());

        let mut too_many_instructions = transaction(Some(1));
        too_many_instructions.truncate(instruction_count_offset);
        too_many_instructions.extend_from_slice(&[0xff, 0x7f]);
        assert!(decode_v1_4_25_padded_entries(&batch(&[too_many_instructions])).is_err());

        let mut too_many_transactions = batch(&[]);
        too_many_transactions[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_v1_4_25_padded_entries(&too_many_transactions).is_err());
    }
}
