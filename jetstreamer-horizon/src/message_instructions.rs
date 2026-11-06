//! Packet-bounded top-level instructions with the original Horizon wire form.
//!
//! Messages can contain more instructions than an execution trace can execute.
//! Keep small descriptors plus one shared byte arena, rather than reserving a
//! complete maximum-size instruction for every possible top-level instruction.
//! The descriptor offsets are private memory layout: the codec still writes a
//! count followed by program index, account-index bytes and data for each item.

use core::{fmt, iter::FusedIterator, ops::Range};
use lencode::prelude::*;

use crate::{
    limits::{MAX_IX_ACCOUNTS, MAX_IX_DATA_LEN, MAX_TX_INSTRUCTION_BYTES, MAX_TX_INSTRUCTIONS},
    zero_vec::{ZeroAlloc, ZeroVec, assert_zero_alloc},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct InstructionMeta {
    program_id_index: u8,
    accounts_end: u16,
    data_end: u16,
}

/// Borrowed instruction contents in their original order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionView<'a> {
    pub program_id_index: u8,
    pub accounts: &'a [u8],
    pub data: &'a [u8],
}

/// A failed append leaves the arena unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushInstructionError {
    pub field: &'static str,
    pub len: usize,
    pub max: usize,
}

impl fmt::Display for PushInstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: length {} exceeds capacity {}",
            self.field, self.len, self.max
        )
    }
}

impl std::error::Error for PushInstructionError {}

/// Ordered top-level instructions backed by a shared inline byte arena.
///
/// All fields admit an all-zero empty state, including during the transaction
/// decoder's in-place Legacy/V0 variant swaps. No field owns heap memory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[repr(C)]
pub struct MessageInstructions {
    meta: ZeroVec<MAX_TX_INSTRUCTIONS, InstructionMeta>,
    bytes: ZeroVec<MAX_TX_INSTRUCTION_BYTES, u8>,
}

impl MessageInstructions {
    #[inline]
    pub const fn new() -> Self {
        Self {
            meta: ZeroVec::new(),
            bytes: ZeroVec::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.meta.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }

    /// Combined account-index and instruction-data bytes currently retained.
    #[inline]
    pub fn data_len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.meta.clear();
        self.bytes.clear();
    }

    /// Appends one instruction after checking every bound, before mutation.
    pub fn push(
        &mut self,
        program_id_index: u8,
        accounts: &[u8],
        data: &[u8],
    ) -> Result<(), PushInstructionError> {
        for (field, len, max) in [
            ("message.instructions", self.len() + 1, MAX_TX_INSTRUCTIONS),
            ("instruction.accounts", accounts.len(), MAX_IX_ACCOUNTS),
            ("instruction.data", data.len(), MAX_IX_DATA_LEN),
        ] {
            if len > max {
                return Err(PushInstructionError { field, len, max });
            }
        }
        // Individual lengths above are bounded before adding them, so this
        // cannot overflow usize. No offset is published until both copies fit.
        let accounts_end = self.bytes.len() + accounts.len();
        let data_end = accounts_end + data.len();
        if data_end > MAX_TX_INSTRUCTION_BYTES {
            return Err(PushInstructionError {
                field: "message.instructions.bytes",
                len: data_end,
                max: MAX_TX_INSTRUCTION_BYTES,
            });
        }
        self.bytes.extend_from_slice(accounts);
        self.bytes.extend_from_slice(data);
        self.meta.push(InstructionMeta {
            program_id_index,
            accounts_end: accounts_end as u16,
            data_end: data_end as u16,
        });
        Ok(())
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<InstructionView<'_>> {
        let meta = self.meta.get(index)?;
        let start = if index == 0 {
            0
        } else {
            self.meta[index - 1].data_end as usize
        };
        Some(InstructionView {
            program_id_index: meta.program_id_index,
            accounts: &self.bytes[start..meta.accounts_end as usize],
            data: &self.bytes[meta.accounts_end as usize..meta.data_end as usize],
        })
    }

    #[inline]
    pub fn iter(&self) -> InstructionIter<'_> {
        InstructionIter {
            instructions: self,
            remaining: 0..self.len(),
        }
    }

    /// Reuses the arena directly, decoding the original instruction-list wire
    /// form. An error may retain a decoded prefix, but never an incomplete item;
    /// the next decode starts by clearing that prefix.
    pub fn decode_into<R: Read>(
        &mut self,
        reader: &mut R,
        mut ctx: Option<&mut lencode::context::DecoderContext>,
    ) -> lencode::Result<()> {
        self.clear();
        let len = Self::decode_len(reader)?;
        reader.claim_sequence(len, 1)?;
        if len > MAX_TX_INSTRUCTIONS {
            return Err(lencode::io::Error::InvalidData);
        }
        let mut scratch = [0u8; MAX_TX_INSTRUCTION_BYTES];
        for _ in 0..len {
            let program_id_index = u8::decode_ext(reader, ctx.as_deref_mut())?;
            let remaining = MAX_TX_INSTRUCTION_BYTES - self.bytes.len();
            let accounts_len = decode_bytes(reader, &mut scratch[..remaining], MAX_IX_ACCOUNTS)?;
            let data_len = decode_bytes(
                reader,
                &mut scratch[accounts_len..remaining],
                MAX_IX_DATA_LEN,
            )?;
            self.push(
                program_id_index,
                &scratch[..accounts_len],
                &scratch[accounts_len..accounts_len + data_len],
            )
            .map_err(|_| lencode::io::Error::InvalidData)?;
        }
        Ok(())
    }
}

/// Iterates borrowed views without constructing full inline instructions.
#[derive(Clone)]
pub struct InstructionIter<'a> {
    instructions: &'a MessageInstructions,
    remaining: Range<usize>,
}

impl<'a> Iterator for InstructionIter<'a> {
    type Item = InstructionView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining.next().and_then(|i| self.instructions.get(i))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.remaining.size_hint()
    }
}

impl DoubleEndedIterator for InstructionIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.remaining
            .next_back()
            .and_then(|i| self.instructions.get(i))
    }
}

impl ExactSizeIterator for InstructionIter<'_> {}
impl FusedIterator for InstructionIter<'_> {}

impl<'a> IntoIterator for &'a MessageInstructions {
    type Item = InstructionView<'a>;
    type IntoIter = InstructionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Encode for MessageInstructions {
    fn encode_ext(
        &self,
        writer: &mut impl Write,
        mut ctx: Option<&mut lencode::context::EncoderContext>,
    ) -> lencode::Result<usize> {
        let mut written = Self::encode_len(self.len(), writer)?;
        for ix in self {
            written += ix.program_id_index.encode_ext(writer, ctx.as_deref_mut())?;
            for bytes in [ix.accounts, ix.data] {
                // Same uncompressed-u8 flag as ZeroVec<_, u8>. Offsets and
                // arena layout never appear in the archive.
                written += Self::encode_len(bytes.len() << 1, writer)?;
                if writer.write(bytes)? != bytes.len() {
                    return Err(lencode::io::Error::WriterOutOfSpace);
                }
                written += bytes.len();
            }
        }
        Ok(written)
    }
}

impl Decode for MessageInstructions {
    fn decode_ext(
        reader: &mut impl Read,
        ctx: Option<&mut lencode::context::DecoderContext>,
    ) -> lencode::Result<Self> {
        let mut result = Self::new();
        result.decode_into(reader, ctx)?;
        Ok(result)
    }
}

/// Decode one original ZeroVec<u8> field into initialized bounded scratch.
/// Short streaming reads are allowed; zero progress and over-reporting fail.
fn decode_bytes(
    reader: &mut impl Read,
    destination: &mut [u8],
    maximum: usize,
) -> lencode::Result<usize> {
    let flagged = MessageInstructions::decode_len(reader)?;
    if flagged & 1 != 0 {
        return Err(lencode::io::Error::InvalidData);
    }
    let len = flagged >> 1;
    reader.claim_blob(len)?;
    if len > maximum || len > destination.len() {
        return Err(lencode::io::Error::InvalidData);
    }
    let mut offset = 0;
    while offset < len {
        let read = reader.read(&mut destination[offset..len])?;
        if read == 0 {
            return Err(lencode::io::Error::ReaderOutOfData);
        }
        if read > len - offset {
            return Err(lencode::io::Error::InvalidData);
        }
        offset += read;
    }
    Ok(len)
}

impl ZeroAlloc for InstructionMeta {}
impl ZeroAlloc for MessageInstructions {}

const _: () = assert!(MAX_TX_INSTRUCTION_BYTES <= u16::MAX as usize);
const _: fn() = || {
    assert_zero_alloc::<u8>();
    assert_zero_alloc::<u16>();
    assert_zero_alloc::<ZeroVec<MAX_TX_INSTRUCTIONS, InstructionMeta>>();
    assert_zero_alloc::<ZeroVec<MAX_TX_INSTRUCTION_BYTES, u8>>();
    assert_zero_alloc::<MessageInstructions>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::CompiledInstruction;
    use lencode::io::{Cursor, DecodeLimits, LimitedReader};

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut bytes = vec![0u8; 16 * 1024];
        let len = value
            .encode_ext(&mut Cursor::new(&mut bytes[..]), None)
            .unwrap();
        bytes.truncate(len);
        bytes
    }

    // The original element codec is the independent wire reference. Vec and
    // ZeroVec both use the same count-prefixed element sequence for this type.
    fn original_instructions(count: usize) -> Vec<CompiledInstruction> {
        (0..count)
            .map(|i| {
                let mut ix = CompiledInstruction::default();
                ix.program_id_index = (i % 4) as u8;
                ix.accounts.extend_from_slice(&[0, (i % 7) as u8]);
                ix.data.extend_from_slice(&[i as u8, 17]);
                ix
            })
            .collect()
    }

    fn arena_from(original: &[CompiledInstruction]) -> MessageInstructions {
        let mut result = MessageInstructions::new();
        for ix in original {
            result
                .push(
                    ix.program_id_index,
                    ix.accounts.as_slice(),
                    ix.data.as_slice(),
                )
                .unwrap();
        }
        result
    }

    #[test]
    fn old_instruction_wire_is_unchanged_including_empty_and_64_items() {
        // Reserve only test stack for the old 64 * 10 KiB representation.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for count in [0, 1, 64] {
                    let original = original_instructions(count);
                    let mut old = ZeroVec::<64, CompiledInstruction>::new();
                    let arena = arena_from(&original);
                    for ix in original {
                        old.push(ix);
                    }
                    let bytes = encode(&old);
                    assert_eq!(encode(&arena), bytes);
                    let decoded =
                        MessageInstructions::decode_ext(&mut Cursor::new(bytes.as_slice()), None)
                            .unwrap();
                    assert_eq!(decoded, arena);

                    let mut old_context = lencode::context::EncoderContext::with_all();
                    let mut new_context = lencode::context::EncoderContext::with_all();
                    let mut old_bytes = vec![0u8; 16 * 1024];
                    let mut new_bytes = vec![0u8; 16 * 1024];
                    let old_len = old
                        .encode_ext(&mut Cursor::new(&mut old_bytes[..]), Some(&mut old_context))
                        .unwrap();
                    let new_len = arena
                        .encode_ext(&mut Cursor::new(&mut new_bytes[..]), Some(&mut new_context))
                        .unwrap();
                    assert_eq!(&old_bytes[..old_len], &new_bytes[..new_len]);
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn sixty_five_instructions_preserve_all_program_accounts_and_data_bytes() {
        let original = original_instructions(65);
        let wire = encode(&original);
        let arena =
            MessageInstructions::decode_ext(&mut Cursor::new(wire.as_slice()), None).unwrap();
        assert_eq!(arena.len(), 65);
        assert_eq!(encode(&arena), wire);
        for (actual, expected) in arena.iter().zip(&original) {
            assert_eq!(actual.program_id_index, expected.program_id_index);
            assert_eq!(actual.accounts, expected.accounts.as_slice());
            assert_eq!(actual.data, expected.data.as_slice());
        }
        assert!(arena.get(65).is_none());
        assert!(arena.get(usize::MAX).is_none());
        let mut iter = arena.iter();
        assert_eq!(iter.len(), 65);
        assert_eq!(iter.next().unwrap(), arena.get(0).unwrap());
        assert_eq!(iter.next_back().unwrap(), arena.get(64).unwrap());
        assert_eq!(iter.len(), 63);
    }

    #[test]
    fn packet_derived_descriptor_limit_does_not_multiply_inner_arena() {
        assert_eq!(MAX_TX_INSTRUCTIONS, 1_232 / 3);
        assert_eq!(crate::limits::MAX_TX_INNER_IX, 4096);
        assert!(core::mem::size_of::<MessageInstructions>() < 8 * 1024);
        assert!(
            core::mem::size_of::<MessageInstructions>()
                < core::mem::size_of::<CompiledInstruction>()
        );
        let mut arena = MessageInstructions::new();
        for i in 0..MAX_TX_INSTRUCTIONS {
            arena.push(i as u8, &[], &[]).unwrap();
        }
        let before = arena.clone();
        assert_eq!(
            arena.push(0, &[], &[]).unwrap_err(),
            PushInstructionError {
                field: "message.instructions",
                len: MAX_TX_INSTRUCTIONS + 1,
                max: MAX_TX_INSTRUCTIONS,
            }
        );
        assert_eq!(arena, before);
        let decoded =
            MessageInstructions::decode_ext(&mut Cursor::new(encode(&arena).as_slice()), None)
                .unwrap();
        assert_eq!(decoded, arena);
    }

    #[test]
    fn shared_payload_and_individual_field_limits_fail_before_mutation() {
        let mut arena = MessageInstructions::new();
        arena
            .push(1, &[0, 1], &vec![7; MAX_TX_INSTRUCTION_BYTES - 2])
            .unwrap();
        assert_eq!(arena.data_len(), MAX_TX_INSTRUCTION_BYTES);
        let before = arena.clone();
        assert_eq!(
            arena.push(2, &[], &[3]).unwrap_err().field,
            "message.instructions.bytes"
        );
        assert_eq!(
            arena
                .push(2, &vec![0; MAX_IX_ACCOUNTS + 1], &[])
                .unwrap_err()
                .field,
            "instruction.accounts"
        );
        assert_eq!(
            arena
                .push(2, &[], &vec![0; MAX_IX_DATA_LEN + 1])
                .unwrap_err()
                .field,
            "instruction.data"
        );
        assert_eq!(arena, before);
        arena.clear();
        arena.push(9, &[], &[4]).unwrap();
        assert_eq!(arena.len(), 1);
        assert_eq!(arena.data_len(), 1);
        assert_eq!(arena.get(0).unwrap().accounts, &[]);
        assert_eq!(arena.get(0).unwrap().data, &[4]);
    }

    struct Chunked<'a> {
        bytes: &'a [u8],
        max_chunk: usize,
    }

    impl Read for Chunked<'_> {
        fn read(&mut self, destination: &mut [u8]) -> lencode::Result<usize> {
            let len = destination.len().min(self.max_chunk).min(self.bytes.len());
            destination[..len].copy_from_slice(&self.bytes[..len]);
            self.bytes = &self.bytes[len..];
            Ok(len)
        }
    }

    #[test]
    fn streaming_short_reads_match_contiguous_decode() {
        let original = original_instructions(65);
        let wire = encode(&original);
        let mut chunks = Chunked {
            bytes: &wire,
            max_chunk: 1,
        };
        let decoded = MessageInstructions::decode_ext(&mut chunks, None).unwrap();
        assert_eq!(decoded, arena_from(&original));
        assert!(chunks.bytes.is_empty());
    }

    #[test]
    fn truncated_item_is_never_committed_and_decode_can_reuse_arena() {
        let original = original_instructions(2);
        let wire = encode(&original);
        let mut arena = arena_from(&original_instructions(65));
        for end in 0..wire.len() {
            let mut chunks = Chunked {
                bytes: &wire[..end],
                max_chunk: 2,
            };
            assert!(arena.decode_into(&mut chunks, None).is_err());
            assert!(arena.len() <= 1);
            if let Some(ix) = arena.get(0) {
                assert_eq!(ix.data, original[0].data.as_slice());
            }
        }
        arena
            .decode_into(&mut Cursor::new(wire.as_slice()), None)
            .unwrap();
        assert_eq!(arena, arena_from(&original));
    }

    #[test]
    fn rejects_compressed_flags_excess_count_and_oversized_payloads() {
        for bytes in [&[1, 0, 1][..], &[1, 0, 0, 1][..]] {
            assert!(MessageInstructions::decode_ext(&mut Cursor::new(bytes), None).is_err());
        }
        let mut bytes = vec![0u8; 16];
        let len = MessageInstructions::encode_len(
            MAX_TX_INSTRUCTIONS + 1,
            &mut Cursor::new(&mut bytes[..]),
        )
        .unwrap();
        assert!(MessageInstructions::decode_ext(&mut Cursor::new(&bytes[..len]), None).is_err());

        let mut original = original_instructions(2);
        original[0].data.clear();
        original[0].data.extend_from_slice(&vec![1; 1000]);
        original[1].data.clear();
        original[1].data.extend_from_slice(&vec![2; 229]); // 4 account bytes + 1,229 data bytes.
        let wire = encode(&original);
        let mut arena = MessageInstructions::new();
        assert!(
            arena
                .decode_into(&mut Cursor::new(wire.as_slice()), None)
                .is_err()
        );
        assert_eq!(arena.len(), 1);
        assert_eq!(arena.get(0).unwrap().data.len(), 1000);

        // Preserve the previous per-instruction account bound as well.
        let mut wire = vec![0u8; 1024];
        let mut cursor = Cursor::new(&mut wire[..]);
        MessageInstructions::encode_len(1, &mut cursor).unwrap();
        0u8.encode_ext(&mut cursor, None).unwrap();
        MessageInstructions::encode_len((MAX_IX_ACCOUNTS + 1) << 1, &mut cursor).unwrap();
        assert!(MessageInstructions::decode_ext(&mut Cursor::new(wire.as_slice()), None).is_err());
    }

    #[test]
    fn reader_decode_budgets_are_not_bypassed_by_flat_storage() {
        let original = original_instructions(65);
        let wire = encode(&original);
        let mut reader = LimitedReader::new(
            Cursor::new(wire.as_slice()),
            DecodeLimits::new(wire.len(), 64, usize::MAX),
        );
        assert!(matches!(
            MessageInstructions::decode_ext(&mut reader, None),
            Err(lencode::io::Error::DecodeLimitExceeded)
        ));
        let mut reader = LimitedReader::new(
            Cursor::new(wire.as_slice()),
            DecodeLimits::new(wire.len(), MAX_TX_INSTRUCTIONS, 0),
        );
        assert!(matches!(
            MessageInstructions::decode_ext(&mut reader, None),
            Err(lencode::io::Error::DecodeLimitExceeded)
        ));
    }

    struct OverreportPayload<'a> {
        headers: &'a [u8],
    }

    impl Read for OverreportPayload<'_> {
        fn read(&mut self, destination: &mut [u8]) -> lencode::Result<usize> {
            if let Some((&first, rest)) = self.headers.split_first() {
                destination[0] = first;
                self.headers = rest;
                Ok(1)
            } else {
                Ok(destination.len() + 1)
            }
        }
    }

    #[test]
    fn an_overreporting_safe_reader_cannot_publish_an_item() {
        // One item, program 0, account bytes length 2. Over-report only when
        // the decoder asks for the actual account payload.
        let mut reader = OverreportPayload {
            headers: &[1, 0, 4],
        };
        let mut arena = MessageInstructions::new();
        assert!(matches!(
            arena.decode_into(&mut reader, None),
            Err(lencode::io::Error::InvalidData)
        ));
        assert!(arena.is_empty());
        assert_eq!(arena.data_len(), 0);
    }
}
