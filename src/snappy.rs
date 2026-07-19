//! Snappy literal extraction without full decompression.
//!
//! This module parses Snappy framed streams, collects literal chunks, and skips
//! copy chunks. The extracted data is grouped into [`CompressedBlock`] values
//! suitable for bloom-filter indexing.
//!
//! Snappy framing format:
//! - Stream identifier (0xff + 6-byte "sNaPpY")
//! - Chunks with 1-byte type tag + 2-3 byte length + data
//! - Type 0x00: Compressed data
//! - Type 0x01: Uncompressed data
//! - Type 0xfe: Padding
//! - Type 0xff: Stream identifier
//!
//! We extract only literals, skipping copy resolution.

use crate::{CompressedBlock, ZiftError};

/// Maximum Snappy chunk size (64KB).
const MAX_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum number of chunks per stream to prevent `DoS`.
const MAX_CHUNKS_PER_STREAM: usize = 100_000;

/// Maximum total literals to prevent memory exhaustion.
const MAX_TOTAL_LITERALS: usize = 256 * 1024 * 1024; // 256MB

/// Maximum decompression ratio to prevent zip bombs.
const MAX_DECOMPRESSION_RATIO: usize = 250;

fn handle_snappy_chunk(
    chunk_type: u8,
    chunk_data: &[u8],
    current_literals: &mut Vec<u8>,
    pos: usize,
) -> Result<(), ZiftError> {
    match chunk_type {
        0x00 => {
            if chunk_data.len() < 4 {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "compressed snappy chunk too short for CRC. Fix: use a valid Snappy stream".to_string(),
                });
            }
            let compressed = &chunk_data[4..];
            let uncompressed_len = snap::raw::decompress_len(compressed).map_err(|_| {
                ZiftError::InvalidData {
                    offset: pos,
                    reason: "invalid snappy compressed chunk. Fix: use a valid Snappy stream".to_string(),
                }
            })?;
            if uncompressed_len > MAX_TOTAL_LITERALS {
                return Err(ZiftError::BlockTooLarge {
                    size: uncompressed_len,
                    max: MAX_TOTAL_LITERALS,
                });
            }
            let mut decoder = snap::raw::Decoder::new();
            let literals = decoder.decompress_vec(compressed).map_err(|_| {
                ZiftError::InvalidData {
                    offset: pos,
                    reason: "snappy decompression failed. Fix: use a valid Snappy stream".to_string(),
                }
            })?;
            current_literals.extend_from_slice(&literals);
        }
        0x01 => {
            // Uncompressed chunk = 4-byte CRC-32C + raw data. A chunk of length
            // <= 4 has no data after the CRC (or not even a full CRC): it is
            // malformed. Fail CLOSED instead of silently dropping it (the old
            // `if len > 4` guard swallowed such a chunk, losing literals with no
            // signal - mirrors the compressed-chunk `< 4` check above).
            if chunk_data.len() <= 4 {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "uncompressed snappy chunk too short (needs 4-byte CRC + data). Fix: use a valid Snappy stream".to_string(),
                });
            }
            current_literals.extend_from_slice(&chunk_data[4..]);
        }
        0xfe | 0xff => {
            // Padding (0xfe) and stream identifier (0xff) (skip).
        }
        0x02..=0xfd => {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!("reserved unskippable snappy chunk type 0x{chunk_type:02x}. Fix: use a standard Snappy framing stream"),
            });
        }
    }
    Ok(())
}

/// Extract literal bytes from a Snappy-framed stream.
///
/// Parses Snappy framing chunks, collecting literals from uncompressed
/// and compressed data chunks while skipping padding and stream identifiers.
///
/// # Parameters
///
/// - `data`: Snappy-framed byte slice.
///
/// # Returns
///
/// A vector of [`CompressedBlock`] values containing extracted literals.
///
/// # Errors
///
/// Returns [`ZiftError::InvalidData`] if the stream is truncated or contains
/// malformed chunks, or [`ZiftError::BlockTooLarge`] if limits are exceeded.
pub fn extract_literals(data: &[u8]) -> Result<Vec<CompressedBlock>, ZiftError> {
    if data.is_empty() {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: "empty snappy input. Fix: provide non-empty Snappy data".to_string(),
        });
    }

    let mut blocks = Vec::new();
    let mut pos = 0usize;
    let mut chunk_count = 0usize;
    let mut total_literals = 0usize;

    // Skip stream identifier if present
    // Snappy stream identifier: ff 06 00 00 73 4e 61 50 70 59 (10 bytes)
    if data.starts_with(&[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]) {
        pos = 10; // Skip stream identifier
    }

    let mut current_literals = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut block_start = pos;

    while pos < data.len() {
        // Prevent DoS from too many chunks
        chunk_count += 1;
        if chunk_count >= MAX_CHUNKS_PER_STREAM {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!("too many Snappy chunks (max {MAX_CHUNKS_PER_STREAM}). Fix: use a smaller Snappy stream or increase MAX_CHUNKS_PER_STREAM"),
            });
        }

        // Check total literals limit
        if total_literals.saturating_add(current_literals.len()) > MAX_TOTAL_LITERALS {
            return Err(ZiftError::BlockTooLarge {
                size: total_literals + current_literals.len(),
                max: MAX_TOTAL_LITERALS,
            });
        }

        let max_allowed_literals = data
            .len()
            .saturating_mul(MAX_DECOMPRESSION_RATIO)
            .max(1024 * 1024);
        if total_literals > max_allowed_literals {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!("decompression ratio exceeded limit of {MAX_DECOMPRESSION_RATIO}. Fix: use a non-malicious Snappy stream or increase MAX_DECOMPRESSION_RATIO"),
            });
        }

        if pos >= data.len() {
            break;
        }

        let chunk_type = data[pos];
        pos += 1;

        // Decode chunk length (1-3 bytes)
        let (chunk_len, tag_len) = decode_chunk_len(data, pos)?;
        pos += tag_len;

        if chunk_len > MAX_CHUNK_SIZE {
            return Err(ZiftError::BlockTooLarge {
                size: chunk_len,
                max: MAX_CHUNK_SIZE,
            });
        }

        if pos + chunk_len > data.len() {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: "chunk exceeds data bounds. Fix: use a complete Snappy stream".to_string(),
            });
        }

        let chunk_data = &data[pos..pos + chunk_len];

        handle_snappy_chunk(chunk_type, chunk_data, &mut current_literals, pos)?;

        // Flush block if getting large
        if current_literals.len() > 32 * 1024 {
            total_literals = flush_block(
                &mut blocks,
                &mut current_literals,
                block_start,
                pos,
                total_literals,
            )?;
            block_start = pos;
        }

        pos += chunk_len;
    }

    // Don't forget final block
    if !current_literals.is_empty() {
        let _ = flush_block(
            &mut blocks,
            &mut current_literals,
            block_start,
            pos,
            total_literals,
        )?;
    }

    Ok(blocks)
}

fn flush_block(
    blocks: &mut Vec<CompressedBlock>,
    literals: &mut Vec<u8>,
    block_start: usize,
    pos: usize,
    total_literals: usize,
) -> Result<usize, ZiftError> {
    let new_total = total_literals + literals.len();
    if new_total > MAX_TOTAL_LITERALS {
        return Err(ZiftError::BlockTooLarge {
            size: new_total,
            max: MAX_TOTAL_LITERALS,
        });
    }
    let mut block = CompressedBlock::new(
        u64::try_from(block_start).unwrap_or(u64::MAX),
        u32::try_from(pos - block_start).unwrap_or(u32::MAX),
    );
    block.uncompressed_len = Some(u32::try_from(literals.len()).unwrap_or(u32::MAX));
    // Move the literals into the block, then restore the streaming buffer's
    // capacity. `std::mem::take` hands the whole allocation (with its capacity)
    // to the block and leaves `*literals` empty at capacity 0, so the NEXT chunk
    // would regrow it from scratch one reallocation at a time. Re-reserving the
    // just-flushed capacity gives the reused buffer a head start sized to the
    // previous block, avoiding those repeated reallocations (no copy: the bytes
    // still move into the block).
    let flushed_capacity = literals.capacity();
    block.literals = std::mem::take(literals);
    literals.reserve(flushed_capacity);
    blocks.push(block);
    Ok(new_total)
}

/// Decode Snappy chunk length.
///
/// Returns (length, number of bytes consumed from length encoding).
/// Decode the 3-byte little-endian chunk length per Snappy framing spec.
///
/// Snappy framing format (<https://github.com/google/snappy/blob/main/framing_format.txt>):
/// - 1 byte chunk type (already consumed by caller)
/// - 3 bytes little-endian chunk data length
/// - chunk data bytes
///
/// Returns (`chunk_length`, `bytes_consumed_for_length` = 3).
fn decode_chunk_len(data: &[u8], start: usize) -> Result<(usize, usize), ZiftError> {
    if start + 3 > data.len() {
        return Err(ZiftError::InvalidData {
            offset: start,
            reason: "truncated chunk length, need 3 bytes for Snappy framing length. Fix: use a complete Snappy stream".to_string(),
        });
    }

    // 3-byte little-endian length per spec
    let len = data[start] as usize
        | ((data[start + 1] as usize) << 8)
        | ((data[start + 2] as usize) << 16);
    Ok((len, 3))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data_rejected() {
        let data = [];
        let result = extract_literals(&data);
        assert!(matches!(result, Err(ZiftError::InvalidData { .. })));
    }

    #[test]
    fn test_rejects_invalid_compressed_chunk() {
        // Stream identifier followed by a 0x00 compressed chunk with truncated data
        // Chunk length = 5 (4-byte CRC + 1 byte of compressed data).
        // The 1-byte compressed payload (0x01) is a valid varint length but missing data.
        let data = [
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream identifier
            0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Invalid compressed chunk
        ];
        let result = extract_literals(&data);
        assert!(matches!(result, Err(ZiftError::InvalidData { .. })));
    }

    #[test]
    fn test_rejects_reserved_chunk() {
        let data = [
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream identifier
            0x02, 0x00, 0x00, 0x00, // Reserved unskippable chunk
        ];
        let result = extract_literals(&data);
        assert!(matches!(result, Err(ZiftError::InvalidData { .. })));
    }

    #[test]
    fn uncompressed_chunk_of_only_crc_is_rejected_not_silently_dropped() {
        // An uncompressed chunk (0x01) of length 4 carries only the CRC-32C and
        // no data - malformed. It must fail closed (InvalidData), not be
        // silently skipped (which would drop literals with no signal).
        let data = [
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream identifier
            0x01, 0x04, 0x00, 0x00, // Uncompressed chunk, length = 4 (CRC only)
            0xaa, 0xbb, 0xcc, 0xdd, // the 4 CRC bytes, no payload after them
        ];
        let result = extract_literals(&data);
        assert!(
            matches!(result, Err(ZiftError::InvalidData { .. })),
            "a 4-byte uncompressed chunk (CRC only, no data) must return InvalidData, got {result:?}"
        );
    }

    #[test]
    fn uncompressed_chunk_with_one_data_byte_is_accepted() {
        // Guard against over-rejection: length 5 (4-byte CRC + 1 data byte) is
        // the smallest valid uncompressed chunk and must extract that byte.
        let data = [
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream identifier
            0x01, 0x05, 0x00, 0x00, // Uncompressed chunk, length = 5
            0xaa, 0xbb, 0xcc, 0xdd, // 4-byte CRC
            0x5a, // one data byte
        ];
        let blocks = extract_literals(&data).expect("valid single-byte uncompressed chunk");
        let literals: Vec<u8> = blocks.iter().flat_map(|b| b.literals().to_vec()).collect();
        assert_eq!(literals, vec![0x5a], "the single data byte must be extracted");
    }

    #[test]
    fn flush_block_retains_literals_capacity_for_reuse() {
        // `flush_block` moves the literals into the block; the streaming buffer
        // must retain its capacity so the next chunk does not regrow from zero
        // (the old `std::mem::take` left it at capacity 0).
        let mut blocks = Vec::new();
        let mut literals = Vec::with_capacity(4096);
        literals.extend_from_slice(&[7u8; 100]);
        let cap_before = literals.capacity();

        let total = flush_block(&mut blocks, &mut literals, 0, 100, 0).expect("flush");

        assert_eq!(total, 100, "returns the new running literal total");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].literals().len(), 100, "the block owns the 100 literals");
        assert!(literals.is_empty(), "streaming buffer is drained of content");
        assert!(
            literals.capacity() >= cap_before,
            "streaming buffer must retain capacity for reuse (was {cap_before}, now {})",
            literals.capacity()
        );
    }
}
