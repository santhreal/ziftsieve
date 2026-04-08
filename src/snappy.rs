//! Snappy literal extraction without full decompression.
//!
//! This module parses Snappy framed streams, collects literal chunks, and skips
//! copy chunks. The extracted data is grouped into [`CompressedBlock`] values
//! suitable for bloom-filter indexing.
//!
//! Snappy framing format:
//! - Stream identifier (0xff + 6-byte "sNaPpY")
//! - Chunks with 1-byte type tag + 2-3 byte length + data
//! - Type 0x00: Literal
//! - Type 0x01: Copy (back-reference)
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

/// Extract literals from Snappy compressed data.
///
/// # Errors
///
/// Returns `ZiftError` if the chunk length exceeds maximum limits,
/// if data bounds are exceeded, or if an unexpected stream identifier
/// is encountered mid-stream.
///
/// # Parameters
///
/// - `data`: Snappy framed stream bytes.
///
/// # Returns
///
/// Parsed blocks with their extracted literals.
pub fn extract_literals(data: &[u8]) -> Result<Vec<CompressedBlock>, ZiftError> {
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
                reason: format!("too many Snappy chunks (max {MAX_CHUNKS_PER_STREAM})"),
            });
        }

        // Check total literals limit
        if total_literals + current_literals.len() > MAX_TOTAL_LITERALS {
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
                reason: format!("decompression ratio exceeded limit of {MAX_DECOMPRESSION_RATIO}"),
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
                reason: "chunk exceeds data bounds".to_string(),
            });
        }

        let chunk_data = &data[pos..pos + chunk_len];

        match chunk_type {
            0x00 => {
                // Compressed data chunk (per Snappy framing spec).
                // First 4 bytes = masked CRC-32C of uncompressed data. Skip.
                // Remaining bytes = Snappy-compressed block.
                // We cannot extract just literals without skipping backreferences
                // which leads to silent data loss. Full decompression is required
                // but currently unsupported.
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "compressed snappy blocks are not supported, only uncompressed blocks are supported".to_string(),
                });
            }
            0x01 => {
                // Uncompressed data chunk — the literal bytes ARE the chunk data.
                // First 4 bytes = masked CRC-32C. Rest is raw uncompressed data.
                if chunk_data.len() > 4 {
                    current_literals.extend_from_slice(&chunk_data[4..]);
                }
            }
            _ => {
                // Other chunks (Stream identifier, Padding, Reserved) — skip.
            }
        }

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
    block.literals = std::mem::take(literals);
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
            reason: "truncated chunk length — need 3 bytes for Snappy framing length".to_string(),
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
    fn test_empty_data() {
        let data = [];
        let blocks = extract_literals(&data).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_rejects_compressed_chunk() {
        // Stream identifier followed by a 0x00 compressed chunk
        // Chunk type 0x00, Length 5 (0x05, 0x00, 0x00), CRC (4 bytes), 1 byte data
        let data = [
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream identifier
            0x00, 0x05, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, // Compressed chunk
        ];
        let result = extract_literals(&data);
        assert!(matches!(result, Err(ZiftError::InvalidData { .. })));
    }
}
