//! LZ4 literal extraction without full decompression.
//!
//! This parser walks LZ4 blocks and frame members, extracts literal runs, and
//! skips match resolution. The resulting literals can be indexed directly or
//! attached to [`CompressedBlock`] values for later verification.
//!
//! LZ4 format:
//! ```text
//! Token: [literal_length:4][match_length:4]
//! If literal_length == 15: additional bytes follow (sum until < 255)
//! Literal bytes: [literal_length bytes]
//! If match_length > 0:
//!   Match offset: [offset: u16 LE]
//!   If match_length == 15: additional bytes follow
//! ```
//!
//! This module extracts only the literal bytes, skipping match resolution.

use crate::{CompressedBlock, ZiftError};

/// Maximum LZ4 block size (4MB as per spec).
const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const LZ4_FRAME_MAGIC: [u8; 4] = [0x04, 0x22, 0x4D, 0x18];

/// Extract literals from an LZ4 block without decompressing matches.
///
/// This is the core optimization: we parse the LZ4 token stream but skip
/// the expensive part (resolving back-references). Only literal bytes are
/// extracted and returned.
///
/// # Performance
///
/// - Full decompression: `O(uncompressed_size)`
/// - Literal extraction: `O(compressed_size)` + `O(total_literal_bytes)`
///
/// For typical compression ratios (2:1 to 4:1), this is 2-4× faster.
/// For high-compressibility data (logs with repeated patterns), can be
/// 10-100× faster since we skip resolving long match chains.
///
/// # Errors
///
/// Returns `ZiftError` if the literal exceeds block bounds or if the
/// match offset is truncated.
///
/// # Parameters
///
/// - `compressed`: Encoded LZ4 block payload.
/// - `max_output`: Maximum number of literal bytes to collect before stopping.
///
/// # Returns
///
/// The literal bytes encountered while scanning the block.
/// Maximum number of sequences per block to prevent `DoS`.
const MAX_SEQUENCES_PER_BLOCK: usize = 100_000;

/// Extract literals from an LZ4 block without decompressing matches.
///
/// This function now properly respects `max_output` by truncating literals
/// at the limit rather than allowing over-allocation. It also includes
/// sequence counting to prevent `DoS` from streams with too many sequences.
///
/// # Performance
///
/// Uses chunked reservation to minimize reallocations while preventing
/// quadratic behavior on malicious input.
/// # Errors
///
/// Returns `ZiftError::InvalidData` if the block is malformed or exceeds maximum sequences limit.
pub fn extract_literals(compressed: &[u8], max_output: usize) -> Result<Vec<u8>, ZiftError> {
    // Pre-allocate with a reasonable estimate: compressed size × 2 or max_output, whichever is smaller.
    // This reduces reallocations while preventing over-allocation on small inputs.
    let initial_cap = (compressed.len().saturating_mul(2))
        .min(max_output)
        .min(MAX_BLOCK_SIZE);
    let mut literals = Vec::with_capacity(initial_cap);
    let mut pos = 0usize;
    let mut sequence_count = 0usize;

    while pos < compressed.len() && literals.len() < max_output {
        // Prevent DoS from too many sequences
        sequence_count += 1;
        if sequence_count >= MAX_SEQUENCES_PER_BLOCK {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!("too many LZ4 sequences (max {MAX_SEQUENCES_PER_BLOCK})"),
            });
        }

        // Read token
        if pos >= compressed.len() {
            break;
        }
        let token = compressed[pos];
        pos += 1;

        let literal_len = (token >> 4) as usize;
        let match_len = (token & 0x0F) as usize;

        // Decode variable-length literal length
        let literal_len = if literal_len == 15 {
            decode_length(compressed, &mut pos, literal_len)?
        } else {
            literal_len
        };

        // Validate literal length before allocation
        if literal_len > MAX_BLOCK_SIZE {
            return Err(ZiftError::BlockTooLarge {
                size: literal_len,
                max: MAX_BLOCK_SIZE,
            });
        }

        // Check if adding this literal would exceed max_output
        let remaining_output = max_output.saturating_sub(literals.len());
        let to_copy = literal_len.min(remaining_output);

        // Copy literal bytes
        if to_copy > 0 {
            if pos + to_copy > compressed.len() {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "literal exceeds block bounds".to_string(),
                });
            }

            // Reserve space in chunks to reduce reallocations
            if to_copy > 1024 && literals.capacity() - literals.len() < to_copy {
                let reserve_amount = (MAX_BLOCK_SIZE / 4)
                    .min(remaining_output.saturating_sub(literals.capacity() - literals.len()));
                if reserve_amount > 0 {
                    literals.reserve(reserve_amount);
                }
            }

            literals.extend_from_slice(&compressed[pos..pos + to_copy]);
        }

        // Advance position by full literal_len even if we truncated
        pos = pos.saturating_add(literal_len);

        // Skip match data (we don't resolve back-references).
        // In LZ4, every sequence except the LAST has a match section.
        // The last sequence is detected by being at end-of-block after literals.
        // Match offset (2 bytes) is ALWAYS present when there's a match section,
        // even when token low nibble is 0 (which means min match length of 4).
        if pos < compressed.len() {
            // Read match offset (2 bytes, always present for non-final sequences)
            if pos + 2 > compressed.len() {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "truncated match offset".to_string(),
                });
            }
            pos += 2; // Skip offset

            // Decode variable-length match length
            if match_len == 15 {
                let _ = decode_length(compressed, &mut pos, match_len)?;
            }
        }
    }

    Ok(literals)
}

/// Decode a variable-length length field.
///
/// LZ4 uses additive encoding: if initial value is 15, sum subsequent
/// bytes until one < 255 is found.
fn decode_length(data: &[u8], pos: &mut usize, initial: usize) -> Result<usize, ZiftError> {
    let mut len = initial;

    loop {
        if *pos >= data.len() {
            return Err(ZiftError::InvalidData {
                offset: *pos,
                reason: "truncated length encoding".to_string(),
            });
        }
        let byte = data[*pos];
        *pos += 1;
        len = len
            .checked_add(byte as usize)
            .ok_or(ZiftError::InvalidData {
                offset: *pos,
                reason: "length overflow in variable-length encoding".to_string(),
            })?;

        if byte < 255 {
            break;
        }

        // Safety: cap iterations to prevent infinite loop on malicious input
        // (all-255 bytes). Max realistic LZ4 block is 4MB.
        if len > MAX_BLOCK_SIZE {
            return Err(ZiftError::BlockTooLarge {
                size: len,
                max: MAX_BLOCK_SIZE,
            });
        }
    }

    Ok(len)
}

/// Maximum number of blocks per stream to prevent `DoS`.
const MAX_BLOCKS_PER_STREAM: usize = 10_000;

/// Maximum total literals per stream to prevent OOM.
const MAX_TOTAL_LITERALS: usize = 256 * 1024 * 1024; // 256 MB

/// Maximum decompression ratio to prevent zip bombs.
const MAX_DECOMPRESSION_RATIO: usize = 250;

/// Parse multiple LZ4 blocks and extract literals from each.
///
/// # Errors
///
/// Returns `ZiftError` if the data is truncated, if block size exceeds
/// maximum limits, or if literal extraction fails.
///
/// # Parameters
///
/// - `data`: LZ4 frame or block bytes.
///
/// # Returns
///
/// A vector of [`CompressedBlock`] values in stream order.
pub fn parse_lz4_blocks(data: &[u8]) -> Result<Vec<CompressedBlock>, ZiftError> {
    let mut blocks = Vec::new();
    let mut offset = parse_frame_header(data)? as u64;

    let mut total_literals = 0usize;

    while offset < data.len() as u64 {
        // Prevent DoS from too many blocks
        if blocks.len() >= MAX_BLOCKS_PER_STREAM {
            return Err(ZiftError::InvalidData {
                offset: usize::try_from(offset).unwrap_or(0),
                reason: format!("too many LZ4 blocks (max {MAX_BLOCKS_PER_STREAM})"),
            });
        }

        if offset + 4 > data.len() as u64 {
            break; // Incomplete block header
        }

        // Read block header (compressed size)
        let block_size = u32::from_le_bytes([
            data[usize::try_from(offset).unwrap_or(0)],
            data[usize::try_from(offset).unwrap_or(0) + 1],
            data[usize::try_from(offset).unwrap_or(0) + 2],
            data[usize::try_from(offset).unwrap_or(0) + 3],
        ]) as usize;

        // High bit indicates uncompressed block
        let is_uncompressed = (block_size & 0x8000_0000) != 0;
        let size = block_size & 0x7FFF_FFFF;

        if size == 0 {
            // End marker
            break;
        }

        if size > MAX_BLOCK_SIZE {
            return Err(ZiftError::BlockTooLarge {
                size,
                max: MAX_BLOCK_SIZE,
            });
        }

        let header_size = 4usize;
        let data_start = usize::try_from(offset).unwrap_or(0) + header_size;
        let data_end = data_start + size;

        if data_end > data.len() {
            return Err(ZiftError::InvalidData {
                offset: usize::try_from(offset).unwrap_or(0),
                reason: "truncated block".to_string(),
            });
        }

        let block_data = &data[data_start..data_end];

        let mut block = CompressedBlock::new(
            offset,
            u32::try_from(size).map_err(|_| ZiftError::BlockTooLarge {
                size,
                max: MAX_BLOCK_SIZE,
            })?,
        );

        if is_uncompressed {
            // Uncompressed block - all bytes are literals
            block.literals = block_data.to_vec();
        } else {
            // Compressed block - extract literals
            block.literals = extract_literals(block_data, MAX_BLOCK_SIZE)?;
        }

        total_literals = total_literals.saturating_add(block.literals.len());
        if total_literals > MAX_TOTAL_LITERALS {
            return Err(ZiftError::BlockTooLarge {
                size: total_literals,
                max: MAX_TOTAL_LITERALS,
            });
        }

        let max_allowed_literals = data
            .len()
            .saturating_mul(MAX_DECOMPRESSION_RATIO)
            .max(1024 * 1024);
        if total_literals > max_allowed_literals {
            return Err(ZiftError::InvalidData {
                offset: usize::try_from(offset).unwrap_or(0),
                reason: format!("decompression ratio exceeded limit of {MAX_DECOMPRESSION_RATIO}"),
            });
        }

        blocks.push(block);
        offset = u64::try_from(data_end).map_err(|_| ZiftError::InvalidData {
            offset: usize::try_from(offset).unwrap_or(0),
            reason: "offset overflow".to_string(),
        })?;
    }

    Ok(blocks)
}

fn parse_frame_header(data: &[u8]) -> Result<usize, ZiftError> {
    if data.is_empty() {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: "empty input is not valid LZ4 data".to_string(),
        });
    }
    if data.len() < 4 || data[..4] != LZ4_FRAME_MAGIC {
        // Not a framed LZ4 stream — treat as raw block data (legacy format).
        // Start parsing from offset 0.
        return Ok(0);
    }
    if data.len() < 7 {
        return Err(ZiftError::InvalidData {
            offset: data.len(),
            reason: "truncated lz4 frame header".to_string(),
        });
    }

    let flg = data[4];

    // Version is in bits 6-7; only version 1 (0b01) is supported.
    if (flg & 0xC0) != 0x40 {
        return Err(ZiftError::InvalidData {
            offset: 4,
            reason: "unsupported LZ4 frame version".to_string(),
        });
    }

    let mut pos = 6usize;

    if (flg & 0x08) != 0 {
        pos += 8;
    }
    if (flg & 0x01) != 0 {
        pos += 1;
    }
    if pos >= data.len() {
        return Err(ZiftError::InvalidData {
            offset: pos,
            reason: "truncated lz4 frame descriptor".to_string(),
        });
    }

    pos += 1; // header checksum
    Ok(pos)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_length() {
        // Length with extension (15 + 100 = 115)
        let data = [100u8];
        let mut pos = 0;
        assert_eq!(decode_length(&data, &mut pos, 15).unwrap(), 115);
        assert_eq!(pos, 1); // Consumed 1 byte

        // Length with multiple extensions (15 + 255 + 50 = 320)
        let data = [255u8, 50];
        let mut pos = 0;
        assert_eq!(decode_length(&data, &mut pos, 15).unwrap(), 320);
        assert_eq!(pos, 2); // Consumed 2 bytes
    }

    #[test]
    fn test_extract_literals_with_match() {
        // Token: 0x11 = literal_len=1, match_len=1
        // Literal: 'A'
        // Match offset: 0x0001 (1 byte back)
        // We should skip the match, only get 'A'
        let data = [0x11, b'A', 0x01, 0x00];
        let literals = extract_literals(&data, 1024).unwrap();
        assert_eq!(literals, b"A");
    }

    #[test]
    fn test_extract_literals_extended() {
        // Token: 0xF0 = literal_len=15 (needs extension), match_len=0
        // Extension: 10 (total = 25)
        // 25 literal bytes
        let mut data = vec![0xF0, 10]; // 15 + 10 = 25 literal bytes
        data.extend_from_slice(&[b'X'; 25]);

        let literals = extract_literals(&data, 1024).unwrap();
        assert_eq!(literals.len(), 25);
        assert!(literals.iter().all(|&b| b == b'X'));
    }

    #[test]
    fn test_extract_literals_truncated() {
        // Claimed literal length exceeds data
        let data = [0x20, b'A']; // Claims 2 literals, only 1 present
        let result = extract_literals(&data, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lz4_blocks_empty() {
        let data = []; // Empty
        let result = parse_lz4_blocks(&data);
        assert!(
            result.is_err(),
            "empty input must be rejected as invalid LZ4"
        );
    }

    #[test]
    fn test_parse_lz4_blocks_non_framed() {
        // Data without LZ4 frame magic is treated as raw block data (legacy format).
        // With invalid block headers, it should return empty blocks (no panic).
        let data = [0x00, 0x00, 0x00, 0x00]; // End-of-frame marker (size=0)
        let blocks = parse_lz4_blocks(&data).unwrap();
        assert!(
            blocks.is_empty(),
            "end-of-frame marker should produce empty blocks"
        );
    }

    #[test]
    fn test_parse_lz4_frame_header_then_blocks() {
        let mut data = vec![0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x00];
        data.extend_from_slice(&0x8000_0001_u32.to_le_bytes());
        data.push(b'A');
        data.extend_from_slice(&0_u32.to_le_bytes());

        let blocks = parse_lz4_blocks(&data).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].literals(), b"A");
    }

    #[test]
    fn test_extract_literals_simple() {
        // Token: 0x10 = literal_len=1, match_len=0
        // Literal: 'A'
        let data = [0x10, b'A'];
        let literals = extract_literals(&data, 1024).unwrap();
        assert_eq!(literals, b"A");
    }
}
