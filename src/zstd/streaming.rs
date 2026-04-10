//! Streaming zstd extraction orchestrator.

use super::decoder::extract_literals_from_block;
use super::frame::{parse_frame_header, BlockType, MAX_BLOCK_SIZE};
use crate::{CompressedBlock, ZiftError};

/// Maximum Zstd total literals size (256MB).
pub(crate) const MAX_TOTAL_LITERALS: usize = 256 * 1024 * 1024; // 256 MB

/// Maximum decompression ratio to prevent zip bombs.
const MAX_DECOMPRESSION_RATIO: usize = 250;

/// Parse Zstd frame and extract literals from each block.
///
/// # Errors
///
/// Returns `ZiftError` if the frame header is invalid, if there are too many
/// blocks (>100K), or if block parsing fails.
///
/// # Parameters
///
/// - `data`: Zstd frame bytes.
///
/// # Returns
///
/// Parsed blocks in frame order, each carrying any recoverable literals.
pub fn extract_literals(data: &[u8]) -> Result<Vec<CompressedBlock>, ZiftError> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;
    let mut total_literals = 0usize;

    // Parse frame header (currently returns unit type)
    parse_frame_header(data, &mut pos)?;

    // Note: header.dict_id indicates dictionary-compressed frames.
    // Dictionary mode requires external dictionary for full decompression.
    // Raw and RLE literals can still be extracted, but Huffman-compressed
    // literals in treeless mode (type 3) will return empty.

    // Parse blocks until last_block flag
    loop {
        let (block, is_last) = parse_block(data, &mut pos)?;

        total_literals = total_literals.saturating_add(block.literals().len());
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
                offset: pos,
                reason: format!("decompression ratio exceeded limit of {MAX_DECOMPRESSION_RATIO}. Fix: use a non-malicious Zstd stream or increase MAX_DECOMPRESSION_RATIO"),
            });
        }

        blocks.push(block);

        if is_last {
            break;
        }

        // Safety: prevent infinite loop on malformed data
        if blocks.len() >= 100_000 {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: "too many blocks (>100K), likely malformed. Fix: use a valid Zstd stream".to_string(),
            });
        }
    }

    Ok(blocks)
}

pub(crate) fn parse_block(
    data: &[u8],
    pos: &mut usize,
) -> Result<(CompressedBlock, bool), ZiftError> {
    if *pos + 3 > data.len() {
        return Err(ZiftError::InvalidData {
            offset: *pos,
            reason: "truncated block header. Fix: use a complete Zstd stream".to_string(),
        });
    }

    // Block header (3 bytes)
    let b0 = data[*pos];
    let b1 = data[*pos + 1];
    let b2 = data[*pos + 2];
    *pos += 3;

    let last_block = (b0 & 0x01) != 0;
    let block_type = BlockType::from_u8((b0 >> 1) & 0x03).ok_or(ZiftError::InvalidData {
        offset: *pos - 3,
        reason: "invalid block type. Fix: use a valid Zstd stream".to_string(),
    })?;

    let block_size = ((b0 >> 3) as usize) | ((b1 as usize) << 5) | ((b2 as usize) << 13);

    if block_size > MAX_BLOCK_SIZE {
        return Err(ZiftError::BlockTooLarge {
            size: block_size,
            max: MAX_BLOCK_SIZE,
        });
    }

    // For Raw and Compressed blocks, block_size is the data size in the stream.
    // For RLE blocks, block_size is the uncompressed repeat count, but the stream
    // contains exactly 1 byte (RFC 8878 Section 3.1.1.2.1).
    let stream_data_size = match block_type {
        BlockType::Rle => 1usize,
        _ => block_size,
    };

    if pos.saturating_add(stream_data_size) > data.len() {
        return Err(ZiftError::InvalidData {
            offset: *pos,
            reason: format!(
                "block data size {stream_data_size} exceeds remaining data {}. Fix: use a complete Zstd stream",
                data.len() - *pos
            ),
        });
    }

    let block_data = &data[*pos..*pos + stream_data_size];
    // block_size is bounded by MAX_BLOCK_SIZE (128KB), so these conversions are safe
    let compressed_offset = u64::try_from(*pos - 3).unwrap_or(u64::MAX); // Include header
    let compressed_len = u32::try_from(stream_data_size + 3).unwrap_or(u32::MAX);

    let mut block = CompressedBlock::new(compressed_offset, compressed_len);

    match block_type {
        BlockType::Raw => {
            // Raw block - all bytes are literals
            block.literals = block_data.to_vec();
            // block_size is bounded by MAX_BLOCK_SIZE (128KB), so this conversion is safe
            block.uncompressed_len = Some(u32::try_from(block_size).unwrap_or(u32::MAX));
        }
        BlockType::Rle => {
            // RLE block - one byte repeated block_size times
            if !block_data.is_empty() {
                block.literals = vec![block_data[0]; block_size];
                // block_size is bounded by MAX_BLOCK_SIZE (128KB), so this conversion is safe
                block.uncompressed_len = Some(u32::try_from(block_size).unwrap_or(u32::MAX));
            }
        }
        BlockType::Compressed => {
            // Compressed block - extract literals
            block.literals = extract_literals_from_block(block_data)?;
            // block_size is bounded by MAX_BLOCK_SIZE (128KB), so this conversion is safe
            block.uncompressed_len = Some(u32::try_from(block_size).unwrap_or(u32::MAX));
            // Actually regenerated size
        }
        BlockType::Reserved => {
            return Err(ZiftError::InvalidData {
                offset: *pos - 3,
                reason: "reserved block type. Fix: use a valid Zstd stream".to_string(),
            });
        }
    }

    *pos += stream_data_size;
    Ok((block, last_block))
}
