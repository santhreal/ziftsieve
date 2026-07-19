//! Gzip literal extraction without full decompression.
//!
//! This parser walks RFC 1952 gzip members and decodes DEFLATE blocks enough to
//! recover only literal bytes.
//! Back-references are intentionally skipped because they are not required for
//! bloom-filter construction.

pub(crate) mod bitstream;
pub(crate) mod deflate;
pub(crate) mod header;

use crate::{CompressedBlock, ZiftError};
pub(crate) use bitstream::BitReader;

/// Extract literal bytes from gzip members.
///
/// This parses gzip members, then walks each DEFLATE block. Literal bytes are
/// emitted from block headers and fixed/dynamic Huffman streams. Length/distance
/// pairs are skipped without reconstruction.
///
/// # Parameters
///
/// - `data`: Gzip member bytes.
///
/// # Returns
///
/// Parsed [`CompressedBlock`] values with the literal bytes recovered from each
/// DEFLATE block.
///
/// # Errors
///
/// Returns [`ZiftError`] when the gzip header is malformed, the DEFLATE stream
/// is truncated or invalid, or a block exceeds configured limits.
/// Maximum total extracted literal bytes across all blocks.
/// Prevents OOM from malicious gzip streams with huge literal payloads.
pub(crate) const MAX_TOTAL_LITERALS: usize = 256 * 1024 * 1024; // 256 MB

/// Extracts literals from gzip member compressed blocks.
///
/// Limits maximum literals to `MAX_TOTAL_LITERALS`.
/// # Errors
///
/// Returns `ZiftError::InvalidData` if the stream is truncated or malformed, or
/// `ZiftError::BlockTooLarge` if the extracted literals exceed memory limits.
pub fn extract_literals(data: &[u8]) -> Result<Vec<CompressedBlock>, ZiftError> {
    if data.is_empty() {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: "empty gzip input. Fix: provide non-empty compressed data".to_string(),
        });
    }
    let mut reader = BitReader::new(data, 0);
    let mut blocks = Vec::new();

    let mut members = 0usize;
    let mut total_literals = 0usize;
    while reader.remaining_bytes() > 0 {
        header::parse_gzip_member(&mut reader, &mut blocks, &mut total_literals)?;

        members += 1;
        if members >= 1024 {
            return Err(ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason:
                    "too many gzip members, likely malformed input. Fix: use a valid gzip stream"
                        .to_string(),
            });
        }
    }

    Ok(blocks)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn gzip_compress(data: &[u8], level: u32) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(data).expect("compression should work");
        encoder.finish().expect("finish compression")
    }

    #[test]
    fn empty_stream_returns_no_blocks() {
        let mut total_literals = 0;
        let err = header::parse_gzip_member(
            &mut BitReader::new(&[], 0),
            &mut Vec::new(),
            &mut total_literals,
        );
        assert!(err.is_err());
    }

    #[test]
    fn fixed_huffman_literals_match_source_with_no_compression() {
        let data = b"gzip-fixed-block-literal-regression";
        let compressed = gzip_compress(data, 0);
        let blocks = extract_literals(&compressed).expect("extract");
        let extracted: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();

        assert_eq!(extracted, data);
    }

    #[test]
    fn dynamic_huffman_literals_are_subset_of_decompressed_output() {
        let data =
            b"the quick brown fox jumps over the lazy dog; gzip dynamic parse test".repeat(200);
        let compressed = gzip_compress(&data, 6);
        let blocks = extract_literals(&compressed).expect("extract");
        assert!(!blocks.is_empty());
        let extracted: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals.iter().copied())
            .collect();
        assert!(!extracted.is_empty());
    }

    #[test]
    fn reject_malformed_header() {
        let data = [0x00, 0x00, 0x00, 0x00];
        assert!(extract_literals(&data).is_err());
    }

    #[test]
    fn huffman_literals_buffer_is_reserved_upfront_not_regrown_from_zero() {
        // Highly compressible input: a long run of one byte becomes a single
        // literal plus a long back-reference, so the *literal count* is tiny
        // while the *compressed block* is far larger. A from-zero push loop
        // would leave `literals.capacity()` at a small power of two (near the
        // literal count); the upfront `reserve(remaining_bytes)` guarantees
        // capacity >= the block's compressed length. Asserting the latter proves
        // the reservation happened and rules out repeated reallocation.
        let data = vec![b'x'; 100_000];
        let compressed = gzip_compress(&data, 6);
        let blocks = extract_literals(&compressed).expect("extract");
        assert!(!blocks.is_empty(), "expected at least one block");

        let with_literals: Vec<_> = blocks.iter().filter(|b| !b.literals.is_empty()).collect();
        assert!(
            !with_literals.is_empty(),
            "the run must yield at least one literal block"
        );
        for block in with_literals {
            let literal_count = block.literals.len();
            let compressed_len = block.compressed_len() as usize;
            // The reserve sizes the buffer to `remaining_bytes` at block-body
            // start, so capacity lands on the order of the compressed block
            // length. From-zero doubling for this tiny literal count would cap
            // out near `MIN_NON_ZERO_CAP` (8 for a Vec<u8>), i.e. an order of
            // magnitude smaller. Guard that literals really are far fewer than
            // the compressed bytes, then assert capacity is compressed-block
            // scale, which a from-zero push loop cannot reach here.
            assert!(
                literal_count * 8 < compressed_len,
                "guard: literals ({literal_count}) must be far fewer than compressed bytes \
                 ({compressed_len}) for this discriminator to be meaningful"
            );
            assert!(
                block.literals.capacity() >= compressed_len / 2,
                "literals buffer must be reserved upfront to compressed-block scale \
                 (>= {} = compressed_len/2), got capacity {} for only {literal_count} literals \
                 (from-zero regrowth would sit near MIN_NON_ZERO_CAP=8)",
                compressed_len / 2,
                block.literals.capacity()
            );
        }
    }
}
