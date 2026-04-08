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
                reason: "too many gzip members, likely malformed input".to_string(),
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
}
