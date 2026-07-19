//! Zstd literal extraction without full decompression.
//!
//! The parser walks Zstd frames and block headers, extracts raw, RLE, and
//! Huffman-decoded literals when possible, and skips sequence execution. This
//! yields a conservative literal view suitable for indexing.
//!
//! Zstd format:
//! - Frame header
//! - Blocks (compressed or raw)
//! - Each block has:
//!   - Block header (3 bytes): `last_block`, `block_type`, `block_size`
//!   - For compressed blocks:
//!     - Literals section (Huffman or raw)
//!     - Sequences section (match/length/offset)
//!
//! This module extracts only the literals section, skipping sequence decoding.

pub(crate) mod bit_io;
pub(crate) mod decoder;
pub(crate) mod frame;
pub(crate) mod fse;
pub(crate) mod huffman;
pub mod streaming;

pub use streaming::extract_literals;

#[cfg(test)]
mod tests {
    use super::decoder::extract_literals_from_block;
    use super::frame::{parse_frame_header, BlockType};
    use crate::ZiftError;

    #[test]
    fn test_parse_frame_header_invalid_magic() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let mut pos = 0;
        assert!(parse_frame_header(&data, &mut pos).is_err());
    }

    #[test]
    fn parse_frame_header_returns_false_when_stream_is_only_a_skippable_frame() {
        // Skippable frame magic 0x184D2A50 (LE), size 4, then 4 content bytes,
        // and nothing after: a valid, complete stream with no standard frame.
        let mut data = vec![0x50, 0x2A, 0x4D, 0x18];
        data.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        data.extend_from_slice(b"skip");
        let mut pos = 0;
        // Previously this returned a "truncated frame header" error.
        let has_standard_frame =
            parse_frame_header(&data, &mut pos).expect("skippable-only stream is valid");
        assert!(!has_standard_frame);
        assert_eq!(pos, data.len());
    }

    #[test]
    fn extract_literals_of_skippable_only_stream_is_empty_not_error() {
        let mut data = vec![0x50, 0x2A, 0x4D, 0x18];
        data.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        data.extend_from_slice(b"skip");
        let blocks =
            super::extract_literals(&data).expect("skippable-only stream yields no blocks");
        assert!(blocks.is_empty());
    }

    #[test]
    fn parse_standard_frame_header_rejects_truncated_content_size() {
        // Standard magic + fh_desc with fcs_id=3 (8-byte FCS) and single_segment=1,
        // but no FCS bytes present. The FCS bounds check must reject this.
        // fh_desc: fcs_id=3 (bits 7-6 = 11), single_segment=1 (bit 5) => 0b1110_0000.
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0b1110_0000];
        let mut pos = 0;
        let result = parse_frame_header(&data, &mut pos);
        assert!(matches!(
            result,
            Err(ZiftError::InvalidData { ref reason, .. }) if reason.contains("frame content size")
        ));
    }

    #[test]
    fn test_block_type_parsing() {
        assert_eq!(BlockType::from_u8(0), Some(BlockType::Raw));
        assert_eq!(BlockType::from_u8(1), Some(BlockType::Rle));
        assert_eq!(BlockType::from_u8(2), Some(BlockType::Compressed));
        assert_eq!(BlockType::from_u8(3), Some(BlockType::Reserved));
        assert_eq!(BlockType::from_u8(4), None);
    }

    #[test]
    fn test_treeless_compressed_literals_error() {
        let data = [0x03]; // ls_type = 3
        let result = extract_literals_from_block(&data);
        assert!(
            matches!(result, Err(ZiftError::InvalidData { ref reason, .. }) if reason.contains("treeless"))
        );
    }
}
