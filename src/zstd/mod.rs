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

pub(crate) mod decoder;
pub(crate) mod frame;
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
