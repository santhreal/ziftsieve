//! Search compressed data without full decompression.
//!
//! `ziftsieve` extracts literal bytes from compressed blocks and builds bloom
//! filters over them. This allows skipping decompression for blocks that
//! provably cannot contain a search pattern.
//!
//! # What this crate does
//!
//! This crate provides a high-performance streaming decompression partial-parser.
//! Instead of fully decompressing streams (which requires resolving all back-references
//! and dictionaries), `ziftsieve` rapidly extracts only the raw literal bytes and
//! constructs per-block Bloom filters over them.
//!
//! # Why use it
//!
//! By indexing literals into a Bloom filter, tools can rapidly scan massive compressed
//! archives (like PCAPs, database dumps, or logs) and skip full decompression for any
//! block that provably does not contain the target byte pattern. For large-scale data
//! ingestion and security scanning, this yields orders of magnitude speedups.
//!
//! # How to get started in 3 lines
//!
//! ```rust
//! use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
//! let index = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(b"...").unwrap();
//! if !index.candidate_blocks(b"my_secret").is_empty() { /* decompress and verify */ }
//! ```
//!
//! # Supported Formats
//!
//! - **Gzip:** Supports standard `.gz` files and DEFLATE streams.
//! - **LZ4:** Supports both the LZ4 frame format and raw block format.
//! - **Snappy:** Supports the Snappy framing format (common in database logs).
//! - **Zstd:** Supports Zstandard frames.
//!
//! Each format is available as an optional crate feature.

#![warn(missing_docs, clippy::pedantic)]
#![allow(unknown_lints)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod bloom;
pub mod builder;
pub mod detect;
pub mod extract;
#[cfg(feature = "gzip")]
pub mod gzip;
pub mod index;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "snappy")]
pub mod snappy;
#[cfg(feature = "zstd")]
pub mod zstd;

pub use builder::{CompressedIndexBuilder, StreamingIndexBuilder};
pub use extract::extract_from_bytes;
#[cfg(feature = "gzip")]
pub use extract::scan_tarball_literals;
pub use extract::CompressedBlock;
#[cfg(feature = "gzip")]
pub use flashsieve::NgramBloom;
pub use index::{BloomStats, CompressedIndex};

/// Compression formats supported for literal extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressionFormat {
    /// LZ4 block or frame format.
    Lz4,
    /// Snappy framing format.
    Snappy,
    /// Gzip container with DEFLATE blocks.
    Gzip,
    /// Zstd frame format.
    Zstd,
}

/// Errors returned while parsing compressed data or building indexes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ZiftError {
    /// Unsupported compression format.
    #[error("unsupported compression format: {0}")]
    UnsupportedFormat(CompressionFormat),
    /// Corrupted or invalid compressed data.
    #[error("invalid compressed data at offset {offset}: {reason}")]
    InvalidData {
        /// Byte offset where error occurred.
        offset: usize,
        /// Human-readable error description.
        reason: String,
    },
    /// Feature not compiled in.
    #[error("format {format} not enabled, compile with --features {feature}")]
    FeatureNotEnabled {
        /// The requested format.
        format: CompressionFormat,
        /// Feature flag name.
        feature: &'static str,
    },
    /// Block size exceeds limits.
    #[error("block size {size} exceeds maximum {max}")]
    BlockTooLarge {
        /// Actual block size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// I/O failure raised by caller-provided readers or writers.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Build a 2-byte n-gram bloom filter from extracted literals.
///
/// This is intentionally aligned with `flashsieve` behavior: only 2-byte windows
/// are inserted and membership checks are equivalent to
/// [`flashsieve::NgramBloom::maybe_contains`].
///
/// # Parameters
///
/// - `blocks`: Literal-bearing [`CompressedBlock`] values.
/// - `num_bits`: Target number of bits for the bloom filter.
///
/// # Errors
///
/// Returns a [`flashsieve::Error`] when `num_bits` is invalid (for example,
/// zero bits).
#[cfg(feature = "gzip")]
pub fn bloom_from_literals(
    blocks: &[CompressedBlock],
    num_bits: usize,
) -> flashsieve::Result<NgramBloom> {
    let mut bloom = NgramBloom::new(num_bits)?;
    for block in blocks {
        for window in block.literals.windows(2) {
            bloom.insert_ngram(window[0], window[1]);
        }
    }

    Ok(bloom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_format_display() {
        assert_eq!(CompressionFormat::Lz4.to_string(), "LZ4");
    }

    #[test]
    fn test_compressed_block_verify() {
        let block = CompressedBlock {
            compressed_offset: 0,
            compressed_len: 100,
            uncompressed_len: Some(200),
            literals: b"hello world ERROR message".to_vec(),
        };

        assert!(block.verify_contains(b"ERROR"));
        assert!(block.verify_contains(b"hello"));
        assert!(!block.verify_contains(b"FATAL"));
        assert!(block.verify_contains(b""));
    }

    #[test]
    fn test_compressed_block_empty_literals() {
        let block = CompressedBlock {
            compressed_offset: 0,
            compressed_len: 0,
            uncompressed_len: Some(0),
            literals: Vec::new(),
        };

        assert!(!block.verify_contains(b"anything"));
        assert!(block.verify_contains(b""));
    }

    #[test]
    fn test_zift_error_feature_not_enabled() {
        let err = ZiftError::FeatureNotEnabled {
            format: CompressionFormat::Lz4,
            feature: "lz4",
        };
        assert!(err.to_string().contains("lz4"));
    }

    #[test]
    fn test_builder_pattern() {
        let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4)
            .expected_items(1000)
            .false_positive_rate(0.01);
        assert_eq!(
            builder
                .expected_items(1000)
                .expected_items(1000)
                .bloom_bits(1024)
                .bloom_hashes(3)
                .expected_items,
            Some(1000)
        );
    }
}
