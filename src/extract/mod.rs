//! Orchestration of literal extraction across supported formats.

#[cfg(feature = "gzip")]
use crate::gzip;
#[cfg(feature = "lz4")]
use crate::lz4;
#[cfg(feature = "snappy")]
use crate::snappy;
#[cfg(feature = "zstd")]
use crate::zstd;
use crate::{CompressionFormat, ZiftError};

#[cfg(feature = "gzip")]
mod tarball;

#[cfg(feature = "gzip")]
pub use tarball::scan_tarball_literals;

/// A block of compressed data with extractable literals.
///
/// The block stores the compressed location metadata plus the literal bytes
/// recovered from the format-specific parser. Literal bytes are suitable for
/// bloom-filter prefiltering and lightweight verification.
#[derive(Debug, Clone)]
pub struct CompressedBlock {
    /// Offset in the compressed stream.
    ///
    /// For blocks returned by tarball scanning, this offset refers to the
    /// decompressed tar archive rather than the original gzip stream.
    pub(crate) compressed_offset: u64,
    /// Length in the compressed stream.
    pub(crate) compressed_len: u32,
    /// Uncompressed length (if known).
    pub(crate) uncompressed_len: Option<u32>,
    /// Extracted literal bytes from this block.
    pub(crate) literals: Vec<u8>,
}

impl CompressedBlock {
    /// Creates block metadata with no known uncompressed length and no literals.
    ///
    /// # Parameters
    ///
    /// - `offset`: Starting byte offset of the block in the compressed stream.
    /// - `compressed_len`: Serialized length of the block in bytes.
    ///
    /// # Returns
    ///
    /// A new [`CompressedBlock`] ready for a parser to populate.
    #[must_use]
    pub fn new(offset: u64, compressed_len: u32) -> Self {
        Self {
            compressed_offset: offset,
            compressed_len,
            uncompressed_len: None,
            literals: Vec::new(),
        }
    }

    /// Returns the starting byte offset of this block in the compressed stream.
    ///
    /// # Returns
    ///
    /// The compressed-stream byte offset recorded when the block was parsed.
    #[must_use]
    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    /// Returns the serialized compressed size of this block.
    ///
    /// # Returns
    ///
    /// The number of compressed bytes that belong to this block.
    #[must_use]
    pub fn compressed_len(&self) -> u32 {
        self.compressed_len
    }

    /// Returns the uncompressed size when the format exposes it cheaply.
    ///
    /// # Returns
    ///
    /// `Some(len)` when the parser could determine the block's uncompressed
    /// length, or `None` when it is unknown.
    #[must_use]
    pub fn uncompressed_len(&self) -> Option<u32> {
        self.uncompressed_len
    }

    /// Returns the extracted literal bytes for this block.
    ///
    /// # Returns
    ///
    /// A read-only slice of the literal bytes recovered during parsing.
    #[must_use]
    pub fn literals(&self) -> &[u8] {
        &self.literals
    }

    /// Verify that this block actually contains `pattern`.
    ///
    /// This performs a linear search through literals and is meant for
    /// verifying bloom filter candidates, not for primary search.
    ///
    /// # Parameters
    ///
    /// - `pattern`: Byte sequence to search for within the extracted literals.
    ///
    /// # Returns
    ///
    /// `true` when the literal byte stream contains `pattern`, otherwise
    /// `false`. An empty pattern always matches.
    #[must_use]
    pub fn verify_contains(&self, pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return true;
        }
        if pattern.len() > self.literals.len() {
            return false;
        }

        if pattern.len() == 1 {
            return self.literals.contains(&pattern[0]);
        }

        self.literals
            .windows(pattern.len())
            .any(|window| window == pattern)
    }

    /// Estimate match probability based on literal density.
    ///
    /// Returns ratio of literals to expected uncompressed size.
    /// Higher values mean more confident bloom filter results.
    ///
    /// # Returns
    ///
    /// A value in the range `0.0..=1.0` when the uncompressed size is known,
    /// or `1.0` when it is unknown.
    ///
    /// # Precision
    /// Uses `f64` for calculation. For very large blocks (> 2^52 bytes),
    /// precision loss may occur in the least significant bits.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn literal_density(&self) -> f64 {
        match self.uncompressed_len {
            Some(ulen) if ulen > 0 => self.literals.len() as f64 / f64::from(ulen),
            _ => 1.0,
        }
    }
}

/// Orchestrates literal extraction from a compressed byte slice.
///
/// # Example
/// ```
/// use ziftsieve::{extract_from_bytes, CompressionFormat};
/// // let blocks = extract_from_bytes(CompressionFormat::Lz4, b"LZ4 data...").unwrap();
/// ```
///
/// # Errors
///
/// Returns [`ZiftError`] if the format is unsupported or data is malformed.
pub fn extract_from_bytes(
    format: CompressionFormat,
    data: &[u8],
) -> Result<Vec<CompressedBlock>, ZiftError> {
    match format {
        #[cfg(feature = "lz4")]
        CompressionFormat::Lz4 => lz4::parse_lz4_blocks(data),
        #[cfg(not(feature = "lz4"))]
        CompressionFormat::Lz4 => Err(ZiftError::FeatureNotEnabled {
            format,
            feature: format.feature_name(),
        }),
        #[cfg(feature = "snappy")]
        CompressionFormat::Snappy => snappy::extract_literals(data),
        #[cfg(not(feature = "snappy"))]
        CompressionFormat::Snappy => Err(ZiftError::FeatureNotEnabled {
            format,
            feature: format.feature_name(),
        }),
        #[cfg(feature = "gzip")]
        CompressionFormat::Gzip => gzip::extract_literals(data),
        #[cfg(not(feature = "gzip"))]
        CompressionFormat::Gzip => Err(ZiftError::FeatureNotEnabled {
            format,
            feature: format.feature_name(),
        }),
        #[cfg(feature = "zstd")]
        CompressionFormat::Zstd => zstd::extract_literals(data),
        #[cfg(not(feature = "zstd"))]
        CompressionFormat::Zstd => Err(ZiftError::FeatureNotEnabled {
            format,
            feature: format.feature_name(),
        }),
    }
}
