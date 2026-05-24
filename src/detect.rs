//! Logic for identifying and describing compression formats.

use crate::CompressionFormat;
use std::fmt;

impl fmt::Display for CompressionFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lz4 => write!(f, "LZ4"),
            Self::Snappy => write!(f, "Snappy"),
            Self::Gzip => write!(f, "Gzip"),
            Self::Zstd => write!(f, "Zstd"),
        }
    }
}

impl CompressionFormat {
    /// Returns the feature flag name for this format.
    pub(crate) fn feature_name(self) -> &'static str {
        match self {
            Self::Lz4 => "lz4",
            Self::Snappy => "snappy",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }

    /// Automatically detect compression format from magic numbers.
    ///
    /// # Parameters
    ///
    /// - `data`: Leading bytes of a compressed stream.
    ///
    /// Returns
    ///
    /// `Some(CompressionFormat)` if a known signature matches, otherwise `None`.
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<Self> {
        // `starts_with` safely handles cases where `data.len()` is less than the pattern length.
        // We do not enforce a global minimum length because signatures vary in length
        // (e.g., Gzip is 2 bytes, Snappy is 10 bytes).

        // Gzip: 1F 8B
        if data.starts_with(&[0x1f, 0x8b]) {
            return Some(Self::Gzip);
        }

        // LZ4: 04 22 4D 18 (frame) or 02 21 4C 18 (legacy frame)
        if data.starts_with(&[0x04, 0x22, 0x4d, 0x18])
            || data.starts_with(&[0x02, 0x21, 0x4c, 0x18])
        {
            return Some(Self::Lz4);
        }

        // Zstd: 28 B5 2F FD
        if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            return Some(Self::Zstd);
        }

        // Snappy framing: ff 06 00 00 73 4e 61 50 70 59
        if data.starts_with(&[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]) {
            return Some(Self::Snappy);
        }

        None
    }
}
