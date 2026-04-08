//! Core index structure for compressed literal search.

use crate::bloom::BloomFilter;
use crate::{CompressedBlock, CompressionFormat};

/// Block with its own bloom filter for precise filtering.
#[derive(Debug)]
pub(crate) struct BlockWithBloom {
    /// The compressed block data.
    pub(crate) block: CompressedBlock,
    /// Bloom filter for this block's literals.
    pub(crate) bloom: BloomFilter,
}

/// Index of extracted literals with one bloom filter per compressed block.
///
/// Querying the index is cheap: the bloom filter pass rejects blocks that
/// definitely do not contain the pattern, leaving only a smaller candidate set
/// for verification.
#[derive(Debug)]
pub struct CompressedIndex {
    pub(crate) format: CompressionFormat,
    pub(crate) blocks: Vec<BlockWithBloom>,
}

impl CompressedIndex {
    /// Check if a pattern might be in a bloom filter.
    ///
    /// # Limitation (False Negative Risk)
    /// If a pattern spans across block boundaries (e.g., partial match at the end
    /// of one block and the rest at the beginning of the next), checking per-block
    /// bloom filters may result in a false negative. The position advancement during
    /// extraction or indexing advances by `literal_len`, meaning split matches won't
    /// be fully represented in a single block's bloom filter. Use a sliding window
    /// over decompressed data if cross-block matches are strictly required.
    fn pattern_might_contain(bloom: &BloomFilter, pattern: &[u8]) -> bool {
        if pattern.len() <= 4 {
            bloom.may_contain(pattern)
        } else {
            // For longer patterns, check all 4-byte windows
            pattern.windows(4).any(|window| bloom.may_contain(window))
        }
    }

    /// Returns block indices that might contain `pattern` based on per-block bloom filters.
    ///
    /// This checks each block's bloom filter and only returns indices of blocks
    /// that might contain the pattern. Each returned block must still be verified
    /// with `CompressedBlock::verify_contains()`.
    ///
    /// # Parameters
    ///
    /// - `pattern`: Byte sequence to test against each block bloom filter.
    ///
    /// # Returns
    ///
    /// A vector of candidate block indices in stream order.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// // let indices = index.candidate_blocks(b"error");
    /// ```
    #[must_use]
    pub fn candidate_blocks(&self, pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() {
            return (0..self.blocks.len()).collect();
        }

        self.blocks
            .iter()
            .enumerate()
            .filter(|(_, bwb)| Self::pattern_might_contain(&bwb.bloom, pattern))
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Returns an iterator over candidate blocks without allocation.
    ///
    /// # Parameters
    ///
    /// - `pattern`: Byte sequence to test against each block bloom filter.
    ///
    /// # Returns
    ///
    /// An iterator of block indices whose bloom filters may contain `pattern`.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// // for block_idx in index.candidate_blocks_iter(b"error") { ... }
    /// ```
    pub fn candidate_blocks_iter<'a>(
        &'a self,
        pattern: &'a [u8],
    ) -> impl Iterator<Item = usize> + 'a {
        self.blocks
            .iter()
            .enumerate()
            .filter(move |(_, bwb)| Self::pattern_might_contain(&bwb.bloom, pattern))
            .map(|(idx, _)| idx)
    }

    /// Returns a block by index.
    ///
    /// # Parameters
    ///
    /// - `idx`: Zero-based block index returned by a candidate query.
    ///
    /// # Returns
    ///
    /// `Some(&CompressedBlock)` when the index exists, otherwise `None`.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// // if let Some(block) = index.get_block(0) { ... }
    /// ```
    #[must_use]
    pub fn get_block(&self, idx: usize) -> Option<&CompressedBlock> {
        self.blocks.get(idx).map(|bwb| &bwb.block)
    }

    /// Returns the number of indexed blocks.
    ///
    /// # Returns
    ///
    /// The total number of blocks stored in this index.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// // println!("Total blocks: {}", index.block_count());
    /// ```
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the compression format used to build this index.
    ///
    /// # Returns
    ///
    /// The [`CompressionFormat`] supplied to the builder.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// // assert_eq!(index.format(), CompressionFormat::Lz4);
    /// ```
    #[must_use]
    pub fn format(&self) -> CompressionFormat {
        self.format
    }

    /// Get aggregate bloom filter statistics.
    ///
    /// Returns `None` if the index contains no blocks.
    ///
    /// # Returns
    ///
    /// Aggregate bloom-filter statistics across all indexed blocks, or `None`
    /// when the index is empty.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// // if let Some(stats) = index.bloom_stats() { println!("{stats:?}"); }
    /// ```
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn bloom_stats(&self) -> Option<BloomStats> {
        let num_blocks = self.blocks.len();
        if num_blocks == 0 {
            return None;
        }
        let total_bits: usize = self.blocks.iter().map(|bwb| bwb.bloom.num_bits()).sum();
        let total_hashes: u32 = self
            .blocks
            .iter()
            .map(|bwb| bwb.bloom.num_hashes())
            .sum::<u32>()
            / u32::try_from(num_blocks).unwrap_or(u32::MAX);
        let avg_fill: f64 = self
            .blocks
            .iter()
            .map(|bwb| bwb.bloom.fill_ratio())
            .sum::<f64>()
            / num_blocks as f64;
        let avg_fpr: f64 = self
            .blocks
            .iter()
            .map(|bwb| bwb.bloom.estimated_fpr())
            .sum::<f64>()
            / num_blocks as f64;

        Some(BloomStats {
            num_bits: total_bits,
            num_hashes: total_hashes,
            fill_ratio: avg_fill,
            estimated_fpr: avg_fpr,
        })
    }

    /// Estimate false positive rate for given number of items per block.
    ///
    /// # Parameters
    ///
    /// - `num_items`: Estimated number of inserted items per block.
    ///
    /// # Returns
    ///
    /// An estimated false-positive rate for a representative block bloom
    /// filter, or `0.0` when the index is empty.
    ///
    /// # Precision
    /// Uses `f64` for calculations.
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
    pub fn estimated_fpr(&self, num_items: usize) -> f64 {
        if self.blocks.is_empty() {
            return 0.0;
        }
        // Estimate based on average block bloom filter
        let k = f64::from(self.blocks[0].bloom.num_hashes());
        let m = self.blocks[0].bloom.num_bits() as f64;
        let n = num_items as f64;
        let pow_hashes = i32::try_from(self.blocks[0].bloom.num_hashes()).unwrap_or(i32::MAX);
        (1.0 - (-k * n / m).exp()).powi(pow_hashes)
    }
}

/// Aggregate bloom-filter statistics for an index.
#[derive(Debug, Clone, Copy)]
pub struct BloomStats {
    /// Number of bits in filter.
    pub num_bits: usize,
    /// Number of hash functions.
    pub num_hashes: u32,
    /// Current fill ratio (0.0 to 1.0).
    pub fill_ratio: f64,
    /// Estimated false positive rate.
    pub estimated_fpr: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bloom::BloomFilter;

    #[test]
    fn test_pattern_might_contain_false_negative_limitation() {
        let mut bloom = BloomFilter::new(100, 0.01);

        // A pattern spanning blocks might only have its parts inserted.
        // E.g., block 1 has "AB", block 2 has "CD".
        bloom.insert(b"AB");
        bloom.insert(b"CD");

        // The query pattern is "ABCD" (length 4).
        // Since "ABCD" wasn't inserted as a 4-byte window, `may_contain` returns false.
        // This proves the documented false negative risk.
        assert!(!CompressedIndex::pattern_might_contain(&bloom, b"ABCD"));
    }
}
