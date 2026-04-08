//! Builders for constructing compressed indexes.

use crate::bloom::BloomFilter;
use crate::extract;
use crate::index::BlockWithBloom;
use crate::{CompressedBlock, CompressedIndex, CompressionFormat, ZiftError};

/// Builder for [`CompressedIndex`] with configurable bloom-filter sizing.
#[derive(Debug, Clone)]
pub struct CompressedIndexBuilder {
    pub(crate) format: CompressionFormat,
    pub(crate) expected_items: Option<usize>,
    pub(crate) false_positive_rate: Option<f64>,
    pub(crate) num_bits: Option<usize>,
    pub(crate) num_hashes: Option<u32>,
}

impl CompressedIndexBuilder {
    /// Creates a builder for a specific compression format.
    ///
    /// # Parameters
    ///
    /// - `format`: Compression format to parse when building the index.
    ///
    /// # Returns
    ///
    /// A new builder with default sizing behavior.
    #[must_use]
    pub fn new(format: CompressionFormat) -> Self {
        Self {
            format,
            expected_items: None,
            false_positive_rate: None,
            num_bits: None,
            num_hashes: None,
        }
    }

    /// Sets the expected item count used for automatic bloom-filter sizing.
    #[must_use]
    pub fn expected_items(mut self, n: usize) -> Self {
        self.expected_items = Some(n);
        self
    }

    /// Sets the target false-positive rate for automatically sized filters.
    #[must_use]
    pub fn false_positive_rate(mut self, p: f64) -> Self {
        self.false_positive_rate = Some(p);
        self
    }

    /// Overrides automatic sizing with an explicit bit count.
    #[must_use]
    pub fn bloom_bits(mut self, bits: usize) -> Self {
        self.num_bits = Some(bits);
        self
    }

    /// Overrides automatic sizing with an explicit hash count.
    #[must_use]
    pub fn bloom_hashes(mut self, hashes: u32) -> Self {
        self.num_hashes = Some(hashes);
        self
    }

    /// Build index from compressed bytes with per-block bloom filters.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{CompressedIndexBuilder, CompressionFormat};
    /// let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    /// // let index = builder.build_from_bytes(&compressed_data).unwrap();
    /// ```
    ///
    /// # Errors
    /// Returns `ZiftError` if parsing fails.
    pub fn build_from_bytes(self, data: &[u8]) -> Result<CompressedIndex, ZiftError> {
        let blocks = extract::extract_from_bytes(self.format, data)?;
        let num_blocks = blocks.len().max(1);
        let blocks_with_bloom: Vec<BlockWithBloom> = blocks
            .into_iter()
            .map(|block| self.build_block_with_bloom(block, num_blocks))
            .collect();

        Ok(CompressedIndex {
            format: self.format,
            blocks: blocks_with_bloom,
        })
    }

    fn build_block_with_bloom(&self, block: CompressedBlock, num_blocks: usize) -> BlockWithBloom {
        let literal_count = block.literals.len();
        let mut bloom = if let (Some(bits), Some(hashes)) = (self.num_bits, self.num_hashes) {
            BloomFilter::with_params(bits, hashes)
        } else {
            let items = self
                .expected_items
                .map_or(literal_count.max(16), |e| e / num_blocks);
            let fpr = self.false_positive_rate.unwrap_or(0.01);
            BloomFilter::new(items.max(16), fpr)
        };

        for window in block.literals.windows(4) {
            bloom.insert(window);
        }
        for window in block.literals.windows(3) {
            bloom.insert(window);
        }
        for window in block.literals.windows(2) {
            bloom.insert(window);
        }
        for &byte in &block.literals {
            bloom.insert(&[byte]);
        }

        BlockWithBloom { block, bloom }
    }
}

/// Incremental builder for indexing compressed data larger than memory.
pub struct StreamingIndexBuilder {
    format: CompressionFormat,
    blocks: Vec<BlockWithBloom>,
    expected_items: Option<usize>,
    false_positive_rate: Option<f64>,
    num_bits: Option<usize>,
    num_hashes: Option<u32>,
}

impl StreamingIndexBuilder {
    /// Creates a streaming builder for the specified compression format.
    #[must_use]
    pub fn new(format: CompressionFormat) -> Self {
        Self {
            format,
            blocks: Vec::new(),
            expected_items: None,
            false_positive_rate: None,
            num_bits: None,
            num_hashes: None,
        }
    }

    /// Sets the expected item count for automatic bloom-filter sizing.
    #[must_use]
    pub fn expected_items(mut self, n: usize) -> Self {
        self.expected_items = Some(n);
        self
    }

    /// Process a chunk of compressed data.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{StreamingIndexBuilder, CompressionFormat};
    /// let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    /// // builder.process_chunk(&chunk).unwrap();
    /// ```
    ///
    /// # Errors
    /// Returns `ZiftError` if parsing fails.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), ZiftError> {
        let new_blocks = extract::extract_from_bytes(self.format, chunk)?;
        for block in new_blocks {
            let bwb = self.build_block_with_bloom(block);
            self.blocks.push(bwb);
        }
        Ok(())
    }

    fn build_block_with_bloom(&self, block: CompressedBlock) -> BlockWithBloom {
        let literal_count = block.literals.len();
        let mut bloom = if let (Some(bits), Some(hashes)) = (self.num_bits, self.num_hashes) {
            BloomFilter::with_params(bits, hashes)
        } else {
            let items = self.expected_items.unwrap_or(literal_count.max(16));
            let fpr = self.false_positive_rate.unwrap_or(0.01);
            BloomFilter::new(items.max(16), fpr)
        };

        for window in block.literals.windows(4) {
            bloom.insert(window);
        }
        for window in block.literals.windows(3) {
            bloom.insert(window);
        }
        for window in block.literals.windows(2) {
            bloom.insert(window);
        }
        for &byte in &block.literals {
            bloom.insert(&[byte]);
        }

        BlockWithBloom { block, bloom }
    }

    /// Finalize and build the index.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::{StreamingIndexBuilder, CompressionFormat};
    /// let builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    /// let index = builder.finalize().unwrap();
    /// ```
    ///
    /// # Errors
    /// Currently always returns `Ok`.
    pub fn finalize(self) -> Result<CompressedIndex, ZiftError> {
        Ok(CompressedIndex {
            format: self.format,
            blocks: self.blocks,
        })
    }
}
