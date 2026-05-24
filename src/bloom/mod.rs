//! Bloom filter implementation for fast set membership testing.
//!
//! # Architecture Note: Cross-Crate Coherence
//!
//! This implementation (`BloomFilter`) is intentionally separate from the specialized
//! `NgramBloom` in `flashsieve`.
//!
//! While both are Bloom filters using FNV-1a hashing, they serve fundamentally
//! different purposes and have divergent performance requirements:
//!
//! 1. **Data Model**: `ziftsieve::BloomFilter` is a general-purpose filter designed
//!    to handle arbitrary length byte slices (`&[u8]`), whereas `flashsieve` is
//!    strictly limited to exactly 2-byte n-grams (`u8`, `u8`).
//! 2. **Flexibility**: `ziftsieve` supports a configurable number of hash functions
//!    (`k` from 1 to 32) and calculates sizes dynamically. `flashsieve` hardcodes
//!    `k=3` and relies on fixed-size optimizations.
//! 3. **Acceleration**: `flashsieve` uses an exact pair table for zero false
//!    positives on 2-byte inputs, an optimization that does not apply to the
//!    variable-length slice inputs required by `ziftsieve`.
//!
//! Merging them would bloat the n-gram specific filter or remove the flexibility
//! needed for general block literal filtering in ziftsieve.
//!
//! The bloom filter is the crate's main prefiltering primitive. It stores
//! fixed-size signatures for literal windows so queries can cheaply reject
//! blocks that definitely do not contain a pattern.
//!
//! The implementation uses:
//! - 64-bit hash functions with double hashing
//! - automatic sizing from expected item counts and false-positive targets
//! - explicit constructors for callers that need stable serialized parameters

mod filter;
mod hash;

pub use filter::BloomFilter;

/// Builder for [`BloomFilter`] with progressive configuration.
#[derive(Debug)]
pub struct BloomFilterBuilder {
    expected_items: Option<usize>,
    false_positive_rate: Option<f64>,
    num_bits: Option<usize>,
    num_hashes: Option<u32>,
}

impl Default for BloomFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomFilterBuilder {
    /// Creates an empty bloom-filter builder.
    ///
    /// # Returns
    ///
    /// A builder with no explicit sizing choices.
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_items: None,
            false_positive_rate: None,
            num_bits: None,
            num_hashes: None,
        }
    }

    /// Sets the expected item count used for automatic sizing.
    ///
    /// # Parameters
    ///
    /// - `n`: Expected number of inserted items.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[must_use]
    pub fn expected_items(mut self, n: usize) -> Self {
        self.expected_items = Some(n);
        self
    }

    /// Sets the desired false-positive rate for automatic sizing.
    ///
    /// # Parameters
    ///
    /// - `p`: Target false-positive rate.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[must_use]
    pub fn false_positive_rate(mut self, p: f64) -> Self {
        self.false_positive_rate = Some(p);
        self
    }

    /// Sets an explicit bit count.
    ///
    /// # Parameters
    ///
    /// - `bits`: Number of bits to allocate.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[must_use]
    pub fn num_bits(mut self, bits: usize) -> Self {
        self.num_bits = Some(bits);
        self
    }

    /// Sets an explicit hash count.
    ///
    /// # Parameters
    ///
    /// - `hashes`: Number of hash rounds to use.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[must_use]
    pub fn num_hashes(mut self, hashes: u32) -> Self {
        self.num_hashes = Some(hashes);
        self
    }

    /// Build bloom filter.
    ///
    /// Uses explicit `num_bits` and `num_hashes` if both are set, otherwise uses
    /// `expected_items` and `false_positive_rate`.
    ///
    /// # Returns
    ///
    /// A configured [`BloomFilter`].
    #[must_use]
    pub fn build(self) -> BloomFilter {
        if let (Some(bits), Some(hashes)) = (self.num_bits, self.num_hashes) {
            BloomFilter::with_params(bits, hashes)
        } else {
            // Default to 1000 items at 1% FPR if not specified
            let items = self.expected_items.unwrap_or(1000);
            let fpr = self.false_positive_rate.unwrap_or(0.01);
            BloomFilter::new(items, fpr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut bf = BloomFilter::new(1000, 0.01);

        bf.insert(b"hello");
        bf.insert(b"world");

        assert!(bf.may_contain(b"hello"));
        assert!(bf.may_contain(b"world"));
        assert!(!bf.may_contain(b"not_inserted"));
    }

    #[test]
    fn test_bloom_filter_no_false_negatives() {
        let mut bf = BloomFilter::new(10000, 0.01);

        // Insert 1000 items
        for i in 0..1000 {
            let item = format!("item_{i}");
            bf.insert(item.as_bytes());
        }

        // All inserted items should be found (no false negatives)
        for i in 0..1000 {
            let item = format!("item_{i}");
            assert!(
                bf.may_contain(item.as_bytes()),
                "False negative for item {i}",
            );
        }
    }

    #[test]
    fn test_hash_distribution() {
        use super::hash::{hash_fnv1a, hash_fnv1a_alt};

        // Hash should distribute across all bits
        let h1 = hash_fnv1a(b"test");
        let h2 = hash_fnv1a_alt(b"test");
        assert_ne!(h1, h2);

        // Different inputs should produce different hashes
        let h1a = hash_fnv1a(b"input_a");
        let h1b = hash_fnv1a(b"input_b");
        assert_ne!(h1a, h1b);
    }

    #[test]
    fn test_builder_pattern() {
        let bf = BloomFilterBuilder::new()
            .expected_items(500)
            .false_positive_rate(0.001)
            .build();

        assert!(bf.num_bits() > 0);
        assert_eq!(bf.num_hashes(), 10); // Should be ~10 for these params
    }

    #[test]
    fn test_clear() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(b"item");
        assert!(bf.may_contain(b"item"));

        bf.clear();
        assert!(!bf.may_contain(b"item"));
    }
}
