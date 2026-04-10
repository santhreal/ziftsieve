//! Bloom filter implementation for fast set membership testing.

use bit_vec::BitVec;

use super::hash::{hash_pair, nth_hash};
use crate::ZiftError;

/// Maximum number of bits allowed in a bloom filter to prevent OOM.
const MAX_BLOOM_BITS: usize = 1 << 30;

/// Bloom filter for approximate membership checks over byte slices.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub(crate) bits: BitVec,
    pub(crate) num_hashes: u32,
    pub(crate) num_bits: usize,
}

impl BloomFilter {
    /// Create a new bloom filter with desired capacity and false positive rate.
    ///
    /// # Arguments
    /// * `expected_items` - Expected number of items to insert (clamped to >= 1)
    /// * `false_positive_rate` - Desired false positive rate, e.g., 0.01 for 1% (clamped to 0.0001-0.9999)
    ///
    /// # Formula
    /// * `m = -n × ln(p) / (ln(2)²)`
    /// * `k = m/n × ln(2)`
    ///
    /// # Implementation Notes
    /// The calculations use `f64` for precision then cast to integer sizes.
    /// This is intentional - the formulas produce positive values that are
    /// clamped to reasonable bounds after ceiling/rounding.
    ///
    /// # Precision
    /// Uses `f64` for intermediate calculations. For filters with > 2^52 bits
    /// or > 2^53 expected items, precision loss may occur.
    ///
    /// # Parameters
    ///
    /// - `expected_items`: Expected number of inserted items. Values below `1`
    ///   are clamped to `1`.
    /// - `false_positive_rate`: Desired false-positive rate. Values are clamped
    ///   to the range `0.0001..=0.9999`.
    ///
    /// # Returns
    ///
    /// A bloom filter sized from the provided workload estimate.
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        // Clamp inputs to valid ranges instead of panicking
        let n = expected_items.max(1) as f64;
        let p = false_positive_rate.clamp(0.0001, 0.9999);

        // Optimal number of bits: m = -n * ln(p) / ln(2)^2
        let m_f64 = (-n * p.ln() / (2.0_f64.ln().powi(2))).ceil();
        let m = (if m_f64 > MAX_BLOOM_BITS as f64 {
            MAX_BLOOM_BITS
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let val = m_f64 as usize;
            val
        })
        .clamp(64, MAX_BLOOM_BITS); // Clamp to safe range

        // Optimal number of hash functions: k = m/n * ln(2)
        let k_f64 = ((m as f64 / n) * 2.0_f64.ln()).round();
        let k = (if k_f64 > f64::from(u32::MAX) {
            u32::MAX
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let val = k_f64 as u32;
            val
        })
        .clamp(1, 32); // Clamp to 1-32

        Self {
            bits: BitVec::from_elem(m, false),
            num_hashes: k,
            num_bits: m,
        }
    }

    /// Creates a bloom filter with explicit bit and hash counts.
    ///
    /// # Parameters
    ///
    /// - `num_bits`: Number of bits to allocate in the backing bit vector.
    /// - `num_hashes`: Number of hash rounds to use. Values are clamped to
    ///   `1..=32`.
    ///
    /// # Returns
    ///
    /// A bloom filter with the requested parameters.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::bloom::BloomFilter;
    /// let bf = BloomFilter::with_params(1024, 3);
    /// ```
    #[must_use]
    pub fn with_params(num_bits: usize, num_hashes: u32) -> Self {
        let num_bits = num_bits.clamp(1, MAX_BLOOM_BITS);
        Self {
            bits: BitVec::from_elem(num_bits, false),
            num_hashes: num_hashes.clamp(1, 32),
            num_bits,
        }
    }

    /// Inserts an item into the bloom filter.
    ///
    /// # Parameters
    ///
    /// - `item`: Byte slice to add to the set.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::bloom::BloomFilter;
    /// let mut bf = BloomFilter::new(100, 0.01);
    /// bf.insert(b"test");
    /// ```
    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = hash_pair(item);

        for i in 0..self.num_hashes {
            let idx = nth_hash(h1, h2, i, self.num_bits);
            self.bits.set(idx, true);
        }
    }

    /// Check if an item might be in the set.
    ///
    /// Returns:
    /// - `false` if definitely not in set
    /// - `true` if possibly in set (may be false positive)
    ///
    /// # Parameters
    ///
    /// - `item`: Byte slice to query.
    ///
    /// # Returns
    ///
    /// `false` when the item is definitely absent, or `true` when it may be
    /// present.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::bloom::BloomFilter;
    /// let mut bf = BloomFilter::new(100, 0.01);
    /// bf.insert(b"test");
    /// assert!(bf.may_contain(b"test"));
    /// assert!(!bf.may_contain(b"missing")); // likely false
    /// ```
    #[must_use]
    pub fn may_contain(&self, item: &[u8]) -> bool {
        let (h1, h2) = hash_pair(item);

        for i in 0..self.num_hashes {
            let idx = nth_hash(h1, h2, i, self.num_bits);
            if !self.bits.get(idx).unwrap_or(false) {
                return false;
            }
        }
        true
    }

    /// Check if any pattern in the list might be in the set.
    ///
    /// Short-circuits on first match.
    ///
    /// # Parameters
    ///
    /// - `patterns`: Slice of byte-slice patterns to test.
    ///
    /// # Returns
    ///
    /// `true` if any pattern may be present, otherwise `false`.
    #[must_use]
    pub fn may_contain_any(&self, patterns: &[&[u8]]) -> bool {
        patterns.iter().any(|p| self.may_contain(p))
    }

    /// Clears all bits in the filter.
    pub fn clear(&mut self) {
        self.bits.clear();
        self.bits.grow(self.num_bits, false);
    }

    /// Returns the number of bits in the filter.
    ///
    /// # Returns
    ///
    /// The length of the backing bit vector.
    #[must_use]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Returns the number of hash functions applied per item.
    ///
    /// # Returns
    ///
    /// The hash count used by [`BloomFilter::insert`] and
    /// [`BloomFilter::may_contain`].
    #[must_use]
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Calculate current fill ratio (0.0 to 1.0).
    ///
    /// # Precision
    /// Uses `f64` for calculation. For filters with > 2^52 bits (~4 petabits),
    /// precision loss may occur in the least significant bits.
    ///
    /// # Returns
    ///
    /// The fraction of bits currently set to `1`.
    ///
    /// # Example
    /// ```
    /// use ziftsieve::bloom::BloomFilter;
    /// let bf = BloomFilter::new(100, 0.01);
    /// assert_eq!(bf.fill_ratio(), 0.0);
    /// ```
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fill_ratio(&self) -> f64 {
        let set_bits = self.bits.iter().filter(|b| *b).count();
        set_bits as f64 / self.num_bits as f64
    }

    /// Estimate current false positive rate.
    ///
    /// # Precision
    /// Uses `f64` for calculations. The result is an estimate based on
    /// theoretical bloom filter properties.
    ///
    /// # Returns
    ///
    /// The estimated false-positive rate implied by the current fill ratio.
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
    pub fn estimated_fpr(&self) -> f64 {
        let k = f64::from(self.num_hashes);
        let m = self.num_bits as f64;
        let n = -m / k * (1.0 - self.fill_ratio()).ln();
        // num_hashes is clamped to 1-32 in constructor, so cast to i32 is safe
        let pow_hashes = i32::try_from(self.num_hashes).unwrap_or(i32::MAX);
        (1.0 - (-k * n / m).exp()).powi(pow_hashes)
    }

    /// Returns the raw bit vector for serialization or inspection.
    ///
    /// # Returns
    ///
    /// A shared reference to the backing [`BitVec`].
    #[must_use]
    pub fn bits(&self) -> &BitVec {
        &self.bits
    }

    /// Reconstructs a bloom filter from a raw bit vector.
    ///
    /// # Parameters
    ///
    /// - `bits`: Serialized bit vector to reuse as storage.
    /// - `num_hashes`: Number of hash rounds associated with the serialized
    ///   filter.
    ///
    /// # Returns
    ///
    /// A bloom filter that reuses the supplied bit vector.
    ///
    /// # Errors
    ///
    /// Returns `ZiftError::InvalidData` when `bits` is empty.
    pub fn from_bits(bits: BitVec, num_hashes: u32) -> Result<Self, ZiftError> {
        let num_bits = bits.len();
        if num_bits == 0 {
            return Err(ZiftError::InvalidData {
                offset: 0,
                reason: "BloomFilter requires at least 1 bit. Fix: pass a non-empty bit vector".to_string(),
            });
        }
        Ok(Self {
            bits,
            num_hashes: num_hashes.clamp(1, 32),
            num_bits,
        })
    }
}
