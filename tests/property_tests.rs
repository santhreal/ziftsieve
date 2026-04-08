#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    clippy::panic,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    unused_comparisons,
    clippy::ignored_unit_patterns
)]
//! Property-based tests for ziftsieve bloom filter.

use proptest::prelude::*;
use ziftsieve::bloom::BloomFilter;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        ..ProptestConfig::default()
    })]

    /// Bloom filter never has false negatives.
    #[test]
    fn bloom_no_false_negatives(
        items in prop::collection::vec(prop::collection::vec(0u8..=255, 1..20), 1..100)
    ) {
        let mut bloom = BloomFilter::new(items.len().max(10), 0.01);

        // Insert all items
        for item in &items {
            bloom.insert(item);
        }

        // All inserted items should be found (no false negatives)
        for item in &items {
            prop_assert!(bloom.may_contain(item), "False negative detected");
        }
    }
}
