#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use ziftsieve::{CompressedBlock, CompressedIndexBuilder, CompressionFormat};

proptest! {
    // We only test with up to 10KB chunks to keep the test fast, but it tests
    // arbitrary bytes, covering many weird edge cases and invalid formats.
    #[test]
    fn test_property_no_panics_lz4(data in prop::collection::vec(any::<u8>(), 0..10_000)) {
        let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
        let result = builder.build_from_bytes(&data);
        match result {
            Ok(index) => {
                // If by some chance random bytes parse successfully as LZ4 blocks, we assert format is correct
                assert_eq!(index.format(), CompressionFormat::Lz4);
            }
            Err(e) => {
                // Expected failures are parse/validation related
                let e_str = e.to_string();
                assert!(e_str.contains("invalid") || e_str.contains("too many") || e_str.contains("truncated") || e_str.contains("exceeds"));
            }
        }
    }

    #[test]
    fn test_property_block_verify_contains(pattern in prop::collection::vec(any::<u8>(), 0..100)) {
        let block = CompressedBlock::new(0, 100);
        let result = block.verify_contains(&pattern);
        if pattern.is_empty() {
            assert!(result);
        } else {
            assert!(!result); // empty literals, so it should not contain non-empty patterns
        }
    }

    #[test]
    fn test_property_block_literal_density(compressed_len in 0..1_000_000_u32) {
        let block = CompressedBlock::new(0, compressed_len);
        let density = block.literal_density();
        assert!(density >= 0.0 && density <= 1.0);
    }
}
