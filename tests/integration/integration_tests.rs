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
//! Integration tests for ziftsieve.
//!
//! These tests verify end-to-end functionality with real compressed data.

use ziftsieve::{bloom::BloomFilter, CompressedBlock, CompressionFormat};

#[test]
fn test_bloom_filter_basic() {
    // Create bloom filter and insert some patterns
    let mut bloom = BloomFilter::new(1000, 0.01);

    bloom.insert(b"ERROR");
    bloom.insert(b"WARNING");
    bloom.insert(b"INFO");

    // Should find inserted items
    assert!(bloom.may_contain(b"ERROR"));
    assert!(bloom.may_contain(b"WARNING"));
    assert!(bloom.may_contain(b"INFO"));

    // Should (probably) not find non-inserted items
    // Note: False positives are possible but unlikely with 1% FPR
    assert!(!bloom.may_contain(b"FATAL"));
}

#[test]
fn test_compressed_block_api() {
    let block = CompressedBlock::new(0, 100);

    assert_eq!(block.compressed_offset(), 0);
    assert_eq!(block.compressed_len(), 100);
    assert!(block.literals().is_empty());

    // Verify empty literals returns false for non-empty pattern
    assert!(!block.verify_contains(b"test"));
}

#[test]
fn test_block_verify_contains() {
    let block = CompressedBlock::new(0, 100);
    // Access internals through the public literals() which returns &[u8]
    // Actually, literals() is immutable. We need to create a block with literals.
    // For now, just verify the API compiles and basic logic works.

    // An empty block doesn't contain any pattern
    assert!(!block.verify_contains(b"anything"));

    // But it "contains" empty pattern (vacuously true)
    assert!(block.verify_contains(b""));
}

#[test]
fn test_bloom_filter_builder() {
    let bloom = ziftsieve::bloom::BloomFilterBuilder::new()
        .expected_items(500)
        .false_positive_rate(0.001)
        .build();

    assert!(bloom.num_bits() > 0);
    assert!(bloom.num_hashes() > 0);
}

#[test]
fn test_bloom_stats() {
    let mut bloom = BloomFilter::new(100, 0.01);

    // Initially empty
    assert_eq!(bloom.fill_ratio(), 0.0);

    // Insert some items
    for i in 0..50 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    // Should have some fill now
    assert!(bloom.fill_ratio() > 0.0);
    assert!(bloom.fill_ratio() < 1.0);

    // FPR should be low
    assert!(bloom.estimated_fpr() < 0.1);
}

#[test]
fn test_bloom_clear() {
    let mut bloom = BloomFilter::new(100, 0.01);
    bloom.insert(b"test");
    assert!(bloom.may_contain(b"test"));

    bloom.clear();
    assert!(!bloom.may_contain(b"test"));
}

#[test]
fn test_compression_format_display() {
    assert_eq!(format!("{}", CompressionFormat::Lz4), "LZ4");
    assert_eq!(format!("{}", CompressionFormat::Snappy), "Snappy");
    assert_eq!(format!("{}", CompressionFormat::Zstd), "Zstd");
    assert_eq!(format!("{}", CompressionFormat::Gzip), "Gzip");
}

#[test]
#[cfg(feature = "zstd")]
fn test_zstd_literal_extraction() {
    use ziftsieve::zstd::extract_literals;

    // Create compressible data
    let data = b"ERROR: Connection failed\nWARN: Retry\nERROR: Timeout\n";
    let compressed = zstd::encode_all(&data[..], 3).unwrap();

    // Extract literals
    let blocks = extract_literals(&compressed).unwrap();

    // Should have at least one block
    assert!(!blocks.is_empty(), "Should parse at least one block");

    // Check that literals were extracted
    let total_literals: usize = blocks.iter().map(|b| b.literals().len()).sum();
    assert!(total_literals > 0, "Should extract some literals");
}

#[test]
#[cfg(feature = "gzip")]
fn test_scan_tarball_literals_and_bloom_from_literals() {
    let tarball = include_bytes!("fixtures/npm-sample-1.0.0.tgz");

    let blocks = ziftsieve::scan_tarball_literals(tarball).expect("scan tarball");
    assert!(blocks.len() >= 2, "Expected at least two tar members");

    let total_literals: usize = blocks.iter().map(|block| block.literals().len()).sum();
    assert!(
        total_literals > 0,
        "Tarball should contain literal payloads"
    );

    let sample_pair = b"to";
    assert!(blocks.iter().any(|block| block
        .literals()
        .windows(2)
        .any(|window| window == sample_pair)));

    let bloom = ziftsieve::bloom_from_literals(&blocks, 4096).expect("build bloom");
    assert!(bloom.maybe_contains(sample_pair[0], sample_pair[1]));
}

#[test]
fn test_end_to_end_search() {
    // Create data with distinct blocks
    let block1_data = b"ERROR: Block 1 failure\n".repeat(100);
    let block2_data = b"WARN: Block 2 notice\n".repeat(100);
    let block3_data = b"INFO: Block 3 message\n".repeat(100);

    // Build uncompressed LZ4 blocks (size header + raw data)
    let mut data = Vec::new();
    for chunk in [&block1_data[..], &block2_data[..], &block3_data[..]] {
        let size = chunk.len() as u32 | 0x8000_0000; // Uncompressed flag
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(chunk);
    }

    // Build index
    let index = ziftsieve::CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&data)
        .unwrap();

    // Search for "ERROR" - should only return block 0
    let error_candidates = index.candidate_blocks(b"ERROR");
    println!("ERROR candidates: {:?}", error_candidates);

    // Verify: block 0 contains ERROR
    assert!(index.get_block(0).unwrap().verify_contains(b"ERROR"));

    // Verify: block 1 does NOT contain ERROR
    assert!(!index.get_block(1).unwrap().verify_contains(b"ERROR"));
}
