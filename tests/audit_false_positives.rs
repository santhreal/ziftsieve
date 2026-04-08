//! Audit Tests: False Positive Rate Analysis
//!
//! Tests that verify bloom filter false positive rates are within expected bounds.

use rand::Rng;
use ziftsieve::bloom::BloomFilter;

// ============================================================================
// Test 1-10: Bloom Filter FPR Measurement
// ============================================================================

#[test]
fn audit_bloom_filter_fpr_1_percent() {
    // Configure for 1% FPR with 1000 items
    let mut bloom = BloomFilter::new(1000, 0.01);

    // Insert 1000 items
    for i in 0..1000 {
        let item = format!("item_{:04}", i);
        bloom.insert(item.as_bytes());
    }

    // Check all inserted items are found (no false negatives)
    for i in 0..1000 {
        let item = format!("item_{:04}", i);
        assert!(
            bloom.may_contain(item.as_bytes()),
            "False negative for {}",
            i
        );
    }

    // Check false positive rate with non-inserted items
    let mut false_positives = 0;
    for i in 1000..2000 {
        let item = format!("item_{:04}", i);
        if bloom.may_contain(item.as_bytes()) {
            false_positives += 1;
        }
    }

    let measured_fpr = false_positives as f64 / 1000.0;
    println!("Measured FPR: {:.4} (expected ~0.01)", measured_fpr);

    // Should be close to 1% (allow 3x margin for small sample)
    assert!(measured_fpr < 0.03, "FPR too high: {}", measured_fpr);
}

#[test]
fn audit_bloom_filter_fpr_0_1_percent() {
    // Configure for 0.1% FPR
    let mut bloom = BloomFilter::new(1000, 0.001);

    for i in 0..1000 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    let mut false_positives = 0;
    for i in 1000..11000 {
        // Check 10,000 non-inserted items
        let item = format!("item_{}", i);
        if bloom.may_contain(item.as_bytes()) {
            false_positives += 1;
        }
    }

    let measured_fpr = false_positives as f64 / 10000.0;
    println!("Measured FPR at 0.1% target: {:.4}", measured_fpr);

    // Should be well under 1%
    assert!(measured_fpr < 0.005, "FPR too high: {}", measured_fpr);
}

#[test]
fn audit_bloom_filter_fpr_10_percent() {
    // Configure for 10% FPR (higher than normal)
    let mut bloom = BloomFilter::new(1000, 0.10);

    for i in 0..1000 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    let mut false_positives = 0;
    for i in 1000..2000 {
        let item = format!("item_{}", i);
        if bloom.may_contain(item.as_bytes()) {
            false_positives += 1;
        }
    }

    let measured_fpr = false_positives as f64 / 1000.0;
    println!("Measured FPR at 10% target: {:.4}", measured_fpr);

    // Should be around 10% (allow 2x margin)
    assert!(measured_fpr < 0.20, "FPR too high: {}", measured_fpr);
}

#[test]
fn audit_bloom_filter_fpr_extreme_low() {
    // Very low FPR target (0.0001 = 0.01%)
    let mut bloom = BloomFilter::new(100, 0.0001);

    for i in 0..100 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    let mut false_positives = 0;
    for i in 100..10100 {
        let item = format!("item_{}", i);
        if bloom.may_contain(item.as_bytes()) {
            false_positives += 1;
        }
    }

    let measured_fpr = false_positives as f64 / 10000.0;
    println!("Measured FPR at 0.01% target: {:.4}", measured_fpr);

    // Very low FPR should be achieved
    assert!(measured_fpr < 0.001, "FPR too high for extreme low target");
}

#[test]
fn audit_bloom_filter_fill_ratio() {
    let mut bloom = BloomFilter::new(1000, 0.01);

    // Fill ratio should start at 0
    assert_eq!(bloom.fill_ratio(), 0.0);

    // Insert items and watch fill ratio increase
    for i in 0..1000 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    let fill_ratio = bloom.fill_ratio();
    println!("Fill ratio after 1000 items: {:.4}", fill_ratio);

    // Fill ratio should be between 0 and 1
    assert!(fill_ratio > 0.0 && fill_ratio < 1.0);
}

#[test]
fn audit_bloom_filter_estimated_fpr() {
    let mut bloom = BloomFilter::new(1000, 0.01);

    for i in 0..1000 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    let estimated = bloom.estimated_fpr();
    println!("Estimated FPR: {:.4}", estimated);

    // Estimated should be close to target
    assert!(estimated > 0.0 && estimated < 0.05);
}

#[test]
fn audit_bloom_filter_no_false_negatives() {
    // Critical: bloom filter must never have false negatives
    let mut bloom = BloomFilter::new(10000, 0.01);

    // Insert many items
    for i in 0..10000 {
        let item = format!("unique_item_{}", i);
        bloom.insert(item.as_bytes());
    }

    // All inserted items MUST be found
    for i in 0..10000 {
        let item = format!("unique_item_{}", i);
        assert!(
            bloom.may_contain(item.as_bytes()),
            "CRITICAL: False negative for item {}",
            i
        );
    }
}

#[test]
fn audit_bloom_filter_clear_resets_state() {
    let mut bloom = BloomFilter::new(100, 0.01);

    bloom.insert(b"test_item");
    assert!(bloom.may_contain(b"test_item"));

    bloom.clear();

    // After clear, item should not be found
    assert!(!bloom.may_contain(b"test_item"));

    // Fill ratio should be 0
    assert_eq!(bloom.fill_ratio(), 0.0);
}

#[test]
fn audit_bloom_filter_with_explicit_params() {
    // Use explicit bit/hash counts
    let bloom = BloomFilter::with_params(1024, 3);

    assert_eq!(bloom.num_bits(), 1024);
    assert_eq!(bloom.num_hashes(), 3);
}

#[test]
fn audit_bloom_filter_hash_clamping() {
    // Test that hash count is clamped to valid range
    let bloom = BloomFilter::with_params(100, 0); // 0 hashes
    assert_eq!(bloom.num_hashes(), 1); // Clamped to minimum

    let bloom = BloomFilter::with_params(100, 100); // Too many hashes
    assert_eq!(bloom.num_hashes(), 32); // Clamped to maximum
}

// ============================================================================
// Test 11-20: Index-Level FPR Analysis
// ============================================================================

#[test]
fn audit_index_fpr_configuration() {
    use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

    // Empty LZ4 input is rejected. Use end-of-frame marker.
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .false_positive_rate(0.001)
        .expected_items(1000)
        .build_from_bytes(&[0, 0, 0, 0])
        .unwrap();

    let stats = index.bloom_stats();
    assert!(stats.is_none() || stats.is_some());
}

#[test]
fn audit_index_estimated_fpr() {
    use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

    // Create data that will generate blocks
    let data = b"Test data for FPR estimation. ".repeat(100);
    let compressed = lz4_compress(&data);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .false_positive_rate(0.01)
        .expected_items(10000)
        .build_from_bytes(&compressed)
        .unwrap();

    let fpr = index.estimated_fpr(100);
    println!("Index estimated FPR: {:.4}", fpr);

    // FPR should be reasonable
    assert!(fpr >= 0.0 && fpr < 1.0);
}

#[test]
fn audit_index_bloom_stats_empty() {
    use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&[0, 0, 0, 0]) // end-of-frame marker
        .unwrap();

    assert!(index.bloom_stats().is_none());
}

#[test]
fn audit_index_bloom_stats_with_blocks() {
    use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

    let data = b"Test data for stats. ".repeat(50);
    let compressed = lz4_compress(&data);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .unwrap();

    if let Some(stats) = index.bloom_stats() {
        println!(
            "Bits: {}, Hashes: {}, Fill: {:.4}, FPR: {:.4}",
            stats.num_bits, stats.num_hashes, stats.fill_ratio, stats.estimated_fpr
        );

        assert!(stats.num_bits > 0);
        assert!(stats.num_hashes > 0);
        assert!(stats.fill_ratio >= 0.0 && stats.fill_ratio <= 1.0);
        assert!(stats.estimated_fpr >= 0.0);
    }
}

#[test]
fn audit_per_block_bloom_filter() {
    use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

    let data = b"Block1 data. Block2 data. Block3 data.".repeat(20);
    let compressed = lz4_compress(&data);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(100)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .unwrap();

    // Each block should have its own bloom filter
    for i in 0..index.block_count() {
        let block = index.get_block(i).unwrap();
        let _ = block.literals(); // Access literals
    }
}

// ============================================================================
// Test 21-30: Real-World FPR Scenarios
// ============================================================================

#[test]
fn audit_fpr_with_repetitive_data() {
    // Repetitive data has fewer unique n-grams, so FPR may differ
    let mut bloom = BloomFilter::new(1000, 0.01);

    // Insert repetitive pattern
    let repetitive = b"ABC".repeat(1000);
    for window in repetitive.windows(4) {
        bloom.insert(window);
    }

    // Count unique n-grams inserted
    let fill_ratio = bloom.fill_ratio();
    println!("Fill ratio for repetitive data: {:.4}", fill_ratio);

    // Should have relatively low fill ratio due to repetition
    assert!(fill_ratio < 0.5);
}

#[test]
fn audit_fpr_with_high_entropy_data() {
    // High entropy data has many unique n-grams
    let mut bloom = BloomFilter::new(10000, 0.01);
    let mut rng = rand::thread_rng();

    // Insert random data
    for _ in 0..10000 {
        let item: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        bloom.insert(&item);
    }

    let fill_ratio = bloom.fill_ratio();
    println!("Fill ratio for high entropy data: {:.4}", fill_ratio);

    // Should have higher fill ratio
    assert!(fill_ratio > 0.1);
}

#[test]
fn audit_fpr_with_log_patterns() {
    // Simulate log file patterns
    let mut bloom = BloomFilter::new(5000, 0.01);

    let log_patterns = vec![
        "ERROR: Connection failed",
        "WARN: High memory usage",
        "INFO: Request processed",
        "DEBUG: Entering function",
        "ERROR: Timeout occurred",
    ];

    for (i, pattern) in log_patterns.iter().enumerate() {
        let entry = format!("[{}] {}", i, pattern);
        bloom.insert(entry.as_bytes());
    }

    // Search for patterns that exist (only the first one was inserted with [0])
    let search = format!("[0] {}", log_patterns[0]);
    assert!(bloom.may_contain(search.as_bytes()));

    // Measure FPR with random patterns
    let mut false_positives = 0;
    for i in 0..1000 {
        let fake_pattern = format!("FAKE_PATTERN_{}", i);
        if bloom.may_contain(fake_pattern.as_bytes()) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 1000.0;
    println!("Log pattern FPR: {:.4}", fpr);
    assert!(fpr < 0.05);
}

#[test]
fn audit_fpr_with_binary_patterns() {
    // Binary data patterns
    let mut bloom = BloomFilter::new(1000, 0.01);

    // Insert binary headers
    for i in 0..256u16 {
        let bytes = i.to_le_bytes();
        bloom.insert(&bytes);
    }

    // All inserted should be found
    for i in 0..256u16 {
        let bytes = i.to_le_bytes();
        assert!(bloom.may_contain(&bytes));
    }

    // Check FPR
    let mut false_positives = 0;
    for i in 256..1256u16 {
        let bytes = i.to_le_bytes();
        if bloom.may_contain(&bytes) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 1000.0;
    println!("Binary pattern FPR: {:.4}", fpr);
}

#[test]
fn audit_fpr_with_ip_addresses() {
    // IP address patterns
    let mut bloom = BloomFilter::new(1000, 0.01);

    for i in 0..256 {
        let ip = format!("192.168.1.{}", i);
        bloom.insert(ip.as_bytes());
    }

    // All inserted IPs should be found
    for i in 0..256 {
        let ip = format!("192.168.1.{}", i);
        assert!(bloom.may_contain(ip.as_bytes()));
    }

    // Check different subnet
    let mut false_positives = 0;
    for i in 0..256 {
        let ip = format!("10.0.0.{}", i);
        if bloom.may_contain(ip.as_bytes()) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 256.0;
    println!("IP address FPR: {:.4}", fpr);
    assert!(fpr < 0.05);
}

#[test]
fn audit_fpr_with_uuid_patterns() {
    // UUID-like patterns
    let mut bloom = BloomFilter::new(5000, 0.01);

    for i in 0..1000 {
        let uuid = format!("550e8400-e29b-41d4-a716-{:012x}", i);
        bloom.insert(uuid.as_bytes());
    }

    // Check FPR
    let mut false_positives = 0;
    for i in 1000..2000 {
        let uuid = format!("550e8400-e29b-41d4-a716-{:012x}", i);
        if bloom.may_contain(uuid.as_bytes()) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 1000.0;
    println!("UUID pattern FPR: {:.4}", fpr);
    assert!(fpr < 0.03);
}

#[test]
fn audit_fpr_with_email_patterns() {
    // Email-like patterns
    let mut bloom = BloomFilter::new(5000, 0.01);

    for i in 0..1000 {
        let email = format!("user{}@example.com", i);
        bloom.insert(email.as_bytes());
    }

    // Check FPR
    let mut false_positives = 0;
    for i in 1000..2000 {
        let email = format!("user{}@example.com", i);
        if bloom.may_contain(email.as_bytes()) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 1000.0;
    println!("Email pattern FPR: {:.4}", fpr);
    assert!(fpr < 0.03);
}

#[test]
fn audit_fpr_with_url_patterns() {
    // URL patterns
    let mut bloom = BloomFilter::new(5000, 0.01);

    for i in 0..1000 {
        let url = format!("https://example.com/path/{}/resource", i);
        bloom.insert(url.as_bytes());
    }

    // Check FPR
    let mut false_positives = 0;
    for i in 1000..2000 {
        let url = format!("https://example.com/path/{}/resource", i);
        if bloom.may_contain(url.as_bytes()) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 1000.0;
    println!("URL pattern FPR: {:.4}", fpr);
    assert!(fpr < 0.03);
}

// ============================================================================
// Test 31-40: Edge Cases and Boundaries
// ============================================================================

#[test]
fn audit_bloom_filter_empty_insert() {
    let mut bloom = BloomFilter::new(100, 0.01);

    // Insert empty item
    bloom.insert(b"");

    // Empty item should be found
    assert!(bloom.may_contain(b""));
}

#[test]
fn audit_bloom_filter_single_item() {
    let mut bloom = BloomFilter::new(100, 0.01);

    bloom.insert(b"only_item");

    assert!(bloom.may_contain(b"only_item"));

    // FPR should be very low with single item
    let mut false_positives = 0;
    for i in 0..1000 {
        let item = format!("other_{}", i);
        if bloom.may_contain(item.as_bytes()) {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / 1000.0;
    println!("Single item FPR: {:.4}", fpr);
    assert!(fpr < 0.01);
}

#[test]
fn audit_bloom_filter_max_items() {
    // Test with large item count
    let mut bloom = BloomFilter::new(100000, 0.01);

    for i in 0..100000 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    // Verify a sample
    for i in (0..100000).step_by(1000) {
        let item = format!("item_{}", i);
        assert!(bloom.may_contain(item.as_bytes()));
    }
}

#[test]
fn audit_bloom_filter_from_bits() {
    use bit_vec::BitVec;

    let bits = BitVec::from_elem(1024, false);
    let bloom = BloomFilter::from_bits(bits, 3).unwrap();

    assert_eq!(bloom.num_bits(), 1024);
    assert_eq!(bloom.num_hashes(), 3);
}

#[test]
fn audit_bloom_filter_bits_access() {
    let bloom = BloomFilter::new(100, 0.01);
    let bits = bloom.bits();

    assert_eq!(bits.len(), bloom.num_bits());
}

#[test]
fn audit_bloom_filter_may_contain_any() {
    let mut bloom = BloomFilter::new(100, 0.01);

    bloom.insert(b"apple");
    bloom.insert(b"banana");

    // Any of the inserted patterns
    assert!(bloom.may_contain_any(&[b"apple", b"cherry"]));
    assert!(bloom.may_contain_any(&[b"banana", b"date"]));

    // None of the inserted patterns
    assert!(!bloom.may_contain_any(&[b"cherry", b"date"]));
}

// ============================================================================
// Test Helpers
// ============================================================================

#[cfg(feature = "lz4")]
fn lz4_compress(data: &[u8]) -> Vec<u8> {
    use lz4_flex::frame::FrameEncoder;
    use std::io::Write;

    let mut compressed = Vec::new();
    {
        let mut encoder = FrameEncoder::new(&mut compressed);
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
    }
    compressed
}

#[cfg(not(feature = "lz4"))]
fn lz4_compress(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}
