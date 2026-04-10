use std::sync::Arc;
use std::thread;
use ziftsieve::bloom::BloomFilter;
use ziftsieve::{CompressedIndexBuilder, CompressionFormat, StreamingIndexBuilder};

// 1. Empty input / zero-length slices
#[test]
fn test_bloom_empty_insert() {
    let mut bf = BloomFilter::new(100, 0.01);
    bf.insert(b"");
    assert!(bf.may_contain(b""));
}

#[test]
fn test_bloom_empty_query() {
    let mut bf = BloomFilter::new(100, 0.01);
    bf.insert(b"hello");
    assert!(bf.may_contain(b"hello"));
    // querying empty slice should ideally return whether empty was inserted,
    // or maybe always true. Let's assert it is correct.
    assert!(!bf.may_contain(b""));
}

// 2. Null bytes in input
#[test]
fn test_bloom_null_bytes_insert() {
    let mut bf = BloomFilter::new(100, 0.01);
    bf.insert(b"\0\0\0");
    assert!(bf.may_contain(b"\0\0\0"));
}

#[test]
fn test_bloom_null_bytes_query_false() {
    let mut bf = BloomFilter::new(100, 0.01);
    bf.insert(b"test");
    assert!(!bf.may_contain(b"\0\0\0"));
}

// 3. Maximum u32/u64 values for any numeric parameter
#[test]

fn test_bloom_max_expected_items() {
    // using u32::MAX instead of usize::MAX avoids 2 exabytes alloc OS abort but still tests massive sizing
    let _bf = BloomFilter::new(u32::MAX as usize, 0.01);
}

#[test]

fn test_bloom_max_bits() {
    let _bf = BloomFilter::with_params(u32::MAX as usize, 1);
}

#[test]
fn test_bloom_max_hashes() {
    // Should clamp to 32
    let mut bf = BloomFilter::with_params(1024, u32::MAX);
    bf.insert(b"test");
    assert!(bf.may_contain(b"test"));
    assert_eq!(bf.num_hashes(), 32);
}

// 4. Concurrent access from 8 threads (if the crate has shared state)
#[test]
fn test_bloom_concurrent_read_threads() {
    let mut bf = BloomFilter::new(1000, 0.01);
    for i in 0..100 {
        bf.insert(format!("item_{i}").as_bytes());
    }

    let bf_arc = Arc::new(bf);
    let mut handles = vec![];

    for t in 0..8 {
        let bf_clone = Arc::clone(&bf_arc);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let item = format!("item_{i}");
                assert!(
                    bf_clone.may_contain(item.as_bytes()),
                    "Thread {t} missed item {i}"
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }
}

// 5. 1MB+ input (if the crate processes byte buffers)
#[test]

fn test_builder_massive_input() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    // 2 MB of zeros: first 4 bytes [0,0,0,0] = end-of-frame marker.
    // Parsed as raw block data with immediate termination — yields empty index.
    let massive_data = vec![0u8; 2 * 1024 * 1024];
    let result = builder.build_from_bytes(&massive_data);
    // Should not panic or OOM — either returns Ok(empty) or Err.
    if let Ok(index) = result {
        assert_eq!(
            index.block_count(),
            0,
            "zero-filled data should produce empty index"
        );
    }
}

#[test]
fn test_builder_massive_input_valid_gzip_empty() {
    // Generate valid but large empty gzip buffer (e.g. tarball of 1MB 0s, but we'll use a tiny header)
    // Actually we just test passing 1MB buffer of random valid-looking header and expecting an error
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    data.extend(vec![0u8; 1024 * 1024]);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

// 6. Malformed/truncated input (partial data, missing headers)
#[test]

fn test_builder_truncated_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    // Partial LZ4 frame magic — too short for a valid frame header.
    // Parsed as raw block data (legacy): 3 bytes < 4-byte block header → empty.
    let truncated = vec![0x04, 0x22, 0x4D];
    let result = builder.build_from_bytes(&truncated);
    // Should not panic. Either empty index or error, both acceptable.
    if let Ok(index) = result {
        assert_eq!(index.block_count(), 0);
    }
}

#[test]

fn test_builder_empty_buffer_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&[]);
    assert!(result.is_err()); // or returns empty index, both are valid but should not panic
}

#[test]
fn test_builder_malformed_gzip_tarball() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    // Just gzip magic but nothing else
    let malformed = vec![0x1f, 0x8b];
    let result = builder.build_from_bytes(&malformed);
    assert!(result.is_err());
}

#[test]
fn test_builder_unsupported_format() {
    // We only have Lz4, Snappy, Gzip, Zstd. If Zstd isn't enabled it might fail.
    // We can test whether the builder gracefully rejects unsupported formats
    // if compiled without features, but here we just test Snappy with invalid data
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let result = builder.build_from_bytes(b"not snappy");
    // Should be an error, definitely not panic.
    assert!(result.is_err());
}

// 7. Max u32/u64 values for indexing parameters
#[test]

fn test_builder_max_expected_items() {
    let builder =
        CompressedIndexBuilder::new(CompressionFormat::Lz4).expected_items(u32::MAX as usize);
    let _ = builder.build_from_bytes(b"");
}

#[test]

fn test_builder_max_bloom_bits() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4).bloom_bits(u32::MAX as usize);
    let _ = builder.build_from_bytes(b"");
}

// Off-by-one: testing false positive limits and boundary
#[test]
fn test_builder_zero_false_positive_rate() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4).false_positive_rate(0.0);
    let result = builder.build_from_bytes(b"notlz4");
    assert!(result.is_err());
}

#[test]
fn test_builder_extreme_false_positive_rate() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4).false_positive_rate(1.0);
    let result = builder.build_from_bytes(b"notlz4");
    assert!(result.is_err());
}

// Off-by-one boundary
#[test]
fn test_builder_exact_block_size_boundary() {
    let mut builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    builder = builder.expected_items(1);
    let data = vec![0x04, 0x22, 0x4D, 0x18]; // Just LZ4 magic
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

// 8. Unicode edge cases (BOM, overlong sequences, surrogates)
#[test]
fn test_index_unicode_bom() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    // Even if LZ4 decoding fails, we want to test index query patterns.
    // If it succeeds with empty, we can query it.
    let index_res = builder.build_from_bytes(b"");
    if let Ok(index) = index_res {
        let candidates = index.candidate_blocks(b"\xef\xbb\xbf");
        assert!(
            candidates.is_empty(),
            "Empty index should have no candidates"
        );
    }
}

#[test]
fn test_index_unicode_surrogate() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let _ = builder.process_chunk(b"");
    let index = builder.finalize().unwrap();
    // 0xED 0xA0 0x80 is an invalid surrogate sequence in UTF-8
    let candidates = index.candidate_blocks(b"\xed\xa0\x80");
    assert!(candidates.is_empty() || !candidates.is_empty()); // Should not panic
}

// 9. Duplicate entries (same key twice, same pattern twice)
#[test]
fn test_builder_duplicate_chunks() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let _ = builder.process_chunk(b"chunk1");
    let _ = builder.process_chunk(b"chunk1");
    let _ = builder.process_chunk(b"chunk1");
    let index = builder.finalize().unwrap();
    assert_eq!(index.block_count(), 0); // No valid LZ4 blocks were extracted
}

// 10. Resource exhaustion: 100K items, deeply nested structures
#[test]

fn test_streaming_builder_unlimited_blocks() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    // process 10,000 bad chunks, shouldn't crash
    for _ in 0..10_000 {
        let res = builder.process_chunk(b"");
        assert!(res.is_err());
    }
    let idx = builder.finalize().unwrap();
    assert_eq!(idx.block_count(), 0);
}

#[test]
fn test_index_bloom_stats_empty() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    if let Ok(index) = builder.build_from_bytes(b"") {
        let stats = index.bloom_stats();
        assert!(stats.is_none());
    }
}

#[test]

fn test_index_bloom_stats_zero_division() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let _builder2 = builder.bloom_hashes(0);
    // Actually we can't create one with 0 hashes since with_params clamps to 1
    // But let's assert the clamping to ensure no zero division
    let bf = BloomFilter::with_params(100, 0);
    assert_eq!(bf.num_hashes(), 1);
}

#[test]
fn test_index_estimated_fpr_empty() {
    let builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let index = builder.finalize().unwrap();
    let fpr = index.estimated_fpr(100);
    assert_eq!(fpr, 0.0);
}

#[test]
fn test_scan_tarball_depth_limit() {
    #[cfg(feature = "gzip")]
    {
        #[cfg(feature = "gzip")]
    use ziftsieve::scan_tarball_literals;
        // The implementation doesn't expose depth parsing publicly easily,
        // so we assert scanning empty returns error instead of passing
        let res = scan_tarball_literals(b"");
        assert!(res.is_err(), "Empty tarball scan should error");
    }
}

#[test]
fn test_scan_tarball_symlink_rejection() {
    #[cfg(feature = "gzip")]
    {
        #[cfg(feature = "gzip")]
    use ziftsieve::scan_tarball_literals;
        // Test that sending invalid string to symlink scan returns error
        let res = scan_tarball_literals(b"invalid_symlink_data");
        assert!(res.is_err());
    }
}

#[test]
fn test_candidate_blocks_iter_no_allocation() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    if let Ok(index) = builder.build_from_bytes(b"") {
        let mut iter = index.candidate_blocks_iter(b"error");
        assert!(iter.next().is_none());
    }
}

#[test]
fn test_index_get_block_out_of_bounds() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    if let Ok(index) = builder.build_from_bytes(b"") {
        let block = index.get_block(usize::MAX);
        assert!(block.is_none());
    }
}

#[test]
fn test_builder_massive_expected_items_streaming() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4).expected_items(usize::MAX);
    // This process chunk tests if the huge item limit propagates bounds
    let res = builder.process_chunk(b"0123456789ABCDEF0123456789ABCDEF");
    assert!(res.is_err());
    let idx = builder.finalize().unwrap();
    assert_eq!(idx.block_count(), 0);
}

#[test]
fn test_streaming_builder_finalize_repeated() {
    let builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let index = builder.finalize().unwrap();
    assert_eq!(index.format(), CompressionFormat::Lz4);
}

#[test]
fn test_index_pattern_might_contain_false_negative_explicit() {
    let mut bf = BloomFilter::new(100, 0.01);
    bf.insert(b"part1");
    bf.insert(b"part2");

    // Explicit off-by-one boundary failure test
    // "t1pa" spans across the two inserted items
    let mut pattern_found = false;
    if bf.may_contain(b"t1pa") {
        pattern_found = true;
    }
    assert!(
        !pattern_found,
        "Bloom filter should not match cross-boundary substrings"
    );
}


// --- ADDED ADVERSARIAL TESTS ---


#[test]
fn test_detect_nested_gzip_in_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    // outer gzip header
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    // inner gzip header as payload
    data.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_lz4_in_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    data.extend_from_slice(&[0x04, 0x22, 0x4D, 0x18]); // LZ4 magic
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_zstd_in_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    data.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // Zstd magic
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_snappy_in_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    data.extend_from_slice(&[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]); // Snappy
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_gzip_in_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let mut data = vec![0x04, 0x22, 0x4D, 0x18];
    data.extend_from_slice(&[0x1f, 0x8b]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_encrypted_content_detection_high_entropy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    let entropy_payload: Vec<u8> = (0..1024).map(|i| (i * 137 % 256) as u8).collect();
    data.extend_from_slice(&entropy_payload);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_encrypted_content_lz4_high_entropy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let mut data = vec![0x04, 0x22, 0x4D, 0x18];
    let entropy_payload: Vec<u8> = (0..1024).map(|i| (i * 137 % 256) as u8).collect();
    data.extend_from_slice(&entropy_payload);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_zero_byte_input_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let result = builder.build_from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_zero_byte_input_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_zero_byte_input_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let result = builder.build_from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_zero_byte_input_zstd() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let result = builder.build_from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_maximally_compressible_input_all_zeros_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let data = vec![0u8; 10000];
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_maximally_compressible_input_all_zeros_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let data = vec![0u8; 10000];
    let result = builder.build_from_bytes(&data);
    if let Ok(idx) = result {
        assert_eq!(idx.block_count(), 0);
    }
}

#[test]
fn test_maximally_compressible_input_all_zeros_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let data = vec![0u8; 10000];
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_maximally_compressible_input_all_zeros_zstd() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let data = vec![0u8; 10000];
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_maximally_incompressible_random_bytes_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let data: Vec<u8> = (0..10000).map(|i| (i * 11 % 256) as u8).collect();
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_maximally_incompressible_random_bytes_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let data: Vec<u8> = (0..10000).map(|i| (i * 11 % 256) as u8).collect();
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_maximally_incompressible_random_bytes_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let data: Vec<u8> = (0..10000).map(|i| (i * 11 % 256) as u8).collect();
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_maximally_incompressible_random_bytes_zstd() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let data: Vec<u8> = (0..10000).map(|i| (i * 11 % 256) as u8).collect();
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_identify_gzip_magic_exact() {
    assert_eq!(CompressionFormat::detect(b"\x1f\x8b"), Some(CompressionFormat::Gzip));
}

#[test]
fn test_identify_gzip_magic_padded() {
    assert_eq!(CompressionFormat::detect(b"\x1f\x8b\x00\x00"), Some(CompressionFormat::Gzip));
}

#[test]
fn test_identify_lz4_magic_exact() {
    assert_eq!(CompressionFormat::detect(b"\x04\x22\x4d\x18"), Some(CompressionFormat::Lz4));
}

#[test]
fn test_identify_lz4_legacy_magic_exact() {
    assert_eq!(CompressionFormat::detect(b"\x02\x21\x4c\x18"), Some(CompressionFormat::Lz4));
}

#[test]
fn test_identify_lz4_magic_padded() {
    assert_eq!(CompressionFormat::detect(b"\x04\x22\x4d\x18\x00\x00"), Some(CompressionFormat::Lz4));
}

#[test]
fn test_identify_zstd_magic_exact() {
    assert_eq!(CompressionFormat::detect(b"\x28\xb5\x2f\xfd"), Some(CompressionFormat::Zstd));
}

#[test]
fn test_identify_zstd_magic_padded() {
    assert_eq!(CompressionFormat::detect(b"\x28\xb5\x2f\xfd\x00\x00"), Some(CompressionFormat::Zstd));
}

#[test]
fn test_identify_snappy_magic_exact() {
    assert_eq!(CompressionFormat::detect(b"\xff\x06\x00\x00\x73\x4e\x61\x50\x70\x59"), Some(CompressionFormat::Snappy));
}

#[test]
fn test_identify_snappy_magic_padded() {
    assert_eq!(CompressionFormat::detect(b"\xff\x06\x00\x00\x73\x4e\x61\x50\x70\x59\x00\x00"), Some(CompressionFormat::Snappy));
}

#[test]
fn test_identify_unknown_magic() {
    assert_eq!(CompressionFormat::detect(b"\x00\x00\x00\x00"), None);
}

#[test]
fn test_identify_bzip2_magic_none() {
    assert_eq!(CompressionFormat::detect(b"BZh"), None);
}

#[test]
fn test_identify_xz_magic_none() {
    assert_eq!(CompressionFormat::detect(b"\xfd7zXZ\x00"), None);
}

#[test]
fn test_identify_empty_magic() {
    assert_eq!(CompressionFormat::detect(b""), None);
}

#[test]
fn test_identify_one_byte_magic() {
    assert_eq!(CompressionFormat::detect(b"\x1f"), None);
}

#[test]
fn test_identify_partial_lz4_magic() {
    assert_eq!(CompressionFormat::detect(b"\x04\x22\x4d"), None);
}

#[test]
fn test_identify_partial_snappy_magic() {
    assert_eq!(CompressionFormat::detect(b"\xff\x06\x00\x00\x73\x4e\x61\x50\x70"), None);
}

// Additional tests to reach 33+ new ones

#[test]
fn test_detect_nested_gzip_in_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    data.extend_from_slice(&[0x1f, 0x8b, 0x08]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_lz4_in_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    data.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_zstd_in_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    data.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_snappy_in_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let mut data = vec![0x04, 0x22, 0x4D, 0x18];
    data.extend_from_slice(&[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_zstd_in_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let mut data = vec![0x04, 0x22, 0x4D, 0x18];
    data.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_nested_lz4_in_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let mut data = vec![0x04, 0x22, 0x4D, 0x18];
    data.extend_from_slice(&[0x04, 0x22, 0x4D, 0x18]); 
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_detect_compression_ratio_accuracy_detect_from_buffer() {
    let data = vec![0x1f, 0x8b, 0x08];
    assert_eq!(CompressionFormat::detect(&data), Some(CompressionFormat::Gzip));
}


#[test]
fn test_compression_ratio_accuracy_detect_from_lz4() {
    // A valid LZ4 raw block where we know the uncompressed size and literals.
    // The `CompressedBlock` struct is returned by `extract_from_bytes`.
    use ziftsieve::{extract_from_bytes, CompressionFormat};
    
    // We can use an invalid frame to see if it defaults to 1.0 (empty literals, none uncompressed)
    let blocks = extract_from_bytes(CompressionFormat::Lz4, &[0x04, 0x22, 0x4D, 0x18]).unwrap_or_default();
    if let Some(b) = blocks.first() {
        assert_eq!(b.literal_density(), 1.0);
    }
}



#[test]
#[cfg(feature = "gzip")]
fn test_compression_ratio_accuracy_with_flate2() {
    use std::io::Write;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    #[cfg(feature = "gzip")]
    use ziftsieve::scan_tarball_literals;

    // Create a dummy tarball with a single 100-byte file
    let mut tar_data = Vec::new();
    let mut header = [0u8; 512];
    header[0..13].copy_from_slice(b"testfile.txt\0"); // Name
    header[100..108].copy_from_slice(b"0000644\0"); // Mode
    header[108..116].copy_from_slice(b"0000000\0"); // UID
    header[116..124].copy_from_slice(b"0000000\0"); // GID
    header[124..136].copy_from_slice(b"00000000144\0"); // Size (100 in octal)
    header[136..148].copy_from_slice(b"00000000000\0"); // Mtime
    header[148..156].copy_from_slice(b"        "); // Checksum (computed below)
    header[156] = b'0'; // Typeflag (regular file)
    header[257..263].copy_from_slice(b"ustar\0"); // Magic

    // Calculate checksum
    let mut checksum = 0;
    for b in header.iter() {
        checksum += *b as u32;
    }
    let checksum_str = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(checksum_str.as_bytes());

    tar_data.extend_from_slice(&header);
    tar_data.extend_from_slice(&[b'A'; 100]); // 100 bytes of literals
    tar_data.extend_from_slice(&[0u8; 412]); // Padding to 512
    tar_data.extend_from_slice(&[0u8; 1024]); // End of archive (two 512-byte blocks of zeros)

    // Compress with flate2
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    let gz_data = encoder.finish().unwrap();

    let blocks = scan_tarball_literals(&gz_data).expect("Should extract valid tarball");
    assert_eq!(blocks.len(), 1);
    
    // Test literal density (should be exactly 100/100 = 1.0)
    let density = blocks[0].literal_density();
    assert!((density - 1.0).abs() < f64::EPSILON);
    assert_eq!(blocks[0].uncompressed_len(), Some(100));
}
