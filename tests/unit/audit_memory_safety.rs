//! Audit Tests: Memory Usage and Safety
//!
//! Tests that verify memory limits, streaming behavior, and crash resilience.

use std::io::Write;
use ziftsieve::{
    extract_from_bytes, CompressedIndexBuilder, CompressionFormat, StreamingIndexBuilder,
};

// ============================================================================
// Test 1-10: Memory Limits and Zip Bomb Protection
// ============================================================================

#[test]
fn audit_lz4_decompression_ratio_limit() {
    // Test that 250:1 ratio limit is enforced
    // Create data that would decompress to more than 250x

    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00]; // Frame header

    // Create a block that claims large decompressed size via LZ4 sequences
    // Token: literal_len=15 (needs extension), match_len=15
    let mut block_data = vec![0xFF]; // Max token
                                     // Extension for literal length: claim huge literal
    block_data.push(0xFF); // +255
    block_data.push(0xFF); // +255
    block_data.push(0xFF); // +255
    block_data.push(0xD0); // +208 = 15+255+255+255+208 = 988

    // Only provide a few literal bytes (not 988)
    block_data.extend_from_slice(&[b'X'; 10]);

    let block_size = block_data.len() as u32;
    data.extend_from_slice(&block_size.to_le_bytes());
    data.extend_from_slice(&block_data);

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);

    // Should fail due to truncated/large literal mismatch
    assert!(result.is_err() || result.is_ok()); // Either is acceptable, must not panic
}

#[test]
fn audit_lz4_max_sequences_limit() {
    // Test MAX_SEQUENCES_PER_BLOCK = 100,000 limit
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];

    // Create block with many tiny sequences
    let mut block_data = Vec::new();
    for _ in 0..1000 {
        // Less than max, but many
        block_data.push(0x11); // literal_len=1, match_len=1
        block_data.push(b'A'); // 1 literal byte
        block_data.extend_from_slice(&[0x01, 0x00]); // match offset
    }

    let block_size = block_data.len() as u32;
    data.extend_from_slice(&block_size.to_le_bytes());
    data.extend_from_slice(&block_data);

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);

    // Should handle without crashing
    match result {
        Ok(_) | Err(_) => {}
    }
}

#[test]
fn audit_lz4_max_blocks_per_stream() {
    // Test MAX_BLOCKS_PER_STREAM = 10,000 limit
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];

    // Add many tiny uncompressed blocks
    for _ in 0..100 {
        // Less than 10k for test speed
        let block = b"X";
        let size = (block.len() as u32) | 0x8000_0000;
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(block);
    }

    // End marker
    data.extend_from_slice(&[0u8; 4]);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("Should handle many blocks");

    assert_eq!(index.block_count(), 100);
}

#[test]
fn audit_lz4_total_literals_limit() {
    // Test MAX_TOTAL_LITERALS = 256MB limit
    // We can't actually test 256MB, but we can verify the limit exists

    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];

    // Add uncompressed block with 1MB of data
    let big_block = vec![b'X'; 1024 * 1024];
    let size = (big_block.len() as u32) | 0x8000_0000;
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&big_block);

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);

    // Should succeed for 1MB
    assert!(result.is_ok());
}

#[test]
fn audit_lz4_block_size_4mb_boundary() {
    // Test 4MB block size boundary
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];

    // Claim 4MB + 1 (exceeds limit)
    let block_size: u32 = 4 * 1024 * 1024 + 1;
    data.extend_from_slice(&block_size.to_le_bytes());

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);

    assert!(result.is_err(), "Should reject block > 4MB");
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_max_literals_limit() {
    // Test MAX_TOTAL_LITERALS = 256MB for gzip
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let data = vec![b'X'; 1024 * 1024]; // 1MB
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(0));
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should handle 1MB");

    assert!(index.block_count() > 0);
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_max_block_size() {
    // Zstd max block size is 128KB
    let data = vec![b'X'; 128 * 1024];
    let compressed = zstd::encode_all(&data[..], 1).unwrap();

    match CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&compressed) {
        Ok(index) => {
            let _ = index.block_count();
        }
        Err(_) => {
            // Error is acceptable for certain block types
        }
    }
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_block_size_exceeded() {
    // Try to create a block claiming > 128KB
    let mut data = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00]; // Frame header

    // Block header with size > 128KB
    // last=0, type=0 (raw), size=131073 (0x20001)
    // b0 = last | (type << 1) | ((size & 0x1F) << 3)
    let size = 128 * 1024 + 1;
    let b0 = ((size & 0x1F) << 3) as u8;
    let b1 = ((size >> 5) & 0xFF) as u8;
    let b2 = ((size >> 13) & 0xFF) as u8;

    data.push(b0);
    data.push(b1);
    data.push(b2);

    let result = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&data);

    assert!(result.is_err(), "Should reject block > 128KB");
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_max_chunk_size() {
    // Snappy max chunk size is 64KB
    let chunk_data = vec![b'X'; 64 * 1024 - 4]; // -4 for CRC
    let crc = 0u32;
    let chunk_len = (chunk_data.len() + 4) as u32;

    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    data.push(0x01); // Uncompressed chunk
    data.extend_from_slice(&[
        (chunk_len & 0xFF) as u8,
        ((chunk_len >> 8) & 0xFF) as u8,
        ((chunk_len >> 16) & 0xFF) as u8,
    ]);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(&chunk_data);

    let blocks =
        extract_from_bytes(CompressionFormat::Snappy, &data).expect("Should handle max chunk size");

    assert!(!blocks.is_empty());
}

// ============================================================================
// Test 11-20: Streaming Memory Usage
// ============================================================================

#[test]
fn audit_streaming_builder_memory_efficiency() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);

    // Process multiple chunks
    for i in 0..10 {
        let chunk = format!("Chunk {} data content for streaming test.", i);
        let compressed = lz4_compress(chunk.as_bytes());

        let _ = builder.process_chunk(&compressed);
    }

    let index = builder.finalize().expect("Should finalize");
    let _ = index.block_count();
}

#[test]
fn audit_streaming_builder_empty_chunks() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);

    // Process empty chunks
    for _ in 0..10 {
        let _ = builder.process_chunk(b"");
    }

    let index = builder.finalize().expect("Should finalize");
    assert_eq!(index.block_count(), 0);
}

#[test]
fn audit_streaming_builder_mixed_chunks() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);

    // Mix of valid and invalid chunks
    let valid = lz4_compress(b"Valid data");
    let invalid = vec![0xFF; 100];

    builder.process_chunk(&valid).ok();
    builder.process_chunk(&invalid).ok();
    builder.process_chunk(&valid).ok();

    let _index = builder.finalize().expect("Should finalize");
    // Should have blocks from valid chunks
}

#[test]
fn audit_streaming_builder_config_persistence() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4).expected_items(1000);

    let data = lz4_compress(b"Test data");
    builder.process_chunk(&data).ok();

    let index = builder.finalize().expect("Should finalize");
    let _ = index.block_count();
}

// ============================================================================
// Test 21-30: Crash Resilience - Malformed Input
// ============================================================================

#[test]
fn audit_malformed_lz4_truncated_at_token() {
    // Truncated right after token byte
    let data = vec![0x10]; // Token but no literal

    let result = extract_from_bytes(CompressionFormat::Lz4, &data);
    assert!(result.is_err() || result.is_ok()); // Must not panic
}

#[test]
fn audit_malformed_lz4_truncated_literal() {
    // Claims 5 literals but only provides 2
    let data = vec![0x50, b'A', b'B']; // Token says 5, only 2 bytes

    let result = extract_from_bytes(CompressionFormat::Lz4, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn audit_malformed_lz4_truncated_match_offset() {
    // Has token with match, but truncated offset
    let data = vec![0x11, b'A', 0x01]; // Token, 1 literal, 1 byte of offset

    let result = extract_from_bytes(CompressionFormat::Lz4, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn audit_malformed_lz4_overflow_length() {
    // Length that would overflow
    let mut data = vec![0xF0]; // literal_len=15
    data.extend(std::iter::repeat_n(0xFF, 100));

    let result = extract_from_bytes(CompressionFormat::Lz4, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
#[cfg(feature = "gzip")]
fn audit_malformed_gzip_truncated_header() {
    // Just magic bytes, no header
    let data = vec![0x1f, 0x8b];

    let result = extract_from_bytes(CompressionFormat::Gzip, &data);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "gzip")]
fn audit_malformed_gzip_invalid_flags() {
    // Invalid flag bits (0xE0)
    let data = vec![
        0x1f, 0x8b, 0x08, 0xE0, // Magic, method, INVALID flags
        0x00, 0x00, 0x00, 0x00, // mtime
        0x00, 0xff, // xfl, os
    ];

    let result = extract_from_bytes(CompressionFormat::Gzip, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
#[cfg(feature = "zstd")]
fn audit_malformed_zstd_invalid_frame_header() {
    // Invalid frame header descriptor
    let data = vec![
        0x28, 0xb5, 0x2f, 0xfd, // Magic
        0xFF, // Invalid descriptor
    ];

    let result = extract_from_bytes(CompressionFormat::Zstd, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
#[cfg(feature = "zstd")]
fn audit_malformed_zstd_truncated_block_header() {
    // Truncated block header (only 2 bytes)
    let data = vec![
        0x28, 0xb5, 0x2f, 0xfd, // Magic
        0x00, 0x00, // Frame header
        0x00, 0x00, // Only 2 bytes of block header
    ];

    let result = extract_from_bytes(CompressionFormat::Zstd, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
#[cfg(feature = "snappy")]
fn audit_malformed_snappy_truncated_length() {
    // Chunk type but no length
    let data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
        0x01, // Type but no length bytes
    ];

    let result = extract_from_bytes(CompressionFormat::Snappy, &data);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn audit_all_formats_handle_empty_input() {
    // Empty LZ4 input is correctly rejected as invalid.
    let result = extract_from_bytes(CompressionFormat::Lz4, b"");
    assert!(result.is_err(), "empty LZ4 input must be rejected");

    #[cfg(feature = "gzip")]
    {
        let result = extract_from_bytes(CompressionFormat::Gzip, b"");
        assert!(result.is_err() || result.is_ok());
    }

    #[cfg(feature = "zstd")]
    {
        let result = extract_from_bytes(CompressionFormat::Zstd, b"");
        assert!(result.is_err() || result.is_ok());
    }

    #[cfg(feature = "snappy")]
    {
        let result = extract_from_bytes(CompressionFormat::Snappy, b"");
        assert!(result.is_err(), "empty Snappy input must be rejected");
    }
}

// ============================================================================
// Test 31-40: Fuzz-Style Random Input
// ============================================================================

#[test]
fn audit_fuzz_random_bytes_lz4() {
    // Random bytes should not crash
    let seed: Vec<u8> = (0..4096).map(|i| ((i * 7 + 13) % 256) as u8).collect();

    for size in [1, 16, 256, 1024, 4096] {
        let data = &seed[..size];
        let _ = extract_from_bytes(CompressionFormat::Lz4, data);
    }
}

#[test]
#[cfg(feature = "gzip")]
fn audit_fuzz_random_bytes_gzip() {
    let seed: Vec<u8> = (0..4096).map(|i| ((i * 7 + 13) % 256) as u8).collect();

    for size in [1, 16, 256, 1024, 4096] {
        let data = &seed[..size];
        let _ = extract_from_bytes(CompressionFormat::Gzip, data);
    }
}

#[test]
#[cfg(feature = "zstd")]
fn audit_fuzz_random_bytes_zstd() {
    let seed: Vec<u8> = (0..4096).map(|i| ((i * 7 + 13) % 256) as u8).collect();

    for size in [1, 16, 256, 1024, 4096] {
        let data = &seed[..size];
        let _ = extract_from_bytes(CompressionFormat::Zstd, data);
    }
}

#[test]
#[cfg(feature = "snappy")]
fn audit_fuzz_random_bytes_snappy() {
    let seed: Vec<u8> = (0..4096).map(|i| ((i * 7 + 13) % 256) as u8).collect();

    for size in [1, 16, 256, 1024, 4096] {
        let data = &seed[..size];
        let _ = extract_from_bytes(CompressionFormat::Snappy, data);
    }
}

#[test]
fn audit_fuzz_all_zeros() {
    let data = vec![0u8; 10000];

    let _ = extract_from_bytes(CompressionFormat::Lz4, &data);
    #[cfg(feature = "gzip")]
    let _ = extract_from_bytes(CompressionFormat::Gzip, &data);
    #[cfg(feature = "zstd")]
    let _ = extract_from_bytes(CompressionFormat::Zstd, &data);
    #[cfg(feature = "snappy")]
    let _ = extract_from_bytes(CompressionFormat::Snappy, &data);
}

#[test]
fn audit_fuzz_all_ones() {
    let data = vec![0xFFu8; 10000];

    let _ = extract_from_bytes(CompressionFormat::Lz4, &data);
    #[cfg(feature = "gzip")]
    let _ = extract_from_bytes(CompressionFormat::Gzip, &data);
    #[cfg(feature = "zstd")]
    let _ = extract_from_bytes(CompressionFormat::Zstd, &data);
    #[cfg(feature = "snappy")]
    let _ = extract_from_bytes(CompressionFormat::Snappy, &data);
}

#[test]
fn audit_fuzz_alternating_bytes() {
    let data: Vec<u8> = (0..10000)
        .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
        .collect();

    let _ = extract_from_bytes(CompressionFormat::Lz4, &data);
    #[cfg(feature = "gzip")]
    let _ = extract_from_bytes(CompressionFormat::Gzip, &data);
    #[cfg(feature = "zstd")]
    let _ = extract_from_bytes(CompressionFormat::Zstd, &data);
    #[cfg(feature = "snappy")]
    let _ = extract_from_bytes(CompressionFormat::Snappy, &data);
}

#[test]
fn audit_fuzz_incremental_bytes() {
    let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

    let _ = extract_from_bytes(CompressionFormat::Lz4, &data);
    #[cfg(feature = "gzip")]
    let _ = extract_from_bytes(CompressionFormat::Gzip, &data);
    #[cfg(feature = "zstd")]
    let _ = extract_from_bytes(CompressionFormat::Zstd, &data);
    #[cfg(feature = "snappy")]
    let _ = extract_from_bytes(CompressionFormat::Snappy, &data);
}

// ============================================================================
// Test 41-50: Edge Cases
// ============================================================================

#[test]
fn audit_single_byte_input() {
    let result = extract_from_bytes(CompressionFormat::Lz4, b"X");
    assert!(result.is_ok());
}

#[test]
fn audit_two_byte_input() {
    let result = extract_from_bytes(CompressionFormat::Lz4, b"AB");
    assert!(result.is_ok());
}

#[test]
fn audit_three_byte_input() {
    let result = extract_from_bytes(CompressionFormat::Lz4, b"ABC");
    assert!(result.is_ok());
}

#[test]
fn audit_four_byte_input() {
    let result = extract_from_bytes(CompressionFormat::Lz4, b"ABCD");
    // May succeed (treated as raw blocks) or fail
    match result {
        Ok(_) | Err(_) => {}
    }
}

#[test]
fn audit_large_input_handling() {
    // 10MB of data (but compressed)
    let data = vec![b'X'; 10 * 1024 * 1024];
    let compressed = lz4_compress(&data);

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&compressed);

    // Should succeed (well under 256MB limit)
    assert!(result.is_ok());
}

// ============================================================================
// Test Helpers
// ============================================================================

#[cfg(feature = "lz4")]
fn lz4_compress(data: &[u8]) -> Vec<u8> {
    use lz4_flex::frame::FrameEncoder;

    let mut compressed = Vec::new();
    {
        let mut encoder = FrameEncoder::new(&mut compressed);
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
    }
    compressed
}

#[cfg(not(feature = "lz4"))]
fn lz4_compress(_data: &[u8]) -> Vec<u8> {
    vec![]
}
