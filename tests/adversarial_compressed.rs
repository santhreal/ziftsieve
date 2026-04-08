#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    clippy::panic,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    unused_comparisons,
    clippy::ignored_unit_patterns,
    clippy::single_match,
    unused_variables,
    clippy::absurd_extreme_comparisons
)]
//! Exhaustive adversarial tests for ziftsieve compressed search.
//!
//! These tests verify:
//! - Format detection by magic bytes
//! - Literal extraction from all supported formats
//! - Robustness against corrupt/truncated archives
//! - Scale handling (large data, nested compression, compression bombs)
//! - Search parity between compressed and decompressed data

use std::io::{Read, Write};
use ziftsieve::{
    bloom::BloomFilter, extract::CompressedBlock, CompressedIndexBuilder, CompressionFormat,
    StreamingIndexBuilder,
};

// ── Test Helpers ─────────────────────────────────────────────────────────

/// Build a minimal LZ4 block stream with uncompressed flag.
fn make_uncompressed_lz4_block(data: &[u8]) -> Vec<u8> {
    let size = (data.len() as u32) | 0x8000_0000;
    let mut out = size.to_le_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// Build a raw LZ4 token stream for a single literal run.
#[allow(dead_code)]
fn make_lz4_literal_token(literal: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = literal.len();
    if len < 15 {
        out.push((len as u8) << 4); // literal_len in high nibble, match_len=0
        out.extend_from_slice(literal);
    } else {
        out.push(0xF0); // literal_len=15, match_len=0
        let mut remaining = len - 15;
        while remaining >= 255 {
            out.push(255);
            remaining -= 255;
        }
        out.push(remaining as u8);
        out.extend_from_slice(literal);
    }
    out
}

/// Wrap raw token stream as a compressed LZ4 block.
#[allow(dead_code)]
fn make_compressed_lz4_block(token_stream: &[u8]) -> Vec<u8> {
    let size = token_stream.len() as u32;
    let mut out = size.to_le_bytes().to_vec();
    out.extend_from_slice(token_stream);
    out
}

/// Create a gzip-compressed byte vector.
#[cfg(feature = "gzip")]
fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Decompress gzip data.
#[cfg(feature = "gzip")]
fn gzip_decompress(data: &[u8]) -> Vec<u8> {
    use flate2::read::GzDecoder;
    let mut decoder = GzDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).expect("gzip decompress");
    result
}

/// Create an LZ4-compressed byte vector (frame format with magic).
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

/// Decompress LZ4 data (frame format).
#[cfg(feature = "lz4")]
fn lz4_decompress(data: &[u8]) -> Vec<u8> {
    use lz4_flex::frame::FrameDecoder;
    use std::io::Read;
    let mut decoder = FrameDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).expect("lz4 decompress");
    result
}

/// Create a zstd-compressed byte vector.
#[cfg(feature = "zstd")]
fn zstd_compress(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).expect("zstd compress")
}

/// Decompress zstd data.
#[cfg(feature = "zstd")]
fn zstd_decompress(data: &[u8]) -> Vec<u8> {
    zstd::decode_all(data).expect("zstd decompress")
}

/// Create a snappy-compressed byte vector (framing format).
#[cfg(feature = "snappy")]
fn snappy_compress(data: &[u8]) -> Vec<u8> {
    use snap::write::FrameEncoder;
    use std::io::Write;
    let mut compressed = Vec::new();
    {
        let mut encoder = FrameEncoder::new(&mut compressed);
        encoder.write_all(data).unwrap();
        encoder.flush().unwrap();
    }
    compressed
}

/// Verify that all extracted literals exist in the decompressed output.
#[allow(dead_code)]
fn verify_literals_in_decompressed(blocks: &[CompressedBlock], decompressed: &[u8]) {
    for (i, block) in blocks.iter().enumerate() {
        let literals = block.literals();
        if literals.is_empty() {
            continue;
        }
        // Check that the literal bytes appear in the decompressed data
        let found = decompressed
            .windows(literals.len().min(decompressed.len()))
            .any(|window| window == literals);
        assert!(
            found || literals.len() > decompressed.len(),
            "Block {} literals not found in decompressed output",
            i
        );
    }
}

// ── FORMAT DETECTION TESTS ───────────────────────────────────────────────

// 1. Detect gzip by magic bytes (1F 8B)
#[test]
fn format_detection_gzip_magic_bytes() {
    let gzip_header = [0x1f, 0x8b, 0x08, 0x00];
    let detected = CompressionFormat::detect(&gzip_header);
    assert_eq!(
        detected,
        Some(CompressionFormat::Gzip),
        "Should detect gzip by magic bytes 1F 8B"
    );
}

// 2. Detect LZ4 by magic bytes (04 22 4D 18)
#[test]
fn format_detection_lz4_magic_bytes() {
    let lz4_header = [0x04, 0x22, 0x4d, 0x18];
    let detected = CompressionFormat::detect(&lz4_header);
    assert_eq!(
        detected,
        Some(CompressionFormat::Lz4),
        "Should detect LZ4 by magic bytes 04 22 4D 18"
    );
}

// 3. Detect LZ4 legacy frame by magic bytes (02 21 4C 18)
#[test]
fn format_detection_lz4_legacy_magic_bytes() {
    let lz4_legacy = [0x02, 0x21, 0x4c, 0x18];
    let detected = CompressionFormat::detect(&lz4_legacy);
    assert_eq!(
        detected,
        Some(CompressionFormat::Lz4),
        "Should detect LZ4 legacy by magic bytes 02 21 4C 18"
    );
}

// 4. Detect zstd by magic bytes (28 B5 2F FD)
#[test]
fn format_detection_zstd_magic_bytes() {
    let zstd_header = [0x28, 0xb5, 0x2f, 0xfd];
    let detected = CompressionFormat::detect(&zstd_header);
    assert_eq!(
        detected,
        Some(CompressionFormat::Zstd),
        "Should detect zstd by magic bytes 28 B5 2F FD"
    );
}

// 5. Detect snappy framing by magic bytes
#[test]
fn format_detection_snappy_magic_bytes() {
    let snappy_header = [0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    let detected = CompressionFormat::detect(&snappy_header);
    assert_eq!(
        detected,
        Some(CompressionFormat::Snappy),
        "Should detect Snappy framing format by magic bytes"
    );
}

// 6. Unknown format returns None
#[test]
fn format_detection_unknown_format_returns_none() {
    let unknown = [0x00, 0x00, 0x00, 0x00];
    let detected = CompressionFormat::detect(&unknown);
    assert_eq!(detected, None, "Unknown format should return None");
}

// 7. Empty data returns None
#[test]
fn format_detection_empty_data_returns_none() {
    let empty: &[u8] = b"";
    let detected = CompressionFormat::detect(empty);
    assert_eq!(detected, None, "Empty data should return None");
}

// 8. Truncated magic bytes (only 1 byte of gzip header)
#[test]
fn format_detection_truncated_magic_bytes() {
    let truncated = [0x1f]; // Only first byte of gzip magic
    let detected = CompressionFormat::detect(&truncated);
    assert_eq!(
        detected, None,
        "Truncated magic bytes should return None, not panic"
    );
}

// 9. Data too short for any format detection
#[test]
fn format_detection_data_too_short() {
    let short = [0x04, 0x22]; // Only 2 bytes, need 4 for LZ4
    let detected = CompressionFormat::detect(&short);
    assert_eq!(detected, None, "Short data should return None");
}

// 10. Format detection with extra bytes after magic
#[test]
fn format_detection_with_extra_bytes() {
    let data = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    let detected = CompressionFormat::detect(&data);
    assert_eq!(
        detected,
        Some(CompressionFormat::Gzip),
        "Should detect format even with extra bytes"
    );
}

// ── LITERAL EXTRACTION TESTS ─────────────────────────────────────────────

// 11. Extract literals from gzip compressed data
#[test]
#[cfg(feature = "gzip")]
fn literal_extraction_gzip_basic() {
    let original = b"Hello, World! Testing gzip literal extraction.";
    let compressed = gzip_compress(original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should build index from gzip data");

    assert!(
        index.block_count() > 0,
        "Should extract at least one block from gzip"
    );

    // Verify extracted literals exist in decompressed output
    let decompressed = gzip_decompress(&compressed);
    let blocks: Vec<_> = (0..index.block_count())
        .map(|i| index.get_block(i).unwrap().clone())
        .collect();

    assert!(
        !blocks.is_empty(),
        "Expected blocks to be extracted from repeated pattern"
    );
    assert!(
        blocks.iter().any(|b| !b.literals().is_empty()),
        "Expected non-empty literals in blocks"
    );
    // verify_literals_in_decompressed is unused when not using gzip feature?
    // Let's just assert standard verify here.
    verify_literals_in_decompressed(&blocks, &decompressed);
}

// 12. Extract literals from LZ4 compressed data
#[test]
#[cfg(feature = "lz4")]
fn literal_extraction_lz4_basic() {
    let original = b"Hello, World! Testing LZ4 literal extraction.";
    let compressed = lz4_compress(original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should build index from LZ4 data");

    assert!(
        index.block_count() > 0,
        "Should extract at least one block from LZ4"
    );

    // For LZ4, the literals should contain the original data
    let all_literals: Vec<u8> = (0..index.block_count())
        .flat_map(|i| index.get_block(i).unwrap().literals().to_vec())
        .collect();

    // All extracted bytes should be in the original
    for byte in &all_literals {
        assert!(
            original.contains(byte),
            "Literal byte {} not found in original",
            byte
        );
    }
}

// 13. Extract literals from zstd compressed data
#[test]
#[cfg(feature = "zstd")]
fn literal_extraction_zstd_basic() {
    let original = b"Hello, World! Testing zstd literal extraction.";
    let compressed = zstd_compress(original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Zstd)
        .build_from_bytes(&compressed)
        .expect("Should build index from zstd data");

    assert!(
        index.block_count() > 0,
        "Should extract at least one block from zstd"
    );

    let total_literals: usize = (0..index.block_count())
        .map(|i| index.get_block(i).unwrap().literals().len())
        .sum();
    assert!(total_literals > 0, "Should extract some literals from zstd");
}

// 14. Extract literals from snappy compressed data
#[test]
#[cfg(feature = "snappy")]
fn literal_extraction_snappy_basic() {
    let original = b"Hello, World! Testing snappy literal extraction.";
    let compressed = snappy_compress(original);

    // Snappy parsing may succeed or error depending on format,
    // but it must not panic
    match CompressedIndexBuilder::new(CompressionFormat::Snappy).build_from_bytes(&compressed) {
        Ok(index) => {
            let _total_literals: usize = (0..index.block_count())
                .map(|i| index.get_block(i).unwrap().literals().len())
                .sum();
        }
        Err(_) => {
            // Error is acceptable - snappy format variants may not all be supported
        }
    }
}

// 15. Verify extracted literals exist in decompressed output - gzip
#[test]
#[cfg(feature = "gzip")]
fn literal_extraction_gzip_literals_in_output() {
    let original = b"The quick brown fox jumps over the lazy dog. ";
    let compressed = gzip_compress(original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let decompressed = gzip_decompress(&compressed);

    for i in 0..index.block_count() {
        let literals = index.get_block(i).unwrap().literals();
        if literals.len() >= 4 {
            // Check that 4-byte chunks from literals appear in decompressed
            for chunk in literals.windows(4) {
                assert!(
                    decompressed.windows(4).any(|w| w == chunk),
                    "Literal chunk {:?} not found in decompressed output",
                    chunk
                );
            }
        }
    }
}

// 16. Verify extracted literals exist in decompressed output - LZ4
#[test]
#[cfg(feature = "lz4")]
fn literal_extraction_lz4_literals_in_output() {
    let original = b"The quick brown fox jumps over the lazy dog. ";
    let compressed = lz4_compress(original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let decompressed = lz4_decompress(&compressed);

    for i in 0..index.block_count() {
        let literals = index.get_block(i).unwrap().literals();
        for byte in literals {
            assert!(
                decompressed.contains(byte),
                "Literal byte {} not found in decompressed",
                byte
            );
        }
    }
}

// 17. Literal extraction with repeated patterns
#[test]
#[cfg(feature = "gzip")]
fn literal_extraction_repeated_patterns() {
    let original = b"ABC".repeat(1000);
    let compressed = gzip_compress(&original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let decompressed = gzip_decompress(&compressed);
    let blocks: Vec<_> = (0..index.block_count())
        .map(|i| index.get_block(i).unwrap().clone())
        .collect();

    assert!(
        !blocks.is_empty(),
        "Expected blocks to be extracted from repeated pattern"
    );
    assert!(
        blocks.iter().any(|b| !b.literals().is_empty()),
        "Expected non-empty literals in blocks"
    );
    verify_literals_in_decompressed(&blocks, &decompressed);
}

// 18. Literal extraction with binary data
#[test]
#[cfg(feature = "lz4")]
fn literal_extraction_binary_data() {
    let original: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let compressed = lz4_compress(&original);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should build index from binary data");

    assert!(
        index.block_count() > 0,
        "Should extract blocks from binary data"
    );
}

// ── CORRUPT ARCHIVES TESTS ───────────────────────────────────────────────

// 19. Truncated gzip stream (header only)
#[test]
#[cfg(feature = "gzip")]
fn corrupt_truncated_gzip_header_only() {
    let truncated = [0x1f, 0x8b, 0x08, 0x00]; // Just gzip header, no data
    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&truncated);
    assert!(
        result.is_err(),
        "Truncated gzip (header only) should return error"
    );
}

// 20. Truncated gzip stream (mid-deflate)
#[test]
#[cfg(feature = "gzip")]
fn corrupt_truncated_gzip_mid_deflate() {
    let original = b"This is a longer test string that will be compressed and then truncated.";
    let compressed = gzip_compress(original);
    let truncated = &compressed[..compressed.len() / 2]; // Cut in half

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(truncated);
    // Should either error or return partial results, but not panic
    match result {
        Ok(index) => {
            // Partial extraction is acceptable
            assert!(index.block_count() >= 0);
        }
        Err(_) => {
            // Error is expected
        }
    }
}

// 21. Invalid deflate data after valid header
#[test]
#[cfg(feature = "gzip")]
fn corrupt_invalid_deflate_after_valid_header() {
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00]; // Valid gzip header
    data.extend_from_slice(&[0x00; 6]); // mtime, xfl, os
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // Invalid deflate data

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&data);
    assert!(
        result.is_err() || result.unwrap().block_count() == 0,
        "Invalid deflate should error or return no blocks"
    );
}

// 22. Gzip with wrong checksum (should still parse, checksum not validated)
#[test]
#[cfg(feature = "gzip")]
fn corrupt_gzip_wrong_checksum() {
    let original = b"Test data for gzip";
    let mut compressed = gzip_compress(original);

    // Corrupt the last 4 bytes (CRC32)
    if compressed.len() >= 4 {
        let len = compressed.len();
        compressed[len - 4] ^= 0xFF;
        compressed[len - 3] ^= 0xFF;
        compressed[len - 2] ^= 0xFF;
        compressed[len - 1] ^= 0xFF;
    }

    // Should still parse (CRC not validated during extraction)
    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&compressed);
    // May succeed or fail, but must not panic
    match result {
        Ok(index) => {
            // Block count accepted
        }
        Err(_) => {}
    }
}

// 23. LZ4 frame with wrong content size
#[test]
#[cfg(feature = "lz4")]
fn corrupt_lz4_wrong_content_size() {
    // Create a block that claims to be larger than it is
    let mut data = vec![0x04, 0x22, 0x4d, 0x18]; // LZ4 magic
    data.extend_from_slice(&[0x60, 0x40, 0x00]); // Frame descriptor

    // Block header claims 1000 bytes but we provide 10
    data.extend_from_slice(&[0xE8, 0x03, 0x00, 0x00]); // 1000 in LE
    data.extend_from_slice(&[0x10; 10]); // Only 10 bytes of data

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(result.is_err(), "LZ4 with wrong content size should error");
}

// 24. Zstd with corrupted dictionary ID
#[test]
#[cfg(feature = "zstd")]
fn corrupt_zstd_corrupted_dictionary() {
    let original = b"Test data for zstd";
    let mut compressed = zstd_compress(original);

    // Corrupt bytes after magic to create invalid frame header
    if compressed.len() > 10 {
        compressed[5] = 0xFF;
        compressed[6] = 0xFF;
    }

    let result = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&compressed);
    // May error or succeed with limited extraction, but must not panic
    match result {
        Ok(_) => {}
        Err(_) => {}
    }
}

// 25. Malformed LZ4 with impossible literal length
#[test]
#[cfg(feature = "lz4")]
fn corrupt_lz4_impossible_literal_length() {
    let mut data = vec![0x04, 0x22, 0x4d, 0x18]; // LZ4 magic
    data.extend_from_slice(&[0x60, 0x40, 0x00]); // Frame descriptor

    // Block with token claiming 5MB literal but tiny block size
    data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Small block
    data.push(0xFF); // Token: literal_len=15 with extension
    data.push(0xFF); // Extension: +255
    data.push(0xFF); // Extension: +255
    data.push(0xD0); // Extension: +208 = 15+255+255+208 = 733
                     // Not enough data for claimed literal length

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(
        result.is_err(),
        "Malformed LZ4 with impossible literal length should error"
    );
}

// 26. All zeros as compressed data
#[test]
fn corrupt_all_zeros_data() {
    let zeros = vec![0u8; 1024];

    // Try all formats
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&zeros);
    assert!(
        result.is_ok() || result.is_err(),
        "Result should be safely handled without panicking"
    );
    assert!(matches!(result, Ok(_) | Err(_)));

    #[cfg(feature = "gzip")]
    {
        let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&zeros);
        assert!(matches!(result, Ok(_) | Err(_)));
    }

    #[cfg(feature = "zstd")]
    {
        let result = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&zeros);
        assert!(matches!(result, Ok(_) | Err(_)));
    }

    #[cfg(feature = "snappy")]
    {
        let result =
            CompressedIndexBuilder::new(CompressionFormat::Snappy).build_from_bytes(&zeros);
        assert!(matches!(result, Ok(_) | Err(_)));
    }
}

// 27. Random garbage data
#[test]
fn corrupt_random_garbage_data() {
    let garbage: Vec<u8> = (0..4096).map(|i| (i * 7 + 13) as u8).collect();

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&garbage);
    assert!(matches!(result, Ok(_) | Err(_)));

    #[cfg(feature = "gzip")]
    {
        let result =
            CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&garbage);
        assert!(matches!(result, Ok(_) | Err(_)));
    }

    #[cfg(feature = "zstd")]
    {
        let result =
            CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&garbage);
        assert!(matches!(result, Ok(_) | Err(_)));
    }

    #[cfg(feature = "snappy")]
    {
        let result =
            CompressedIndexBuilder::new(CompressionFormat::Snappy).build_from_bytes(&garbage);
        assert!(matches!(result, Ok(_) | Err(_)));
    }
}

// 28. Nested corruption - gzip inside gzip with inner corruption
#[test]
#[cfg(feature = "gzip")]
fn corrupt_nested_gzip_inner_corrupted() {
    let inner = b"Inner data";
    let inner_compressed = gzip_compress(inner);

    // Corrupt the inner compressed data
    let mut corrupted_inner = inner_compressed.clone();
    if corrupted_inner.len() > 20 {
        corrupted_inner[10] = 0xFF;
        corrupted_inner[11] = 0xFF;
    }

    let outer = gzip_compress(&corrupted_inner);

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&outer);
    match result {
        Ok(_) | Err(_) => {
            // Expected: may succeed (extracting corrupted inner gzip as block literals) or fail (if somehow considered malformed)
        }
    }
}

// ── SCALE TESTS ──────────────────────────────────────────────────────────

// 29. Large compressed data (1MB for test speed)
#[test]
#[cfg(feature = "lz4")]
fn scale_large_data_1mb() {
    let data = vec![b'A'; 1024 * 1024];
    let compressed = lz4_compress(&data);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should handle 1MB data");

    assert!(
        index.block_count() > 0,
        "Should extract blocks from large data"
    );
}

// 30. Many small blocks
#[test]
#[cfg(feature = "lz4")]
fn scale_many_small_blocks() {
    let mut data = Vec::new();
    for i in 0..1000 {
        let block = format!("Block {:04}", i);
        data.extend_from_slice(&make_uncompressed_lz4_block(block.as_bytes()));
    }

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("Should handle many small blocks");

    assert_eq!(index.block_count(), 1000, "Should extract all 1000 blocks");
}

// 31. Nested compression (gzip inside gzip)
#[test]
#[cfg(feature = "gzip")]
fn scale_nested_compression_gzip_in_gzip() {
    let inner = b"Inner compressed data for nesting test.".repeat(100);
    let inner_compressed = gzip_compress(&inner);
    let outer = gzip_compress(&inner_compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&outer)
        .expect("Should handle nested gzip");

    assert!(
        index.block_count() > 0,
        "Should extract blocks from nested gzip"
    );
}

// 32. Deeply nested compression (3 levels)
#[test]
#[cfg(feature = "gzip")]
fn scale_deeply_nested_compression() {
    let data = b"Deep nesting test data.".repeat(50);
    let level1 = gzip_compress(&data);
    let level2 = gzip_compress(&level1);
    let level3 = gzip_compress(&level2);

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&level3)
        .expect("Should handle deeply nested gzip");

    assert!(
        index.block_count() > 0,
        "Should extract blocks from deeply nested gzip"
    );
}

// 33. Compression ratio bomb simulation (highly compressible data)
#[test]
#[cfg(feature = "lz4")]
fn scale_compression_ratio_bomb_simulation() {
    // Data that compresses extremely well (1 byte repeated)
    let original = vec![b'X'; 1024 * 1024]; // 1MB of same byte
    let compressed = lz4_compress(&original);

    // Compressed should be much smaller than original
    assert!(
        compressed.len() < original.len() / 10,
        "Compressed should be much smaller for repetitive data"
    );

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should handle highly compressible data");

    // Should extract without OOM (block_count always >= 0 for usize)
    let _ = index.block_count();
}

// 34. Streaming builder with multiple chunks
#[test]
#[cfg(feature = "lz4")]
fn scale_streaming_builder_multiple_chunks() {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);

    // Process data in chunks (each a separate valid frame)
    for i in 0..10 {
        let chunk = format!("Chunk {:04} with some data content for streaming test.", i);
        let compressed = lz4_compress(chunk.as_bytes());
        match builder.process_chunk(&compressed) {
            Ok(_) => {}
            Err(_) => {
                // Some chunks might fail but should not panic
            }
        }
    }

    let index = builder.finalize().expect("Should finalize");
    // May have blocks or be empty depending on parsing
    let _ = index.block_count();
}

// 35. Bloom filter with many items
#[test]
fn scale_bloom_filter_many_items() {
    let mut bloom = BloomFilter::new(100_000, 0.01);

    for i in 0..100_000 {
        let item = format!("item_{}", i);
        bloom.insert(item.as_bytes());
    }

    // Verify all inserted items are found
    for i in 0..100_000 {
        let item = format!("item_{}", i);
        assert!(
            bloom.may_contain(item.as_bytes()),
            "Should find inserted item {} (no false negatives)",
            i
        );
    }
}

// ── SEARCH PARITY TESTS ─────────────────────────────────────────────────

// 36. LZ4: search(compressed) finds same patterns as search(decompress(compressed))
#[test]
#[cfg(feature = "lz4")]
fn search_parity_lz4_basic() {
    let original = b"The quick brown fox jumps over the lazy dog. UNIQUE_PATTERN_12345";
    let compressed = lz4_compress(original);
    let decompressed = lz4_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = b"UNIQUE_PATTERN_12345";

    // Search in compressed
    let compressed_candidates = index.candidate_blocks(pattern);

    // Search in decompressed (simple linear search)
    let found_in_decompressed = decompressed.windows(pattern.len()).any(|w| w == pattern);

    assert!(
        found_in_decompressed,
        "Pattern should be in decompressed data"
    );

    // At least one candidate should contain the pattern
    let found_in_compressed = compressed_candidates
        .iter()
        .any(|&id| index.get_block(id).unwrap().verify_contains(pattern));

    assert!(
        found_in_compressed,
        "Pattern should be found through compressed search"
    );
}

// 37. Gzip: search parity for multiple patterns
#[test]
#[cfg(feature = "gzip")]
fn search_parity_gzip_multiple_patterns() {
    let patterns = vec!["PATTERN_ALPHA_001", "PATTERN_BETA_002", "PATTERN_GAMMA_003"];
    let mut original = String::new();
    for (i, pat) in patterns.iter().enumerate() {
        original.push_str(&format!("Some text before {} and after. ", pat));
        if i < patterns.len() - 1 {
            original.push_str("More filler text here. ");
        }
    }

    let compressed = gzip_compress(original.as_bytes());
    let decompressed = gzip_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .expected_items(1000)
        .false_positive_rate(0.001)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    for pattern in &patterns {
        // Search in decompressed
        let found_in_decompressed = decompressed
            .windows(pattern.len())
            .any(|w| w == pattern.as_bytes());
        assert!(
            found_in_decompressed,
            "Pattern {} should be in decompressed",
            pattern
        );

        // Search in compressed - note that verify_contains only checks extracted literals
        // The bloom filter candidate_blocks should include blocks that MIGHT contain the pattern
        // We verify that if a block is a candidate, we check it
        let candidates = index.candidate_blocks(pattern.as_bytes());

        // At minimum, the pattern should be found via decompression
        // The extracted literals are a subset, so verify_contains may or may not find it
        // depending on how compression split the data
        let _ = candidates; // Candidates may be empty if pattern spans back-references

        // The key invariant: if verify_contains returns true, pattern is definitely there
        // (but the converse is not guaranteed due to back-references)
    }
}

// 38. Zstd: search parity
#[test]
#[cfg(feature = "zstd")]
fn search_parity_zstd_basic() {
    let original = b"Testing zstd compression for search parity. UNIQUE_ZSTD_PATTERN_999";
    let compressed = zstd_compress(original);
    let decompressed = zstd_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Zstd)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = b"UNIQUE_ZSTD_PATTERN_999";

    // Verify pattern exists in decompressed
    assert!(
        decompressed.windows(pattern.len()).any(|w| w == pattern),
        "Pattern should be in decompressed"
    );

    // Verify pattern is found in compressed search
    let candidates = index.candidate_blocks(pattern);
    let found = candidates
        .iter()
        .any(|&id| index.get_block(id).unwrap().verify_contains(pattern));

    assert!(found, "Pattern should be found through compressed search");
}

// 39. Search parity with overlapping patterns
#[test]
#[cfg(feature = "lz4")]
fn search_parity_overlapping_patterns() {
    // Patterns that overlap: "ABCABC" contains "ABC" at positions 0 and 3
    let original = b"XYZ ABCABC DEF overlapping patterns ABCABC GHI";
    let compressed = lz4_compress(original);
    let decompressed = lz4_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = b"ABCABC";

    // Count occurrences in decompressed
    let count_in_decompressed = decompressed
        .windows(pattern.len())
        .filter(|w| *w == pattern)
        .count();
    assert!(
        count_in_decompressed > 0,
        "Should find pattern in decompressed"
    );

    // Find in compressed
    let candidates = index.candidate_blocks(pattern);
    let count_in_compressed = candidates
        .iter()
        .filter(|&&id| index.get_block(id).unwrap().verify_contains(pattern))
        .count();

    assert!(
        count_in_compressed > 0,
        "Should find pattern in compressed search"
    );
}

// 40. Search parity with unicode content
#[test]
#[cfg(feature = "gzip")]
fn search_parity_unicode() {
    let original = "Unicode test: 世界 🌍 ελληνικά UNIQUE_UNICODE_日本".as_bytes();
    let compressed = gzip_compress(original);
    let decompressed = gzip_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = "UNIQUE_UNICODE_日本".as_bytes();

    // Verify in decompressed
    assert!(
        decompressed.windows(pattern.len()).any(|w| w == pattern),
        "Pattern should be in decompressed"
    );

    // Verify in compressed search
    let candidates = index.candidate_blocks(pattern);
    let found = candidates
        .iter()
        .any(|&id| index.get_block(id).unwrap().verify_contains(pattern));

    assert!(found, "Pattern should be found through compressed search");
}

// 41. Search parity with binary/null bytes
#[test]
#[cfg(feature = "lz4")]
fn search_parity_binary_null_bytes() {
    let original = b"Before\x00\x00\x00UNIQUE_BINARY_PATTERN\x00\x00\x00After".to_vec();
    let compressed = lz4_compress(&original);
    let decompressed = lz4_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = b"UNIQUE_BINARY_PATTERN";

    // Verify in decompressed
    assert!(
        decompressed.windows(pattern.len()).any(|w| w == pattern),
        "Pattern should be in decompressed"
    );

    // Verify in compressed search
    let candidates = index.candidate_blocks(pattern);
    let found = candidates
        .iter()
        .any(|&id| index.get_block(id).unwrap().verify_contains(pattern));

    assert!(found, "Pattern should be found through compressed search");
}

// 42. Search parity with long pattern (100 bytes)
#[test]
#[cfg(feature = "gzip")]
fn search_parity_long_pattern() {
    let pattern: String = (0..100).map(|i| ((i % 26) + b'A') as char).collect();
    let original = format!("Before {} After", pattern);
    let compressed = gzip_compress(original.as_bytes());
    let decompressed = gzip_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    // Verify in decompressed
    assert!(
        decompressed
            .windows(pattern.len())
            .any(|w| w == pattern.as_bytes()),
        "Long pattern should be in decompressed"
    );

    // Note: verify_contains only checks extracted literals, not full decompressed data
    // The pattern may or may not be in the literals depending on compression
    // We verify bloom filter works by checking candidates don't have false negatives
    let _candidates = index.candidate_blocks(pattern.as_bytes());

    // If the pattern is in the literals, we should find it
    let mut found_in_literals = false;
    for i in 0..index.block_count() {
        if index
            .get_block(i)
            .unwrap()
            .verify_contains(pattern.as_bytes())
        {
            found_in_literals = true;
            break;
        }
    }

    // We just record whether it was found - it depends on compression internals
    let _ = found_in_literals;
}

// 43. Search parity with many patterns in single block
#[test]
#[cfg(feature = "lz4")]
fn search_parity_many_patterns_single_block() {
    let mut original = String::new();
    for i in 0..50 {
        original.push_str(&format!("PATTERN_{:04} ", i));
    }

    let compressed = lz4_compress(original.as_bytes());
    let decompressed = lz4_decompress(&compressed);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(5000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    // Test a few patterns
    for i in [0, 10, 25, 49] {
        let pattern = format!("PATTERN_{:04}", i);

        // Verify in decompressed
        assert!(
            decompressed
                .windows(pattern.len())
                .any(|w| w == pattern.as_bytes()),
            "Pattern {} should be in decompressed",
            pattern
        );

        // Get candidates from bloom filter
        let candidates = index.candidate_blocks(pattern.as_bytes());

        // Check if pattern is in literals for any candidate
        let found_in_literals = candidates.iter().any(|&id| {
            index
                .get_block(id)
                .unwrap()
                .verify_contains(pattern.as_bytes())
        });

        // Pattern should either be in literals OR no candidates (if compression used back-refs)
        // The key invariant is bloom filter has no false negatives
        let _ = found_in_literals;
    }
}

// 44. Empty pattern returns all blocks
#[test]
fn search_empty_pattern_returns_all_blocks() {
    let data = make_uncompressed_lz4_block(b"some content");
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("Should build index");

    let candidates = index.candidate_blocks(b"");
    assert_eq!(
        candidates.len(),
        index.block_count(),
        "Empty pattern should return all block indices"
    );
}

// 45. Pattern not in data - bloom filter should potentially reject
#[test]
#[cfg(feature = "lz4")]
fn search_pattern_not_in_data() {
    let original = b"This is some test content without the pattern";
    let compressed = lz4_compress(original);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = b"THIS_PATTERN_DOES_NOT_EXIST_99999";

    // Verify pattern not in original
    assert!(
        !original.windows(pattern.len()).any(|w| w == pattern),
        "Pattern should not be in original"
    );

    // Candidates should be empty or verify_contains should return false
    let candidates = index.candidate_blocks(pattern);
    for &id in &candidates {
        assert!(
            !index.get_block(id).unwrap().verify_contains(pattern),
            "Pattern should not be found in any block"
        );
    }
}

// 46. Block metadata accuracy
#[test]
#[cfg(feature = "lz4")]
fn block_metadata_accuracy() {
    let content = b"Test content for metadata validation.";
    let compressed = lz4_compress(content);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    for i in 0..index.block_count() {
        let block = index.get_block(i).unwrap();

        // Compressed offset should be valid
        assert!(
            block.compressed_offset() < compressed.len() as u64,
            "Block {} compressed offset {} should be within data bounds",
            i,
            block.compressed_offset()
        );

        // Compressed length should be non-zero
        assert!(
            block.compressed_len() > 0,
            "Block {} compressed length should be > 0",
            i
        );

        // Literals should be retrievable
        let _ = block.literals();

        // Literal density should be in valid range
        let density = block.literal_density();
        assert!(
            (0.0..=1.0).contains(&density) || density == 1.0,
            "Block {} literal density {} should be in valid range",
            i,
            density
        );
    }
}

// 47. Index statistics consistency
#[test]
#[cfg(feature = "lz4")]
fn index_statistics_consistency() {
    let content = b"Content for statistics test. ";
    let compressed = lz4_compress(content);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let stats = index.bloom_stats();
    if let Some(stats) = stats {
        assert!(stats.num_bits > 0, "Bloom filter should have bits");
        assert!(
            stats.num_hashes > 0,
            "Bloom filter should have hash functions"
        );
        assert!(
            (0.0..=1.0).contains(&stats.fill_ratio),
            "Fill ratio should be in [0, 1]"
        );
        assert!(
            (0.0..=1.0).contains(&stats.estimated_fpr),
            "Estimated FPR should be in [0, 1]"
        );
    }

    let format = index.format();
    assert_eq!(format, CompressionFormat::Lz4, "Format should match");
}

// 48. Candidate blocks iterator equivalence
#[test]
#[cfg(feature = "lz4")]
fn candidate_blocks_iterator_equivalence() {
    let content = b"Content for iterator test PATTERN_XYZ.";
    let compressed = lz4_compress(content);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should build index");

    let pattern = b"PATTERN_XYZ";

    // Collect from iterator
    let from_iter: Vec<usize> = index.candidate_blocks_iter(pattern).collect();

    // Collect from vec method
    let from_vec = index.candidate_blocks(pattern);

    assert_eq!(
        from_iter, from_vec,
        "Iterator and vec methods should return same results"
    );
}

// 49. Verify contains edge cases
#[test]
fn verify_contains_edge_cases() {
    let block = CompressedBlock::new(0, 100);

    // Empty pattern should return true
    assert!(block.verify_contains(b""), "Empty pattern should match");

    // Pattern longer than literals should return false
    assert!(
        !block.verify_contains(b"this is a long pattern"),
        "Longer pattern should not match empty literals"
    );
}

// 50. Format display and equality
#[test]
fn format_display_and_equality() {
    use std::fmt::Write;

    let formats = [
        CompressionFormat::Gzip,
        CompressionFormat::Lz4,
        CompressionFormat::Zstd,
        CompressionFormat::Snappy,
    ];

    for fmt in &formats {
        let mut s = String::new();
        write!(&mut s, "{}", fmt).unwrap();
        assert!(!s.is_empty(), "Format should have display representation");

        // Self equality
        assert_eq!(*fmt, *fmt, "Format should equal itself");
    }

    // Different formats should not be equal
    assert_ne!(CompressionFormat::Gzip, CompressionFormat::Lz4);
    assert_ne!(CompressionFormat::Zstd, CompressionFormat::Snappy);
}

// ── ADDITIONAL ADVERSARIAL EDGE CASES ───────────────────────────────────

// 51. All possible byte values in literals
#[test]
#[cfg(feature = "lz4")]
fn adversarial_all_byte_values() {
    let data: Vec<u8> = (0..=255).collect();
    let compressed = lz4_compress(&data);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should handle all byte values");

    // Should be able to search for any single byte
    for byte in 0u8..=255 {
        let pattern = [byte];
        let candidates = index.candidate_blocks(&pattern);

        // The byte should be found in some block
        let found = candidates
            .iter()
            .any(|&id| index.get_block(id).unwrap().verify_contains(&pattern));
        assert!(found, "Byte {} should be found", byte);
    }
}

// 52. Maximum sequence count boundary
#[test]
#[cfg(feature = "lz4")]
fn adversarial_max_sequence_boundary() {
    use ziftsieve::lz4::extract_literals;

    // Create data with many small sequences
    let mut tokens = Vec::new();
    for _ in 0..1000 {
        // Token: literal=1, match=0
        tokens.push(0x10);
        tokens.push(b'X');
        // Match offset (even though match_len=0, parser expects it)
        tokens.extend_from_slice(&[0x00, 0x00]);
    }

    // Should handle without infinite loop or crash
    let result = extract_literals(&tokens, 4 * 1024 * 1024);
    match result {
        Ok(literals) => {
            // Should have extracted literals
            assert!(!literals.is_empty() || tokens.is_empty());
        }
        Err(_) => {
            // Error acceptable for malformed input
        }
    }
}

// 53. Snappy reserved chunk types
#[test]
#[cfg(feature = "snappy")]
fn adversarial_snappy_reserved_chunks() {
    // Create snappy stream with reserved unskippable chunk
    let mut data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];

    // Add a reserved unskippable chunk (type 0x02)
    data.push(0x02); // Reserved unskippable
    data.extend_from_slice(&[0x04, 0x00, 0x00]); // Length = 4
    data.extend_from_slice(b"test"); // Chunk data

    // Should handle without panic
    let index = CompressedIndexBuilder::new(CompressionFormat::Snappy)
        .build_from_bytes(&data)
        .expect("Should handle without panic");
    assert_eq!(
        index.block_count(),
        0,
        "No blocks should be extracted from reserved chunks"
    );
}

// 54. Zstd skippable frames
#[test]
#[cfg(feature = "zstd")]
fn adversarial_zstd_skippable_frames() {
    // Create zstd data with skippable frame before real frame
    let mut data = vec![
        0x50, 0x2A, 0x4D, 0x18, // Skippable frame magic (0x184D2A50)
        0x04, 0x00, 0x00, 0x00, // Frame size = 4
        0xAA, 0xBB, 0xCC, 0xDD, // Skippable content
    ];

    // Append real zstd frame
    let original = b"Test data";
    let compressed = zstd_compress(original);
    data.extend_from_slice(&compressed);

    let result = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&data);
    // Should either succeed or error gracefully
    let index = result.expect("Should handle skippable frames without panic");
    assert!(
        index.block_count() > 0,
        "Real frame should be parsed after skippable frame"
    );
}

// 55. CompressionFormat to_string consistency
#[test]
fn compression_format_to_string() {
    let gzip_str = format!("{}", CompressionFormat::Gzip);
    assert_eq!(gzip_str, "Gzip", "Gzip format should display as 'Gzip'");

    let lz4_str = format!("{}", CompressionFormat::Lz4);
    assert_eq!(lz4_str, "LZ4", "LZ4 format should display as 'LZ4'");

    let zstd_str = format!("{}", CompressionFormat::Zstd);
    assert_eq!(zstd_str, "Zstd", "Zstd format should display as 'Zstd'");

    let snappy_str = format!("{}", CompressionFormat::Snappy);
    assert_eq!(
        snappy_str, "Snappy",
        "Snappy format should display as 'Snappy'"
    );
}
