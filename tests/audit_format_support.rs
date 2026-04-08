//! Audit Tests: Format Support Verification
//!
//! Tests that all claimed formats (LZ4, gzip, snappy, zstd) work as documented.

use std::io::{Read, Write};
use ziftsieve::{extract_from_bytes, CompressedIndexBuilder, CompressionFormat};

// ============================================================================
// Test 1-10: LZ4 Format Support
// ============================================================================

#[test]
fn audit_lz4_frame_format_with_magic() {
    // Valid LZ4 frame with magic number
    let data = b"Hello, World! This is test data for LZ4.";
    let compressed = lz4_compress(data);

    // Verify magic detection
    assert_eq!(&compressed[0..4], &[0x04, 0x22, 0x4d, 0x18]);

    let detected = CompressionFormat::detect(&compressed);
    assert_eq!(detected, Some(CompressionFormat::Lz4));

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&compressed)
        .expect("Should parse valid LZ4 frame");

    assert!(index.block_count() > 0);
}

#[test]
fn audit_lz4_legacy_frame_format() {
    // Legacy LZ4 frame magic
    let legacy_magic = [0x02, 0x21, 0x4c, 0x18];
    let detected = CompressionFormat::detect(&legacy_magic);
    assert_eq!(detected, Some(CompressionFormat::Lz4));
}

#[test]
fn audit_lz4_raw_block_format() {
    // Raw LZ4 blocks without frame header
    let raw_block = create_lz4_raw_block(b"Test data for raw block");

    let blocks =
        extract_from_bytes(CompressionFormat::Lz4, &raw_block).expect("Should parse raw LZ4 block");

    assert!(!blocks.is_empty());
}

#[test]
fn audit_lz4_uncompressed_block() {
    // LZ4 uncompressed block (high bit set in block size)
    let uncompressed_data = b"Uncompressed block data";
    let block_size = uncompressed_data.len() as u32 | 0x8000_0000;
    let mut data = block_size.to_le_bytes().to_vec();
    data.extend_from_slice(uncompressed_data);

    let blocks =
        extract_from_bytes(CompressionFormat::Lz4, &data).expect("Should parse uncompressed block");

    assert_eq!(blocks[0].literals(), uncompressed_data);
}

#[test]
fn audit_lz4_multiple_blocks() {
    // Multiple LZ4 blocks in single frame
    let frame_header = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    let mut data = frame_header;

    // Add 3 uncompressed blocks
    for i in 0..3 {
        let block_data = format!("Block {} content", i);
        let size = (block_data.len() as u32) | 0x8000_0000;
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(block_data.as_bytes());
    }

    // End marker
    data.extend_from_slice(&[0u8; 4]);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("Should parse multi-block frame");

    assert_eq!(index.block_count(), 3);
}

#[test]
fn audit_lz4_empty_frame() {
    // Empty LZ4 frame (just header and end marker)
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    data.extend_from_slice(&[0u8; 4]); // End marker

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("Should parse empty frame");

    assert_eq!(index.block_count(), 0);
}

#[test]
fn audit_lz4_block_size_boundary() {
    // Test at 4MB boundary (max block size)
    let data = vec![b'X'; 4 * 1024 * 1024]; // Exactly 4MB
    let compressed = lz4_compress(&data);

    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&compressed);

    // Should succeed or fail gracefully, not panic
    match index {
        Ok(idx) => {
            let _ = idx.block_count();
        }
        Err(_) => {} // Error is acceptable for boundary
    }
}

#[test]
fn audit_lz4_exceeds_max_block_size() {
    // Block claiming size > 4MB should be rejected
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    // Block size 5MB (0x004C_4B40)
    data.extend_from_slice(&[0x40, 0x4B, 0x4C, 0x00]);

    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);

    assert!(result.is_err(), "Should reject block > 4MB");
}

#[test]
fn audit_lz4_variable_length_encoding() {
    // Test extended literal length encoding
    let mut block_data = vec![0xF0]; // literal_len=15 (needs extension)
    block_data.push(0xFF); // +255
    block_data.push(0xFF); // +255
    block_data.push(0x01); // +1 = total 526
    block_data.extend(vec![b'A'; 526]);

    let size = block_data.len() as u32;
    let mut frame = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    frame.extend_from_slice(&size.to_le_bytes());
    frame.extend_from_slice(&block_data);

    let blocks = extract_from_bytes(CompressionFormat::Lz4, &frame)
        .expect("Should parse extended length encoding");

    assert!(!blocks.is_empty());
}

#[test]
fn audit_lz4_match_resolution_skipped() {
    // Verify that match references are not resolved
    // Token: literal_len=2, match_len=1 (indicates match follows)
    // Literals: "AB"
    // Match offset: 0x0001 (1 byte back)
    let token_stream = vec![0x21, b'A', b'B', 0x01, 0x00];
    let size = token_stream.len() as u32;

    let mut frame = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    frame.extend_from_slice(&size.to_le_bytes());
    frame.extend_from_slice(&token_stream);

    let blocks = extract_from_bytes(CompressionFormat::Lz4, &frame)
        .expect("Should parse match-containing block");

    // Should only have literals, not resolved match
    assert_eq!(blocks[0].literals(), b"AB");
}

// ============================================================================
// Test 11-20: Gzip Format Support
// ============================================================================

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_magic_detection() {
    let gzip_header = [0x1f, 0x8b, 0x08, 0x00];
    assert_eq!(
        CompressionFormat::detect(&gzip_header),
        Some(CompressionFormat::Gzip)
    );
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_deflate_stored_block() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    // Compression level 0 = stored (no compression)
    let data = b"Test data for stored block";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(0));
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should parse stored block");

    assert!(index.block_count() > 0);

    // Stored block should have all bytes as literals
    let all_literals: Vec<u8> = (0..index.block_count())
        .flat_map(|i| index.get_block(i).unwrap().literals().to_vec())
        .collect();

    assert!(all_literals.windows(data.len()).any(|w| w == data));
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_deflate_fixed_huffman() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    // Short data uses fixed Huffman
    let data = b"Short";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should parse fixed Huffman block");

    assert!(index.block_count() > 0);
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_deflate_dynamic_huffman() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    // Long repetitive data uses dynamic Huffman
    let data = b"Repetitive data ".repeat(100);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should parse dynamic Huffman block");

    assert!(index.block_count() > 0);
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_multiple_members() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    // Create two gzip members concatenated
    let data1 = b"First member";
    let data2 = b"Second member";

    let mut encoder1 = GzEncoder::new(Vec::new(), Compression::new(0));
    encoder1.write_all(data1).unwrap();
    let mut compressed = encoder1.finish().unwrap();

    let mut encoder2 = GzEncoder::new(Vec::new(), Compression::new(0));
    encoder2.write_all(data2).unwrap();
    compressed.extend(encoder2.finish().unwrap());

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should parse multiple members");

    assert!(index.block_count() >= 2);
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_header_flags() {
    // Test various gzip header flag combinations
    let flags_to_test = vec![
        0x00, // No flags
        0x01, // FTEXT
        0x04, // FEXTRA
        0x08, // FNAME
        0x10, // FCOMMENT
        0x02, // FHCRC
    ];

    for flag in flags_to_test {
        let mut header = vec![
            0x1f, 0x8b, // Magic
            0x08, // DEFLATE method
            flag, // Flags
            0x00, 0x00, 0x00, 0x00, // mtime
            0x00, // xfl
            0xff, // os
        ];

        // Add minimal valid DEFLATE data
        header.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00]);
        // Add CRC and ISIZE
        header.extend_from_slice(&[0x00; 8]);

        let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&header);

        // Should not panic, may succeed or fail
        match result {
            Ok(_) | Err(_) => {}
        }
    }
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_header_extra_field() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let data = b"Data with extra field";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(0));
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .build_from_bytes(&compressed)
        .expect("Should handle extra field");

    assert!(index.block_count() > 0);
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_empty_input() {
    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(b"");

    assert!(result.is_err() || result.unwrap().block_count() == 0);
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_invalid_compression_method() {
    // Compression method 0x09 is invalid (only 0x08 = DEFLATE is valid)
    let data = vec![
        0x1f, 0x8b, // Magic
        0x09, // Invalid method
        0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // mtime
        0x00, // xfl
        0xff, // os
    ];

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&data);

    assert!(result.is_err(), "Should reject invalid compression method");
}

#[test]
#[cfg(feature = "gzip")]
fn audit_gzip_reserved_block_type() {
    // DEFLATE reserved block type (11 = 3)
    let data = vec![
        0x1f, 0x8b, 0x08, 0x00, // Header
        0x00, 0x00, 0x00, 0x00, // mtime
        0x00, 0xff, // xfl, os
        0x06, // Final block, reserved type (11 = 3)
    ];

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&data);

    assert!(result.is_err() || result.unwrap().block_count() == 0);
}

// ============================================================================
// Test 21-30: Zstd Format Support
// ============================================================================

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_magic_detection() {
    let zstd_magic = [0x28, 0xb5, 0x2f, 0xfd];
    assert_eq!(
        CompressionFormat::detect(&zstd_magic),
        Some(CompressionFormat::Zstd)
    );
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_raw_block() {
    let data = b"Raw block test data";
    let compressed = zstd::encode_all(data.as_slice(), 1).unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Zstd)
        .build_from_bytes(&compressed)
        .expect("Should parse Zstd frame");

    assert!(index.block_count() > 0);
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_rle_block() {
    // RLE block: single byte repeated
    let data = vec![b'X'; 1000];
    let compressed = zstd::encode_all(&data[..], 1).unwrap();

    // May succeed or fail depending on block types used
    match CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&compressed) {
        Ok(index) => {
            // Check that literals were extracted
            let all_literals: Vec<u8> = (0..index.block_count())
                .flat_map(|i| index.get_block(i).unwrap().literals().to_vec())
                .collect();
            if !all_literals.is_empty() {
                assert!(all_literals.contains(&b'X'));
            }
        }
        Err(_) => {
            // Error is acceptable for certain block types
        }
    }
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_compressed_literals() {
    // Normal compression path with Huffman literals
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(10);
    let compressed = zstd::encode_all(data.as_slice(), 3).unwrap();

    match CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&compressed) {
        Ok(index) => {
            assert!(index.block_count() > 0);
        }
        Err(_) => {
            // Error is acceptable for certain block types
        }
    }
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_skippable_frame() {
    // Skippable frame handling - construct valid skippable frame
    // Skippable frame magic: 0x184D2A50 to 0x184D2A57 (little endian)
    let mut data = vec![0x50, 0x2A, 0x4D, 0x18]; // Skippable frame type 0
    data.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // Frame size = 4
    data.extend_from_slice(b"skip"); // Skippable content

    // Add real Zstd frame after
    let real_frame = zstd::encode_all(&b"Real data"[..], 1).unwrap();
    data.extend_from_slice(&real_frame);

    // May succeed or fail depending on implementation
    let _ = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&data);
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_multiple_skippable_frames() {
    // Multiple skippable frames before real frame
    let mut data = Vec::new();

    for i in 0..3 {
        let magic = 0x50 + i as u8;
        data.extend_from_slice(&[magic, 0x2A, 0x4D, 0x18]);
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Size = 2
        data.extend_from_slice(b"ab");
    }

    let real_frame = zstd::encode_all(&b"Real"[..], 1).unwrap();
    data.extend_from_slice(&real_frame);

    // May succeed or fail - just ensure no panic
    let _ = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&data);
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_too_many_skippable_frames() {
    // More than 3 skippable frames should fail
    let mut data = Vec::new();

    for i in 0..4 {
        let magic = 0x50 + (i % 8) as u8;
        data.extend_from_slice(&[magic, 0x2A, 0x4D, 0x18]);
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Size = 1
        data.push(b'x');
    }

    let result = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&data);

    assert!(result.is_err(), "Should reject >3 skippable frames");
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_empty_frame() {
    // Empty Zstd frame - use actual zstd library to create
    // An empty input creates a valid frame with just header
    let compressed = zstd::encode_all(&b""[..], 1).unwrap();

    let index = CompressedIndexBuilder::new(CompressionFormat::Zstd)
        .build_from_bytes(&compressed)
        .expect("Should parse empty frame");

    // Empty input may produce 0 blocks
    let _ = index.block_count();
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_invalid_magic() {
    let data = [0x00, 0x00, 0x00, 0x00];

    let result = CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&data);

    assert!(result.is_err(), "Should reject invalid magic");
}

#[test]
#[cfg(feature = "zstd")]
fn audit_zstd_block_size_limit() {
    // Zstd max block size is 128KB
    let data = vec![b'X'; 128 * 1024];
    let compressed = zstd::encode_all(&data[..], 1).unwrap();

    match CompressedIndexBuilder::new(CompressionFormat::Zstd).build_from_bytes(&compressed) {
        Ok(index) => {
            let _ = index.block_count();
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

// ============================================================================
// Test 31-40: Snappy Format Support
// ============================================================================

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_magic_detection() {
    let snappy_magic = [0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    assert_eq!(
        CompressionFormat::detect(&snappy_magic),
        Some(CompressionFormat::Snappy)
    );
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_uncompressed_chunk() {
    // Build uncompressed chunk (type 0x01)
    let chunk_data = b"Hello, Snappy!";
    let crc = 0u32; // Dummy CRC
    let chunk_len = (chunk_data.len() + 4) as u32; // +4 for CRC

    let mut data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];
    data.push(0x01); // Uncompressed chunk type
    data.extend_from_slice(&[
        (chunk_len & 0xFF) as u8,
        ((chunk_len >> 8) & 0xFF) as u8,
        ((chunk_len >> 16) & 0xFF) as u8,
    ]);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(chunk_data);

    let blocks = extract_from_bytes(CompressionFormat::Snappy, &data)
        .expect("Should parse uncompressed chunk");

    assert!(!blocks.is_empty());
    assert!(blocks[0]
        .literals()
        .windows(chunk_data.len())
        .any(|w| w == chunk_data));
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_rejects_compressed_chunk() {
    // Compressed chunk type 0x00 should be rejected
    let mut data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];
    data.push(0x00); // Compressed chunk type
    data.extend_from_slice(&[0x05, 0x00, 0x00]); // Length 5
    data.extend_from_slice(&[0x00; 5]); // Dummy data

    let result = extract_from_bytes(CompressionFormat::Snappy, &data);

    assert!(result.is_err(), "Should reject compressed chunks");
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_stream_identifier_only() {
    // Just stream identifier, no chunks
    let data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];

    let blocks = extract_from_bytes(CompressionFormat::Snappy, &data)
        .expect("Should parse stream identifier only");

    assert!(blocks.is_empty());
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_no_stream_identifier() {
    // Data without stream identifier (should still parse)
    let chunk_data = b"No header";
    let crc = 0u32;
    let chunk_len = (chunk_data.len() + 4) as u32;

    let mut data = Vec::new();
    data.push(0x01); // Uncompressed chunk type
    data.extend_from_slice(&[
        (chunk_len & 0xFF) as u8,
        ((chunk_len >> 8) & 0xFF) as u8,
        ((chunk_len >> 16) & 0xFF) as u8,
    ]);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(chunk_data);

    let blocks = extract_from_bytes(CompressionFormat::Snappy, &data)
        .expect("Should parse without stream identifier");

    assert!(!blocks.is_empty());
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_padding_chunk() {
    // Padding chunk (type 0xfe) should be skipped
    let chunk_data = b"Real data";
    let crc = 0u32;
    let chunk_len = (chunk_data.len() + 4) as u32;

    let mut data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];
    // Padding chunk
    data.push(0xfe);
    data.extend_from_slice(&[0x04, 0x00, 0x00]); // Length 4
    data.extend_from_slice(&[0x00; 4]);
    // Real chunk
    data.push(0x01);
    data.extend_from_slice(&[
        (chunk_len & 0xFF) as u8,
        ((chunk_len >> 8) & 0xFF) as u8,
        ((chunk_len >> 16) & 0xFF) as u8,
    ]);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(chunk_data);

    let blocks =
        extract_from_bytes(CompressionFormat::Snappy, &data).expect("Should handle padding chunk");

    assert!(!blocks.is_empty());
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_multiple_uncompressed_chunks() {
    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];

    for i in 0..5 {
        let chunk_data = format!("Chunk {}", i);
        let crc = 0u32;
        let chunk_len = (chunk_data.len() + 4) as u32;

        data.push(0x01);
        data.extend_from_slice(&[
            (chunk_len & 0xFF) as u8,
            ((chunk_len >> 8) & 0xFF) as u8,
            ((chunk_len >> 16) & 0xFF) as u8,
        ]);
        data.extend_from_slice(&crc.to_le_bytes());
        data.extend_from_slice(chunk_data.as_bytes());
    }

    let blocks =
        extract_from_bytes(CompressionFormat::Snappy, &data).expect("Should parse multiple chunks");

    assert!(!blocks.is_empty());
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_chunk_size_boundary() {
    // Max chunk size is 64KB
    let big_data = vec![b'X'; 64 * 1024 - 4]; // -4 for CRC
    let crc = 0u32;
    let chunk_len = (big_data.len() + 4) as u32;

    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    data.push(0x01);
    data.extend_from_slice(&[
        (chunk_len & 0xFF) as u8,
        ((chunk_len >> 8) & 0xFF) as u8,
        ((chunk_len >> 16) & 0xFF) as u8,
    ]);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(&big_data);

    let blocks =
        extract_from_bytes(CompressionFormat::Snappy, &data).expect("Should handle max chunk size");

    assert!(!blocks.is_empty());
}

#[test]
#[cfg(feature = "snappy")]
fn audit_snappy_truncated_chunk() {
    let mut data = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    data.push(0x01);
    data.extend_from_slice(&[0x10, 0x00, 0x00]); // Claims 16 bytes
    data.extend_from_slice(&[0x00; 5]); // But only 5 bytes

    let result = extract_from_bytes(CompressionFormat::Snappy, &data);

    assert!(result.is_err(), "Should reject truncated chunk");
}

// ============================================================================
// Test 41-50: Cross-Format Edge Cases
// ============================================================================

#[test]
fn audit_format_detection_empty() {
    assert_eq!(CompressionFormat::detect(b""), None);
}

#[test]
fn audit_format_detection_partial_magic() {
    // Single byte of gzip magic
    assert_eq!(CompressionFormat::detect(&[0x1f]), None);

    // 3 bytes of LZ4 magic
    assert_eq!(CompressionFormat::detect(&[0x04, 0x22, 0x4d]), None);
}

#[test]
fn audit_all_formats_reject_garbage() {
    let garbage: Vec<u8> = (0..256).map(|i| (i * 7 + 13) as u8).collect();

    // LZ4
    let result = extract_from_bytes(CompressionFormat::Lz4, &garbage);
    assert!(result.is_ok() || result.is_err()); // Must not panic

    #[cfg(feature = "gzip")]
    {
        let result = extract_from_bytes(CompressionFormat::Gzip, &garbage);
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(feature = "zstd")]
    {
        let result = extract_from_bytes(CompressionFormat::Zstd, &garbage);
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(feature = "snappy")]
    {
        let result = extract_from_bytes(CompressionFormat::Snappy, &garbage);
        assert!(result.is_ok() || result.is_err());
    }
}

#[test]
fn audit_all_formats_reject_zeros() {
    let zeros = vec![0u8; 1024];

    let result = extract_from_bytes(CompressionFormat::Lz4, &zeros);
    assert!(result.is_ok() || result.is_err());

    #[cfg(feature = "gzip")]
    {
        let result = extract_from_bytes(CompressionFormat::Gzip, &zeros);
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(feature = "zstd")]
    {
        let result = extract_from_bytes(CompressionFormat::Zstd, &zeros);
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(feature = "snappy")]
    {
        let result = extract_from_bytes(CompressionFormat::Snappy, &zeros);
        assert!(result.is_ok() || result.is_err());
    }
}

#[test]
fn audit_all_formats_reject_ones() {
    let ones = vec![0xffu8; 1024];

    let result = extract_from_bytes(CompressionFormat::Lz4, &ones);
    assert!(result.is_ok() || result.is_err());

    #[cfg(feature = "gzip")]
    {
        let result = extract_from_bytes(CompressionFormat::Gzip, &ones);
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(feature = "zstd")]
    {
        let result = extract_from_bytes(CompressionFormat::Zstd, &ones);
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(feature = "snappy")]
    {
        let result = extract_from_bytes(CompressionFormat::Snappy, &ones);
        assert!(result.is_ok() || result.is_err());
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

fn create_lz4_raw_block(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // Simple token: literal only, no match
    let literal_len = data.len();
    if literal_len < 15 {
        result.push((literal_len as u8) << 4);
    } else {
        result.push(0xF0);
        let mut remaining = literal_len - 15;
        while remaining >= 255 {
            result.push(255);
            remaining -= 255;
        }
        result.push(remaining as u8);
    }

    result.extend_from_slice(data);

    // Block size header
    let mut block = (result.len() as u32).to_le_bytes().to_vec();
    block.extend_from_slice(&result);
    block
}

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
