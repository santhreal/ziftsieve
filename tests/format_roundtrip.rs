//! Round-trip, malformed, empty, and large-input tests for every supported format.

use ziftsieve::{extract_from_bytes, CompressedIndexBuilder, CompressionFormat};

// ============================================================================
// LZ4
// ============================================================================

#[test]
fn lz4_empty_input_is_rejected() {
    let result = extract_from_bytes(CompressionFormat::Lz4, b"");
    assert!(
        matches!(result, Err(ziftsieve::ZiftError::InvalidData { .. })),
        "empty input should be rejected"
    );
}

#[test]
fn lz4_truncated_frame_header() {
    // LZ4 magic followed by incomplete header
    let data = [0x04, 0x22, 0x4d, 0x18, 0x60];
    let result = extract_from_bytes(CompressionFormat::Lz4, &data);
    assert!(result.is_err(), "truncated frame header should be rejected");
}

#[test]
fn lz4_corrupted_token_stream() {
    // Framed LZ4 with a COMPRESSED block containing a token that claims more
    // literals than the block contains.
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    // compressed block: size=2, high bit NOT set (compressed)
    data.extend_from_slice(&0x0000_0002_u32.to_le_bytes());
    data.push(0x20); // token: literal_len=2, but only 0 literal bytes follow
    data.extend_from_slice(&0_u32.to_le_bytes()); // end marker
    let result = extract_from_bytes(CompressionFormat::Lz4, &data);
    assert!(result.is_err(), "corrupted token stream should be rejected");
}

#[test]
fn lz4_uncompressed_block_roundtrip() {
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    // uncompressed block: size=5, high bit set
    data.extend_from_slice(&(0x8000_0005_u32).to_le_bytes());
    data.extend_from_slice(b"hello");
    data.extend_from_slice(&0_u32.to_le_bytes()); // end marker

    let blocks = extract_from_bytes(CompressionFormat::Lz4, &data).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].literals(), b"hello");
    assert!(blocks[0].verify_contains(b"ell"));
    assert!(!blocks[0].verify_contains(b"xyz"));
}

#[test]
fn lz4_large_literal_block() {
    let payload = vec![b'a'; 1024 * 1024];
    let mut data = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x00];
    // uncompressed block: size = payload.len(), high bit set
    data.extend_from_slice(&(0x8000_0000u32 | payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&payload);
    data.extend_from_slice(&0_u32.to_le_bytes()); // end marker

    let blocks = extract_from_bytes(CompressionFormat::Lz4, &data).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].literals().len(), payload.len());
    assert!(blocks[0].verify_contains(b"aaaa"));
}

// ============================================================================
// Snappy
// ============================================================================

#[cfg(feature = "snappy")]
mod snappy_tests {
    use super::*;

    #[test]
    fn snappy_empty_input() {
        let blocks = extract_from_bytes(CompressionFormat::Snappy, b"").unwrap();
        assert!(
            blocks.is_empty(),
            "empty snappy input should yield no blocks"
        );
    }

    #[test]
    fn snappy_truncated_stream_id() {
        let data = [0xff, 0x06, 0x00]; // truncated stream identifier
        let result = extract_from_bytes(CompressionFormat::Snappy, &data);
        assert!(
            result.is_err(),
            "truncated stream identifier should be rejected"
        );
    }

    #[test]
    fn snappy_chunk_exceeds_bounds() {
        let mut data = vec![
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
        ];
        data.push(0x01); // Uncompressed chunk
        data.extend_from_slice(&[0x20, 0x00, 0x00]); // Claims 32 bytes, only 0 follow
        let result = extract_from_bytes(CompressionFormat::Snappy, &data);
        assert!(result.is_err(), "chunk exceeding bounds should be rejected");
    }

    #[test]
    fn snappy_uncompressed_chunk_roundtrip() {
        let mut data = vec![
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
        ];
        data.push(0x01); // Uncompressed chunk
        let payload = b"snappy roundtrip";
        data.extend_from_slice(&(payload.len() as u32 + 4).to_le_bytes()[..3]); // length = payload + 4 CRC
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Dummy CRC
        data.extend_from_slice(payload);

        let blocks = extract_from_bytes(CompressionFormat::Snappy, &data).unwrap();
        assert!(!blocks.is_empty(), "should produce at least one block");
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert_eq!(&literals, payload);
    }

    #[test]
    fn snappy_large_payload() {
        // Snappy max chunk size is 64KB, so split into multiple chunks
        let payload = vec![b'x'; 128 * 1024];
        let mut data = vec![
            0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
        ];

        let chunk_size: usize = 60 * 1024; // Stay under 64KB limit (including 4-byte CRC)
        for chunk in payload.chunks(chunk_size) {
            data.push(0x01); // Uncompressed chunk
            data.extend_from_slice(&(chunk.len() as u32 + 4).to_le_bytes()[..3]);
            data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Dummy CRC
            data.extend_from_slice(chunk);
        }

        let blocks = extract_from_bytes(CompressionFormat::Snappy, &data).unwrap();
        assert!(!blocks.is_empty());
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert_eq!(literals.len(), payload.len());
    }
}

// ============================================================================
// Gzip
// ============================================================================

#[cfg(feature = "gzip")]
mod gzip_tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_empty_stream() {
        let compressed = gzip_compress(b"");
        let blocks = extract_from_bytes(CompressionFormat::Gzip, &compressed).unwrap();
        assert!(
            blocks.iter().all(|b| b.literals().is_empty()),
            "empty gzip should yield only empty literal blocks"
        );
    }

    #[test]
    fn gzip_truncated_header() {
        let result = extract_from_bytes(CompressionFormat::Gzip, &[0x1f, 0x8b]);
        assert!(result.is_err(), "truncated gzip header should be rejected");
    }

    #[test]
    fn gzip_corrupted_magic() {
        let result = extract_from_bytes(CompressionFormat::Gzip, &[0x00, 0x00, 0x08, 0x00]);
        assert!(result.is_err(), "invalid magic should be rejected");
    }

    #[test]
    fn gzip_extracts_literals_from_fixed_huffman() {
        let payload = b"gzip fixed huffman roundtrip";
        let compressed = gzip_compress(payload);
        let blocks = extract_from_bytes(CompressionFormat::Gzip, &compressed).unwrap();
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        // Fixed Huffman with small payloads often stores everything as literals
        assert!(!literals.is_empty(), "should extract literals");
        assert!(String::from_utf8_lossy(&literals).contains("gzip"));
    }

    #[test]
    fn gzip_extracts_literals_from_dynamic_huffman() {
        // Repeating data forces dynamic Huffman trees
        let payload = b"dynamic huffman gzip roundtrip test ".repeat(500);
        let compressed = gzip_compress(&payload);
        let blocks = extract_from_bytes(CompressionFormat::Gzip, &compressed).unwrap();
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert!(
            !literals.is_empty(),
            "should extract literals from dynamic huffman"
        );
        assert!(String::from_utf8_lossy(&literals).contains("dynamic"));
    }

    #[test]
    fn gzip_large_payload() {
        let payload = vec![b'y'; 512 * 1024];
        let compressed = gzip_compress(&payload);
        let blocks = extract_from_bytes(CompressionFormat::Gzip, &compressed).unwrap();
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert!(
            !literals.is_empty(),
            "should extract literals from large gzip"
        );
    }
}

// ============================================================================
// Zstd
// ============================================================================

#[cfg(feature = "zstd")]
mod zstd_tests {
    use super::*;
    use zstd::stream::encode_all;

    fn zstd_compress(data: &[u8]) -> Vec<u8> {
        encode_all(data, 1).unwrap()
    }

    #[test]
    fn zstd_empty_input() {
        let compressed = zstd_compress(b"");
        let blocks = extract_from_bytes(CompressionFormat::Zstd, &compressed).unwrap();
        // Empty zstd frames may produce zero blocks
        assert!(
            blocks.iter().all(|b| b.literals().is_empty()),
            "empty zstd should yield empty literals"
        );
    }

    #[test]
    fn zstd_truncated_header() {
        let result = extract_from_bytes(CompressionFormat::Zstd, &[0x28, 0xb5, 0x2f]);
        assert!(result.is_err(), "truncated zstd header should be rejected");
    }

    #[test]
    fn zstd_invalid_magic() {
        let result = extract_from_bytes(CompressionFormat::Zstd, &[0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err(), "invalid magic should be rejected");
    }

    #[test]
    fn zstd_extracts_literals_small() {
        let payload = b"zstd small payload";
        let compressed = zstd_compress(payload);
        let blocks = extract_from_bytes(CompressionFormat::Zstd, &compressed).unwrap();
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert!(!literals.is_empty(), "should extract literals");
        assert!(String::from_utf8_lossy(&literals).contains("zstd"));
    }

    #[test]
    fn zstd_extracts_literals_repeating() {
        let payload = b"repeat ".repeat(1_000);
        let compressed = zstd_compress(&payload);
        let blocks = extract_from_bytes(CompressionFormat::Zstd, &compressed).unwrap();
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert!(
            !literals.is_empty(),
            "should extract literals from repeating data"
        );
    }

    #[test]
    fn zstd_large_payload() {
        let payload = vec![b'z'; 512 * 1024];
        let compressed = zstd_compress(&payload);
        let blocks = extract_from_bytes(CompressionFormat::Zstd, &compressed).unwrap();
        let literals: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.literals().iter().copied())
            .collect();
        assert!(
            !literals.is_empty(),
            "should extract literals from large zstd"
        );
    }
}

// ============================================================================
// Cross-format index builder tests
// ============================================================================

#[test]
fn index_builder_rejects_malformed_lz4() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&[0xff; 100]);
    assert!(result.is_err());
}

#[cfg(feature = "gzip")]
#[test]
fn index_builder_rejects_malformed_gzip() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let result = builder.build_from_bytes(&[0xff; 100]);
    assert!(result.is_err());
}

#[cfg(feature = "snappy")]
#[test]
fn index_builder_rejects_malformed_snappy() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let result = builder.build_from_bytes(&[0xff; 100]);
    assert!(result.is_err());
}

#[cfg(feature = "zstd")]
#[test]
fn index_builder_rejects_malformed_zstd() {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let result = builder.build_from_bytes(&[0xff; 100]);
    assert!(result.is_err());
}
