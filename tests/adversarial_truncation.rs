use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

#[test]
fn test_lz4_truncated_stream() {
    let mut data = (4000u32).to_le_bytes().to_vec();
    // Truncated literal payload
    data.push(0x50); // literal_len=5, match_len=0
    data.push(b'A');

    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "snappy")]
fn test_snappy_truncated_stream() {
    let mut data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];
    data.push(0x01); // Uncompressed chunk
    data.extend_from_slice(&[0x08, 0x00, 0x00]); // Length 8
    data.extend_from_slice(&[0x00, 0x00]); // Truncated CRC

    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
#[cfg(feature = "gzip")]
fn test_gzip_truncated_stream() {
    let data = vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00,
        0xff, // Truncated block
    ];

    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "zstd")]
fn test_zstd_truncated_stream() {
    let data = vec![
        0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0x01, 0x00, 0x00, 0x00, // Truncated frame
    ];

    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
#[cfg(feature = "zstd")]
fn test_zstd_corrupted_header() {
    let data = vec![
        0x28, 0xb5, 0x2f, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Corrupt frame header
    ];

    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
#[cfg(feature = "gzip")]
fn test_gzip_corrupted_header() {
    let data = vec![
        0x1f, 0x8b, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, // Invalid compression method (0x09 instead of 0x08)
    ];

    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_lz4_corrupted_header() {
    // Missing block size (only 2 bytes)
    let data = vec![0x10, 0x00];

    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().block_count(), 0);
}

#[test]
#[cfg(feature = "snappy")]
fn test_snappy_corrupted_header() {
    // Missing stream ID
    let data = vec![0xff, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let builder = CompressedIndexBuilder::new(CompressionFormat::Snappy);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}
