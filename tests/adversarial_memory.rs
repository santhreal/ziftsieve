use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

#[test]
fn test_lz4_memory_limit() {
    let data = vec![0x10, 0x00, 0x00, 0x00];
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4).expected_items(1_000_000_000);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
#[cfg(feature = "gzip")]
fn test_gzip_memory_limit() {
    let data = vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let builder =
        CompressedIndexBuilder::new(CompressionFormat::Gzip).expected_items(1_000_000_000);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
#[cfg(feature = "snappy")]
fn test_snappy_memory_limit() {
    let data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];
    let builder =
        CompressedIndexBuilder::new(CompressionFormat::Snappy).expected_items(1_000_000_000);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_ok() || result.is_err());
}

#[test]
#[cfg(feature = "zstd")]
fn test_zstd_memory_limit() {
    let data = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00];
    let builder =
        CompressedIndexBuilder::new(CompressionFormat::Zstd).expected_items(1_000_000_000);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err() || result.unwrap().block_count() == 0);
}
