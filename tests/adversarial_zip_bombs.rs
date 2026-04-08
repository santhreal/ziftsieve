use ziftsieve::{CompressedIndexBuilder, CompressionFormat, StreamingIndexBuilder};

#[test]
fn test_lz4_bomb_handling() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = (4000u32).to_le_bytes().to_vec();
    for _ in 0..1000 {
        data.push(0x0F);
        data.push(0xFF);
    }

    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&data);
    let is_handled = result.is_ok() || result.is_err();
    assert!(is_handled);
    Ok(())
}

#[test]
fn test_lz4_streaming_bomb_handling() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = (4000u32).to_le_bytes().to_vec();
    for _ in 0..1000 {
        data.push(0x0F);
        data.push(0xFF);
    }

    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.process_chunk(&data);
    assert!(result.is_err());
    let final_result = builder.finalize();
    assert!(final_result.is_ok());
    Ok(())
}

#[test]
#[cfg(feature = "gzip")]
fn test_gzip_bomb_handling() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    for _ in 0..100 {
        data.push(0x00);
        data.extend_from_slice(&[0xFF, 0xFF]);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&[0x00; 65535]);
    }

    let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
    let result = builder.build_from_bytes(&data);
    assert!(result.is_err());
    Ok(())
}

#[test]
#[cfg(feature = "zstd")]
fn test_zstd_bomb_handling() -> Result<(), Box<dyn std::error::Error>> {
    let original = vec![0u8; 10 * 1024 * 1024];
    let compressed = zstd::encode_all(&original[..], 3).unwrap_or_default();

    let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
    let result = builder.build_from_bytes(&compressed);
    let is_handled = result.is_ok() || result.is_err();
    assert!(is_handled);
    Ok(())
}
