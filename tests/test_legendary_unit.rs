#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::error::Error;
use ziftsieve::{
    CompressedBlock, CompressedIndexBuilder, CompressionFormat, StreamingIndexBuilder,
};

#[test]
fn test_compressed_index_builder_lz4() -> Result<(), Box<dyn Error>> {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.01)
        .bloom_bits(1024)
        .bloom_hashes(3);

    // Empty LZ4 is rejected. Use end-of-frame marker.
    assert!(builder.clone().build_from_bytes(b"").is_err());
    let index = builder.build_from_bytes(&[0, 0, 0, 0])?;

    assert_eq!(index.format(), CompressionFormat::Lz4);
    assert_eq!(index.block_count(), 0);
    assert!(index.bloom_stats().is_none());
    assert_eq!(index.estimated_fpr(100), 0.0);

    let candidates = index.candidate_blocks(b"test");
    assert!(candidates.is_empty());

    let empty_candidates = index.candidate_blocks(b"");
    assert!(empty_candidates.is_empty());

    Ok(())
}

#[test]
fn test_streaming_index_builder_lz4() -> Result<(), Box<dyn Error>> {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4).expected_items(1000);

    // Empty chunk is a no-op for streaming builder.
    builder.process_chunk(&[0, 0, 0, 0])?;

    let index = builder.finalize()?;
    assert_eq!(index.format(), CompressionFormat::Lz4);
    assert_eq!(index.block_count(), 0);

    Ok(())
}

#[test]
fn test_compressed_block_methods() -> Result<(), Box<dyn Error>> {
    let block = CompressedBlock::new(100, 500);
    assert_eq!(block.compressed_offset(), 100);
    assert_eq!(block.compressed_len(), 500);
    assert_eq!(block.uncompressed_len(), None);
    assert_eq!(block.literals(), b"");
    assert_eq!(block.literal_density(), 1.0); // uncompressed_len is None

    // Test empty slice verify behavior
    assert!(block.verify_contains(b""));
    assert!(!block.verify_contains(b"foo"));

    Ok(())
}
