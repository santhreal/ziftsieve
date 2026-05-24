#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    clippy::panic,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    unused_comparisons,
    clippy::ignored_unit_patterns
)]
//! LZ4 parser test harness — adversarial and correctness testing.
//!
//! The LZ4 parser extracts literals from compressed blocks without decompression.
//! It must handle every possible malformed input without panicking, and correctly
//! extract literals from valid LZ4 data.

use proptest::prelude::*;
use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

// ── Helper: build raw LZ4 block data ────────────────────────────────────

/// Build a minimal LZ4 block stream: [4-byte size header][block data]
/// with the uncompressed flag set.
fn make_uncompressed_lz4_block(data: &[u8]) -> Vec<u8> {
    let size = (data.len() as u32) | 0x8000_0000;
    let mut out = size.to_le_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// Build multiple uncompressed LZ4 blocks.
fn make_uncompressed_lz4_blocks(blocks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for block in blocks {
        out.extend_from_slice(&make_uncompressed_lz4_block(block));
    }
    out
}

/// Build a raw LZ4 token stream for a single literal run.
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

/// Wrap raw token stream as a compressed LZ4 block (no uncompressed flag).
fn make_compressed_lz4_block(token_stream: &[u8]) -> Vec<u8> {
    let size = token_stream.len() as u32; // No 0x80000000 flag = compressed
    let mut out = size.to_le_bytes().to_vec();
    out.extend_from_slice(token_stream);
    out
}

// ── Correctness: uncompressed blocks ────────────────────────────────────

#[test]
fn uncompressed_single_block_extracts_all_literals() {
    let data = b"ERROR: connection refused";
    let blocks = make_uncompressed_lz4_block(data);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&blocks)
        .expect("valid uncompressed block");
    assert_eq!(index.block_count(), 1);
    assert_eq!(index.get_block(0).unwrap().literals(), data);
}

#[test]
fn uncompressed_multiple_blocks_separates_correctly() {
    let b1 = b"ERROR in block one";
    let b2 = b"WARNING in block two";
    let b3 = b"INFO in block three";
    let data = make_uncompressed_lz4_blocks(&[b1, b2, b3]);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid blocks");
    assert_eq!(index.block_count(), 3);
    assert_eq!(index.get_block(0).unwrap().literals(), b1.as_slice());
    assert_eq!(index.get_block(1).unwrap().literals(), b2.as_slice());
    assert_eq!(index.get_block(2).unwrap().literals(), b3.as_slice());
}

#[test]
fn uncompressed_empty_data_yields_no_blocks() {
    // Empty LZ4 input is rejected (no valid header).
    assert!(CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&[])
        .is_err());
    // End-of-frame marker produces empty index.
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&[0, 0, 0, 0])
        .expect("end-of-frame is valid");
    assert_eq!(index.block_count(), 0);
}

// ── Correctness: compressed blocks with literal tokens ──────────────────

#[test]
fn compressed_block_short_literal() {
    let literal = b"hello";
    let tokens = make_lz4_literal_token(literal);
    let data = make_compressed_lz4_block(&tokens);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid compressed block");
    assert_eq!(index.block_count(), 1);
    assert_eq!(index.get_block(0).unwrap().literals(), literal.as_slice());
}

#[test]
fn compressed_block_extended_literal() {
    // Literal length > 15 triggers extended encoding
    let literal = vec![b'X'; 300];
    let tokens = make_lz4_literal_token(&literal);
    let data = make_compressed_lz4_block(&tokens);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid extended literal");
    assert_eq!(index.get_block(0).unwrap().literals(), literal.as_slice());
}

#[test]
fn compressed_block_very_long_literal() {
    // Literal requiring multiple extension bytes (> 15 + 255*N)
    let literal = vec![b'Z'; 1500];
    let tokens = make_lz4_literal_token(&literal);
    let data = make_compressed_lz4_block(&tokens);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid long literal");
    assert_eq!(index.get_block(0).unwrap().literals(), literal.as_slice());
}

// ── Correctness: literal with match reference ───────────────────────────

#[test]
fn literal_followed_by_match_extracts_only_literal() {
    // Token: literal_len=3, match_len=4 (min match)
    // Literal: "ABC"
    // Match offset: 0x0001, match_len extension: none
    let mut tokens = vec![0x34]; // literal_len=3, match_len=4
    tokens.extend_from_slice(b"ABC");
    tokens.extend_from_slice(&[0x01, 0x00]); // match offset 1

    let data = make_compressed_lz4_block(&tokens);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid literal+match");
    assert_eq!(index.get_block(0).unwrap().literals(), b"ABC");
}

// ── Bloom filter integration ────────────────────────────────────────────

#[test]
fn bloom_filter_finds_pattern_in_correct_block() {
    let b1 = b"ERROR: disk full";
    let b2 = b"WARNING: low memory";
    let b3 = b"INFO: startup complete";
    let data = make_uncompressed_lz4_blocks(&[b1, b2, b3]);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(1000)
        .false_positive_rate(0.001)
        .build_from_bytes(&data)
        .expect("valid blocks");

    // "ERROR" should match block 0 (and maybe others as FP)
    let candidates = index.candidate_blocks(b"ERROR");
    assert!(
        candidates.contains(&0),
        "block 0 must be a candidate for 'ERROR'"
    );
    // Verify: block 0 actually contains it
    assert!(index.get_block(0).unwrap().verify_contains(b"ERROR"));
    // Verify: block 1 does NOT contain it
    assert!(!index.get_block(1).unwrap().verify_contains(b"ERROR"));
    // Verify: block 2 does NOT contain it
    assert!(!index.get_block(2).unwrap().verify_contains(b"ERROR"));
}

#[test]
fn bloom_filter_empty_pattern_returns_all_blocks() {
    let data = make_uncompressed_lz4_blocks(&[b"one", b"two", b"three"]);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid");
    let candidates = index.candidate_blocks(b"");
    assert_eq!(candidates.len(), 3);
}

#[test]
fn bloom_stats_populated_after_build() {
    let data = make_uncompressed_lz4_blocks(&[b"block with enough data for stats"]);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(100)
        .false_positive_rate(0.01)
        .build_from_bytes(&data)
        .expect("valid");
    let stats = index.bloom_stats().expect("should have stats");
    assert!(stats.num_bits > 0);
    assert!(stats.num_hashes > 0);
    assert!(stats.fill_ratio >= 0.0);
    assert!(stats.fill_ratio <= 1.0);
}

// ── Adversarial: malformed LZ4 data ─────────────────────────────────────

#[test]
fn truncated_block_header() {
    // Only 3 bytes — block header needs 4
    let result =
        CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&[0x10, 0x00, 0x00]);
    // Should succeed with 0 blocks (incomplete header = stop parsing)
    assert!(result.is_ok());
    assert_eq!(result.unwrap().block_count(), 0);
}

#[test]
fn block_size_exceeds_data() {
    // Block header claims 1000 bytes but only 10 exist
    let mut data = (1000u32).to_le_bytes().to_vec();
    data.extend_from_slice(&[0u8; 10]);
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn block_size_exceeds_max() {
    // Block header claims > 4MB (MAX_BLOCK_SIZE)
    let huge_size = 5 * 1024 * 1024u32;
    let data = huge_size.to_le_bytes();
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn zero_size_block_is_end_marker() {
    let data = [0u8; 4]; // size = 0 = end marker
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("zero size = end marker");
    assert_eq!(index.block_count(), 0);
}

#[test]
fn compressed_block_with_truncated_literal() {
    // Token claims 5 literal bytes but block only has 2
    let mut data = (3u32).to_le_bytes().to_vec(); // block size = 3
    data.push(0x50); // literal_len=5, match_len=0
    data.push(b'A'); // Only 1 literal byte (need 5)
    data.push(b'B');
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn compressed_block_with_truncated_match_offset() {
    // Token: literal=1, match=1. Literal byte present. Match offset truncated.
    let mut data = (3u32).to_le_bytes().to_vec(); // block size = 3
    data.push(0x11); // literal_len=1, match_len=1
    data.push(b'A'); // literal
    data.push(0x01); // Only 1 byte of offset (need 2)
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn compressed_block_with_truncated_length_extension() {
    // Token with literal_len=15, then extension byte is missing
    let mut data = (1u32).to_le_bytes().to_vec(); // block size = 1
    data.push(0xF0); // literal_len=15 (needs extension), match_len=0
                     // No extension byte!
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn all_0xff_bytes_dont_panic() {
    let data = vec![0xFF; 1024];
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    // Should error, not panic
    assert!(result.is_err());
}

#[test]
fn all_zeros_dont_panic() {
    let data = vec![0x00; 1024];
    let result = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    // size=0 is end marker, so this should succeed with 0 blocks
    assert!(result.is_ok());
}

#[test]
fn random_noise_doesnt_panic() {
    // Pseudo-random bytes generated deterministically
    let mut data = Vec::with_capacity(4096);
    let mut state = 0x12345678u64;
    for _ in 0..4096 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((state >> 33) as u8);
    }
    let _ = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(&data);
    // Don't care about result — just must not panic
}

// ── Streaming builder ───────────────────────────────────────────────────

#[test]
fn streaming_builder_matches_batch() {
    let b1 = make_uncompressed_lz4_block(b"first block data");
    let b2 = make_uncompressed_lz4_block(b"second block data");

    // Batch build
    let mut combined = b1.clone();
    combined.extend_from_slice(&b2);
    let batch_index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&combined)
        .expect("batch valid");

    // Streaming build
    let mut streaming = ziftsieve::StreamingIndexBuilder::new(CompressionFormat::Lz4);
    streaming.process_chunk(&b1).expect("chunk 1");
    streaming.process_chunk(&b2).expect("chunk 2");
    let stream_index = streaming.finalize().expect("finalize");

    assert_eq!(batch_index.block_count(), stream_index.block_count());
    for i in 0..batch_index.block_count() {
        assert_eq!(
            batch_index.get_block(i).unwrap().literals(),
            stream_index.get_block(i).unwrap().literals(),
            "block {i} literals differ between batch and streaming"
        );
    }
}

#[test]
fn streaming_builder_empty_finalize() {
    let streaming = ziftsieve::StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let index = streaming.finalize().expect("empty finalize");
    assert_eq!(index.block_count(), 0);
}

// ── Candidate block iterator ────────────────────────────────────────────

#[test]
fn candidate_blocks_iter_matches_vec() {
    let data = make_uncompressed_lz4_blocks(&[b"ERROR here", b"WARNING there", b"INFO that"]);
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .expected_items(100)
        .false_positive_rate(0.01)
        .build_from_bytes(&data)
        .expect("valid");

    let vec_result = index.candidate_blocks(b"ERROR");
    let iter_result: Vec<usize> = index.candidate_blocks_iter(b"ERROR").collect();
    assert_eq!(vec_result, iter_result);
}

// ── verify_contains edge cases ──────────────────────────────────────────

#[test]
fn verify_contains_pattern_longer_than_literals() {
    let data = make_uncompressed_lz4_block(b"hi");
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid");
    assert!(!index
        .get_block(0)
        .unwrap()
        .verify_contains(b"this is way longer than hi"));
}

#[test]
fn verify_contains_single_byte_pattern() {
    let data = make_uncompressed_lz4_block(b"abcdef");
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid");
    assert!(index.get_block(0).unwrap().verify_contains(b"c"));
    assert!(!index.get_block(0).unwrap().verify_contains(b"z"));
}

#[test]
fn verify_contains_pattern_at_boundaries() {
    let data = make_uncompressed_lz4_block(b"startmiddleend");
    let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
        .build_from_bytes(&data)
        .expect("valid");
    assert!(index.get_block(0).unwrap().verify_contains(b"start"));
    assert!(index.get_block(0).unwrap().verify_contains(b"end"));
    assert!(index
        .get_block(0)
        .unwrap()
        .verify_contains(b"startmiddleend"));
}

// ── Property tests ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        ..ProptestConfig::default()
    })]

    /// Uncompressed blocks always round-trip their literals correctly.
    #[test]
    fn uncompressed_block_roundtrip(
        content in prop::collection::vec(0u8..=255, 1..10000)
    ) {
        let data = make_uncompressed_lz4_block(&content);
        let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
            .build_from_bytes(&data)
            .expect("valid uncompressed block");
        prop_assert_eq!(index.block_count(), 1);
        prop_assert_eq!(index.get_block(0).unwrap().literals(), content.as_slice());
    }

    /// Arbitrary bytes never panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(
        data in prop::collection::vec(0u8..=255, 0..8192)
    ) {
        let _ = CompressedIndexBuilder::new(CompressionFormat::Lz4)
            .build_from_bytes(&data);
        // Must not panic — result doesn't matter
    }

    /// verify_contains is consistent with direct search.
    #[test]
    fn verify_contains_matches_naive_search(
        content in prop::collection::vec(0u8..=255, 1..500),
        pattern in prop::collection::vec(0u8..=255, 1..20)
    ) {
        let data = make_uncompressed_lz4_block(&content);
        let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
            .build_from_bytes(&data)
            .expect("valid");
        let block = index.get_block(0).unwrap();

        // Naive window search
        let expected = if pattern.len() <= content.len() {
            content.windows(pattern.len()).any(|w| w == pattern.as_slice())
        } else {
            false
        };
        prop_assert_eq!(block.verify_contains(&pattern), expected);
    }

    /// If bloom says "no", verify_contains must also say "no" for that block.
    /// (Bloom false negatives are bugs.)
    #[test]
    fn bloom_no_means_verify_no(
        content in prop::collection::vec(0u8..=255, 10..1000),
        pattern in prop::collection::vec(0u8..=255, 1..10)
    ) {
        let data = make_uncompressed_lz4_block(&content);
        let index = CompressedIndexBuilder::new(CompressionFormat::Lz4)
            .expected_items(content.len())
            .false_positive_rate(0.01)
            .build_from_bytes(&data)
            .expect("valid");

        let candidates = index.candidate_blocks(&pattern);
        let block = index.get_block(0).unwrap();

        if block.verify_contains(&pattern) {
            // If the pattern is truly there, bloom MUST say "maybe"
            prop_assert!(
                candidates.contains(&0),
                "bloom filter false negative: pattern is in block but bloom excluded it"
            );
        }
        // Note: bloom saying "maybe" when pattern is absent is OK (false positive)
    }
}
