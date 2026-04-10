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
//! Gzip parser test harness.
#![cfg(feature = "gzip")]

use std::io::Read;

use flate2::read::MultiGzDecoder;
use flate2::{write::GzEncoder, Compression};
use proptest::prelude::*;
use std::io::Write;
use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

fn gzip_compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).expect("valid input");
    encoder.finish().expect("gzip encode")
}

fn gzip_decompress(data: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).expect("gzip decode");
    out
}

fn is_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }

    let mut idx = 0usize;
    for byte in haystack {
        if *byte == needle[idx] {
            idx += 1;
            if idx == needle.len() {
                return true;
            }
        }
    }
    false
}

fn manual_two_block_gzip(blocks: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut crc_hasher = crc32fast::Hasher::new();
    for (idx, block) in blocks.iter().enumerate() {
        assert!(block.len() <= u16::MAX as usize);
        let bfinal = if idx + 1 == blocks.len() { 1u8 } else { 0u8 };
        out.push(bfinal);
        let len = u16::try_from(block.len()).expect("stored block length fits u16");
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(block);
        crc_hasher.update(block);
    }
    out.extend_from_slice(&crc_hasher.finalize().to_le_bytes());
    let isize = blocks
        .iter()
        .fold(0u64, |acc, block| acc.saturating_add(block.len() as u64));
    out.extend_from_slice(&(isize as u32).to_le_bytes());
    out
}

#[test]
fn gzip_extract_matches_decompressed_literals_for_no_compression_block() {
    let payload = b"gzip literal extraction checks with deterministic input. no repetitions here.";
    let compressed = gzip_compress(payload, 0);
    let blocks = ziftsieve::gzip::extract_literals(&compressed).expect("extract blocks");
    let extracted: Vec<u8> = blocks
        .iter()
        .flat_map(|b| b.literals().iter().copied())
        .collect();
    let decompressed = gzip_decompress(&compressed);

    assert_eq!(decompressed, payload);
    assert_eq!(extracted, payload);
}

#[test]
fn gzip_bloom_rejects_non_matching_blocks() {
    let first = gzip_compress(b"ERROR: alpha block with unique token A1", 0);
    let second = gzip_compress(b"WARN: beta block with unique token B2", 0);
    let mut data = Vec::new();
    data.extend_from_slice(&first);
    data.extend_from_slice(&second);

    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .bloom_bits(1_000_000)
        .bloom_hashes(4)
        .build_from_bytes(&data)
        .expect("build index");

    let candidates = index.candidate_blocks(b"WARN");
    assert!(candidates.contains(&1));
    assert!(!index.get_block(0).unwrap().verify_contains(b"WARN"));
}

#[test]
fn gzip_end_to_end_query_then_verify_with_full_decompression() {
    let block1 = b"INFO: service started ok";
    let block2 = b"ERROR: critical timeout occurred on node 17";
    let block3 = b"TRACE: heartbeat sequence";
    let input = [block1.as_ref(), block2.as_ref(), block3.as_ref()].concat();

    let compressed = gzip_compress(&input, 6);
    let index = CompressedIndexBuilder::new(CompressionFormat::Gzip)
        .expected_items(10_000)
        .false_positive_rate(0.001)
        .build_from_bytes(&compressed)
        .expect("build index");

    let pattern = b"critical";
    let candidates = index.candidate_blocks(pattern);
    assert!(!candidates.is_empty());

    let decompressed = gzip_decompress(&compressed);
    assert!(decompressed.windows(pattern.len()).any(|w| w == pattern));
    let found = candidates
        .iter()
        .any(|id| index.get_block(*id).unwrap().verify_contains(pattern));
    assert!(found);
}

#[test]
fn gzip_multi_block_member_parsed_as_multiple_blocks() {
    let payloads: [&[u8]; 2] = [b"first literal block", b"second literal block"];
    let raw = manual_two_block_gzip(&payloads);
    let blocks = ziftsieve::gzip::extract_literals(&raw).expect("extract");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].literals(), payloads[0]);
    assert_eq!(blocks[1].literals(), payloads[1]);
}

#[test]
fn gzip_multiple_members_parse_as_multiple_blocks() {
    let first = gzip_compress(b"member one literal text", 0);
    let second = gzip_compress(b"member two payload with different bytes", 0);
    let mut data = Vec::new();
    data.extend_from_slice(&first);
    data.extend_from_slice(&second);

    let blocks = ziftsieve::gzip::extract_literals(&data).expect("extract members");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].literals(), b"member one literal text");
    assert_eq!(
        blocks[1].literals(),
        b"member two payload with different bytes"
    );
}

proptest! {
    #[test]
    fn dynamic_huffman_literals_are_subsequence_of_decompressed_output(input in proptest::collection::vec(any::<u8>(), 0..128)) {
        let data = input;
        let compressed = gzip_compress(&data, 6);
        let blocks = ziftsieve::gzip::extract_literals(&compressed).expect("extract");
        let extracted: Vec<u8> = blocks.iter().flat_map(|b| b.literals().iter().copied()).collect();
        let decompressed = gzip_decompress(&compressed);
        assert!(extracted.len() <= data.len());
        assert!(is_subsequence(&decompressed, &extracted));
        assert_eq!(decompressed, data);
    }

    #[test]
    fn compressed_round_trip_stored_blocks_match_literals_exactly(input in proptest::collection::vec(any::<u8>(), 0..128)) {
        let compressed = gzip_compress(&input, 0);
        let blocks = ziftsieve::gzip::extract_literals(&compressed).expect("extract");
        let extracted: Vec<u8> = blocks.iter().flat_map(|b| b.literals().iter().copied()).collect();
        let decompressed = gzip_decompress(&compressed);
        assert_eq!(decompressed, input);
        assert_eq!(extracted, input);
    }
}
