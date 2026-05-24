use crate::gzip::bitstream::{BitReader, HuffmanDecoder};
use crate::gzip::deflate::{parse_huffman_block_with_limit, MAX_DEFLATE_INSTRUCTIONS};
use crate::CompressedBlock;

#[test]
fn max_deflate_instructions_is_ten_million() {
    assert_eq!(MAX_DEFLATE_INSTRUCTIONS, 10_000_000);
}

/// Builds a bitstream with `num_zeros` symbol-0 reads followed by one symbol-256 read,
/// using a 1-bit code tree where code 0 = symbol 0 and code 1 = symbol 256.
fn build_simple_huffman_stream(num_zeros: usize) -> Vec<u8> {
    let total_bits = num_zeros + 1; // num_zeros zeros + one 1 for end-of-block
    let num_bytes = total_bits.div_ceil(8);
    let mut bytes = vec![0_u8; num_bytes];
    let byte_idx = num_zeros / 8;
    let bit_idx = num_zeros % 8;
    bytes[byte_idx] |= 1 << bit_idx;
    bytes
}

#[test]
fn huffman_block_instruction_limit_enforced() {
    let mut lengths = vec![0u8; 257];
    lengths[0] = 1;
    lengths[256] = 1;
    let literal_decoder = HuffmanDecoder::from_lengths(&lengths, "test").unwrap();
    let distance_decoder = HuffmanDecoder::from_lengths(&[0u8; 32], "test dist").unwrap();

    let data = build_simple_huffman_stream(100);
    let mut reader = BitReader::new(&data, 0);
    let mut block = CompressedBlock::new(0, 0);

    let result = parse_huffman_block_with_limit(
        &mut reader,
        &mut block,
        &literal_decoder,
        &distance_decoder,
        50,
    );
    assert!(result.is_err());
    let msg = format!("{result:?}");
    assert!(
        msg.contains("DEFLATE instruction limit exceeded"),
        "expected instruction-limit error, got {msg}"
    );
}

#[test]
fn huffman_block_just_under_limit_succeeds() {
    let mut lengths = vec![0u8; 257];
    lengths[0] = 1;
    lengths[256] = 1;
    let literal_decoder = HuffmanDecoder::from_lengths(&lengths, "test").unwrap();
    let distance_decoder = HuffmanDecoder::from_lengths(&[0u8; 32], "test dist").unwrap();

    let data = build_simple_huffman_stream(100);
    let mut reader = BitReader::new(&data, 0);
    let mut block = CompressedBlock::new(0, 0);

    let result = parse_huffman_block_with_limit(
        &mut reader,
        &mut block,
        &literal_decoder,
        &distance_decoder,
        101,
    );
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert_eq!(block.literals.len(), 100);
}
