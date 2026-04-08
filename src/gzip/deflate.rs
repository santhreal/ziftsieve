//! DEFLATE block decoding logic.

use super::bitstream::{BitReader, HuffmanDecoder};
use crate::{CompressedBlock, ZiftError};

pub(crate) const DEFLATE_MAX_BITS: usize = 15;
pub(crate) const MAX_BLOCK_LITERALS: usize = 16 * 1024 * 1024; // 16 MiB per compressed block.
pub(crate) const MAX_DEFLATE_BLOCKS_PER_MEMBER: usize = 100_000;

pub(crate) const HCLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub(crate) const FIXED_LITLEN_CODE_LENGTHS: [u8; 288] = {
    let mut lengths = [0u8; 288];
    let mut i = 0;
    while i < 144 {
        lengths[i] = 8;
        i += 1;
    }
    while i < 256 {
        lengths[i] = 9;
        i += 1;
    }
    while i < 280 {
        lengths[i] = 7;
        i += 1;
    }
    while i < 288 {
        lengths[i] = 8;
        i += 1;
    }
    lengths
};

pub(crate) const FIXED_DIST_CODE_LENGTHS: [u8; 32] = [
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
];

pub(crate) const LITERAL_LENGTH_BASES: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, // 257..264
    11, 13, 15, 17, // 265..268
    19, 23, 27, 31, // 269..272
    35, 43, 51, 59, // 273..276
    67, 83, 99, 115, // 277..280
    131, 163, 195, 227, // 281..284
    258, // 285
];
pub(crate) const LITERAL_LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, // 257..264
    1, 1, 1, 1, // 265..268
    2, 2, 2, 2, // 269..272
    3, 3, 3, 3, // 273..276
    4, 4, 4, 4, // 277..280
    5, 5, 5, 5, // 281..284
    0, // 285
];

pub(crate) const DISTANCE_BASES: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
pub(crate) const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

pub(crate) fn parse_deflate_stream(
    reader: &mut BitReader<'_>,
    blocks: &mut Vec<CompressedBlock>,
    total_literals: &mut usize,
) -> Result<bool, ZiftError> {
    let mut had_matches = false;
    loop {
        if blocks.len() >= MAX_DEFLATE_BLOCKS_PER_MEMBER {
            return Err(ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: "too many DEFLATE blocks across all members (likely malformed stream)"
                    .to_string(),
            });
        }

        let block_start = reader.bit_offset();
        let block_offset = block_start / 8;
        let is_final = reader.read_bits(1)? == 1;
        let block_type = reader.read_bits(2)?;

        let mut block = CompressedBlock::new(
            u64::try_from(block_offset).map_err(|_| ZiftError::InvalidData {
                offset: block_offset,
                reason: "block offset overflow".to_string(),
            })?,
            0,
        );

        let matches = parse_single_block(reader, block_type, &mut block)?;
        if matches {
            had_matches = true;
        }

        *total_literals = total_literals.saturating_add(block.literals().len());
        if *total_literals > crate::gzip::MAX_TOTAL_LITERALS {
            return Err(ZiftError::BlockTooLarge {
                size: *total_literals,
                max: crate::gzip::MAX_TOTAL_LITERALS,
            });
        }

        let block_end = reader.bit_offset();
        let used_bits = block_end.saturating_sub(block_start);
        let used_bytes = used_bits.div_ceil(8);
        block.compressed_len = u32::try_from(used_bytes).map_err(|_| ZiftError::BlockTooLarge {
            size: used_bytes,
            max: usize::MAX,
        })?;

        blocks.push(block);

        if is_final {
            break;
        }
    }

    Ok(had_matches)
}

fn parse_single_block(
    reader: &mut BitReader<'_>,
    block_type: u32,
    block: &mut CompressedBlock,
) -> Result<bool, ZiftError> {
    match block_type {
        0 => {
            parse_stored_block(reader, block)?;
            Ok(false)
        }
        1 => {
            let literal_decoder =
                HuffmanDecoder::from_lengths(&FIXED_LITLEN_CODE_LENGTHS, "fixed")?;
            let distance_decoder =
                HuffmanDecoder::from_lengths(&FIXED_DIST_CODE_LENGTHS, "fixed distance")?;
            parse_huffman_block(reader, block, &literal_decoder, &distance_decoder)
        }
        2 => {
            let (literal_decoder, distance_decoder) = parse_dynamic_trees(reader)?;
            parse_huffman_block(reader, block, &literal_decoder, &distance_decoder)
        }
        3 => Err(ZiftError::InvalidData {
            offset: reader.byte_pos.saturating_sub(1),
            reason: "reserved DEFLATE block type 3".to_string(),
        }),
        _ => unreachable!(),
    }
}

fn parse_stored_block(
    reader: &mut BitReader<'_>,
    block: &mut CompressedBlock,
) -> Result<(), ZiftError> {
    reader.align_to_byte();
    let len = usize::from(reader.read_u16_le()?);
    let nlen = usize::from(reader.read_u16_le()?);

    if len != (!nlen & 0xFFFF) {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "stored block length mismatch (LEN != ~NLEN)".to_string(),
        });
    }

    if !fits_literal_cap(block.literals.len(), len) {
        return Err(ZiftError::BlockTooLarge {
            size: block.literals.len() + len,
            max: MAX_BLOCK_LITERALS,
        });
    }

    let bytes = reader.read_bytes(len)?;
    block.literals.extend_from_slice(bytes);
    Ok(())
}

fn parse_dynamic_trees(
    reader: &mut BitReader<'_>,
) -> Result<(HuffmanDecoder, HuffmanDecoder), ZiftError> {
    let hlit = reader.read_bits_usize(5)? + 257;
    let hdist = reader.read_bits_usize(5)? + 1;
    let hclen = reader.read_bits_usize(4)? + 4;

    if hlit > 286 || hdist > 30 {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "invalid dynamic Huffman header sizes".to_string(),
        });
    }

    let mut code_length_lengths = [0u8; 19];
    for &symbol in HCLEN_ORDER.iter().take(hclen) {
        code_length_lengths[symbol] = reader.read_bits_u8(3)?;
    }

    let code_length_decoder = HuffmanDecoder::from_lengths(&code_length_lengths, "code length")?;

    let mut lengths = vec![0u8; hlit + hdist];
    decode_code_lengths(reader, &code_length_decoder, &mut lengths)?;

    let (literal_lengths, distance_lengths) = lengths.split_at(hlit);

    let literal_decoder = HuffmanDecoder::from_lengths(literal_lengths, "literal/length")?;
    let distance_decoder = HuffmanDecoder::from_lengths(distance_lengths, "distance")?;

    Ok((literal_decoder, distance_decoder))
}

fn decode_code_lengths(
    reader: &mut BitReader<'_>,
    decoder: &HuffmanDecoder,
    lengths: &mut [u8],
) -> Result<(), ZiftError> {
    let mut i = 0usize;
    let mut prev = 0u8;

    while i < lengths.len() {
        let symbol = decoder.decode(reader)?;
        i = handle_code_length_symbol(reader, symbol, lengths, i, &mut prev)?;
    }
    Ok(())
}

fn handle_code_length_symbol(
    reader: &mut BitReader<'_>,
    symbol: u16,
    lengths: &mut [u8],
    mut i: usize,
    prev: &mut u8,
) -> Result<usize, ZiftError> {
    match symbol {
        0..=15 => {
            let length = u8::try_from(symbol).map_err(|_| ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: "code length symbol does not fit in u8".to_string(),
            })?;
            lengths[i] = length;
            *prev = length;
            i += 1;
        }
        16 => {
            if i == 0 {
                return Err(ZiftError::InvalidData {
                    offset: reader.byte_pos,
                    reason: "distance code repetition before any length".to_string(),
                });
            }
            let repeat = 3 + reader.read_bits_usize(2)?;
            i = fill_lengths(lengths, i, *prev, repeat, reader.byte_pos)?;
        }
        17 => {
            let repeat = 3 + reader.read_bits_usize(3)?;
            i = fill_lengths(lengths, i, 0, repeat, reader.byte_pos)?;
        }
        18 => {
            let repeat = 11 + reader.read_bits_usize(7)?;
            i = fill_lengths(lengths, i, 0, repeat, reader.byte_pos)?;
        }
        _ => unreachable!(),
    }
    Ok(i)
}

fn fill_lengths(
    lengths: &mut [u8],
    mut i: usize,
    value: u8,
    repeat: usize,
    offset: usize,
) -> Result<usize, ZiftError> {
    for _ in 0..repeat {
        if i >= lengths.len() {
            return Err(ZiftError::InvalidData {
                offset,
                reason: "dynamic tree length overflow".to_string(),
            });
        }
        lengths[i] = value;
        i += 1;
    }
    Ok(i)
}

fn parse_huffman_block(
    reader: &mut BitReader<'_>,
    block: &mut CompressedBlock,
    literal_decoder: &HuffmanDecoder,
    distance_decoder: &HuffmanDecoder,
) -> Result<bool, ZiftError> {
    let mut had_matches = false;
    loop {
        let symbol = literal_decoder.decode(reader)?;

        match symbol {
            0..=255 => {
                if !fits_literal_cap(block.literals.len(), 1) {
                    return Err(ZiftError::BlockTooLarge {
                        size: block.literals.len() + 1,
                        max: MAX_BLOCK_LITERALS,
                    });
                }
                block
                    .literals
                    .push(u8::try_from(symbol).map_err(|_| ZiftError::InvalidData {
                        offset: reader.byte_pos,
                        reason: "literal symbol does not fit in u8".to_string(),
                    })?);
            }
            256 => break,
            257..=285 => {
                parse_match(reader, symbol, distance_decoder)?;
                had_matches = true;
            }
            286 | 287 => {
                return Err(ZiftError::InvalidData {
                    offset: reader.byte_pos,
                    reason: "invalid fixed/dynamic literal/length code".to_string(),
                })
            }
            _ => {
                return Err(ZiftError::InvalidData {
                    offset: reader.byte_pos,
                    reason: "invalid literal/length code".to_string(),
                });
            }
        }
    }
    Ok(had_matches)
}

fn parse_match(
    reader: &mut BitReader<'_>,
    symbol: u16,
    distance_decoder: &HuffmanDecoder,
) -> Result<(), ZiftError> {
    let idx = usize::from(symbol - 257);
    let extra_bits = usize::from(LITERAL_LENGTH_EXTRA_BITS[idx]);
    let mut match_length = LITERAL_LENGTH_BASES[idx];

    if extra_bits > 0 {
        match_length +=
            usize::try_from(reader.read_bits(u8::try_from(extra_bits).map_err(|_| {
                ZiftError::InvalidData {
                    offset: reader.byte_pos,
                    reason: "invalid literal length extra-bits".to_string(),
                }
            })?)?)
            .map_err(|_| ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: "literal length extra bits overflow usize".to_string(),
            })?;
    }

    let dist_symbol = distance_decoder.decode(reader)?;
    if dist_symbol >= 30 {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "invalid distance code".to_string(),
        });
    }
    let mut match_distance = DISTANCE_BASES[usize::from(dist_symbol)];
    let dist_extra = usize::from(DISTANCE_EXTRA_BITS[usize::from(dist_symbol)]);
    if dist_extra > 0 {
        match_distance +=
            usize::try_from(reader.read_bits(u8::try_from(dist_extra).map_err(|_| {
                ZiftError::InvalidData {
                    offset: reader.byte_pos,
                    reason: "invalid distance extra bits".to_string(),
                }
            })?)?)
            .map_err(|_| ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: "distance extra bits overflow usize".to_string(),
            })?;
    }
    let _ = (match_length, match_distance);
    Ok(())
}

fn fits_literal_cap(current: usize, additional: usize) -> bool {
    current.saturating_add(additional) <= MAX_BLOCK_LITERALS
}
