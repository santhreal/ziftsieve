use super::huffman::decode_literals;
use crate::ZiftError;

/// Extract literals from a compressed Zstd block.
///
/// This parses the literals section of a Zstd block without decoding
/// the sequences (which would require resolving matches).
pub(crate) fn extract_literals_from_block(data: &[u8]) -> Result<Vec<u8>, ZiftError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut pos = 0;

    // Literals section header
    let ls_header = data[pos];
    pos += 1;

    let ls_type = ls_header & 0x03;

    match ls_type {
        0 => {
            // Raw literals - all bytes are literals
            let (regenerated_size, header_size) = read_raw_rle_size(ls_header, data)?;
            pos += header_size.saturating_sub(1); // header byte already consumed
            if pos + regenerated_size > data.len() {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "raw literals exceed block size".to_string(),
                });
            }
            Ok(data[pos..pos + regenerated_size].to_vec())
        }
        1 => {
            // RLE literals - one byte repeated
            let (regenerated_size, header_size) = read_raw_rle_size(ls_header, data)?;
            pos += header_size.saturating_sub(1); // header byte already consumed
            if pos >= data.len() {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: "truncated RLE literal".to_string(),
                });
            }
            let byte = data[pos];
            Ok(vec![byte; regenerated_size])
        }
        2 => {
            // Compressed literals (Huffman)
            let (regenerated_size, compressed_size, header_size) =
                read_compressed_size(ls_header, data)?;
            pos += header_size.saturating_sub(1); // header byte already consumed

            if compressed_size == 0 {
                // Uncompressed
                if pos + regenerated_size > data.len() {
                    return Err(ZiftError::InvalidData {
                        offset: pos,
                        reason: "uncompressed literals exceed block bounds".to_string(),
                    });
                }
                Ok(data[pos..pos + regenerated_size].to_vec())
            } else {
                // Huffman decode
                if pos + compressed_size > data.len() {
                    return Err(ZiftError::InvalidData {
                        offset: pos,
                        reason: "compressed literals exceed block bounds".to_string(),
                    });
                }
                let compressed = &data[pos..pos + compressed_size];

                match decode_literals(compressed, regenerated_size) {
                    Some(literals) => Ok(literals),
                    None => {
                        // Decoding failed - return raw bytes as fallback
                        Ok(compressed.to_vec())
                    }
                }
            }
        }
        3 => {
            // Treeless compressed literals (dictionary)
            // Requires external dictionary - cannot extract without it
            Err(ZiftError::InvalidData {
                offset: pos,
                reason: "treeless compressed literals (dictionary) are not supported".to_string(),
            })
        }
        _ => unreachable!(),
    }
}

/// Parse size for Raw (type 0) or RLE (type 1) literal sections.
///
/// Per the Zstandard reference implementation (`zstd_decompress_block.c`),
/// `lhlCode = (header >> 2) & 3`:
/// - 0, 2: 1-byte header, size = header >> 3
/// - 1:    2-byte header, size = LE16(data) >> 4
/// - 3:    3-byte header, size = LE24(data) >> 4
fn read_raw_rle_size(header: u8, data: &[u8]) -> Result<(usize, usize), ZiftError> {
    let lhl_code = (header >> 2) & 0x03;

    match lhl_code {
        0 | 2 => {
            // 1 byte total
            let size = (header >> 3) as usize;
            Ok((size, 1))
        }
        1 => {
            // 2 bytes total
            if data.len() < 2 {
                return Err(ZiftError::InvalidData {
                    offset: 1,
                    reason: "truncated raw/RLE literal size".to_string(),
                });
            }
            let le16 = u16::from_le_bytes([data[0], data[1]]);
            let size = (le16 >> 4) as usize;
            Ok((size, 2))
        }
        3 => {
            // 3 bytes total
            if data.len() < 3 {
                return Err(ZiftError::InvalidData {
                    offset: 1,
                    reason: "truncated raw/RLE literal size".to_string(),
                });
            }
            let le24 = u32::from_le_bytes([data[0], data[1], data[2], 0]);
            let size = (le24 >> 4) as usize;
            Ok((size, 3))
        }
        _ => unreachable!(),
    }
}

/// Parse sizes for Compressed (type 2) or Treeless (type 3) literal sections.
///
/// Per the Zstandard reference implementation:
/// `lhlCode = (header >> 2) & 3`:
/// - 0, 1: 3-byte header, size = (LE32(data) >> 4) & 0x3FF, csize = (LE32(data) >> 14) & 0x3FF
/// - 2:    4-byte header, size = (LE32(data) >> 4) & 0x3FFF, csize = LE32(data) >> 18
/// - 3:    5-byte header, size = (LE32(data) >> 4) & 0x3FFFF,
///   csize = (LE32(data) >> 22) + (data[4] << 10)
fn read_compressed_size(header: u8, data: &[u8]) -> Result<(usize, usize, usize), ZiftError> {
    let lhl_code = (header >> 2) & 0x03;

    match lhl_code {
        0 | 1 => {
            // 3 bytes total
            if data.len() < 4 {
                return Err(ZiftError::InvalidData {
                    offset: 1,
                    reason: "truncated compressed literal size".to_string(),
                });
            }
            let le32 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let size = ((le32 >> 4) & 0x3FF) as usize;
            let csize = ((le32 >> 14) & 0x3FF) as usize;
            Ok((size, csize, 3))
        }
        2 => {
            // 4 bytes total
            if data.len() < 4 {
                return Err(ZiftError::InvalidData {
                    offset: 1,
                    reason: "truncated compressed literal size".to_string(),
                });
            }
            let le32 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let size = ((le32 >> 4) & 0x3FFF) as usize;
            let csize = (le32 >> 18) as usize;
            Ok((size, csize, 4))
        }
        3 => {
            // 5 bytes total
            if data.len() < 5 {
                return Err(ZiftError::InvalidData {
                    offset: 1,
                    reason: "truncated compressed literal size".to_string(),
                });
            }
            let le32 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let size = ((le32 >> 4) & 0x3FFFF) as usize;
            let csize = ((le32 >> 22) as usize) | ((data[4] as usize) << 10);
            Ok((size, csize, 5))
        }
        _ => unreachable!(),
    }
}
