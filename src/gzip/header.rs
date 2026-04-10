//! Gzip member header parsing.

use super::bitstream::BitReader;
use super::deflate::parse_deflate_stream;
use crate::{CompressedBlock, ZiftError};
use std::io::Read;

pub(crate) const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

pub(crate) fn parse_gzip_member(
    reader: &mut BitReader<'_>,
    blocks: &mut Vec<CompressedBlock>,
    total_literals: &mut usize,
) -> Result<(), ZiftError> {
    let member_start = reader.byte_pos;
    parse_gzip_header(reader)?;
    let start_idx = blocks.len();
    let had_matches = parse_deflate_stream(reader, blocks, total_literals)?;
    reader.align_to_byte()?;
    let expected_crc32 = reader.read_u32_le()?; // CRC32
    reader.read_u32_le()?; // ISIZE

    // Calculate actual CRC32 over extracted literals
    let mut hasher = crc32fast::Hasher::new();
    for block in &blocks[start_idx..] {
        hasher.update(&block.literals);
    }
    let actual_crc32 = hasher.finalize();

    if had_matches {
        // When back-references were present, we must fully decompress the member
        // to validate the CRC32. We stream-decompress in chunks to avoid OOM.
        let member_end = reader.byte_pos;
        let member_data = &reader.data[member_start..member_end];
        let mut decoder = flate2::read::GzDecoder::new(member_data);
        let mut chunk = [0u8; 16_384];
        let mut decompressed = 0usize;
        loop {
            let n = decoder.read(&mut chunk).map_err(ZiftError::Io)?;
            if n == 0 {
                break;
            }
            decompressed = decompressed.saturating_add(n);
            if decompressed > crate::gzip::MAX_TOTAL_LITERALS {
                return Err(ZiftError::BlockTooLarge {
                    size: decompressed,
                    max: crate::gzip::MAX_TOTAL_LITERALS,
                });
            }
        }
    } else if expected_crc32 != actual_crc32 {
        // Without back-references, the extracted literals are the full decompressed data,
        // so we can validate CRC directly.
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: format!("CRC32 mismatch for literal stream: expected {expected_crc32:08x}, got {actual_crc32:08x}. Fix: use an uncorrupted gzip stream"),
        });
    }

    Ok(())
}

fn parse_gzip_header(reader: &mut BitReader<'_>) -> Result<(), ZiftError> {
    if reader.bit_pos != 0 {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "gzip header must start on byte boundary. Fix: use a valid gzip stream".to_string(),
        });
    }

    if reader.remaining_bytes() < 10 {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "truncated gzip header. Fix: use a complete gzip stream".to_string(),
        });
    }

    if reader.peek_u8()? != GZIP_MAGIC[0] {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "invalid gzip magic number. Fix: use a valid gzip stream".to_string(),
        });
    }
    reader.read_u8()?; // consume magic 1

    if reader.peek_u8()? != GZIP_MAGIC[1] {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "invalid gzip magic number. Fix: use a valid gzip stream".to_string(),
        });
    }
    reader.read_u8()?; // consume magic 2

    let compression_method = reader.read_u8()?;
    if compression_method != 8 {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos.saturating_sub(1),
            reason: "unsupported gzip compression method (expected DEFLATE). Fix: use DEFLATE-compressed gzip data".to_string(),
        });
    }

    let flags = reader.read_u8()?;
    if flags & 0xE0 != 0 {
        return Err(ZiftError::InvalidData {
            offset: reader.byte_pos.saturating_sub(1),
            reason: "invalid gzip flag bits. Fix: use a valid gzip stream".to_string(),
        });
    }

    // mtime (4 bytes), xfl (1 byte), os (1 byte)
    reader.skip_bytes(4)?;
    reader.read_u8()?;
    reader.read_u8()?;

    parse_gzip_extra_fields(reader, flags)?;

    Ok(())
}

fn parse_gzip_extra_fields(reader: &mut BitReader<'_>, flags: u8) -> Result<(), ZiftError> {
    if flags & 0x04 != 0 {
        let xlen = reader.read_u16_le()?;
        let len = usize::from(xlen);
        reader.skip_bytes(len)?;
    }

    if flags & 0x08 != 0 {
        skip_zero_terminated(reader)?;
    }

    if flags & 0x10 != 0 {
        skip_zero_terminated(reader)?;
    }

    if flags & 0x02 != 0 {
        reader.skip_bytes(2)?;
    }

    Ok(())
}

/// Maximum length for zero-terminated header fields (FNAME, FCOMMENT).
const MAX_HEADER_FIELD_LEN: usize = 1024;

/// Skips a zero-terminated string field in the gzip header.
///
/// **Rationale**: We skip zero-terminated fields (like FNAME and FCOMMENT) because
/// `ziftsieve` only extracts literals from the compressed data for indexing, and
/// does not need the file metadata. A maximum length (`MAX_HEADER_FIELD_LEN`)
/// is strictly enforced to prevent Denial of Service (`DoS`) attacks via maliciously
/// long or non-terminated string fields.
fn skip_zero_terminated(reader: &mut BitReader<'_>) -> Result<(), ZiftError> {
    let mut count = 0usize;
    loop {
        if count > MAX_HEADER_FIELD_LEN {
            return Err(ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: format!(
                    "header field exceeds maximum length ({MAX_HEADER_FIELD_LEN} bytes)"
                ),
            });
        }
        let value = reader.read_u8()?;
        if value == 0 {
            return Ok(());
        }
        count += 1;
    }
}
