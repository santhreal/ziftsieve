use crate::ZiftError;

/// Maximum Zstd block size (128KB).
///
/// Verified against Zstandard Specification (RFC 8878, Section 3.1.1.2):
/// "The maximum block size is 128 KB (131072 bytes)."
pub(crate) const MAX_BLOCK_SIZE: usize = 128 * 1024;

/// Zstd block types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
    Reserved = 3,
}

impl BlockType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Raw),
            1 => Some(Self::Rle),
            2 => Some(Self::Compressed),
            3 => Some(Self::Reserved),
            _ => None,
        }
    }
}

// Frame header information (currently just tracks position after header)
pub(crate) type FrameHeader = ();

pub(crate) fn parse_frame_header(data: &[u8], pos: &mut usize) -> Result<FrameHeader, ZiftError> {
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

    if data.len() < 4 {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: "data too short for frame header. Fix: use a complete Zstd stream".to_string(),
        });
    }

    // Handle skippable frames (up to 3 as per Zstd spec)
    let mut iterations = 0;
    loop {
        if iterations >= 3 {
            return Err(ZiftError::InvalidData {
                offset: *pos,
                reason: "too many skippable frames. Fix: use a valid Zstd stream".to_string(),
            });
        }
        iterations += 1;

        if *pos + 4 > data.len() {
            return Err(ZiftError::InvalidData {
                offset: *pos,
                reason: "truncated frame header after skippable frame. Fix: use a complete Zstd stream".to_string(),
            });
        }

        // Check for standard frame
        if data[*pos..*pos + 4] == ZSTD_MAGIC {
            return parse_standard_frame_header(data, pos);
        }

        // Check for skippable frame (magic 0x184D2A50-0x184D2A57)
        if data[*pos] >= 0x50
            && data[*pos] <= 0x57
            && data[*pos + 1] == 0x2A
            && data[*pos + 2] == 0x4D
            && data[*pos + 3] == 0x18
        {
            if *pos + 8 > data.len() {
                return Err(ZiftError::InvalidData {
                    offset: *pos,
                    reason: "truncated skippable frame header. Fix: use a complete Zstd stream".to_string(),
                });
            }
            let frame_size = usize::try_from(u32::from_le_bytes([
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]))
            .unwrap_or(usize::MAX);
            *pos = (*pos)
                .checked_add(8)
                .and_then(|p| p.checked_add(frame_size))
                .ok_or(ZiftError::InvalidData {
                    offset: *pos,
                    reason: "skippable frame size overflow. Fix: use a valid Zstd stream".to_string(),
                })?;

            if *pos > data.len() {
                return Err(ZiftError::InvalidData {
                    offset: *pos,
                    reason: "skippable frame extends beyond data. Fix: use a complete Zstd stream".to_string(),
                });
            }
            continue; // Try again after skipping
        }

        return Err(ZiftError::InvalidData {
            offset: *pos,
            reason: "invalid Zstd magic number. Fix: use a valid Zstd stream".to_string(),
        });
    }
}

pub(crate) fn parse_standard_frame_header(
    data: &[u8],
    pos: &mut usize,
) -> Result<FrameHeader, ZiftError> {
    *pos += 4; // Skip magic

    if *pos >= data.len() {
        return Err(ZiftError::InvalidData {
            offset: *pos,
            reason: "truncated frame header descriptor. Fix: use a complete Zstd stream".to_string(),
        });
    }

    // Frame header descriptor
    let fh_desc = data[*pos];
    *pos += 1;

    let fcs_id = (fh_desc >> 6) & 0x03;
    let single_segment = (fh_desc >> 5) & 0x01;
    let dict_id_flag = fh_desc & 0x03;

    // Parse window descriptor if not single segment
    let _window_size = if single_segment == 0 {
        if *pos >= data.len() {
            return Err(ZiftError::InvalidData {
                offset: *pos,
                reason: "truncated window descriptor. Fix: use a complete Zstd stream".to_string(),
            });
        }
        let wd = data[*pos];
        *pos += 1;

        // Window descriptor: exponent (5 bits) + mantissa (3 bits)
        let exponent = (wd >> 3) as usize;
        let mantissa = (wd & 0x07) as usize;

        // Calculate window size per Zstd spec
        // base = 1KB * 2^exponent (clamped to prevent overflow)
        // exponent is at most 31 (5 bits), so cast to u32 is safe.
        #[allow(clippy::cast_possible_truncation)]
        let base = 1024usize.checked_shl(exponent as u32).unwrap_or(usize::MAX);
        base.saturating_add(mantissa.saturating_mul(base) / 8)
    } else {
        0
    };

    // Parse dictionary ID
    let _dict_id = match dict_id_flag {
        0 => None,
        1 => {
            if *pos >= data.len() {
                return Err(ZiftError::InvalidData {
                    offset: *pos,
                    reason: "truncated dictionary ID. Fix: use a complete Zstd stream".to_string(),
                });
            }
            let id = u64::from(data[*pos]);
            *pos += 1;
            Some(id)
        }
        2 => {
            if *pos + 2 > data.len() {
                return Err(ZiftError::InvalidData {
                    offset: *pos,
                    reason: "truncated dictionary ID. Fix: use a complete Zstd stream".to_string(),
                });
            }
            let id = u64::from(u16::from_le_bytes([data[*pos], data[*pos + 1]]));
            *pos += 2;
            Some(id)
        }
        3 => {
            if *pos + 4 > data.len() {
                return Err(ZiftError::InvalidData {
                    offset: *pos,
                    reason: "truncated dictionary ID. Fix: use a complete Zstd stream".to_string(),
                });
            }
            let id = u64::from(u32::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]));
            *pos += 4;
            Some(id)
        }
        _ => unreachable!(),
    };

    // Skip frame content size
    let fcs_size = match fcs_id {
        0 => usize::from(single_segment != 0),
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    *pos += fcs_size;

    Ok(())
}
