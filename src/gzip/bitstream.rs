//! Bit-level reading and Huffman decoding for DEFLATE.

use super::deflate::DEFLATE_MAX_BITS;
use crate::ZiftError;

#[derive(Clone)]
pub(crate) struct HuffmanDecoder {
    nodes: Vec<HuffmanNode>,
    max_bits: u8,
}

#[derive(Clone, Copy)]
struct HuffmanNode {
    children: [i16; 2],
    symbol: i16,
}

impl HuffmanDecoder {
    fn new() -> Self {
        Self {
            nodes: vec![HuffmanNode {
                children: [-1, -1],
                symbol: -1,
            }],
            max_bits: 0,
        }
    }

    pub(crate) fn from_lengths(lengths: &[u8], kind: &str) -> Result<Self, ZiftError> {
        let mut decoder = Self::new();

        let max = match lengths.iter().copied().max() {
            Some(v) if v > 0 => usize::from(v),
            Some(_) | None => 0,
        };
        if max > DEFLATE_MAX_BITS {
            return Err(ZiftError::InvalidData {
                offset: 0,
                reason: format!("invalid {kind} code length {max} > 15. Fix: use a valid gzip stream"),
            });
        }
        if max == 0 {
            return Ok(decoder);
        }

        let mut count = vec![0u16; max + 1];
        for &len in lengths {
            if len > 0 {
                if usize::from(len) >= count.len() {
                    return Err(ZiftError::InvalidData {
                        offset: 0,
                        reason: format!("invalid {kind} code length. Fix: use a valid gzip stream"),
                    });
                }
                count[usize::from(len)] += 1;
            }
        }

        let next_code = calculate_next_codes(max, &count);

        decoder.populate_nodes(lengths, &next_code, max)?;

        decoder.max_bits = u8::try_from(max).map_err(|_| ZiftError::InvalidData {
            offset: 0,
            reason: "huffman max bits does not fit in u8. Fix: use a valid gzip stream".to_string(),
        })?;
        Ok(decoder)
    }

    fn populate_nodes(
        &mut self,
        lengths: &[u8],
        next_code: &[u16],
        max: usize,
    ) -> Result<(), ZiftError> {
        let mut next_code = next_code.to_vec();
        for (symbol, &len_u8) in lengths.iter().enumerate() {
            if len_u8 == 0 {
                continue;
            }
            let len = usize::from(len_u8);
            if len > max {
                continue;
            }
            let code = next_code[len];
            next_code[len] = code.wrapping_add(1);
            let len_u8 = u8::try_from(len).map_err(|_| ZiftError::InvalidData {
                offset: 0,
                reason: "huffman code length does not fit in u8. Fix: use a valid gzip stream".to_string(),
            })?;
            let symbol_u16 = u16::try_from(symbol).map_err(|_| ZiftError::InvalidData {
                offset: 0,
                reason: "huffman symbol does not fit in u16. Fix: use a valid gzip stream".to_string(),
            })?;
            let code_bits = reverse_bits(code, len_u8);
            self.insert(code_bits, len_u8, symbol_u16)?;
        }
        Ok(())
    }

    fn insert(&mut self, code: u16, bits: u8, symbol: u16) -> Result<(), ZiftError> {
        let mut node = 0usize;
        for i in 0..bits {
            let bit = ((code >> i) & 1) as usize;
            let next = self.nodes[node].children[bit];
            if next == -1 {
                let next_idx = self.nodes.len();
                self.nodes.push(HuffmanNode {
                    children: [-1, -1],
                    symbol: -1,
                });
                self.nodes[node].children[bit] =
                    i16::try_from(next_idx).map_err(|_| ZiftError::InvalidData {
                        offset: 0,
                        reason: "invalid huffman tree size. Fix: use a valid gzip stream".to_string(),
                    })?;
                node = next_idx;
            } else {
                node = usize::try_from(next).map_err(|_| ZiftError::InvalidData {
                    offset: 0,
                    reason: "invalid huffman child index. Fix: use a valid gzip stream".to_string(),
                })?;
            }
        }

        if self.nodes[node].symbol != -1 {
            return Err(ZiftError::InvalidData {
                offset: 0,
                reason: "duplicate huffman code. Fix: use a valid gzip stream".to_string(),
            });
        }

        self.nodes[node].symbol = i16::try_from(symbol).map_err(|_| ZiftError::InvalidData {
            offset: 0,
            reason: "huffman symbol out of range. Fix: use a valid gzip stream".to_string(),
        })?;
        Ok(())
    }

    pub(crate) fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, ZiftError> {
        if self.max_bits == 0 {
            return Err(ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: "huffman decoder is empty. Fix: use a valid gzip stream".to_string(),
            });
        }

        let mut node = 0usize;
        for _ in 0..self.max_bits {
            let bit = reader.read_bit()?;
            let next = self.nodes[node].children[usize::from(bit)];
            if next < 0 {
                return Err(ZiftError::InvalidData {
                    offset: reader.byte_pos,
                    reason: "invalid huffman code. Fix: use a valid gzip stream".to_string(),
                });
            }
            node = usize::try_from(next).map_err(|_| ZiftError::InvalidData {
                offset: reader.byte_pos,
                reason: "invalid huffman node index. Fix: use a valid gzip stream".to_string(),
            })?;

            if self.nodes[node].symbol >= 0 {
                return u16::try_from(self.nodes[node].symbol).map_err(|_| {
                    ZiftError::InvalidData {
                        offset: reader.byte_pos,
                        reason: "decoded huffman symbol is negative. Fix: use a valid gzip stream".to_string(),
                    }
                });
            }
        }

        Err(ZiftError::InvalidData {
            offset: reader.byte_pos,
            reason: "huffman decode exceeded max symbol length. Fix: use a valid gzip stream".to_string(),
        })
    }
}

fn calculate_next_codes(max: usize, count: &[u16]) -> Vec<u16> {
    let mut next_code = vec![0u16; max + 1];
    let mut code = 0u16;
    for bits in 1..=max {
        code = (code + count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    next_code
}

fn reverse_bits(mut value: u16, len: u8) -> u16 {
    let mut out = 0u16;
    let mut i = 0u8;
    while i < len {
        out = (out << 1) | (value & 1);
        value >>= 1;
        i += 1;
    }
    out
}

pub(crate) struct BitReader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) byte_pos: usize,
    pub(crate) bit_pos: u8,
    buffer: u64,
    bits_in_buffer: u8,
    next_byte_to_pull: usize,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            byte_pos: start,
            bit_pos: 0,
            buffer: 0,
            bits_in_buffer: 0,
            next_byte_to_pull: start,
        }
    }

    pub(crate) fn bit_offset(&self) -> usize {
        self.byte_pos
            .saturating_mul(8)
            .saturating_add(self.bit_pos as usize)
    }

    pub(crate) fn remaining_bytes(&self) -> usize {
        (self.data.len().saturating_sub(self.next_byte_to_pull))
            .saturating_add(usize::from(self.bits_in_buffer / 8))
    }

    fn refill(&mut self) {
        while self.bits_in_buffer <= 56 && self.next_byte_to_pull < self.data.len() {
            self.buffer |= (u64::from(self.data[self.next_byte_to_pull])) << self.bits_in_buffer;
            self.next_byte_to_pull = self.next_byte_to_pull.wrapping_add(1);
            self.bits_in_buffer = self.bits_in_buffer.wrapping_add(8);
        }
    }

    pub(crate) fn read_bit(&mut self) -> Result<u8, ZiftError> {
        self.read_bits_u8(1)
    }

    pub(crate) fn read_bits(&mut self, bits: u8) -> Result<u32, ZiftError> {
        if bits == 0 {
            return Ok(0);
        }

        if bits > 32 {
            return Err(ZiftError::InvalidData {
                offset: self.byte_pos,
                reason: format!("requested too many bits: {bits} (max 32). Fix: use a valid gzip stream"),
            });
        }

        if self.bits_in_buffer < bits {
            self.refill();
            if self.bits_in_buffer < bits {
                return Err(ZiftError::InvalidData {
                    offset: self.byte_pos,
                    reason: "truncated bitstream. Fix: use a complete gzip stream".to_string(),
                });
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let out = (self.buffer & ((1u64 << bits) - 1)) as u32;
        self.buffer >>= bits;
        self.bits_in_buffer -= bits;

        // Update public fields for compatibility with other modules that access them directly.
        let new_bit_pos = u32::from(self.bit_pos) + u32::from(bits);
        self.byte_pos = self.byte_pos.saturating_add((new_bit_pos / 8) as usize);
        self.bit_pos = (new_bit_pos % 8) as u8;

        Ok(out)
    }

    pub(crate) fn read_bits_u8(&mut self, bits: u8) -> Result<u8, ZiftError> {
        u8::try_from(self.read_bits(bits)?).map_err(|_| ZiftError::InvalidData {
            offset: self.byte_pos,
            reason: "bit value does not fit in u8. Fix: use a valid gzip stream".to_string(),
        })
    }

    pub(crate) fn read_bits_usize(&mut self, bits: u8) -> Result<usize, ZiftError> {
        usize::try_from(self.read_bits(bits)?).map_err(|_| ZiftError::InvalidData {
            offset: self.byte_pos,
            reason: "bit value does not fit in usize. Fix: use a valid gzip stream".to_string(),
        })
    }

    pub(crate) fn align_to_byte(&mut self) -> Result<(), ZiftError> {
        if self.bit_pos != 0 {
            let bits_to_skip = 8 - self.bit_pos;
            self.read_bits(bits_to_skip)?;
        }
        Ok(())
    }

    pub(crate) fn peek_u8(&mut self) -> Result<u8, ZiftError> {
        if self.bit_pos != 0 {
            return Err(ZiftError::InvalidData {
                offset: self.byte_pos,
                reason: "peek_u8 must be byte-aligned. Fix: use a valid gzip stream".to_string(),
            });
        }
        if self.bits_in_buffer < 8 {
            self.refill();
        }
        if self.bits_in_buffer < 8 {
            return Err(ZiftError::InvalidData {
                offset: self.byte_pos,
                reason: "truncated byte peek. Fix: use a complete gzip stream".to_string(),
            });
        }
        Ok((self.buffer & 0xFF) as u8)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, ZiftError> {
        if self.bit_pos != 0 {
            return Err(ZiftError::InvalidData {
                offset: self.byte_pos,
                reason: "expected byte boundary. Fix: use a valid gzip stream".to_string(),
            });
        }
        self.read_bits_u8(8)
    }

    pub(crate) fn read_u16_le(&mut self) -> Result<u16, ZiftError> {
        let lo = self.read_u8()?;
        let hi = self.read_u8()?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32, ZiftError> {
        let lo = self.read_u16_le()?;
        let hi = self.read_u16_le()?;
        Ok(u32::from(lo) | (u32::from(hi) << 16))
    }

    pub(crate) fn skip_bytes(&mut self, count: usize) -> Result<(), ZiftError> {
        self.read_bytes(count).map(|_| ())
    }

    pub(crate) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], ZiftError> {
        if self.bit_pos != 0 {
            return Err(ZiftError::InvalidData {
                offset: self.byte_pos,
                reason: "byte read must be aligned. Fix: use a valid gzip stream".to_string(),
            });
        }

        let start = self.byte_pos;
        let end = start.saturating_add(count);
        if end > self.data.len() {
            return Err(ZiftError::InvalidData {
                offset: self.byte_pos,
                reason: "truncated byte data. Fix: use a complete gzip stream".to_string(),
            });
        }

        // Reset buffer state as we're jumping past potentially buffered data
        self.byte_pos = end;
        self.bit_pos = 0;
        self.buffer = 0;
        self.bits_in_buffer = 0;
        self.next_byte_to_pull = end;

        Ok(&self.data[start..end])
    }
}
