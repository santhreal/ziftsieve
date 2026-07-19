//! Low-level bit readers used by the Zstd FSE and Huffman decoders.
//!
//! These are adapted from the `ruzstd` reference implementation (MIT licensed).

#![allow(clippy::unwrap_used)]

use std::convert::TryInto;

/// Wraps a slice and enables reading arbitrary amounts of bits from that slice.
///
/// Bits are read in little-endian order: the least-significant bit of each byte is read first.
pub struct BitReader<'s> {
    idx: usize,
    source: &'s [u8],
}

impl<'s> BitReader<'s> {
    pub fn new(source: &'s [u8]) -> BitReader<'s> {
        BitReader { idx: 0, source }
    }

    pub fn bits_left(&self) -> usize {
        self.source.len() * 8 - self.idx
    }

    pub fn bits_read(&self) -> usize {
        self.idx
    }

    pub fn return_bits(&mut self, n: usize) {
        self.idx -= n;
    }

    pub fn get_bits(&mut self, n: usize) -> Option<u64> {
        if n > 64 {
            return None;
        }
        if self.bits_left() < n {
            return None;
        }

        let old_idx = self.idx;

        let bits_left_in_current_byte = 8 - (self.idx % 8);
        let bits_not_needed_in_current_byte = 8 - bits_left_in_current_byte;

        let mut value = u64::from(self.source[self.idx / 8] >> bits_not_needed_in_current_byte);

        if bits_left_in_current_byte >= n {
            value &= (1 << n) - 1;
            self.idx += n;
        } else {
            self.idx += bits_left_in_current_byte;

            let full_bytes_needed = (n - bits_left_in_current_byte) / 8;
            let bits_in_last_byte_needed = n - bits_left_in_current_byte - full_bytes_needed * 8;

            let mut bit_shift = bits_left_in_current_byte;

            for _ in 0..full_bytes_needed {
                value |= u64::from(self.source[self.idx / 8]) << bit_shift;
                self.idx += 8;
                bit_shift += 8;
            }

            if bits_in_last_byte_needed > 0 {
                let val_last_byte =
                    u64::from(self.source[self.idx / 8]) & ((1 << bits_in_last_byte_needed) - 1);
                value |= val_last_byte << bit_shift;
                self.idx += bits_in_last_byte_needed;
            }
        }

        debug_assert_eq!(self.idx, old_idx + n);

        Some(value)
    }
}

/// Reads bits from the end of a slice, as required by Zstd's reverse-encoded streams.
///
/// Bytes are treated as little-endian, but within each byte bits are read from the most
/// significant bit down to the least significant bit.
pub struct BitReaderReversed<'s> {
    index: usize,
    bits_consumed: u8,
    extra_bits: usize,
    source: &'s [u8],
    bit_container: u64,
}

impl<'s> BitReaderReversed<'s> {
    /// Number of bits remaining before the reader has consumed the whole input.
    pub fn bits_remaining(&self) -> isize {
        self.index as isize * 8 + (64 - self.bits_consumed as isize) - self.extra_bits as isize
    }

    pub fn new(source: &'s [u8]) -> BitReaderReversed<'s> {
        BitReaderReversed {
            index: source.len(),
            bits_consumed: 64,
            extra_bits: 0,
            source,
            bit_container: 0,
        }
    }

    #[cold]
    fn refill(&mut self) {
        let bytes_consumed = self.bits_consumed as usize / 8;
        if bytes_consumed == 0 {
            return;
        }

        if self.index >= bytes_consumed {
            self.index -= bytes_consumed;
            self.bits_consumed &= 7;
            self.bit_container =
                u64::from_le_bytes((&self.source[self.index..][..8]).try_into().unwrap());
        } else if self.index > 0 {
            if self.source.len() >= 8 {
                self.bit_container = u64::from_le_bytes((&self.source[..8]).try_into().unwrap());
            } else {
                let mut value = [0; 8];
                value[..self.source.len()].copy_from_slice(self.source);
                self.bit_container = u64::from_le_bytes(value);
            }

            self.bits_consumed -= 8 * self.index as u8;
            self.index = 0;

            self.bit_container <<= self.bits_consumed;
            self.extra_bits += self.bits_consumed as usize;
            self.bits_consumed = 0;
        } else if self.bits_consumed < 64 {
            self.bit_container <<= self.bits_consumed;
            self.extra_bits += self.bits_consumed as usize;
            self.bits_consumed = 0;
        } else {
            self.extra_bits += self.bits_consumed as usize;
            self.bits_consumed = 0;
            self.bit_container = 0;
        }

        debug_assert!(self.bits_consumed < 8);
    }

    /// Read `n` bits from the source. At most 56 bits can be read in one call.
    ///
    /// Once the input is exhausted, the reader returns zero bits.
    pub fn get_bits(&mut self, n: u8) -> u64 {
        if self.bits_consumed + n > 64 {
            self.refill();
        }

        let value = self.peek_bits(n);
        self.consume(n);
        value
    }

    pub fn peek_bits(&mut self, n: u8) -> u64 {
        if n == 0 {
            return 0;
        }

        let mask = (1u64 << n) - 1u64;
        let shift_by = 64 - self.bits_consumed - n;
        (self.bit_container >> shift_by) & mask
    }

    pub fn consume(&mut self, n: u8) {
        self.bits_consumed += n;
        debug_assert!(self.bits_consumed <= 64);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reverse_reader_matches_ruzstd() {
        let data = [0b10101010u8, 0b01010101];
        let mut br = super::BitReaderReversed::new(&data);
        assert_eq!(br.get_bits(1), 0);
        assert_eq!(br.get_bits(1), 1);
        assert_eq!(br.get_bits(1), 0);
        assert_eq!(br.get_bits(4), 0b1010);
        assert_eq!(br.get_bits(4), 0b1101);
        assert_eq!(br.get_bits(4), 0b0101);
        // Last 0 from source, three zeroes filled in
        assert_eq!(br.get_bits(4), 0b0000);
        // All zeroes filled in
        assert_eq!(br.get_bits(4), 0b0000);
        assert_eq!(br.bits_remaining(), -7);
    }
}
