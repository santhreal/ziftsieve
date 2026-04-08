//! Zstd Huffman decoder for compressed literals.
//!
//! Zstd uses canonical Huffman coding with these properties:
//! - Each symbol (0-255) has a weight (0-11)
//! - Weight 0 = unused symbol
//! - Weights 1-11 = code length in bits (max 11 bits)
//! - Codes are assigned canonically: shorter codes first, same-length codes in symbol order

/// Huffman decoding table used for Zstd literal reconstruction.
pub struct Decoder {
    /// Lookup table: index by code bits, get (symbol, `bits_used`).
    /// Table size is `2^max_bits` (max 2048 entries for 11-bit codes).
    table: Vec<(u16, u8)>,
    /// Maximum code length in bits.
    max_bits: u8,
}

impl Decoder {
    /// Build decoder from symbol weights.
    ///
    /// `weights[i]` is the weight (0-11) for symbol i.
    /// Weight 0 means unused. Weights 1-11 are code lengths.
    ///
    /// # Parameters
    ///
    /// - `weights`: Canonical code weights indexed by symbol.
    ///
    /// # Returns
    ///
    /// A decoder when the weights form a valid Huffman tree, otherwise `None`.
    pub fn from_weights(weights: &[u8; 256]) -> Option<Self> {
        // Find max weight and validate
        let max_bits = *weights.iter().max()?;
        if max_bits == 0 || max_bits > 11 {
            return None;
        }

        // Count symbols per code length
        let mut count = [0u32; 12];
        for &w in weights {
            if w <= 11 {
                count[w as usize] += 1;
            }
        }
        count[0] = 0; // Weight 0 doesn't contribute

        // Validate: total codes must be > 0 and <= 256
        let total: u32 = count.iter().sum();
        if total == 0 || total > 256 {
            return None;
        }

        // Calculate first code for each bit length using canonical Huffman
        // First code of length n: (first_code[n-1] + count[n-1]) * 2
        let mut first_code = [0u32; 12];
        let mut code: u32 = 0;
        for bits in 1..=max_bits as usize {
            code = (code + count[bits - 1]) << 1;
            first_code[bits] = code;
        }

        // Check Kraft-McMillan inequality (should equal 1.0 for complete tree)
        // max_bits is at most 11, so precision loss is not a concern for these small values
        #[allow(clippy::cast_precision_loss)]
        let kraft: f64 = (1..=max_bits)
            .map(|b| f64::from(count[b as usize]) / f64::from(1u32 << b))
            .sum();
        if !(0.999..=1.001).contains(&kraft) {
            // Invalid tree
            return None;
        }

        // Build fast lookup table
        let table_size = 1usize << max_bits;
        let mut table = vec![(0u16, 0u8); table_size];

        // Track next code for each bit length
        let mut next_code = first_code;

        for (symbol, &weight) in weights.iter().enumerate() {
            if weight == 0 {
                continue;
            }
            let bits = weight as usize;
            let base_code = next_code[bits];
            let num_entries = 1usize << (max_bits as usize - bits);

            // Fill all table entries that start with this code
            for i in 0..num_entries {
                let idx = ((base_code as usize) << (max_bits as usize - bits)) | i;
                table[idx] = (u16::try_from(symbol).unwrap_or(0), weight);
            }
            next_code[bits] += 1;
        }

        Some(Self { table, max_bits })
    }

    /// Decode symbols from bit stream using a bulk bit accumulator.
    ///
    /// `data` is the compressed bit stream.
    /// `num_symbols` is the expected number of symbols to decode.
    ///
    /// Uses a u64 accumulator that is refilled in bulk to avoid per-symbol
    /// bounds checking (reducing ~3 checks per symbol to ~1 per 8 symbols).
    ///
    /// # Parameters
    ///
    /// - `data`: Huffman-coded bit stream.
    /// - `num_symbols`: Number of decoded bytes expected from the stream.
    ///
    /// # Returns
    ///
    /// The decoded bytes on success, or `None` if decoding fails.
    pub fn decode(&self, data: &[u8], num_symbols: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(num_symbols);
        let total_bits = data.len() * 8;

        // Bit accumulator: holds up to 56 bits of pending data.
        // Refilled when fewer than max_bits remain.
        let mut acc: u64 = 0;
        let mut acc_bits: u32 = 0;
        let mut byte_pos: usize = 0;
        let max = u32::from(self.max_bits);
        let table_mask = (1u64 << max) - 1;

        while result.len() < num_symbols {
            // Refill accumulator with full bytes until we have >= max_bits.
            // Each refill loads up to 7 bytes (56 bits), keeping acc_bits < 64.
            while acc_bits < max && byte_pos < data.len() {
                acc |= u64::from(data[byte_pos]) << acc_bits;
                acc_bits += 8;
                byte_pos += 1;
            }

            if acc_bits < max {
                return None; // Not enough bits remaining
            }

            let code = usize::try_from(acc & table_mask).ok()?;
            let (symbol, bits_used) = self.table[code];

            if bits_used == 0 {
                return None; // Invalid code
            }

            let consumed = u32::from(bits_used);
            // Verify we haven't exceeded total stream (including partial byte)
            let bit_pos_after =
                (byte_pos * 8).saturating_sub(acc_bits as usize) + consumed as usize;
            if bit_pos_after > total_bits {
                return None;
            }

            // Skip symbols > 255 (corrupt Huffman table) rather than
            // silently inserting 0 which could cause false negatives.
            if let Ok(byte) = u8::try_from(symbol) {
                result.push(byte);
            }
            acc >>= consumed;
            acc_bits -= consumed;
        }

        Some(result)
    }
}

/// Read up to 16 bits from byte slice at bit position.
/// Uses little-endian bit order (LSB first) as per Zstd spec.
#[cfg(test)]
fn read_bits(data: &[u8], bit_pos: usize, num_bits: u8) -> Option<u16> {
    if num_bits == 0 || num_bits > 16 {
        return None;
    }

    let byte_idx = bit_pos >> 3;
    let bit_idx = bit_pos & 7;

    if byte_idx >= data.len() {
        return None;
    }

    // Read bytes and combine in little-endian order
    let b0 = u32::from(data[byte_idx]);
    let b1 = u32::from(data.get(byte_idx + 1).copied().unwrap_or(0));
    let b2 = u32::from(data.get(byte_idx + 2).copied().unwrap_or(0));

    // Create bit stream: bits are read LSB first from each byte
    // Position 0 = bit 0 of byte 0, position 7 = bit 7 of byte 0,
    // position 8 = bit 0 of byte 1, etc.
    let value = b0 | (b1 << 8) | (b2 << 16);

    // Extract bits starting from bit_idx
    let shift = bit_idx;
    let mask = (1u32 << num_bits) - 1;
    // mask is at most 0xFFFF since num_bits <= 16, so this conversion is safe
    Some(u16::try_from((value >> shift) & mask).unwrap_or(0))
}

/// Parses a Huffman tree description from a Zstd literals section.
///
/// # Parameters
///
/// - `data`: Bytes beginning at the tree description.
///
/// # Returns
///
/// A tuple of `(weights, bytes_consumed)` on success, or `None` when the tree
/// description is invalid or truncated.
pub fn parse_tree(data: &[u8]) -> Option<([u8; 256], usize)> {
    if data.is_empty() {
        return None;
    }

    let mut pos = 0;
    let header = data[pos];
    pos += 1;

    // Header: bit 7 = use 4-bit weights, bits 0-6 = num_weights - 1
    let num_weights = ((header & 0x7F) as usize) + 1;
    let use_4bit = (header & 0x80) != 0;

    if num_weights > 256 {
        return None;
    }

    let mut weights = [0u8; 256];

    if use_4bit {
        // 2 weights per byte (low nibble first)
        let bytes_needed = num_weights.div_ceil(2);
        if pos + bytes_needed > data.len() {
            return None;
        }

        for i in 0..num_weights {
            let byte = data[pos + (i >> 1)];
            let weight = if i & 1 == 0 { byte & 0x0F } else { byte >> 4 };
            // Zstd weights are 0-11, but 4-bit can store 0-15
            weights[i] = weight.min(11);
        }
        pos += bytes_needed;
    } else {
        // 1 weight per byte
        if pos + num_weights > data.len() {
            return None;
        }

        for i in 0..num_weights {
            weights[i] = data[pos + i].min(11);
        }
        pos += num_weights;
    }

    Some((weights, pos))
}

/// Decodes Huffman-compressed literals from a Zstd literals section payload.
///
/// `data` contains tree description followed by coded literals.
/// `num_literals` is the expected number of decoded literals.
///
/// # Parameters
///
/// - `data`: Tree description followed by the coded literal stream.
/// - `num_literals`: Number of literal bytes expected in the output.
///
/// # Returns
///
/// The decoded literals on success, or `None` when decoding fails.
pub fn decode_literals(data: &[u8], num_literals: usize) -> Option<Vec<u8>> {
    // Sanity checks to prevent abuse
    if num_literals > 128 * 1024 {
        // Max Zstd block size
        return None;
    }
    if data.len() > 128 * 1024 {
        return None;
    }

    let (weights, tree_size) = parse_tree(data)?;

    if tree_size >= data.len() {
        return None;
    }

    let compressed_size = data.len() - tree_size;
    // Each Huffman symbol takes at least 1 bit.
    // So the maximum possible number of symbols is compressed_size * 8.
    // If num_literals is larger than this, the block is invalid.
    if num_literals > compressed_size * 8 {
        return None;
    }

    let decoder = Decoder::from_weights(&weights)?;
    decoder.decode(&data[tree_size..], num_literals)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bits() {
        // Data: 0xB3 = 0b10110011, 0x55 = 0b01010101
        // Little-endian bit order: bit 0 is LSB
        let data = vec![0xB3, 0x55];

        // Read 4 bits starting at bit 0: bits 0-3 of byte 0 = 0b0011 = 3
        assert_eq!(read_bits(&data, 0, 4), Some(0x3));

        // Read 4 bits starting at bit 4: bits 4-7 of byte 0 = 0b1011 = 11
        assert_eq!(read_bits(&data, 4, 4), Some(0xB));

        // Read 8 bits starting at bit 4: bits 4-7 of byte 0 + bits 0-3 of byte 1
        // = 0b1011 + 0b0101 = 0b0101_1011 = 0x5B
        assert_eq!(read_bits(&data, 4, 8), Some(0x5B));

        // Read across byte boundary: bits 6-7 of byte 0 + bits 0-1 of byte 1
        // = 0b10 + 0b01 = 0b01_10 = 6
        assert_eq!(read_bits(&data, 6, 4), Some(6));
    }

    #[test]
    fn test_huffman_basic() {
        // Simple tree: 4 symbols, all with 2-bit codes
        // Symbol 0 = 00, Symbol 1 = 01, Symbol 2 = 10, Symbol 3 = 11 (MSB-first codes)
        let mut weights = [0u8; 256];
        weights[0] = 2;
        weights[1] = 2;
        weights[2] = 2;
        weights[3] = 2;

        let decoder = Decoder::from_weights(&weights).unwrap();
        assert_eq!(decoder.max_bits, 2);

        // When reading LSB-first, codes appear reversed:
        // Stream with symbols 0,1,2,3: codes 00,01,10,11 in MSB-first
        // As byte (MSB-first): 00_01_10_11 = 0b00011011 = 0x1B
        // Reading LSB-first: 11,10,01,00 = symbols 3,2,1,0
        let data = vec![0b0001_1011];
        let decoded_symbols = decoder.decode(&data, 4).unwrap();
        assert_eq!(decoded_symbols, vec![3, 2, 1, 0]);
    }

    #[test]
    fn test_parse_tree_4bit() {
        // Header: 0x81 = 4-bit mode, 1 weight (0+1)
        // Actually 0x81 means: 4-bit mode (0x80), 1 weight (0x01+1=2 weights)
        let data = vec![0x81, 0x12]; // 2 weights: 0x2, 0x1

        let (weights, consumed) = parse_tree(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(weights[0], 2);
        assert_eq!(weights[1], 1);
    }

    #[test]
    fn test_parse_tree_8bit() {
        // Header: 0x01 = 8-bit mode, 1 weight (0+1=1 weight)
        let data = vec![0x00, 0x05]; // 1 weight: 5

        let (weights, consumed) = parse_tree(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(weights[0], 5);
    }

    #[test]
    fn test_decode_literals_flow() {
        // Build a simple tree with 2 symbols:
        // Symbol 0: weight 1 (1-bit code: 0)
        // Symbol 1: weight 1 (1-bit code: 1)
        // Tree header: 0x81 (4-bit, 2 weights)
        // Weights: 0x11 (symbol 0=1, symbol 1=1)

        let mut tree_and_data = vec![0x81, 0x11]; // Tree: 2 weights, both = 1
                                                  // Encoded data: symbols 1,1,1 (three 1s)
                                                  // Codes: 0=0, 1=1 (1 bit each, LSB-first)
                                                  // Stream: bits 1,1,1 = 0b0000_0111 = 0x07
        tree_and_data.push(0x07);

        let literals = decode_literals(&tree_and_data, 3).unwrap();
        assert_eq!(literals, vec![1, 1, 1]);
    }

    #[test]
    fn test_decode_literals_bounds_check() {
        // Tree header: 0x81 (4-bit, 2 weights)
        // Weights: 0x11 (symbol 0=1, symbol 1=1)
        let mut tree_and_data = vec![0x81, 0x11];
        tree_and_data.push(0x07); // 1 byte of compressed data

        // compressed_size = 1, max possible literals = 8. Requesting 9 should fail.
        let literals = decode_literals(&tree_and_data, 9);
        assert!(literals.is_none());
    }
}
