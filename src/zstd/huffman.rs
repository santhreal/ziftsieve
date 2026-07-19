//! Zstd Huffman decoder for compressed literals.
//!
//! Zstd stores Huffman weights, not code lengths. The number of bits for a
//! symbol is `max_bits + 1 - weight` where `max_bits` is derived from the Kraft
//! sum of the weights. The last weight is implied and completes the sum to the
//! next power of two. Weights may be stored directly (4 bits per weight) or
//! compressed with FSE.
//!
//! Adapted from the `ruzstd` reference implementation (MIT licensed).

use super::bit_io::BitReaderReversed;
use super::fse::{FSEDecoder, FSETable};

const MAX_MAX_NUM_BITS: u8 = 11;

pub struct HuffmanDecoder<'table> {
    table: &'table HuffmanTable,
    pub state: u64,
}

impl<'t> HuffmanDecoder<'t> {
    pub fn new(table: &'t HuffmanTable) -> HuffmanDecoder<'t> {
        HuffmanDecoder { table, state: 0 }
    }

    pub fn decode_symbol(&mut self) -> u8 {
        self.table.decode[self.state as usize].symbol
    }

    pub fn init_state(&mut self, br: &mut BitReaderReversed<'_>) -> u8 {
        let num_bits = self.table.max_num_bits;
        let new_bits = br.get_bits(num_bits);
        self.state = new_bits;
        num_bits
    }

    pub fn next_state(&mut self, br: &mut BitReaderReversed<'_>) -> u8 {
        let num_bits = self.table.decode[self.state as usize].num_bits;
        let new_bits = br.get_bits(num_bits);

        self.state <<= num_bits;
        self.state &= self.table.decode.len() as u64 - 1;
        self.state |= new_bits;
        num_bits
    }
}

pub struct HuffmanTable {
    decode: Vec<Entry>,
    weights: Vec<u8>,
    pub max_num_bits: u8,
    bits: Vec<u8>,
    bit_ranks: Vec<u32>,
    rank_indexes: Vec<usize>,
    fse_table: FSETable,
}

impl HuffmanTable {
    pub fn new() -> HuffmanTable {
        HuffmanTable {
            decode: Vec::new(),
            weights: Vec::with_capacity(256),
            max_num_bits: 0,
            bits: Vec::with_capacity(256),
            bit_ranks: Vec::with_capacity(11),
            rank_indexes: Vec::with_capacity(11),
            fse_table: FSETable::new(255),
        }
    }

    #[allow(dead_code)] // Decoder API surface for table reuse.
    pub fn reset(&mut self) {
        self.decode.clear();
        self.weights.clear();
        self.max_num_bits = 0;
        self.bits.clear();
        self.bit_ranks.clear();
        self.rank_indexes.clear();
        self.fse_table.reset();
    }

    /// Read the Huffman tree description from `source`, build the decoding
    /// table, and return the number of bytes consumed by the tree description.
    pub fn build_decoder(&mut self, source: &[u8]) -> Option<u32> {
        self.decode.clear();

        let bytes_used = self.read_weights(source)?;
        self.build_table_from_weights()?;
        Some(bytes_used)
    }

    fn read_weights(&mut self, source: &[u8]) -> Option<u32> {
        if source.is_empty() {
            return None;
        }
        let header = source[0];
        let mut bits_read = 8u32;

        if let 0..=127 = header {
            let fse_stream = &source[1..];
            if header as usize > fse_stream.len() {
                return None;
            }

            let bytes_used_by_fse_header = self.fse_table.build_decoder(fse_stream, 6)?;
            if bytes_used_by_fse_header > header as usize {
                return None;
            }

            let compressed_start = bytes_used_by_fse_header;
            let compressed_length = header as usize - bytes_used_by_fse_header;

            let compressed_weights = &fse_stream[compressed_start..];
            if compressed_weights.len() < compressed_length {
                return None;
            }
            let compressed_weights = &compressed_weights[..compressed_length];
            let mut br = BitReaderReversed::new(compressed_weights);

            bits_read += (bytes_used_by_fse_header + compressed_length) as u32 * 8;

            // Skip the zero padding at the end of the last byte of the
            // bitstream and discard the first 1 found.
            let mut skipped_bits = 0;
            loop {
                let val = br.get_bits(1);
                skipped_bits += 1;
                if val == 1 || skipped_bits > 8 {
                    break;
                }
            }
            if skipped_bits > 8 {
                return None;
            }

            // The FSE streams for Huffman weights are interleaved: the first
            // decoder handles even symbols, the second handles odd symbols.
            let fse_table = &self.fse_table;
            let mut dec1 = FSEDecoder::new(fse_table);
            let mut dec2 = FSEDecoder::new(fse_table);

            dec1.init_state(&mut br)?;
            dec2.init_state(&mut br)?;

            self.weights.clear();

            loop {
                let w = dec1.decode_symbol();
                self.weights.push(w);
                dec1.update_state(&mut br);

                if br.bits_remaining() <= -1 {
                    self.weights.push(dec2.decode_symbol());
                    break;
                }

                let w = dec2.decode_symbol();
                self.weights.push(w);
                dec2.update_state(&mut br);

                if br.bits_remaining() <= -1 {
                    self.weights.push(dec1.decode_symbol());
                    break;
                }

                if self.weights.len() > 255 {
                    return None;
                }
            }
        } else {
            // Direct representation: 4 bits per weight.
            let weights_raw = &source[1..];
            let num_weights = header - 127;
            self.weights.resize(num_weights as usize, 0);

            let bytes_needed = if num_weights % 2 == 0 {
                num_weights as usize / 2
            } else {
                (num_weights as usize / 2) + 1
            };

            if weights_raw.len() < bytes_needed {
                return None;
            }

            for idx in 0..num_weights {
                if idx % 2 == 0 {
                    self.weights[idx as usize] = weights_raw[idx as usize / 2] >> 4;
                } else {
                    self.weights[idx as usize] = weights_raw[idx as usize / 2] & 0x0F;
                }
                bits_read += 4;
            }
        }

        let bytes_read = if bits_read % 8 == 0 {
            bits_read / 8
        } else {
            (bits_read / 8) + 1
        };
        Some(bytes_read)
    }

    fn build_table_from_weights(&mut self) -> Option<()> {
        self.bits.clear();
        self.bits.resize(self.weights.len() + 1, 0);

        let mut weight_sum: u32 = 0;
        for w in &self.weights {
            if *w > MAX_MAX_NUM_BITS {
                return None;
            }
            weight_sum += if *w > 0 { 1u32 << (*w - 1) } else { 0 };
        }

        if weight_sum == 0 {
            return None;
        }

        let max_bits = highest_bit_set(weight_sum) as u8;
        let left_over = (1u32 << max_bits) - weight_sum;

        if !left_over.is_power_of_two() {
            return None;
        }

        let last_weight = highest_bit_set(left_over) as u8;

        for symbol in 0..self.weights.len() {
            let bits = if self.weights[symbol] > 0 {
                max_bits + 1 - self.weights[symbol]
            } else {
                0
            };
            self.bits[symbol] = bits;
        }

        self.bits[self.weights.len()] = max_bits + 1 - last_weight;
        self.max_num_bits = max_bits;

        if max_bits > MAX_MAX_NUM_BITS {
            return None;
        }

        self.bit_ranks.clear();
        self.bit_ranks.resize((max_bits + 1) as usize, 0);
        for num_bits in &self.bits {
            self.bit_ranks[(*num_bits) as usize] += 1;
        }

        self.decode.clear();
        self.decode.resize(
            1 << self.max_num_bits,
            Entry {
                symbol: 0,
                num_bits: 0,
            },
        );

        self.rank_indexes.clear();
        self.rank_indexes.resize((max_bits + 1) as usize, 0);

        self.rank_indexes[max_bits as usize] = 0;
        for bits in (1..self.rank_indexes.len() as u8).rev() {
            self.rank_indexes[bits as usize - 1] = self.rank_indexes[bits as usize]
                + self.bit_ranks[bits as usize] as usize * (1 << (max_bits - bits));
        }

        if self.rank_indexes[0] != self.decode.len() {
            return None;
        }

        for symbol in 0..self.bits.len() {
            let bits_for_symbol = self.bits[symbol];
            if bits_for_symbol != 0 {
                let base_idx = self.rank_indexes[bits_for_symbol as usize];
                let len = 1 << (max_bits - bits_for_symbol);
                self.rank_indexes[bits_for_symbol as usize] += len;
                for idx in 0..len {
                    self.decode[base_idx + idx].symbol = symbol as u8;
                    self.decode[base_idx + idx].num_bits = bits_for_symbol;
                }
            }
        }

        Some(())
    }
}

impl Default for HuffmanTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug)]
struct Entry {
    symbol: u8,
    num_bits: u8,
}

fn highest_bit_set(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    u32::BITS - x.leading_zeros()
}

/// Parses a Huffman tree description from a Zstd literals section.
///
/// Returns the full weights vector (including the implied last weight) and the
/// number of bytes consumed by the tree description.
#[allow(dead_code)] // Exercised by unit tests; kept as a public helper.
pub fn parse_tree(data: &[u8]) -> Option<([u8; 256], usize)> {
    let mut table = HuffmanTable::new();
    let bytes_read = table.read_weights(data)?;

    let mut weights = [0u8; 256];
    for (i, &w) in table.weights.iter().enumerate() {
        weights[i] = w;
    }

    let mut weight_sum: u32 = 0;
    for &w in &table.weights {
        weight_sum += if w > 0 { 1u32 << (w - 1) } else { 0 };
    }
    if weight_sum == 0 {
        return None;
    }

    let max_bits = highest_bit_set(weight_sum);
    let left_over = (1u32 << max_bits) - weight_sum;
    if !left_over.is_power_of_two() {
        return None;
    }
    let last_weight = highest_bit_set(left_over);

    if table.weights.len() >= 256 {
        return None;
    }
    weights[table.weights.len()] = last_weight as u8;

    Some((weights, bytes_read as usize))
}

/// Decodes one Huffman-coded stream into `out`.
fn decode_stream(table: &HuffmanTable, stream: &[u8], out: &mut Vec<u8>) -> Option<()> {
    if stream.is_empty() {
        return Some(());
    }

    let mut br = BitReaderReversed::new(stream);

    // Skip the zero padding at the end of the bitstream and discard the first 1.
    let mut skipped = 0;
    loop {
        let val = br.get_bits(1);
        skipped += 1;
        if val == 1 || skipped > 8 {
            break;
        }
    }
    if skipped > 8 {
        return None;
    }

    let mut decoder = HuffmanDecoder::new(table);
    decoder.init_state(&mut br);

    while br.bits_remaining() > -(table.max_num_bits as isize) {
        out.push(decoder.decode_symbol());
        decoder.next_state(&mut br);
    }

    Some(())
}

/// Decodes Huffman-compressed literals from a Zstd literals section payload.
///
/// `data` contains the tree description followed by the coded literal stream(s).
/// `num_literals` is the expected total number of decoded literals.
/// `num_streams` is the number of interleaved Huffman streams (1 or 4).
pub fn decode_literals(data: &[u8], num_literals: usize, num_streams: u8) -> Option<Vec<u8>> {
    if num_literals > 128 * 1024 {
        return None;
    }
    if data.len() > 128 * 1024 {
        return None;
    }

    if num_literals == 0 {
        return Some(Vec::new());
    }

    let mut table = HuffmanTable::new();
    let tree_bytes = table.build_decoder(data)?;
    if tree_bytes as usize >= data.len() {
        return None;
    }

    let payload = &data[tree_bytes as usize..];
    let mut out = Vec::with_capacity(num_literals);

    if num_streams == 1 {
        decode_stream(&table, payload, &mut out)?;
    } else if num_streams == 4 {
        if payload.len() < 6 {
            return None;
        }
        let jump1 = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let jump2 = jump1 + u16::from_le_bytes([payload[2], payload[3]]) as usize;
        let jump3 = jump2 + u16::from_le_bytes([payload[4], payload[5]]) as usize;
        let streams_data = &payload[6..];
        if jump3 > streams_data.len() {
            return None;
        }

        let s1 = &streams_data[..jump1];
        let s2 = &streams_data[jump1..jump2];
        let s3 = &streams_data[jump2..jump3];
        let s4 = &streams_data[jump3..];

        decode_stream(&table, s1, &mut out)?;
        decode_stream(&table, s2, &mut out)?;
        decode_stream(&table, s3, &mut out)?;
        decode_stream(&table, s4, &mut out)?;
    } else {
        return None;
    }

    if out.len() != num_literals {
        return None;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tree_direct_high_nibble_first() {
        // Direct header: 0x81 = 4-bit mode, 2 explicit weights.
        // 0x21: high nibble = 2 (weight 0), low nibble = 1 (weight 1).
        // The third (last) weight is implied to complete the Kraft sum.
        let data = [0x81, 0x21];
        let (weights, consumed) = parse_tree(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(weights[0], 2);
        assert_eq!(weights[1], 1);
        assert_eq!(weights[2], 1);
    }

    #[test]
    fn test_parse_tree_direct_odd_count() {
        // Header 0x82 = 3 explicit weights. 0x23: high nibble=2 (weight 0),
        // low nibble=3 (weight 1). 0x40: high nibble=4 (weight 2), low nibble=0 padding.
        let data = [0x82, 0x23, 0x40];
        let (weights, consumed) = parse_tree(&data).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(weights[0], 2);
        assert_eq!(weights[1], 3);
        assert_eq!(weights[2], 4);
        assert_eq!(weights[3], 2);
    }

    #[test]
    fn test_parse_tree_truncated() {
        // 0x81 requires one more byte for the weights.
        let data = [0x81];
        assert!(parse_tree(&data).is_none());
    }

    #[test]
    fn test_huffman_table_builds_from_direct_weights() {
        // 4 symbols, all weight 2. The encoder would write 3 weights; the last is implied.
        let data = [0x82, 0x22, 0x20]; // explicit weights [2, 2, 2]
        let mut table = HuffmanTable::new();
        let bytes = table.build_decoder(&data).unwrap();
        assert_eq!(bytes, 3);
        assert_eq!(table.max_num_bits, 3);
    }

    #[test]
    fn test_decode_literals_truncated_tree() {
        let data = [0x81]; // missing weight byte
        assert!(decode_literals(&data, 1, 1).is_none());
    }

    /// Generate a de Bruijn sequence over `a..z` of order `n`.
    ///
    /// The returned cyclic sequence of length `26^n` contains every `n`-gram
    /// exactly once. Appending the first `n - 1` characters yields a linear
    /// string with the same property.
    fn debruijn(k: u8, n: usize) -> Vec<u8> {
        // Classic de Bruijn recursion uses short parameter names by convention.
        #[allow(clippy::many_single_char_names)]
        fn db(a: &mut [usize], seq: &mut Vec<u8>, t: usize, p: usize, k: usize, n: usize) {
            if t > n {
                if n % p == 0 {
                    for &val in a.iter().take(p + 1).skip(1) {
                        seq.push((val as u8) + b'a');
                    }
                }
            } else {
                a[t] = a[t - p];
                db(a, seq, t + 1, p, k, n);
                for j in (a[t - p] + 1)..k {
                    a[t] = j;
                    db(a, seq, t + 1, t, k, n);
                }
            }
        }

        let k = k as usize;
        let mut a = vec![0usize; k * n];
        let mut seq = Vec::with_capacity(k.pow(n as u32));
        db(&mut a, &mut seq, 1, 1, k, n);
        seq
    }

    #[test]
    #[cfg(feature = "zstd")]
    fn test_huffman_roundtrip_debruijn() {
        // A de Bruijn sequence of order 3 over a-z contains every 3-gram
        // exactly once, so zstd cannot find any length-3 matches. The output is
        // therefore exactly the literals, and Huffman compression is forced
        // by the small alphabet.
        let mut data = debruijn(26, 3);
        let prefix = data[..2].to_vec();
        data.extend_from_slice(&prefix);

        let compressed = ::zstd::encode_all(&data[..], 3).unwrap();
        let decompressed = ::zstd::decode_all(&compressed[..]).unwrap();
        assert_eq!(decompressed, data, "zstd did not roundtrip the input");
        let blocks = crate::zstd::extract_literals(&compressed).unwrap();

        let mut literals = Vec::with_capacity(data.len());
        for block in blocks {
            literals.extend_from_slice(block.literals());
        }

        assert_eq!(literals, data);
    }
}
