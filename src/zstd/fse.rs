//! Finite State Entropy (FSE) decoder used for Huffman weight decompression.
//!
//! Adapted from the `ruzstd` reference implementation (MIT licensed).

use super::bit_io::{BitReader, BitReaderReversed};

pub struct FSEDecoder<'table> {
    pub state: Entry,
    table: &'table FSETable,
}

impl<'t> FSEDecoder<'t> {
    pub fn new(table: &'t FSETable) -> FSEDecoder<'t> {
        FSEDecoder {
            state: table.decode.first().copied().unwrap_or(Entry {
                base_line: 0,
                num_bits: 0,
                symbol: 0,
            }),
            table,
        }
    }

    pub fn init_state(&mut self, bits: &mut BitReaderReversed<'_>) -> Option<()> {
        if self.table.accuracy_log == 0 {
            return None;
        }
        let new_state = bits.get_bits(self.table.accuracy_log);
        self.state = self.table.decode[new_state as usize];

        Some(())
    }

    pub fn update_state(&mut self, bits: &mut BitReaderReversed<'_>) {
        let num_bits = self.state.num_bits;
        let add = bits.get_bits(num_bits);
        let base_line = self.state.base_line;
        let new_state = base_line + add as u32;
        self.state = self.table.decode[new_state as usize];
    }

    pub fn decode_symbol(&self) -> u8 {
        self.state.symbol
    }
}

#[derive(Debug, Clone)]
pub struct FSETable {
    max_symbol: u8,
    pub decode: Vec<Entry>,
    pub accuracy_log: u8,
    pub symbol_probabilities: Vec<i32>,
    symbol_counter: Vec<u32>,
}

impl FSETable {
    pub fn new(max_symbol: u8) -> FSETable {
        FSETable {
            max_symbol,
            symbol_probabilities: Vec::with_capacity(256),
            symbol_counter: Vec::with_capacity(256),
            decode: Vec::new(),
            accuracy_log: 0,
        }
    }

    pub fn reset(&mut self) {
        self.symbol_counter.clear();
        self.symbol_probabilities.clear();
        self.decode.clear();
        self.accuracy_log = 0;
    }

    /// Returns how many BYTEs (not bits) were read while building the decoder.
    pub fn build_decoder(&mut self, source: &[u8], max_log: u8) -> Option<usize> {
        self.accuracy_log = 0;

        let bytes_read = self.read_probabilities(source, max_log)?;
        self.build_decoding_table()?;

        Some(bytes_read)
    }

    pub fn build_from_probabilities(&mut self, acc_log: u8, probs: &[i32]) -> Option<()> {
        if acc_log == 0 {
            return None;
        }
        self.symbol_probabilities = probs.to_vec();
        self.accuracy_log = acc_log;
        self.build_decoding_table()
    }

    fn build_decoding_table(&mut self) -> Option<()> {
        if self.symbol_probabilities.len() > self.max_symbol as usize + 1 {
            return None;
        }

        self.decode.clear();

        let table_size = 1 << self.accuracy_log;
        if self.decode.len() < table_size {
            self.decode.reserve(table_size - self.decode.len());
        }
        self.decode.resize(
            table_size,
            Entry {
                base_line: 0,
                num_bits: 0,
                symbol: 0,
            },
        );

        let mut negative_idx = table_size;

        for symbol in 0..self.symbol_probabilities.len() {
            if self.symbol_probabilities[symbol] == -1 {
                negative_idx -= 1;
                let entry = &mut self.decode[negative_idx];
                entry.symbol = symbol as u8;
                entry.base_line = 0;
                entry.num_bits = self.accuracy_log;
            }
        }

        let mut position = 0;
        for idx in 0..self.symbol_probabilities.len() {
            let symbol = idx as u8;
            if self.symbol_probabilities[idx] <= 0 {
                continue;
            }

            let prob = self.symbol_probabilities[idx];
            for _ in 0..prob {
                let entry = &mut self.decode[position];
                entry.symbol = symbol;

                position = next_position(position, table_size);
                while position >= negative_idx {
                    position = next_position(position, table_size);
                }
            }
        }

        self.symbol_counter.clear();
        self.symbol_counter
            .resize(self.symbol_probabilities.len(), 0);
        for idx in 0..negative_idx {
            let entry = &mut self.decode[idx];
            let symbol = entry.symbol;
            let prob = self.symbol_probabilities[symbol as usize];

            let symbol_count = self.symbol_counter[symbol as usize];
            let (bl, nb) = calc_baseline_and_numbits(table_size as u32, prob as u32, symbol_count);

            if nb > self.accuracy_log {
                return None;
            }
            self.symbol_counter[symbol as usize] += 1;

            entry.base_line = bl;
            entry.num_bits = nb;
        }
        Some(())
    }

    fn read_probabilities(&mut self, source: &[u8], max_log: u8) -> Option<usize> {
        self.symbol_probabilities.clear();

        let mut br = BitReader::new(source);
        self.accuracy_log = ACC_LOG_OFFSET + (br.get_bits(4)? as u8);
        if self.accuracy_log > max_log {
            return None;
        }
        if self.accuracy_log == 0 {
            return None;
        }

        let probability_sum = 1 << self.accuracy_log;
        let mut probability_counter = 0u32;

        while probability_counter < probability_sum {
            let max_remaining_value = probability_sum - probability_counter + 1;
            let bits_to_read = highest_bit_set(max_remaining_value);

            let unchecked_value = br.get_bits(bits_to_read as usize)? as u32;

            let low_threshold = ((1 << bits_to_read) - 1) - max_remaining_value;
            let mask = (1 << (bits_to_read - 1)) - 1;
            let small_value = unchecked_value & mask;

            let value = if small_value < low_threshold {
                br.return_bits(1);
                small_value
            } else if unchecked_value > mask {
                unchecked_value - low_threshold
            } else {
                unchecked_value
            };

            let prob = (value as i32) - 1;

            self.symbol_probabilities.push(prob);
            if prob != 0 {
                if prob > 0 {
                    probability_counter += prob as u32;
                } else if prob == -1 {
                    probability_counter += 1;
                } else {
                    return None;
                }
            } else {
                loop {
                    let skip_amount = br.get_bits(2)? as usize;

                    self.symbol_probabilities
                        .resize(self.symbol_probabilities.len() + skip_amount, 0);
                    if skip_amount != 3 {
                        break;
                    }
                }
            }
        }

        if probability_counter != probability_sum {
            return None;
        }
        if self.symbol_probabilities.len() > self.max_symbol as usize + 1 {
            return None;
        }

        let bytes_read = if br.bits_read() % 8 == 0 {
            br.bits_read() / 8
        } else {
            (br.bits_read() / 8) + 1
        };

        Some(bytes_read)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Entry {
    pub base_line: u32,
    pub num_bits: u8,
    pub symbol: u8,
}

const ACC_LOG_OFFSET: u8 = 5;

fn highest_bit_set(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    u32::BITS - x.leading_zeros()
}

fn next_position(mut p: usize, table_size: usize) -> usize {
    p += (table_size >> 1) + (table_size >> 3) + 3;
    p &= table_size - 1;
    p
}

fn calc_baseline_and_numbits(
    num_states_total: u32,
    num_states_symbol: u32,
    state_number: u32,
) -> (u32, u8) {
    if num_states_symbol == 0 {
        return (0, 0);
    }
    let num_state_slices = if 1 << (highest_bit_set(num_states_symbol) - 1) == num_states_symbol {
        num_states_symbol
    } else {
        1 << highest_bit_set(num_states_symbol)
    };

    let num_double_width_state_slices = num_state_slices - num_states_symbol;
    let num_single_width_state_slices = num_states_symbol - num_double_width_state_slices;
    let slice_width = num_states_total / num_state_slices;
    let num_bits = highest_bit_set(slice_width) - 1;

    if state_number < num_double_width_state_slices {
        let baseline =
            num_single_width_state_slices * slice_width + state_number * slice_width * 2;
        (baseline, num_bits as u8 + 1)
    } else {
        let index_shifted = state_number - num_double_width_state_slices;
        (index_shifted * slice_width, num_bits as u8)
    }
}
