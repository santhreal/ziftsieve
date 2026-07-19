//! Hash functions for Bloom filter operations.

/// 64-bit FNV-1a hash (delegated to hashkit for consistency).
#[inline]
pub fn hash_fnv1a(data: &[u8]) -> u64 {
    hashkit::fnv::fnv1a_64(data)
}

/// 64-bit FNV-1a variant with different offset.
#[inline]
pub fn hash_fnv1a_alt(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0x1465_0FB0_739D_0383;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Generate hash pair using two independent 64-bit hashes.
#[inline]
pub fn hash_pair(item: &[u8]) -> (u64, u64) {
    (hash_fnv1a(item), hash_fnv1a_alt(item))
}

/// Compute nth hash using double hashing: h1 + n*h2 mod m
#[inline]
pub fn nth_hash(h1: u64, h2: u64, n: u32, num_bits: usize) -> usize {
    let n = u64::from(n);
    let idx = h1.wrapping_add(n.wrapping_mul(h2));
    // Reduce modulo the bit count in full 64-bit space, THEN cast. The old
    // `idx.try_into().unwrap_or(usize::MAX)` collapsed every hash above
    // u32::MAX to the single index `usize::MAX % num_bits` on 32-bit targets,
    // destroying the filter's distribution and inflating its false-positive
    // rate. The reduced value is always < num_bits, so the cast is lossless.
    (idx % num_bits as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::nth_hash;

    #[test]
    fn nth_hash_reduces_in_full_64_bit_space_above_u32_max() {
        // idx = h1 = 4_294_967_303, which is u32::MAX + 8 (exceeds a 32-bit usize).
        // The correct index is 4_294_967_303 % 100 == 3. The old
        // try_into().unwrap_or(usize::MAX) path would have yielded
        // usize::MAX % 100 == 95 on a 32-bit target; here we lock the true value.
        assert_eq!(nth_hash(4_294_967_303, 0, 0, 100), 3);
    }

    #[test]
    fn nth_hash_handles_wrapping_sum_beyond_u32_max() {
        // h1 + 1*h2 wraps to u64::MAX - 1 = 18_446_744_073_709_551_614.
        // % 1000 == 614, a value only reachable when the modulo runs in u64 space.
        assert_eq!(nth_hash(u64::MAX, u64::MAX, 1, 1000), 614);
    }

    #[test]
    fn nth_hash_is_always_within_bounds() {
        for n in 0..64 {
            let idx = nth_hash(0xDEAD_BEEF_CAFE_F00D, 0x0123_4567_89AB_CDEF, n, 4096);
            assert!(idx < 4096, "index {idx} out of range for n={n}");
        }
    }
}
