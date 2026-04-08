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
    // The cast is intentional: bloom filter index wraps naturally
    let idx_usize: usize = idx.try_into().unwrap_or(usize::MAX);
    idx_usize % num_bits
}
