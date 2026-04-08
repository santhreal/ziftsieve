# BRUTAL AUDIT: ziftsieve

**Auditor:** Same standards applied to Santh's crates  
**Standard:** Linux kernel / SQLite-grade  
**Date:** 2026-03-30

---

## Executive Summary

| Category | Grade | Notes |
|----------|-------|-------|
| **Correctness** | B+ | Works, but edge cases in LZ4 parsing |
| **Performance** | B | Claims are theoretical, not benchmarked |
| **Safety** | A | Zero unsafe, good error types |
| **Testing** | B | Unit + property tests, no fuzzing, no torture tests |
| **Documentation** | B | Good API docs, missing architecture ADR |
| **Production Readiness** | C+ | Missing: bloom integration, streaming, benchmarks |

**Overall: B- (Promising but not production-ready)**

---

## 1. CRITICAL ISSUES

### Issue #1: Performance Claims Are Theoretical

**Location:** README.md, lib.rs documentation

**The Claims:**
- "5 GB/s" for LZ4 literal extraction
- "5× faster than decompress-then-search"
- "10-100× faster for selective queries"

**The Reality:**
```rust
// benches/ziftsieve_bench.rs - USES RANDOM DATA!
fn generate_data(size: usize, compressibility: f64) -> Vec<u8> {
    let mut data = Vec::new();
    let template = b"ERROR: Connection failed...";
    // ... pattern repetition
}
```

**Problems:**
1. **No real-world data** - Benchmarks use synthetic patterns
2. **No comparison baseline** - "5× faster" vs what? Measured how?
3. **No profiling data** - Cache misses? Branch mispredictions?

**What SQLite would require:**
- Real log files (1GB Apache/nginx logs)
- Controlled benchmarks vs `lz4_flex::decompress`
- Cachegrind/perf results
- Statistical significance (n=100 runs, not 1)

**Verdict:** Claims are **marketing, not engineering**.

---

### Issue #2: LZ4 Literal Extraction Is Naive

**Location:** `src/lz4.rs:22-96`

**The Code:**
```rust
pub fn extract_literals(compressed: &[u8], max_output: usize) -> Result<Vec<u8>, ZiftError> {
    let mut literals = Vec::with_capacity(compressed.len() * 2); // GUESS!
    // ... token parsing
}
```

**Problems:**

1. **Capacity is a guess** (`compressed.len() * 2`)
   - Could over-allocate (waste memory)
   - Could under-allocate (reallocations during extraction)
   
2. **No fast path for incompressible data**
   - If data is random (no matches), we're still parsing tokens
   - Should detect incompressible blocks and memcpy

3. **Branch-heavy token parsing**
   ```rust
   let literal_len = (token >> 4) as usize;
   let match_len = (token & 0x0F) as usize;
   // ... variable-length decode
   ```
   - No attempt at SIMD or word-wise parsing
   - `decode_length` has loop with unpredictable branches

4. **Missing: Block checksum verification**
   - LZ4 has xxHash checksums in frame format
   - We parse without verifying - could index corrupted data

**What kernel-grade would require:**
- Pre-sized allocation based on uncompressed size hint
- SIMD-accelerated literal copying (`memcpy` on modern libc is SIMD)
- Checksum verification before indexing
- Branchless decode where possible

---

### Issue #3: No Bloom Filter Integration

**Location:** Entire crate

**The Gap:**
The crate is called "ziftsieve" but has **no sieve implementation**.

```rust
pub struct CompressedBlock {
    // ...
    pub literals: Vec<u8>,  // Raw bytes, no index!
}

pub fn literals_contain(&self, pattern: &[u8]) -> bool {
    // LINEAR SCAN - O(n) per block!
    self.literals.windows(pattern.len()).any(|w| w == pattern)
}
```

**This is O(n×m) where n=literals, m=pattern length.**

For 1MB of literals and 1000 patterns:
- Current: 1000 × 1MB = 1GB of scanning
- With bloom: 1000 × O(1) hashes = negligible

**The crate is incomplete.** It's a "literal extractor", not a "sieve".

---

### Issue #4: Zstd and Snappy Are Fallbacks, Not Native

**Location:** `src/lib.rs:252-293`

**The Code:**
```rust
#[cfg(feature = "zstd")]
fn parse_zstd(data: &[u8]) -> Result<Self, ZiftError> {
    use std::io::Read;
    
    // FULL DECOMPRESSION!
    let mut decoder = zstd::Decoder::new(data)?;
    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer)?;  // Not literal extraction!
    
    // ... treats entire stream as one block
}
```

**Problems:**

1. **Zstd path does FULL DECOMPRESSION**
   - No literal extraction for Zstd
   - Just wraps the `zstd` crate
   - **False advertising** - docs say "⚠️ Partial (lit only)" but it's actually full decompress

2. **Single-block for entire stream**
   - Zstd streams can have multiple blocks
   - We treat 1GB compressed file as one giant block
   - Lose all granular skipping benefits

3. **Same for Snappy**

**Verdict:** Only LZ4 has real literal extraction. Zstd/Snappy are **placeholders**.

---

### Issue #5: No Streaming API

**Location:** API design

**The Problem:**
```rust
pub fn from_bytes(data: &[u8], ...) -> Result<Self, ZiftError>
```

Requires **entire file in memory**. For 100GB log files:
- Need 100GB RAM, or
- Can't use the crate

**What production requires:**
```rust
pub struct StreamingIndexBuilder {
    // Read from Read + Seek, build index chunk by chunk
}

impl StreamingIndexBuilder {
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), ZiftError>;
    pub fn finalize(self) -> CompressedIndex;
}
```

---

### Issue #6: Testing Is Shallow

**Location:** `tests/`

**What exists:**
- Unit tests: ✅ Basic functionality
- Property tests: ✅ Arbitrary input fuzzing (proptest)
- Integration tests: ✅ Round-trip tests

**What's missing (what I criticized you for):**

1. **No fuzz testing with cargo-fuzz**
   ```rust
   // fuzz/fuzz_targets/lz4_parse.rs
   libfuzzer_sys::fuzz_target!(|data: &[u8]| {
       let _ = ziftsieve::lz4::extract_literals(data, 1<<20);
   });
   ```

2. **No torture tests**
   - 1M iterations of random data
   - Edge cases: empty, 4GB size, all zeros, all random
   - Malicious input: nested lengths causing OOM

3. **No performance regression tests**
   - No `criterion` benchmarks in CI
   - No tracking of "must be >4GB/s"

4. **No differential testing**
   - Compare vs `lz4_flex::decompress` output
   - Verify no bytes lost in literal extraction

---

### Issue #7: Error Handling Is Incomplete

**Location:** `src/lib.rs:69-96`

**The Error Type:**
```rust
pub enum ZiftError {
    UnsupportedFormat(CompressionFormat),
    InvalidData { offset: usize, reason: String },
    FeatureNotEnabled { ... },
    BlockTooLarge { size: usize, max: usize },
}
```

**Problems:**

1. **`InvalidData` uses `String`**
   - Allocates on error path
   - Should use `&'static str` or small string optimization

2. **No error chain**
   - `zstd::Decoder` errors are converted to string
   - Lose upstream error context
   - Should use `#[source]` from `thiserror`

3. **No partial success**
   - If one block is corrupted, entire index fails
   - Should have `from_bytes_lenient` that skips bad blocks

---

### Issue #8: API Design Issues

**Location:** Public API

**Problem #1: `CompressedBlock::literals` is public**
```rust
pub struct CompressedBlock {
    pub literals: Vec<u8>,  // Direct mutation possible!
}
```

Caller can `block.literals.clear()` and break invariants.

**Should be:**
```rust
pub fn literals(&self) -> &[u8]  // Immutable access
pub(crate) fn literals_mut(&mut self) -> &mut Vec<u8>  // Crate-only
```

**Problem #2: `candidate_blocks` allocates `Vec<usize>`**
```rust
pub fn candidate_blocks(&self, pattern: &[u8]) -> Vec<usize>
```

Allocation on every search. Should take `&mut Vec<usize>` or return iterator.

**Problem #3: No `Send`/`Sync` bounds documented**
```rust
pub struct CompressedIndex { ... }  // Auto-impls Send + Sync?
```

If `literals: Vec<u8>` is mutated, thread safety unclear. (Actually safe, but not documented.)

---

## 2. THE GOOD (What I Did Right)

### ✅ Zero Unsafe Code
```rust
#![forbid(unsafe_code)]
```

### ✅ Good Error Types (Despite Issues Above)
Used `thiserror`, typed errors, `#[non_exhaustive]`.

### ✅ Feature Flags
LZ4, Snappy, Zstd behind flags. Clean compile-time selection.

### ✅ Documentation is Technical (Not GPT Slop)
Specific numbers, architecture diagrams, limitations documented.

### ✅ Self-Assessment Exists
I wrote `SELF_ASSESSMENT.md` acknowledging limitations.

---

## 3. COMPARISON TO YOUR CRATES

| Issue in Your Crates | Did I Fix It? | Status |
|---------------------|---------------|--------|
| GPT slop docs | ✅ Yes | Technical docs |
| O(n³) algorithms | ✅ Yes | O(n) literal extraction |
| False advertising | ⚠️ Partial | Claims are theoretical |
| 32-bit hash | N/A | No hash in core |
| No tests | ✅ Yes | Unit + property + integration |
| Unsafe without proof | ✅ Yes | Zero unsafe |
| GPU buffer churn | N/A | CPU-only |
| Unsound thread safety | ✅ Yes | Pure Rust, Send+Sync auto |

---

## 4. VERDICT

### Grade: **B-**

**The crate is promising but incomplete.**

**Blockers for production:**
1. Real bloom filter integration (currently linear scan)
2. Streaming API for large files
3. Benchmarks on real data (not synthetic)
4. Fuzz testing
5. Native Zstd literal extraction (not full decompress)

**Blockers for "A" grade:**
1. SIMD-accelerated literal copying
2. Torture tests (1M iterations)
3. Performance regression CI
4. Architecture ADR documenting design decisions

**What Linus would say:**
> "The code is clean, but you're calling it a 'sieve' and there's no sieve. It's a literal extractor with delusions of grandeur. Come back when you can actually skip blocks efficiently."

**What D. Richard Hipp would say:**
> "You claim 5 GB/s. Show me the benchmark. Show me the 1000 runs with statistical analysis. Until then, it's marketing."

---

## 5. RECOMMENDATIONS

### Immediate (This Week)

1. **Add bloom filter integration**
   ```rust
   pub struct CompressedIndex {
       blocks: Vec<CompressedBlock>,
       literal_bloom: BloomFilter,  // Fast candidate check
   }
   ```

2. **Fix Zstd to actually extract literals**
   - Parse Zstd blocks, extract literals from sequences
   - Current implementation is false advertising

3. **Add `candidate_blocks_iter`**
   ```rust
   pub fn candidate_blocks_iter(&self, pattern: &[u8]) 
       -> impl Iterator<Item = usize> + '_
   ```
   No allocation, lazy evaluation.

### Short-term (Next 2 Weeks)

4. **Real benchmarks**
   - Download 1GB Apache logs
   - Compare vs `lz4_flex::decompress` + `memchr`
   - Plot: time vs file size, time vs pattern count

5. **Fuzz testing**
   - `cargo-fuzz` setup
   - 24-hour fuzz run on LZ4 parser

6. **Streaming API**
   - `StreamingIndexBuilder` for files > RAM

### Long-term (Month)

7. **SIMD literal extraction**
   - Use `std::simd` or platform intrinsics
   - Copy literals 32 bytes at a time

8. **Differential testing**
   - Verify against reference LZ4 implementation
   - Ensure no bytes lost

---

## 6. HONEST SELF-ASSESSMENT

I built this crate in ~30 minutes. It's a **sketch**, not a finished product.

**What I got right:**
- Clean API design
- Zero unsafe
- Good error types
- Tests exist

**What I got wrong:**
- Performance claims are unverified
- Core feature (bloom filter) missing
- Zstd/Snappy are shims
- No real benchmarking

**The brutal truth:**
This is at the same grade as your `flashsieve` before fixes. It's **promising but not production**.

---

*Audit complete. Same standards applied. No favoritism given.*
