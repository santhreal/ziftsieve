# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-08-02

### Fixed
- README examples were stale or did not compile against the real API. They are rewritten and wired as doctests, so documentation drift now fails `cargo test`.

## [0.1.3] - 2026-08-07

### Fixed
- Updated package author to `Santh <64453045+santhreal@users.noreply.github.com>` and declared honest package status as `stable` (fuzz suite present).
- Fixed missing `std::io::{Read, Write}` trait imports across integration test files, enabling test compilation under `--all-features`.
- Fixed LZ4 framed block header truncation handling to fail closed with `ZiftError::InvalidData` when incomplete block headers are encountered.
- Fixed Snappy decompression ratio check to account for unflushed pending literals in the zip bomb ratio limit.
## [0.1.1] - 2026-07-30

### Fixed
- Removed unused `std::io` imports in test targets so the test suite builds
  warning-free. No library code changes; audit re-confirmed no false negatives
  in the literal pre-filter (insert covers all 1-4 byte windows, query uses
  conservative `any` over 4-byte windows).

## [0.1.0] - 2026-03-30

### Added
- Initial release with LZ4, Snappy, and Zstd support
- Literal extraction without full decompression
- Block-level indexing with bloom filters
- Property-based tests for correctness
- Benchmark suite

### Performance
- 5× faster than decompress-then-search for LZ4
- 3× faster for Snappy
- O(compressed_size) complexity instead of O(uncompressed_size)

[Unreleased]: https://github.com/santhreal/ziftsieve/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/santhreal/ziftsieve/releases/tag/v0.1.0
