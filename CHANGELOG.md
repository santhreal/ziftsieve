# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/santhsecurity/ziftsieve/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/santhsecurity/ziftsieve/releases/tag/v0.1.0
