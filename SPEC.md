# ziftsieve — Technical Spec

## Overview

Search compressed data without full decompression.  `ziftsieve` extracts literal bytes from compressed blocks and builds bloom filters over them. This allows skipping decompression for blocks that provably cannot contain a search pattern.  # What this crate does  This crate provides a high-performance streaming decompression partial-parser. Instead of fully decompressing streams (which requires resolving all back-references and dictionaries), `ziftsieve` rapidly extracts only the raw literal bytes and constructs per-block Bloom filters over them.  # Why use it  By indexing literals into a Bloom filter, tools can rapidly scan massive compressed archives (like PCAPs, database dumps, or logs) and skip full decompression for any block that provably does not contain the target byte pattern. For large-scale data ingestion and security scanning, this yields orders of magnitude speedups.  # How to get started in 3 lines  ```rust use ziftsieve::{CompressedIndexBuilder, CompressionFormat}; let index = CompressedIndexBuilder::new(CompressionFormat::Lz4).build_from_bytes(b"...").unwrap(); if !index.candidate_blocks(b"my_secret").is_empty() { /* decompress and verify */ } ```  # Supported Formats  - **Gzip:** Supports standard `.gz` files and DEFLATE streams. - **LZ4:** Supports both the LZ4 frame format and raw block format. - **Snappy:** Supports the Snappy framing format (common in database logs). - **Zstd:** Supports Zstandard frames.  Each format is available as an optional crate feature.

## Architecture

The crate is organized into the following public modules:

- `bloom`
- `builder`
- `detect`
- `extract`
- `gzip`
- `index`
- `lz4`
- `snappy`
- `zstd`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- `ZiftError`
