#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    clippy::panic,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    unused_comparisons,
    clippy::ignored_unit_patterns
)]
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

/// Generate test data with varying compressibility
fn generate_data(size: usize, compressibility: f64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let pattern = b"ERROR: Connection failed at 2024-01-15T10:30:00Z\n";

    while data.len() < size {
        if rand::random::<f64>() < compressibility {
            // Repeated pattern (compressible)
            data.extend_from_slice(pattern);
        } else {
            // Random data (incompressible)
            data.push(rand::random::<u8>());
        }
    }

    data.truncate(size);
    data
}

/// Build raw LZ4 block data (token stream) with all bytes as literals and no matches.
fn make_raw_lz4_block(data: &[u8]) -> Vec<u8> {
    let mut block = Vec::with_capacity(data.len() + 16);
    let literal_len = data.len();
    let mut token = 0u8;
    if literal_len >= 15 {
        token |= 0xF0;
        block.push(token);
        let mut rem = literal_len - 15;
        while rem >= 255 {
            block.push(255);
            rem -= 255;
        }
        block.push(rem as u8);
    } else {
        token |= (literal_len as u8) << 4;
        block.push(token);
    }
    block.extend_from_slice(data);
    block
}

/// Build a sequence of uncompressed LZ4 blocks (with size headers) for the indexer.
fn make_uncompressed_lz4_blocks(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + (data.len() / block_size + 1) * 4);
    for chunk in data.chunks(block_size) {
        let size = chunk.len() as u32 | 0x8000_0000;
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

fn bench_lz4_literal_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("lz4_literals");
    group.measurement_time(Duration::from_secs(10));

    // High compressibility data (logs)
    let data = generate_data(1_000_000, 0.9);
    let _raw_block = make_raw_lz4_block(&data);
    let compressed = lz4_flex::block::compress(&data);

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("extract_literals_1mb_high_compress", |b| {
        b.iter(|| {
            let literals =
                ziftsieve::lz4::extract_literals(black_box(&compressed), 4 * 1024 * 1024).unwrap();
            black_box(literals);
        });
    });

    // Full decompression for comparison
    group.bench_function("full_decompress_1mb_high_compress", |b| {
        b.iter(|| {
            let decompressed =
                lz4_flex::block::decompress(black_box(&compressed), data.len()).unwrap();
            black_box(decompressed);
        });
    });

    group.finish();
}

fn bench_search_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("search");
    group.measurement_time(Duration::from_secs(10));

    // Create indexed data as uncompressed blocks so the indexer can parse them
    let data = generate_data(10_000_000, 0.8); // 10MB
    let block_data = make_uncompressed_lz4_blocks(&data, 1024 * 1024);

    let index = ziftsieve::CompressedIndexBuilder::new(ziftsieve::CompressionFormat::Lz4)
        .build_from_bytes(&block_data)
        .unwrap();

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("candidate_search_10mb", |b| {
        b.iter(|| {
            let candidates = index.candidate_blocks(black_box(b"ERROR"));
            black_box(candidates);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_lz4_literal_extraction,
    bench_search_throughput
);
criterion_main!(benches);
