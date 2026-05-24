#![no_main]
use libfuzzer_sys::fuzz_target;
use ziftsieve::CompressedIndexBuilder;

fuzz_target!(|data: &[u8]| {
    // Try each format — must not panic on any input for any format
    for format in [
        ziftsieve::CompressionFormat::Gzip,
        ziftsieve::CompressionFormat::Lz4,
        ziftsieve::CompressionFormat::Snappy,
        ziftsieve::CompressionFormat::Zstd,
    ] {
        let _ = CompressedIndexBuilder::new(format).build_from_bytes(data);
    }
});
