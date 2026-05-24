#![no_main]
use libfuzzer_sys::fuzz_target;
use ziftsieve::CompressedIndexBuilder;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any arbitrary bytes interpreted as gzip
    let _ = CompressedIndexBuilder::new(ziftsieve::CompressionFormat::Gzip)
        .build_from_bytes(data);
});
