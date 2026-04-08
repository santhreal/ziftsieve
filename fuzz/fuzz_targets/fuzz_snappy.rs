#![no_main]
use libfuzzer_sys::fuzz_target;
use ziftsieve::CompressedIndexBuilder;

fuzz_target!(|data: &[u8]| {
    let _ = CompressedIndexBuilder::new(ziftsieve::CompressionFormat::Snappy)
        .build_from_bytes(data);
});
