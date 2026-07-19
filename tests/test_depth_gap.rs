#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use faultkit::{inject_scoped, Fault};
use ziftsieve::{CompressedBlock, CompressedIndexBuilder, CompressionFormat};

#[test]
#[should_panic(expected = "literal density should logically be bounded by compressed size")]
fn test_gap_literal_density_unknown_uncompressed_len() {
    let block = CompressedBlock::new(0, 100);
    assert_eq!(block.uncompressed_len(), None);
    let density = block.literal_density();
    assert!(
        density < 1.0,
        "literal density should logically be bounded by compressed size when uncompressed is unknown, but got {}",
        density
    );
}

#[test]
#[should_panic(expected = "Engine should fail gracefully on allocation failure, but succeeded")]
fn test_gap_oom_injection_lz4() {
    // Valid LZ4 frame and block.
    // Frame magic: 0x04, 0x22, 0x4D, 0x18
    // FLG: 0x60 (v1, block indep)
    // BD: 0x40 (max block 64KB)
    // HC: 0x82 (valid checksum for 0x60, 0x40)
    // Block size: 1 byte uncompressed -> 0x80000001
    // Block data: 'A' (0x41)
    let data = vec![
        0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82, 0x01, 0x00, 0x00, 0x80, b'A',
    ];

    // We expect the extraction to fail gracefully due to allocation failure.
    // If not, we assert and fail the test, exposing the gap.
    let _guard = inject_scoped(Fault::Alloc { fail_after: 0 });
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&data);

    assert!(
        result.is_err(),
        "Engine should fail gracefully on allocation failure, but succeeded"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("allocation") || err_msg.contains("OOM"),
        "Error message should indicate allocation failure, got: {}",
        err_msg
    );
}
