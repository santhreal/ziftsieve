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

#[cfg(feature = "gzip")]
#[test]
fn test_gzip_many_blocks_memory_usage() {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use ziftsieve::gzip::extract_literals;

    // Create a gzip member that attempts to exceed the 256MB total literals limit.
    // We write chunks of 1MB until we cross 256MB.
    // By using Compression::none(), the blocks are stored blocks, meaning all bytes
    // become literals, effectively testing the global literal cap.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
    let chunk = vec![0u8; 1024 * 1024]; // 1MB chunk
    for _ in 0..258 {
        encoder.write_all(&chunk).unwrap();
        encoder.flush().unwrap();
    }
    let compressed = encoder.finish().unwrap();

    let result = extract_literals(&compressed);
    // Because we exceed 256MB of extracted literals, it should fail.
    assert!(
        result.is_err(),
        "Should fail with BlockTooLarge due to global literal cap"
    );
    match result {
        Err(ziftsieve::ZiftError::BlockTooLarge { size, max }) => {
            assert!(size >= 256 * 1024 * 1024);
            assert_eq!(max, 256 * 1024 * 1024);
        }
        _ => panic!("Expected BlockTooLarge error"),
    }
}

#[cfg(feature = "gzip")]
#[test]
fn test_gzip_many_members_memory_usage() {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use ziftsieve::gzip::extract_literals;

    let mut all_compressed = Vec::new();
    // The member limit is 1024. We write 1025 members to trigger the cap.
    for i in 0..1025 {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        write!(encoder, "member_{i}").unwrap();
        all_compressed.extend(encoder.finish().unwrap());
    }

    let result = extract_literals(&all_compressed);
    assert!(result.is_err(), "Should fail due to member limit");
    match result {
        Err(ziftsieve::ZiftError::InvalidData { reason, .. }) => {
            assert!(
                reason.contains("too many gzip members"),
                "Unexpected error reason: {reason}"
            );
        }
        _ => panic!("Expected InvalidData error for too many members"),
    }
}
