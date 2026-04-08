#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::error::Error;
use ziftsieve::{CompressedIndexBuilder, CompressionFormat, StreamingIndexBuilder};

#[test]
fn test_adversarial_empty_input() -> Result<(), Box<dyn Error>> {
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    // Empty LZ4 input is correctly rejected.
    assert!(builder.build_from_bytes(b"").is_err());
    Ok(())
}

#[test]
fn test_adversarial_null_bytes() -> Result<(), Box<dyn Error>> {
    let nulls = vec![0; 10000];
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    // Might fail with ZiftError due to invalid LZ4, but shouldn't panic
    let result = builder.build_from_bytes(&nulls);
    match result {
        Ok(index) => assert_eq!(index.block_count(), 0),
        Err(e) => assert!(
            e.to_string().contains("invalid compressed data") || e.to_string().contains("exceeds")
        ),
    }
    Ok(())
}

#[test]
fn test_adversarial_all_ones() -> Result<(), Box<dyn Error>> {
    let ones = vec![0xFF; 10000];
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&ones);
    match result {
        Ok(index) => assert_eq!(index.block_count(), 0),
        Err(e) => assert!(
            e.to_string().contains("invalid compressed data") || e.to_string().contains("exceeds")
        ),
    }
    Ok(())
}

#[test]
fn test_adversarial_streaming_corrupt_chunks() -> Result<(), Box<dyn Error>> {
    let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
    let res1 = builder.process_chunk(&[0xFF; 1024]);
    if let Err(e) = res1 {
        assert!(e.to_string().contains("invalid") || e.to_string().contains("exceeds"));
    }
    let res2 = builder.process_chunk(&[0x00; 1024]);
    if let Err(e) = res2 {
        assert!(e.to_string().contains("invalid") || e.to_string().contains("exceeds"));
    }
    let index = builder.finalize()?;
    assert_eq!(index.format(), CompressionFormat::Lz4);
    Ok(())
}

#[test]
fn test_adversarial_huge_input() -> Result<(), Box<dyn Error>> {
    // Over 1.2MB of valid-looking lz4 blocks to test huge buffers.
    // Each iteration adds 4 bytes. 300,000 * 4 = 1,200,000 bytes (1.2 MB)
    let mut huge = Vec::with_capacity(1_300_000);
    for _ in 0..300_000 {
        // Just empty blocks 0x00000000
        huge.extend_from_slice(&0u32.to_le_bytes());
    }
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&huge);
    match result {
        Ok(index) => assert_eq!(index.block_count(), 0), // end marker blocks are 0
        Err(e) => assert!(e.to_string().contains("invalid") || e.to_string().contains("too many")),
    }
    Ok(())
}

#[test]
fn test_adversarial_unicode() -> Result<(), Box<dyn Error>> {
    let unicode_str = "こんにちは世界, this is 🦊 trying to break it. 𠜎𠜱𠝹";
    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(unicode_str.as_bytes());
    match result {
        Ok(index) => assert_eq!(index.block_count(), 0),
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("invalid")
                    || err_str.contains("truncated")
                    || err_str.contains("exceeds")
            );
        }
    }
    Ok(())
}

#[test]
fn test_adversarial_integer_overflow_boundary() -> Result<(), Box<dyn Error>> {
    // We try to trigger an integer overflow by crafting a block header with the maximum
    // 32-bit integer size for compressed block size, but we only supply a few bytes.
    let mut data = vec![0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x00];

    // Size = u32::MAX. In LZ4, high bit is uncompressed flag, but the size will be 0x7FFFFFFF
    data.extend_from_slice(&u32::MAX.to_le_bytes());
    data.push(b'A');

    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let result = builder.build_from_bytes(&data);
    match result {
        Ok(index) => assert_eq!(index.block_count(), 0),
        Err(e) => {
            let err_str = e.to_string();
            assert!(err_str.contains("exceeds maximum") || err_str.contains("truncated"));
        }
    }
    Ok(())
}

#[test]
fn test_adversarial_extreme_size() -> Result<(), Box<dyn Error>> {
    // We construct a seemingly large frame header or block header
    // In lz4.rs, max block size is 4MB.
    // We supply a frame that claims to be larger.
    let mut data = vec![0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x00];
    // Block size: 0x7FFFFFFF (max possible signed 32-bit, > 4MB)
    data.extend_from_slice(&0x7FFF_FFFF_u32.to_le_bytes());
    data.push(b'A');

    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let res = builder.build_from_bytes(&data);
    assert!(res.is_err());
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("exceeds maximum") || err_str.contains("truncated block"));
    Ok(())
}

#[test]
fn test_adversarial_io_error_injection() -> Result<(), Box<dyn Error>> {
    let data = vec![
        0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82, 0x01, 0x00, 0x00, 0x80, b'A',
    ];

    // Test multiple chunking scenarios using the streaming builder
    // simulating partial writes and IO-like chunks
    for chunk_size in 1..=data.len() {
        let mut builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
        let mut success = true;

        for chunk in data.chunks(chunk_size) {
            if let Err(e) = builder.process_chunk(chunk) {
                success = false;
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("invalid")
                        || err_msg.contains("truncated")
                        || err_msg.contains("exceeds"),
                    "Unexpected error on chunked stream: {}",
                    err_msg
                );
                break;
            }
        }

        let final_res = builder.finalize();
        if !success {
            // Expected either a success or a valid index (with maybe 0 blocks)
            assert!(
                final_res.is_ok(),
                "Finalizing the stream builder must succeed even after errors: {:?}",
                final_res.err()
            );
        }
    }

    Ok(())
}

#[test]
fn test_concurrent_stress() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(vec![
        0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82, 0x01, 0x00, 0x00, 0x80, b'A',
    ]);
    let mut handles = vec![];

    for _ in 0..32 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
            let res1 = builder.build_from_bytes(&d);
            match res1 {
                Ok(_) => {}
                Err(_) => {}
            } // Must not panic

            let mut stream_builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
            let res2 = stream_builder.process_chunk(&d);
            match res2 {
                Ok(_) => {}
                Err(_) => {}
            } // Must not panic
            let final_res = stream_builder.finalize();
            assert!(
                final_res.is_ok(),
                "Finalizing the stream builder should always succeed: {:?}",
                final_res.err()
            );
        }));
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during concurrent stress test");
    }
}

#[test]
fn test_adversarial_boundaries() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],           // Empty
        vec![0x00],       // Single byte
        vec![0xFF],       // Single 0xFF
        vec![0; 1024],    // All zeros
        vec![0xFF; 1024], // All 0xFF
        (0..1024)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect(), // Alternating 0xAA 0x55
                          // We'd test u32::MAX sized vectors if memory allowed, but we'll use a large enough valid looking header instead.
    ];

    for case in cases {
        let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
        let res1 = builder.build_from_bytes(&case);
        match res1 {
            Ok(_) => {}
            Err(_) => {}
        } // Must not panic

        let mut stream_builder = StreamingIndexBuilder::new(CompressionFormat::Lz4);
        let res2 = stream_builder.process_chunk(&case);
        match res2 {
            Ok(_) => {}
            Err(_) => {}
        } // Must not panic
        let final_res = stream_builder.finalize();
        assert!(
            final_res.is_ok(),
            "Finalizing the stream builder should always succeed: {:?}",
            final_res.err()
        );
    }
}

#[test]
fn test_integer_overflows() {
    // Tests meant to probe exact integer boundaries and buffer limits
    let bounds = vec![8, 16, 256, 4096, 65535, 65536];

    for bound in bounds {
        // Build a block size that is exactly the bound
        let mut data = vec![0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82]; // valid header
        let size: u32 = bound as u32;
        let block_size = size | 0x8000_0000; // uncompressed flag
        data.extend_from_slice(&block_size.to_le_bytes());

        // Fill data up to the bound
        data.extend(vec![b'A'; bound]);

        let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
        let res = builder.build_from_bytes(&data);
        assert!(
            res.is_ok(),
            "Engine should handle exact buffer sizes up to {} correctly",
            bound
        );
        if let Ok(index) = res {
            assert_eq!(index.block_count(), 1);
            // Verify extraction didn't truncate
            let block = index.get_block(0).unwrap();
            assert_eq!(block.literals().len(), bound);
        }
    }
}

#[test]
fn test_integer_overflow_truncation_probes() {
    let mut data = vec![0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82];

    // Pass a size that is larger than u32 but disguised (if parser truncated poorly)
    // Actually we only pass u32 here, but we pass large sizes that exceed typical limits
    let large_size: u32 = 0x7FFF_FFFF; // Max signed 32-bit
    let block_size = large_size | 0x8000_0000;
    data.extend_from_slice(&block_size.to_le_bytes());
    data.push(b'A');

    let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
    let res = builder.build_from_bytes(&data);
    assert!(
        res.is_err(),
        "Engine should fail on sizes exceeding bounds rather than truncating and succeeding"
    );
}
