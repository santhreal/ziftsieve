use std::sync::Arc;
use std::thread;
use ziftsieve::{CompressedIndexBuilder, CompressionFormat};

fn spawn_extractors<F>(data: Arc<Vec<u8>>, format: CompressionFormat, check: F)
where
    F: Fn(Result<ziftsieve::CompressedIndex, ziftsieve::ZiftError>) + Send + Sync + 'static,
{
    let check = Arc::new(check);
    let mut handles = vec![];

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        let check_clone = Arc::clone(&check);
        handles.push(thread::spawn(move || {
            let builder = CompressedIndexBuilder::new(format);
            check_clone(builder.build_from_bytes(&data_clone));

            let mut stream_builder = ziftsieve::StreamingIndexBuilder::new(format);
            let _ = stream_builder.process_chunk(&data_clone);
            let _ = stream_builder.finalize();
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

#[test]
fn test_concurrent_extraction_lz4() {
    // Valid LZ4 end-of-frame marker (produces empty blocks)
    let data = Arc::new(vec![0; 100]);
    spawn_extractors(data, CompressionFormat::Lz4, |result| {
        assert!(result.is_ok(), "LZ4 extraction should succeed");
    });
}

#[test]
#[cfg(feature = "gzip")]
fn test_concurrent_extraction_gzip() {
    // Valid empty gzip stream
    let data = Arc::new(vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    spawn_extractors(data, CompressionFormat::Gzip, |result| {
        assert!(result.is_ok(), "gzip extraction should succeed");
    });
}

#[test]
#[cfg(feature = "snappy")]
fn test_concurrent_extraction_snappy() {
    let mut data = vec![
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, // Stream ID
    ];
    data.push(0x01); // Uncompressed chunk
    data.extend_from_slice(&[0x0c, 0x00, 0x00]); // Length 12 (4 CRC + 8 data)
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Dummy CRC
    data.extend_from_slice(b"testdata"); // 8 bytes of data
    let data = Arc::new(data);
    spawn_extractors(data, CompressionFormat::Snappy, |result| {
        assert!(result.is_ok(), "Snappy extraction should succeed");
    });
}

#[test]
#[cfg(feature = "zstd")]
fn test_concurrent_extraction_zstd() {
    // Empty zstd frame
    let data = Arc::new(vec![
        0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
    ]);
    spawn_extractors(data, CompressionFormat::Zstd, |result| {
        assert!(result.is_ok(), "Zstd extraction should succeed");
    });
}

#[test]
fn test_concurrent_memory_limits() {
    let data = Arc::new(vec![0; 100]);
    let mut handles = vec![];

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let builder =
                CompressedIndexBuilder::new(CompressionFormat::Lz4).expected_items(10_000_000);
            let result = builder.build_from_bytes(&data_clone);
            assert!(result.is_ok(), "memory limit test should succeed");
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

#[test]
fn test_concurrent_malformed_data() {
    let data = Arc::new(vec![0xFF; 1024]);
    let mut handles = vec![];

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let builder = CompressedIndexBuilder::new(CompressionFormat::Lz4);
            let result = builder.build_from_bytes(&data_clone);
            assert!(result.is_err(), "malformed data should be rejected");
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

#[test]
#[cfg(feature = "gzip")]
fn test_concurrent_truncated_gzip() {
    let data = Arc::new(vec![0x1f, 0x8b, 0x08, 0x00]);
    let mut handles = vec![];

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let builder = CompressedIndexBuilder::new(CompressionFormat::Gzip);
            let result = builder.build_from_bytes(&data_clone);
            assert!(result.is_err(), "truncated gzip should be rejected");
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

#[test]
#[cfg(feature = "zstd")]
fn test_concurrent_truncated_zstd() {
    let data = Arc::new(vec![0x28, 0xb5, 0x2f, 0xfd, 0x00]);
    let mut handles = vec![];

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let builder = CompressedIndexBuilder::new(CompressionFormat::Zstd);
            let result = builder.build_from_bytes(&data_clone);
            assert!(result.is_err(), "truncated zstd should be rejected");
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

#[test]
fn test_concurrent_streaming_malformed_data() {
    let data = Arc::new(vec![0xFF; 1024]);
    let mut handles = vec![];

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let mut stream_builder = ziftsieve::StreamingIndexBuilder::new(CompressionFormat::Lz4);
            let result = stream_builder.process_chunk(&data_clone);
            assert!(
                result.is_err(),
                "malformed streaming data should be rejected"
            );
        }));
    }

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}
