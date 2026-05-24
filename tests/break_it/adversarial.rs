//! Malformed compressed streams, zip-bomb posture, and parser DoS hooks.

use ziftsieve::{extract_from_bytes, CompressedIndexBuilder, CompressionFormat, ZiftError};

fn assert_zift_actionable(err: &ZiftError) {
    let s = err.to_string();
    assert!(
        s.contains("Fix:") || s.contains("exceeds maximum") || s.contains("likely malformed"),
        "ZiftError must stay actionable for operators at internet scale; got: {s}"
    );
}

// --- LZ4 (default feature) ---

#[test]
fn break_lz4_framed_truncated_block_must_error() {
    // Valid frame header (7 bytes) then a block header claiming payload bytes that are missing.
    // Minimum LZ4 frame header: magic + FLG + BD + header checksum (7 bytes).
    let mut data = vec![
        0x04, 0x22, 0x4d, 0x18, // magic
        0x40, // version 01, no optional fields
        0x00, // BD
        0x00, // header checksum
    ];
    assert_eq!(data.len(), 7);
    // Block: LE u32 size = 4 (compressed), but stream ends before payload.
    data.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);

    let err = extract_from_bytes(CompressionFormat::Lz4, &data).unwrap_err();
    assert_zift_actionable(&err);
}

#[test]
fn break_lz4_legacy_block_claims_payload_beyond_buffer() {
    // Legacy stream (no magic): first u32 is compressed size including header? Parser treats as block header.
    let data = [0xff, 0xff, 0xff, 0x7f]; // huge uncompressed-ish size, no payload follows
    let err = extract_from_bytes(CompressionFormat::Lz4, &data).unwrap_err();
    assert_zift_actionable(&err);
}

#[test]
fn break_lz4_empty_input_errors() {
    let err = extract_from_bytes(CompressionFormat::Lz4, b"").unwrap_err();
    assert_zift_actionable(&err);
}

// --- Gzip / DEFLATE ---

#[cfg(feature = "gzip")]
mod gzip_adversarial {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn break_gzip_zip_bomb_must_fail_closed_at_index_builder() {
        // Highly compressible payload: tiny gzip on disk, massive logical expansion — must not silently index.
        let payload = vec![0u8; 8 * 1024 * 1024];
        let mut enc = GzEncoder::new(Vec::new(), Compression::new(9));
        enc.write_all(&payload).unwrap();
        let gz = enc.finish().unwrap();

        let r = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&gz);
        assert!(
            r.is_err(),
            "Fix: reject gzip-backed indexes when implied decompression exceeds safe ratio versus compressed bytes (zip bomb / index poisoning). gz_len={}",
            gz.len()
        );
        assert_zift_actionable(r.as_ref().unwrap_err());
    }

    #[test]
    fn break_gzip_empty_errors() {
        let err = extract_from_bytes(CompressionFormat::Gzip, b"").unwrap_err();
        assert_zift_actionable(&err);
    }

    #[test]
    fn break_gzip_valid_header_garbage_deflate_body() {
        let mut data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        data.extend_from_slice(&[0x00, 0xff, 0xff]); // invalid DEFLATE stream bits
        let err = extract_from_bytes(CompressionFormat::Gzip, &data).unwrap_err();
        assert_zift_actionable(&err);
    }

    #[test]
    fn break_deflate_instruction_flood_must_hit_safety_cap() {
        // Highly redundant payload — if the parser walks per-symbol without bounding work, this becomes CPU exhaustion.
        let payload = vec![b'q'; 12 * 1024 * 1024];
        let mut enc = GzEncoder::new(Vec::new(), Compression::new(1));
        enc.write_all(&payload).unwrap();
        let gz = enc.finish().unwrap();

        assert!(
            extract_from_bytes(CompressionFormat::Gzip, &gz).is_err(),
            "Fix: DEFLATE literal / instruction walks must trip MAX_DEFLATE_INSTRUCTIONS, literal caps, or gzip ratio guards before returning Ok."
        );
    }
}

// --- Zstd ---

#[cfg(feature = "zstd")]
mod zstd_adversarial {
    use super::*;

    #[test]
    fn break_zstd_truncated_frame_must_error() {
        let mut data = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00];
        data.push(0x00); // incomplete header / blocks
        let err = extract_from_bytes(CompressionFormat::Zstd, &data).unwrap_err();
        assert_zift_actionable(&err);
    }

    #[test]
    fn break_zstd_empty_errors() {
        let err = extract_from_bytes(CompressionFormat::Zstd, b"").unwrap_err();
        assert_zift_actionable(&err);
    }
}

// --- Snappy ---

#[cfg(feature = "snappy")]
mod snappy_adversarial {
    use super::*;

    const STREAM_HDR: &[u8] = &[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];

    #[test]
    fn break_snappy_empty_errors() {
        let err = extract_from_bytes(CompressionFormat::Snappy, b"").unwrap_err();
        assert_zift_actionable(&err);
    }

    #[test]
    fn break_snappy_corrupted_compressed_chunk_must_error() {
        // Valid stream header + compressed chunk (type 0) with nonsense payload (CRC + junk).
        let mut data = Vec::from(STREAM_HDR);
        data.push(0x00); // compressed chunk
        data.extend_from_slice(&[0x01, 0x00]); // varint len = 1
        data.push(0x00); // bogus payload (too short for real snappy frame)

        let err = extract_from_bytes(CompressionFormat::Snappy, &data).unwrap_err();
        assert_zift_actionable(&err);
    }

    #[test]
    fn break_snappy_valid_header_truncated_chunk_must_error() {
        let mut data = Vec::from(STREAM_HDR);
        data.push(0x01); // uncompressed chunk
        data.extend_from_slice(&[0x80, 0x80]); // declares huge length, no bytes follow
        let err = extract_from_bytes(CompressionFormat::Snappy, &data).unwrap_err();
        assert_zift_actionable(&err);
    }
}
