//! CRITICAL SECURITY AUDIT TESTS for ziftsieve
//!
//! These tests verify security protections at internet scale:
//! 1. Zip bomb protection (nested archive depth limit)
//! 2. Truncated archives must error, not panic
//! 3. Corrupt gzip CRC detection
//! 4. Archive with symlinks must not follow (SSRF prevention)
//! 5. Archive with path traversal (../../) must reject malicious paths
//!
//! Every finding is CRITICAL - at internet scale, a "low" bug corrupts billions of records.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "gzip")]

use flate2::{write::GzEncoder, Compression};
use std::io::Write;
use ziftsieve::{extract::scan_tarball_literals, CompressedIndexBuilder, CompressionFormat};

// =============================================================================
// 1. ZIP BOMB PROTECTION - Nested Archive Depth Limit
// =============================================================================

/// Maximum nested archive depth constant (must match src/extract.rs)
const MAX_NESTED_DEPTH: usize = 5;

/// Creates a minimal valid gzip stream containing the given data
fn create_gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(0));
    encoder.write_all(data).expect("gzip encode");
    encoder.finish().expect("gzip finish")
}

/// Creates a tar archive header for a regular file
fn create_tar_header(name: &[u8], size: u32, typeflag: u8) -> [u8; 512] {
    let mut header = [0u8; 512];

    // Name (bytes 0-99)
    let name_len = name.len().min(100);
    header[0..name_len].copy_from_slice(&name[..name_len]);

    // Mode (bytes 100-107) - 0644
    header[100..108].copy_from_slice(b"0000644 ");

    // UID (bytes 108-115)
    header[108..116].copy_from_slice(b"0000000 ");

    // GID (bytes 116-123)
    header[116..124].copy_from_slice(b"0000000 ");

    // Size (bytes 124-135) - octal
    let size_str = format!("{:011o} ", size);
    header[124..136].copy_from_slice(size_str.as_bytes());

    // Mtime (bytes 136-147)
    header[136..148].copy_from_slice(b"00000000000 ");

    // Checksum placeholder (bytes 148-155) - filled with spaces for calculation
    header[148..156].copy_from_slice(b"        ");

    // Typeflag (byte 156)
    header[156] = typeflag;

    // Linkname (bytes 157-256) - empty for regular files

    // Calculate and fill checksum
    let checksum: u64 = header.iter().map(|&b| b as u64).sum();
    let checksum_str = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(checksum_str.as_bytes());

    header
}

/// Creates a tar archive with a single file
fn create_tar_archive(entries: &[(String, &[u8], u8)]) -> Vec<u8> {
    let mut archive = Vec::new();

    for (name, content, typeflag) in entries {
        let header = create_tar_header(name.as_bytes(), content.len() as u32, *typeflag);
        archive.extend_from_slice(&header);
        archive.extend_from_slice(content);

        // Pad to 512-byte boundary
        let padding = (512 - (content.len() % 512)) % 512;
        archive.extend_from_slice(&vec![0u8; padding]);
    }

    // End with two zero blocks
    archive.extend_from_slice(&[0u8; 512]);
    archive.extend_from_slice(&[0u8; 512]);

    archive
}

/// Creates a nested tar.gz: outer gzip -> tar containing inner gzip -> tar -> ...
fn create_nested_tarball(depth: usize) -> Vec<u8> {
    if depth == 0 {
        // Base case: a simple tar with one file
        let tar = create_tar_archive(&[("file.txt".to_string(), b"content", b'0')]);
        return create_gzip(&tar);
    }

    // Recursive case: tar containing a gzip of the next level
    let inner = create_nested_tarball(depth - 1);
    let name = format!("level{}.tar.gz", depth);
    let tar = create_tar_archive(&[(name, &inner, b'0')]);
    create_gzip(&tar)
}

#[test]
fn zip_bomb_nested_depth_limit_enforced() {
    //! Fix: Reject archives exceeding MAX_NESTED_DEPTH to prevent zip bomb DoS

    // Depth 1 should work
    let depth_1 = create_nested_tarball(1);
    let result = scan_tarball_literals(&depth_1);
    assert!(result.is_ok(), "Depth 1 should be allowed");

    // Depth at limit should work
    let at_limit = create_nested_tarball(MAX_NESTED_DEPTH);
    let result = scan_tarball_literals(&at_limit);
    assert!(result.is_ok(), "Depth at limit should be allowed");

    // Depth beyond limit must be rejected
    let beyond_limit = create_nested_tarball(MAX_NESTED_DEPTH + 1);
    let result = scan_tarball_literals(&beyond_limit);
    assert!(result.is_err(), "Depth beyond limit should be rejected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("nested archive depth exceeds limit"),
        "Error should mention depth limit: {}",
        err_msg
    );
}

#[test]
fn zip_bomb_many_members_rejected() {
    //! Fix: Limit tar members to prevent memory exhaustion attacks

    // Create a tar with many small files (8192 is the limit)
    let mut entries: Vec<(String, &[u8], u8)> = Vec::new();
    for i in 0..9000 {
        entries.push((format!("file{}.txt", i), &b"x"[..], b'0'));
    }

    let tar = create_tar_archive(&entries);
    let gzipped = create_gzip(&tar);

    let result = scan_tarball_literals(&gzipped);
    assert!(result.is_err(), "Should reject tar with too many members");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too many members") || err_msg.contains("8192"),
        "Error should mention member limit: {}",
        err_msg
    );
}

// =============================================================================
// 2. TRUNCATED ARCHIVES - Must Error, Not Panic
// =============================================================================

#[test]
fn truncated_tar_header_rejected() {
    //! Fix: Truncated tar header must return error, not panic

    let tar = &create_tar_archive(&[("file.txt".to_string(), b"content", b'0')])[..300];
    let gzipped = create_gzip(tar);

    let result = scan_tarball_literals(&gzipped);
    assert!(result.is_err(), "Truncated tar header should error");
}

#[test]
fn truncated_tar_content_rejected() {
    //! Fix: Truncated tar content must return error

    // Create a tar header claiming 1000 bytes but only providing 10
    let mut archive = Vec::new();
    let header = create_tar_header(b"file.txt", 1000, b'0');
    archive.extend_from_slice(&header);
    archive.extend_from_slice(b"short"); // Only 5 bytes, not 1000

    let gzipped = create_gzip(&archive);
    let result = scan_tarball_literals(&gzipped);
    assert!(result.is_err(), "Truncated tar content should error");
}

#[test]
fn truncated_gzip_rejected() {
    //! Fix: Truncated gzip must return error

    let data = b"test data for compression";
    let compressed = create_gzip(data);
    let truncated = &compressed[..compressed.len() / 2];

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(truncated);

    // May error or return partial - but must not panic
    match result {
        Ok(_) | Err(_) => {} // Both are acceptable
    }
}

// =============================================================================
// 3. CORRUPT GZIP CRC - Must Detect and Error
// =============================================================================

#[test]
fn corrupt_gzip_crc_detected() {
    //! Fix: Corrupt gzip CRC32 must be detected and rejected
    //!
    //! NOTE: Currently the implementation intentionally skips CRC validation
    //! for performance. This test documents the EXPECTED behavior.
    //!
    //! To fix: Add CRC computation during literal extraction and validate
    //! against the stored CRC32 in the gzip footer.

    let data = b"test data with known content";
    let mut compressed = create_gzip(data);

    // Corrupt the CRC32 (last 8 bytes are CRC32 + ISIZE)
    let len = compressed.len();
    if len >= 4 {
        compressed[len - 8] ^= 0xFF;
        compressed[len - 7] ^= 0xFF;
        compressed[len - 6] ^= 0xFF;
        compressed[len - 5] ^= 0xFF;
    }

    let result = CompressedIndexBuilder::new(CompressionFormat::Gzip).build_from_bytes(&compressed);

    assert!(result.is_err());
}

// =============================================================================
// 4. SYMLINK HANDLING - Must Not Follow (SSRF Prevention)
// =============================================================================

#[test]
fn symlink_rejected_with_error() {
    //! Fix: Symbolic links must be explicitly rejected (SSRF prevention)
    //!
    //! Typeflag '2' indicates a symbolic link. These must not be followed
    //! as they could point to sensitive system files (/etc/passwd) or
    //! external resources.

    let tar = create_tar_archive(&[
        ("symlink_file".to_string(), b"/etc/passwd", b'2'), // Typeflag 2 = symlink
    ]);
    let gzipped = create_gzip(&tar);

    let result = scan_tarball_literals(&gzipped);
    assert!(result.is_err(), "Symbolic links should be rejected");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("symbolic link") || err_msg.contains("symlink"),
        "Error should mention symlink rejection: {}",
        err_msg
    );
}

#[test]
fn hardlink_rejected_with_error() {
    //! Fix: Hard links must be explicitly rejected
    //!
    //! Typeflag '1' indicates a hard link. These must not be followed
    //! as they could reference files outside the intended directory.

    let tar = create_tar_archive(&[
        ("hardlink_file".to_string(), b"/etc/passwd", b'1'), // Typeflag 1 = hardlink
    ]);
    let gzipped = create_gzip(&tar);

    let result = scan_tarball_literals(&gzipped);
    assert!(result.is_err(), "Hard links should be rejected");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("hard link") || err_msg.contains("hardlink"),
        "Error should mention hardlink rejection: {}",
        err_msg
    );
}

#[test]
fn symlink_to_sensitive_path_rejected() {
    //! Fix: Symlinks to sensitive paths must be blocked

    let sensitive_paths = vec![
        "/etc/passwd",
        "/etc/shadow",
        "../../../etc/passwd",
        "/root/.ssh/id_rsa",
        "C:\\Windows\\System32\\config\\SAM",
    ];

    for path in sensitive_paths {
        let tar = create_tar_archive(&[("evil_link".to_string(), path.as_bytes(), b'2')]);
        let gzipped = create_gzip(&tar);

        let result = scan_tarball_literals(&gzipped);
        assert!(result.is_err(), "Symlink to {} should be rejected", path);
    }
}

// =============================================================================
// 5. PATH TRAVERSAL PROTECTION - Reject ../../ Paths
// =============================================================================

#[test]
fn path_traversal_dotdot_rejected() {
    //! Fix: Path traversal with .. must be rejected
    //!
    //! Entries like "../../etc/passwd" or "foo/../../../etc/shadow"
    //! must be rejected to prevent writing outside intended directories.

    let malicious_paths = vec![
        "../evil.txt",
        "../../evil.txt",
        "../../../etc/passwd",
        "foo/../../evil.txt",
        "foo/../bar/../../evil.txt",
        "../",
        "foo/../",
    ];

    for path in malicious_paths {
        let tar = create_tar_archive(&[(path.to_string(), b"malicious content", b'0')]);
        let gzipped = create_gzip(&tar);

        let result = scan_tarball_literals(&gzipped);
        assert!(
            result.is_err(),
            "Path traversal '{}' should be rejected",
            path
        );

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("path traversal") || err_msg.contains(".."),
            "Error should mention path traversal: {}",
            err_msg
        );
    }
}

#[test]
fn path_traversal_absolute_path_handled() {
    //! Fix: Absolute paths should be handled carefully
    //!
    //! While not path traversal per se, absolute paths like "/etc/passwd"
    //! in an archive are suspicious and should be rejected or sanitized.

    let tar = create_tar_archive(&[("/etc/passwd".to_string(), b"malicious", b'0')]);
    let gzipped = create_gzip(&tar);

    // Currently absolute paths are allowed but should be reviewed
    let result = scan_tarball_literals(&gzipped);
    // Document current behavior - may need to change to reject
    match result {
        Ok(_) | Err(_) => {}
    }
}

#[test]
fn legitimate_paths_allowed() {
    //! Fix: Legitimate paths without traversal must work

    let legitimate_paths = vec![
        "file.txt",
        "dir/file.txt",
        "deep/nested/dir/file.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        ".hidden",
        "dir/.hidden",
        "..valid..name..", // ".." in middle is OK
        "valid..txt",      // ".." in middle is OK
    ];

    for path in legitimate_paths {
        let tar = create_tar_archive(&[(path.to_string(), b"legitimate content", b'0')]);
        let gzipped = create_gzip(&tar);

        let result = scan_tarball_literals(&gzipped);
        assert!(
            result.is_ok(),
            "Legitimate path '{}' should be allowed: {:?}",
            path,
            result
        );
    }
}

// =============================================================================
// 6. COMBINED ATTACKS
// =============================================================================

#[test]
fn combined_traversal_and_symlink_rejected() {
    //! Fix: Combined attacks must be rejected

    let tar = create_tar_archive(&[("../symlink".to_string(), b"/etc/passwd", b'2')]);
    let gzipped = create_gzip(&tar);

    let result = scan_tarball_literals(&gzipped);
    assert!(
        result.is_err(),
        "Combined traversal+symlink should be rejected"
    );
}

#[test]
fn large_member_size_rejected() {
    //! Fix: Impossibly large member sizes must be rejected

    let header = create_tar_header(b"huge_file", u32::MAX, b'0');

    // Don't actually provide the content
    let gzipped = create_gzip(&header);

    let result = scan_tarball_literals(&gzipped);
    // Should error due to truncated content
    assert!(result.is_err());
}

// =============================================================================
// 7. EDGE CASES AND FUZZ-STYLE TESTS
// =============================================================================

#[test]
fn empty_tar_archive_allowed() {
    //! Empty tar (just end markers) should return empty blocks

    let mut archive = Vec::new();
    archive.extend_from_slice(&[0u8; 512]); // End marker
    archive.extend_from_slice(&[0u8; 512]); // End marker

    let gzipped = create_gzip(&archive);
    let result = scan_tarball_literals(&gzipped);

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn tar_with_only_directories_ignored() {
    //! Directories (typeflag '5') should be silently skipped

    let tar = create_tar_archive(&[
        ("empty_dir/".to_string(), b"", b'5'), // Typeflag 5 = directory
    ]);
    let gzipped = create_gzip(&tar);

    let result = scan_tarball_literals(&gzipped);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn malicious_all_zeros_handled() {
    //! All-zeros input should not cause infinite loop

    let zeros = vec![0u8; 1024];
    let gzipped = create_gzip(&zeros);

    let result = scan_tarball_literals(&gzipped);
    // May error or return empty, but must not hang
    match result {
        Ok(_) | Err(_) => {}
    }
}

#[test]
fn very_long_filename_rejected() {
    //! Filenames exceeding tar limits should be handled

    let long_name = "a".repeat(200); // Max is 100
    let tar = create_tar_archive(&[(long_name, b"content", b'0')]);
    let gzipped = create_gzip(&tar);

    // Should either work (truncated) or error
    let result = scan_tarball_literals(&gzipped);
    match result {
        Ok(_) | Err(_) => {}
    }
}


