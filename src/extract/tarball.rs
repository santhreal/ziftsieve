//! Gzip-wrapped POSIX `.tar.gz` literal extraction.

use super::CompressedBlock;
use crate::ZiftError;
use flate2::read::MultiGzDecoder;
use std::io::Read;

const MAX_TARBALL_BYTES: usize = 256 * 1024 * 1024;
const TAR_BLOCK_SIZE: usize = 512;
const MAX_TAR_MEMBERS: usize = 8_192;

#[derive(Debug, Clone)]
struct TarHeader {
    content_offset: usize,
    content_size: usize,
    is_regular_file: bool,
    is_symlink: bool,
    is_hardlink: bool,
    name: String,
}

fn parse_tar_octal_usize(data: &[u8], offset: usize) -> Result<usize, ZiftError> {
    let mut value: usize = 0;
    let mut found = false;

    for &byte in data {
        if byte == 0 || byte == b' ' {
            if !found {
                continue;
            }
            break;
        }

        if !(b'0'..=b'7').contains(&byte) {
            return Err(ZiftError::InvalidData {
                offset,
                reason: "invalid octal digit in tar header. Fix: use a valid tar archive"
                    .to_string(),
            });
        }

        found = true;
        let digit = usize::from(byte - b'0');
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| ZiftError::InvalidData {
                offset,
                reason: "tar member size overflows usize. Fix: use a smaller tar archive"
                    .to_string(),
            })?;
    }

    Ok(value)
}

fn is_end_of_archive_block(header: &[u8]) -> bool {
    header.iter().all(|&byte| byte == 0)
}

fn is_regular_file(typeflag: u8) -> bool {
    matches!(typeflag, b'0' | 0)
}

fn is_symlink(typeflag: u8) -> bool {
    // Symlink typeflag is '2' per POSIX tar spec
    typeflag == b'2'
}

fn is_hardlink(typeflag: u8) -> bool {
    // Hardlink typeflag is '1' per POSIX tar spec
    typeflag == b'1'
}

/// Maximum depth for nested archive scanning (zip bomb protection).
const MAX_NESTED_DEPTH: usize = 5;

/// Checks if a tar entry name contains path traversal sequences.
/// Rejects: .. / ../ /.. /path/../other /.. /.
fn contains_path_traversal(name: &str) -> bool {
    // Check for ".." as a complete path component
    // This covers: "../", "/..", "/../", ".." at start/end
    if name == ".." {
        return true;
    }
    if name.starts_with("../") || name.ends_with("/..") {
        return true;
    }
    if name.contains("/../") {
        return true;
    }
    // Also check for "/./" and leading "./" which can be used for obfuscation
    if name.starts_with("./") && name.len() > 2 {
        // Allow just "./" but not "./../" etc
        let rest = &name[2..];
        if rest.starts_with('.') || rest.contains('/') {
            return contains_path_traversal(rest);
        }
    }
    false
}

fn next_member_offset(offset: usize, content_size: usize) -> Result<usize, ZiftError> {
    let padded_size = (content_size + (TAR_BLOCK_SIZE - 1)) & !(TAR_BLOCK_SIZE - 1);
    let content_end = offset
        .checked_add(TAR_BLOCK_SIZE)
        .ok_or_else(|| ZiftError::InvalidData {
            offset,
            reason: "tar member boundary overflows usize. Fix: use a smaller tar archive"
                .to_string(),
        })?;

    content_end
        .checked_add(padded_size)
        .ok_or_else(|| ZiftError::InvalidData {
            offset,
            reason: "tar member boundary overflows usize. Fix: use a smaller tar archive"
                .to_string(),
        })
}

fn read_tar_member(content: &[u8], start: usize, offset: usize) -> Result<TarHeader, ZiftError> {
    let header_end = start
        .checked_add(TAR_BLOCK_SIZE)
        .ok_or_else(|| ZiftError::InvalidData {
            offset,
            reason: "tar header boundary overflows usize. Fix: use a smaller tar archive"
                .to_string(),
        })?;

    if header_end > content.len() {
        return Err(ZiftError::InvalidData {
            offset,
            reason: "truncated tar member header. Fix: use a complete tar archive".to_string(),
        });
    }

    let header = &content[start..header_end];
    if is_end_of_archive_block(header) {
        return Err(ZiftError::InvalidData {
            offset,
            reason: "end of tar archive marker. Fix: use a valid tar archive".to_string(),
        });
    }

    let size = parse_tar_octal_usize(&header[124..136], offset + 124)?;
    let typeflag = header[156];

    // Tar name field: NUL-terminated or space-padded; if no NUL, all 100 bytes are used.
    let name_bytes = &header[0..100];
    let name_len = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let name = String::from_utf8_lossy(&name_bytes[..name_len]);

    // SECURITY: Check for path traversal attacks
    if contains_path_traversal(&name) {
        return Err(ZiftError::InvalidData {
            offset,
            reason: format!("tar entry name contains path traversal: {name}. Fix: remove '..' sequences from tar entry names"),
        });
    }

    let content_start = header_end;
    let content_end = content_start
        .checked_add(size)
        .ok_or_else(|| ZiftError::InvalidData {
            offset,
            reason: "tar member content boundary overflows usize. Fix: use a smaller tar archive"
                .to_string(),
        })?;

    if content_end > content.len() {
        return Err(ZiftError::InvalidData {
            offset,
            reason: "truncated tar member content. Fix: use a complete tar archive".to_string(),
        });
    }

    Ok(TarHeader {
        content_offset: content_start,
        content_size: size,
        is_regular_file: is_regular_file(typeflag),
        is_symlink: is_symlink(typeflag),
        is_hardlink: is_hardlink(typeflag),
        name: name.to_string(),
    })
}

fn decompress_gzip_members(data: &[u8]) -> Result<Vec<u8>, ZiftError> {
    let mut decoder = MultiGzDecoder::new(data);
    let mut out = Vec::new();
    let mut chunk = [0_u8; 16_384];

    loop {
        let read = decoder.read(&mut chunk).map_err(ZiftError::Io)?;
        if read == 0 {
            break;
        }

        let new_len = out
            .len()
            .checked_add(read)
            .ok_or_else(|| ZiftError::InvalidData {
                offset: data.len(),
                reason: "decompressed tarball size overflows usize. Fix: use a smaller tarball"
                    .to_string(),
            })?;

        if new_len > MAX_TARBALL_BYTES {
            return Err(ZiftError::InvalidData {
                offset: data.len(),
                reason: format!("decompressed tarball size exceeds {MAX_TARBALL_BYTES}-byte limit. Fix: use a smaller tarball or increase MAX_TARBALL_BYTES"),
            });
        }

        out.extend_from_slice(&chunk[..read]);
    }

    Ok(out)
}

/// Extract literal bytes from a gzip-compressed tarball.
///
/// The tar archive is fully decompressed, then each regular file member's raw
/// payload is emitted as a [`CompressedBlock`].
///
/// # Security Features
///
/// - **Path traversal protection**: Rejects entries with `..` in paths
/// - **Symlink blocking**: Rejects symbolic and hard links (SSRF prevention)
/// - **Member limits**: Enforces `MAX_TAR_MEMBERS` (8192) to prevent `DoS`
/// - **Size limits**: Enforces `MAX_TARBALL_BYTES` (256MB) decompressed limit
///
/// # Parameters
///
/// - `data`: Byte slice expected to contain a `.tar.gz` payload.
///
/// # Example
/// ```
/// use ziftsieve::scan_tarball_literals;
/// // let blocks = scan_tarball_literals(b"GZIP tarball data").unwrap();
/// ```
///
/// # Errors
///
/// Returns [`ZiftError`] if input is not valid gzip, exceeds size limits,
/// contains malformed/truncated tar members, symlinks, or path traversal attempts.
pub fn scan_tarball_literals(data: &[u8]) -> Result<Vec<CompressedBlock>, ZiftError> {
    scan_tarball_literals_with_depth(data, 0)
}

/// Internal implementation with depth tracking for zip bomb protection.
fn scan_tarball_literals_with_depth(
    data: &[u8],
    depth: usize,
) -> Result<Vec<CompressedBlock>, ZiftError> {
    // SECURITY: Limit nested archive depth to prevent zip bombs
    if depth > MAX_NESTED_DEPTH {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: format!("nested archive depth exceeds limit ({MAX_NESTED_DEPTH}). Fix: use a flatter archive structure"),
        });
    }

    if data.len() < 2 || data.get(0..2) != Some(&[0x1f, 0x8b]) {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: "input is not a gzip stream for tarball scanning. Fix: provide a gzip-compressed tar archive".to_string(),
        });
    }

    let tar_data = decompress_gzip_members(data)?;
    if tar_data.is_empty() {
        return Ok(Vec::new());
    }

    scan_decompressed_tar_gz_archive(&tar_data, depth)
}

/// Walk a **decompressed** tar byte stream (not gzip-wrapped).
fn scan_decompressed_tar_gz_archive(
    tar_data: &[u8],
    depth: usize,
) -> Result<Vec<CompressedBlock>, ZiftError> {
    if depth > MAX_NESTED_DEPTH {
        return Err(ZiftError::InvalidData {
            offset: 0,
            reason: format!("nested archive depth exceeds limit ({MAX_NESTED_DEPTH}). Fix: use a flatter archive structure"),
        });
    }

    let mut blocks = Vec::new();
    let mut pos = 0usize;
    let mut members = 0usize;
    let mut total_literals = 0usize;

    while pos < tar_data.len() {
        if members >= MAX_TAR_MEMBERS {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!("tar archive contains too many members (max {MAX_TAR_MEMBERS}). Fix: use a smaller tar archive or increase MAX_TAR_MEMBERS"),
            });
        }

        if pos + TAR_BLOCK_SIZE > tar_data.len() {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: "truncated tar header block. Fix: use a complete tar archive".to_string(),
            });
        }

        let header = &tar_data[pos..pos + TAR_BLOCK_SIZE];
        if is_end_of_archive_block(header) {
            break;
        }

        let member = read_tar_member(&tar_data, pos, pos)?;

        if member.is_symlink {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!(
                    "tar entry '{}' is a symbolic link - symlinks are not supported for security. Fix: remove symlinks from the tar archive",
                    member.name
                ),
            });
        }

        if member.is_hardlink {
            return Err(ZiftError::InvalidData {
                offset: pos,
                reason: format!(
                    "tar entry '{}' is a hard link - hardlinks are not supported for security. Fix: remove hard links from the tar archive",
                    member.name
                ),
            });
        }

        if member.is_regular_file
            && add_regular_file_blocks(
                &tar_data,
                &member,
                pos,
                depth,
                &mut blocks,
                &mut total_literals,
            )?
        {
            pos = next_member_offset(pos, member.content_size)?;
            members += 1;
            continue;
        }

        pos = next_member_offset(pos, member.content_size)?;
        members += 1;
    }

    Ok(blocks)
}

/// True when the first 512-byte tar header looks like POSIX ustar (nested `.tar.gz` heuristic).
fn first_tar_block_has_ustar_magic(tar_data: &[u8]) -> bool {
    tar_data.len() >= TAR_BLOCK_SIZE && tar_data.get(257..262) == Some(b"ustar".as_slice())
}

fn add_regular_file_blocks(
    tar_data: &[u8],
    member: &TarHeader,
    pos: usize,
    depth: usize,
    blocks: &mut Vec<CompressedBlock>,
    total_literals: &mut usize,
) -> Result<bool, ZiftError> {
    let literals = &tar_data[member.content_offset..member.content_offset + member.content_size];

    // Nested `.tar.gz`: require valid gzip, POSIX ustar magic, and a clean tar walk — no silent swallow.
    if !literals.is_empty() && literals.get(0..2) == Some(&[0x1f, 0x8b]) {
        let tar_inner = decompress_gzip_members(literals)?;
        if first_tar_block_has_ustar_magic(&tar_inner) {
            let nested = scan_decompressed_tar_gz_archive(&tar_inner, depth + 1)?;
            let nested_literals: usize = nested.iter().map(|b| b.literals.len()).sum();
            *total_literals = total_literals.saturating_add(nested_literals);
            if *total_literals > MAX_TARBALL_BYTES {
                return Err(ZiftError::InvalidData {
                    offset: pos,
                    reason: format!("extracted tar literals exceed {MAX_TARBALL_BYTES}-byte limit"),
                });
            }
            blocks.extend(nested);
            return Ok(true);
        }
    }

    let literal_len = member.content_size;
    if literal_len > u32::MAX as usize {
        return Err(ZiftError::InvalidData {
            offset: pos,
            reason: "tar member size exceeds 4GiB limit. Fix: use smaller tar members".to_string(),
        });
    }

    let mut block = CompressedBlock::new(
        u64::try_from(pos).map_err(|_| ZiftError::InvalidData {
            offset: pos,
            reason: "tar member offset exceeds u64. Fix: use a smaller tar archive".to_string(),
        })?,
        u32::try_from(literal_len).map_err(|_| ZiftError::InvalidData {
            offset: pos,
            reason: "tar member size exceeds u32. Fix: use smaller tar members".to_string(),
        })?,
    );
    block.literals.extend_from_slice(literals);
    block.uncompressed_len =
        Some(
            u32::try_from(member.content_size).map_err(|_| ZiftError::InvalidData {
                offset: pos,
                reason: "tar member size exceeds u32. Fix: use smaller tar members".to_string(),
            })?,
        );
    *total_literals = total_literals.saturating_add(member.content_size);

    blocks.push(block);

    if *total_literals > MAX_TARBALL_BYTES {
        return Err(ZiftError::InvalidData {
            offset: pos,
            reason: format!("extracted tar literals exceed {MAX_TARBALL_BYTES}-byte limit. Fix: use a smaller tarball or increase MAX_TARBALL_BYTES"),
        });
    }

    Ok(false)
}
