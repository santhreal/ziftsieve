use ziftsieve::CompressionFormat;

#[test]
fn test_detect_gzip() {
    assert_eq!(
        CompressionFormat::detect(b"\x1f\x8b\x08"),
        Some(CompressionFormat::Gzip)
    );
}
