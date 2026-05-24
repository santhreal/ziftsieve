/// Ensure that compression enums derive traits correctly
#[test]
fn doc_test_compression_format() {
    let f = ziftsieve::CompressionFormat::Lz4;
    assert_eq!(format!("{:?}", f), "Lz4");
    assert!(f == ziftsieve::CompressionFormat::Lz4);

    // Check clone
    let f2 = f;
    assert_eq!(f, f2);
}
