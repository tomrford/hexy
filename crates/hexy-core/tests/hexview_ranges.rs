use hexy_core::parse_hexview_ranges;

#[test]
fn test_hexview_ranges_accept_formats() {
    let ranges = parse_hexview_ranges("0x1000,0x200").unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].start(), 0x1000);
    assert_eq!(ranges[0].end(), 0x11FF);

    let ranges = parse_hexview_ranges("0x1000-0x11FF").unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].start(), 0x1000);
    assert_eq!(ranges[0].end(), 0x11FF);
}

#[test]
fn test_hexview_ranges_multiple_and_quotes() {
    let ranges = parse_hexview_ranges("'0x1000,0x10:0x2000-0x2003'").unwrap();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].start(), 0x1000);
    assert_eq!(ranges[0].end(), 0x100F);
    assert_eq!(ranges[1].start(), 0x2000);
    assert_eq!(ranges[1].end(), 0x2003);
}

#[test]
fn test_hexview_ranges_binary_and_suffix() {
    let ranges = parse_hexview_ranges("0b1000,0b10:1000h-10FFh").unwrap();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].start(), 0x8);
    assert_eq!(ranges[0].end(), 0x9);
    assert_eq!(ranges[1].start(), 0x1000);
    assert_eq!(ranges[1].end(), 0x10FF);
}

#[test]
fn test_hexview_ranges_reject_full_space() {
    let err = parse_hexview_ranges("0x0-0xFFFFFFFF").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("entire 4GiB"));
}
