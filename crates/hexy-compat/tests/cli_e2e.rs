mod common;

use common::{assert_success, run_hexy, temp_dir, write_file};
use hexy_core::parse_intel_hex;

#[test]
fn test_cli_multistage_bin_merge_align_output() {
    let dir = temp_dir("cli_multistage");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");

    write_file(&base, &[0x10, 0x11, 0x12, 0x13, 0x14]);
    write_file(&merge, &[0xAA, 0xBB]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x1002", merge.display()),
        "/AR:0x1000-0x1004".to_string(),
        "/AD:3".to_string(),
        "/AL".to_string(),
        "/AF:0xEE".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);

    let data = std::fs::read(&out).unwrap();
    let hexfile = parse_intel_hex(&data).unwrap();
    let norm = hexfile.normalized();

    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x0FFF);
    assert_eq!(
        norm.segments()[0].data(),
        vec![0xEE, 0x10, 0x11, 0xAA, 0xBB, 0x14]
    );
}
