"""The `hexy` CLI and the Python `Pipeline` give byte-identical outputs for the same
workflow, composed from the same typed operations."""

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

import hexy
from hexy import DataProcessing

ROOT = Path(__file__).parents[3]
KEYS = ROOT / "crates" / "hexy-core" / "tests" / "fixtures" / "keys"
AES_KEY = "00112233445566778899AABBCCDDEEFF"


def _cli():
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    name = "hexy.exe" if os.name == "nt" else "hexy"
    for profile in ("debug", "release"):
        if (target / profile / name).is_file():
            return target / profile / name
    reason = f"no {name} in {target}; run `cargo build -p hexy-compat` first"
    if os.environ.get("CI"):
        pytest.fail(reason)
    pytest.skip(reason)


def _pat(length, seed):
    return bytes((seed + i * 7) & 0xFF for i in range(length))


SOURCE = hexy.HexFile(
    [
        hexy.Segment(0x1000, _pat(0x100, 1)),
        hexy.Segment(0x1180, _pat(0x80, 2)),
        hexy.Segment(0x1301, _pat(0x3E, 3)),
        hexy.Segment(0x2000, _pat(6, 4)),
    ]
)


@pytest.fixture
def run(tmp_path):
    """Run the CLI on `SOURCE` in `tmp_path`, returning the bytes of `output`."""
    SOURCE.write_intel_hex(tmp_path / "in.hex")

    def run(*flags, output="out", files=()):
        for name, content in dict(files).items():
            (tmp_path / name).write_text(content)
        args = [_cli(), "in.hex", *flags, "-o", output]
        done = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return (tmp_path / output).read_bytes()

    return run


def _apply(pipeline):
    # The CLI joins adjacent data when it loads a file, as HexView does.
    return pipeline.apply(SOURCE.normalized())


def test_ranges_fill_and_checksum_to_intel_hex(run):
    cli = run(
        "/FR:0x0F00-0x0F3F:0x1100-0x117F",
        "/FP:A55A",
        "/CR:0x1010-0x101F",
        "/AR:0x0F00-0x1FFF",
        "/AD:0x10",
        "/AL",
        "/CSR9:@append",
        "/XI:16",
    )
    pipeline = hexy.Pipeline()
    pipeline.fill(["0x0F00-0x0F3F", "0x1100-0x117F"], pattern=b"\xa5\x5a")
    pipeline.cut(["0x1010-0x101F"])
    pipeline.filter(["0x0F00-0x1FFF"])
    pipeline.align(0x10, length=0x10)
    pipeline.checksum(9, placement="append", reverse=True)
    assert _apply(pipeline).hexfile.to_intel_hex(bytes_per_line=16) == cli


def test_banked_map_split_and_remove_to_srec(run):
    cli = run("/S12XMAP", "/SB:0x100", "/RB=0x40", "/XS:16:2")
    pipeline = hexy.Pipeline()
    pipeline.map_star12x()
    pipeline.split(0x100)
    pipeline.remove_small_blocks(0x40)
    hexfile = _apply(pipeline).hexfile
    assert hexfile.to_srec(bytes_per_line=16, record_type="s3") == cli


def test_signature_placement_and_verification(run):
    key = (KEYS / "rsa_his_private.txt").read_text()
    sign = DataProcessing.sign("rsa-pkcs1v15-sha256", key, metadata=True)
    # /SV verifies the image with the placed signature in it.
    signed = SOURCE.normalized()
    signed.process_data(sign, placement="append")
    signature = signed.normalized().process_data(sign)

    cli = run(
        "/DP33:@append:key.txt;sig.txt",
        f"/SV5:key.txt!{signature.hex()}",
        "/XI",
        files={"key.txt": key},
    )
    pipeline = hexy.Pipeline()
    pipeline.process_data(sign, placement="append")
    pipeline.verify("rsa-pkcs1v15-sha256", key, signature, metadata=True)
    assert _apply(pipeline).hexfile.to_intel_hex() == cli


@pytest.mark.parametrize(
    ("flag", "operation", "placement"),
    [
        (
            f"/DP11:{AES_KEY};PKCS7#IV=000102030405060708090A0B0C0D0E0F",
            DataProcessing.encrypt(
                "cbc", AES_KEY, iv=bytes(range(16)), padding="pkcs7"
            ),
            None,
        ),
        (
            f"/DP31:@0x3000:{AES_KEY};mac.txt",
            DataProcessing.mac("hmac-sha256", AES_KEY, metadata=True),
            0x3000,
        ),
        ("/DP26", DataProcessing.compress(), None),
    ],
    ids=["aes-cbc", "hmac", "lzss"],
)
def test_data_processing(run, flag, operation, placement):
    cli = run(flag, "/XI")
    pipeline = hexy.Pipeline()
    pipeline.process_data(operation, placement=placement)
    assert _apply(pipeline).hexfile.to_intel_hex() == cli


def _created(c_file):
    """The creation time the CLI wrote, as a local aware datetime."""
    text = re.search(rb"File created:  (.+?)\r\n", c_file).group(1).decode()
    return datetime.strptime(text, "%a %b %d %H:%M:%S %Y").astimezone()


def test_validation_structure_and_c_exports(run, tmp_path):
    ini = (
        "[VALIDATION]\nIdTagBegin=0x1234\nIdTagBeginLength=2\nIdTagEnd=0x4321\n"
        "IdTagEndLength=2\nBlockChecksumType=0\nFileChecksumType=9\nValidateChecksum=1\n"
        "EndianType=0\nInsertData=1\nBaseAddress=0x8000\nGenerateCFiles=1\n"
        "CFileName=v.c\nHFileName=v.h\n"
        "[C_EXPORT]\nPrefix=fd\nWordSize=1\n"
    )
    run("/P:cfg.ini", "/vs", "/XC", output="out.c", files={"cfg.ini": ini})
    cli = {
        name: (tmp_path / name).read_bytes()
        for name in ("out.c", "out.h", "v.c", "v.h")
    }

    pipeline = hexy.Pipeline()
    pipeline.validation_structure(
        tag_begin=b"\x12\x34",
        tag_end=b"\x43\x21",
        block_checksum=0,
        file_checksum=9,
        validate_sum=True,
        address=0x8000,
    )
    result = _apply(pipeline)
    c, h = result.validation.to_c("v.c", "v.h", created=_created(cli["v.c"]))
    assert (c, h) == (cli["v.c"], cli["v.h"])
    c, h = result.hexfile.to_c_code(
        "out.c", prefix="fd", word_size=2, xor=0, created=_created(cli["out.c"])
    )
    assert (c, h) == (cli["out.c"], cli["out.h"])
