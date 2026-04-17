# Known Divergences

Current parity status against the `hexy-compat` CLI.

Validation environment lives outside the repo in a local-only checkout.

## Summary

Legacy parity suite:
- `2527 / 2529` pass
- the only failures were HexView timeout/hang cases, not byte-output mismatches

Supplemental parity checks for features not covered by the legacy suite:
- pass: `/IN`, `/IA`, `/II2`, `/S08MAP`, `/S12MAP`, `/S12XMAP`, `/REMAP`, `/CDSPX`, `/CDSPS`, `/CDSPG`, `/XA`, `/XF`, `/XSB`, `/L` with pathless `FileNew`, `/BHFCT`, `/BTFST`, `/BTBS`
- fail: `/XP`, `/XC`

## Known Gaps

### `/XP` Porsche export

Status: implemented, not drop-in compatible yet.

Observed divergence:
- the exercised parity cases were rejected by HexView
- `hexy` succeeded on the same cases

Current conclusion:
- rejection parity is wrong or `/XP` preconditions are narrower than `hexy` currently assumes

### `/XC` C-array export

Status: implemented, not drop-in compatible yet.

Observed divergence:
- generated `.c/.h` output shape is structurally different from HexView
- HexView emits its legacy flash-driver style wrapper/header/macros
- `hexy` emits a smaller modern `stdint.h`-based array/header pair

This is not a cosmetic whitespace issue; the exported contract differs.

## HexView Hang Cases

Legacy suite still found two cases where HexView did not complete and `hexy` did:

1. `fuzz_flash_config_002`
   - args: `/CR:0x1EA,0xC5 /FR:0x38,0x12A /FP:55 /FA /FP:00 /SB:0x40`
2. `fuzz_rand_008_000`
   - args: `/FR:0x4C6,0x132 /FP:DEADBEEF /FA /FP:FF /AD:32 /SWAPLONG`

Current interpretation:
- these are not evidence of `hexy` output mismatch
- they are evidence that HexView can wedge on some composed inputs where `hexy` continues

## Not Yet Parity-Verified

These should not be claimed drop-in compatible yet:

- `/L` commands that embed file paths such as `FileOpen`, because log contents are path-dialect-sensitive across WSL/Windows
- exact `/E` and `/V` text/file semantics against HexView
- proprietary or DLL-backed features such as `/DP`, `/SV`, `/PB`

## Intent

Anything listed above as implemented is part of the current compat CLI surface, so `hexy` is trying to support it.

But “implemented” and “drop-in compatible” are not the same thing. Until a feature is validated here against HexView, or a divergence is closed, treat compatibility claims as scoped.
