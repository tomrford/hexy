# Known Divergences

Current compatibility notes for the `hexy-compat` CLI.

This file tracks behavior that should not be claimed drop-in compatible yet. This is a cleanroom implementation of HexView-style non-proprietary workflows, so remaining references here name the external compatibility target only.

## Known Gaps

### `/XP` Porsche export

Status: implemented, not drop-in compatible yet.

Observed divergence:
- current behavior accepts some cases that the compatibility target appears to reject

Current conclusion:
- rejection parity is wrong or `/XP` preconditions are narrower than `hexy` currently assumes

### `/XC` C-array export

Status: implemented, not drop-in compatible yet.

Observed divergence:
- generated `.c/.h` output shape is structurally different from the compatibility target
- The compatibility target emits its legacy flash-driver style wrapper/header/macros
- `hexy` emits a smaller modern `stdint.h`-based array/header pair

This is not a cosmetic whitespace issue; the exported contract differs.

## Compatibility Notes

These should not be claimed drop-in compatible yet:

- `/L` commands that embed file paths such as `FileOpen`, because path resolution and path dialect assumptions may differ
- exact `/E` and `/V` text/file semantics
- proprietary or DLL-backed features such as `/DP`, `/SV`, `/PB`

## Intent

Anything listed above as implemented is part of the current compat CLI surface, so `hexy` is trying to support it.

But “implemented” and “drop-in compatible” are not the same thing. Until a divergence is closed or compatibility is otherwise established, treat compatibility claims as scoped.
