# Changelog

## 0.2.0 — 2026-11-13

- Target Ghidra 12.2 with JDK 25 and a pinned Gradle wrapper.
- Correct little-endian version-specific FLIRT headers, unsigned lengths and counts,
  long library names, and truncated-input handling.
- Correct tree traversal, CRC and tail-byte bounds, wildcard masks, and module offsets.
- Verify referenced-function constraints before applying names and preserve user-defined names.
- Reject corrupt compressed signatures without hanging, support analysis cancellation,
  and report invalid signatures in the analysis log.
- Add synthetic FLIRT regression fixtures and automated extension builds and tag releases.
- Remove unused generated loader, filesystem and exporter placeholders, and update plugin help.

## 0.1.0

- Initial public release for Ghidra 12.0.x.
