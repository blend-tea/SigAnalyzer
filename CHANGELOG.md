# Changelog

## 0.4.2 — 2026-11-17

- Read FLIRT v11 signatures used by IDA 9.5, including the extra header byte,
  length-prefixed public names, signed offsets and relocation/alternative-site tables.
- Check v11 instruction masks, use the header pattern size for CRC placement,
  and distinguish optional relocation evidence from mandatory reference constraints.
  Preserve conflicts instead of selecting a candidate through disappearing optional evidence.
- Correct v10+ variable-length trie nodes and support wildcard bitmaps longer than 64 bytes.
- Report unsupported Zstandard compression explicitly. Uncompressed and zlib
  v11 signatures are supported; existing v5–v10 behavior remains covered by regression tests.
- Validate all 42 reported v11 files to end-of-stream against an independent reader.
  Add synthetic parsing and headless matching regressions without distributing supplied signatures.

## 0.4.1 — 2026-11-17

- Configure the native YARA executable with a file chooser in **Edit → Tool
  Options → SigAnalyzer → YARA Executable**. Save the tool to persist the path.
- Use the current analysis tool's configured path on each run, while retaining
  legacy per-program analysis settings and PATH lookup for unset/headless cases.
- Update the English/Japanese documentation with the Tool Options location and screenshot.

## 0.4.0 — 2026-11-16

- Apply a selected FLIRT conflict candidate using the right-click menu. The
  explicit choice is undoable, retains provenance and is protected from later
  automatic renaming. Function ID, imported names and entry points remain protected.
- Organize registered signatures into directories, including nested groups,
  and move signatures between groups while preserving their enabled state.
- Add an optional `rules.yar` editor/import per directory. Native YARA matches
  the original imported binary before enabling that directory's signatures;
  rules do not affect subdirectories. Ungated groups retain their existing behavior.
- Skip only the gated group when YARA is unavailable, rules are invalid, the
  scan times out or the original imported bytes cannot be read.
- Include relative group paths in conflict reports and FLIRT comments.
- Add native YARA integration tests to the release workflow.
- Update the English and Japanese READMEs with the new workflows and screenshots.

## 0.3.0 — 2026-11-13

- Run FLIRT after Function ID and exclude functions identified by FID, including
  bookmark-disabled identifications and FID conflicts.
- Collect all FLIRT candidates across every enabled signature before renaming.
  Different matching names leave the function unchanged; duplicate sources for
  the same name remain a single choice.
- Show ambiguous candidates in a dedicated FLIRT Conflicts window with function
  navigation, signature file and library provenance.
- Add an idempotent FLIRT plate-comment block to uniquely identified functions,
  retaining existing comments and listing the matching signatures.

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
