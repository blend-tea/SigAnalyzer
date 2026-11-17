# FLIRT implementation review

Reviewed for SigAnalyzer 0.2.0 and extended through 0.4.2 against these implementations:

- [angr FLIRT parser](https://github.com/angr/angr/blob/8d4cbc652db70a6444a40b90c47326193c10d81b/angr/analyses/flirt/flirt_sig.py)
  and [matcher](https://github.com/angr/angr/blob/8d4cbc652db70a6444a40b90c47326193c10d81b/angr/analyses/flirt/flirt_matcher.py).
- [radare2 FLIRT parser and matcher](https://github.com/radareorg/radare2/blob/727682cf41063831f8b30de420033fa6cc38bf3e/libr/anal/flirt.c).
- [Rizin FLIRT parser](https://github.com/rizinorg/rizin/blob/73df0fc9b4e15fd996941225a59eec79edef2204/librz/sign/flirt.c),
  used to cross-check version-dependent tail/reference counts.
- [flirt-sig v11 reader](https://github.com/coleleavitt/flirt-sig/blob/24d8582d21d0494c5a81e8a45e0d37ded1c66283/src/lib.rs),
  [matcher](https://github.com/coleleavitt/flirt-sig/blob/24d8582d21d0494c5a81e8a45e0d37ded1c66283/src/matcher.rs)
  and [resolver](https://github.com/coleleavitt/flirt-sig/blob/24d8582d21d0494c5a81e8a45e0d37ded1c66283/src/resolve.rs),
  used for IDA 9.5's changed wire format. The older angr/radare2 readers above
  do not support v11. See also the official [IDA 9.5 release description](https://hex-rays.com/blog/ida-9.5-release).

These are implementation references for the reverse-engineered format. No
proprietary signature files are included in the regression suite.

| Area | Finding and correction |
| --- | --- |
| Headers | Header fields are little-endian, including the v6 function count, v8 pattern size and v10 extra field. v11 adds a toolchain byte before the library name. Treat the library-name length and function count as unsigned. Require complete fields and names. |
| Tree data | Tree integers use FLIRT's variable-length big-endian encodings, independently of header endianness. v10+ node lengths use var15; nodes over 64 bytes use a little-endian wildcard bitmap. Preserve wide offsets and reject paths longer than the declared pattern size. |
| Versioned counts | Older versions have one tail/reference entry. v8/v9 use the two-byte encoding for counts; v10 uses the multi-byte encoding. v11 tail counts are one byte, while its legacy-reference count byte is followed by one record; site tables have separate var32 counts. |
| Input errors | EOF is an error rather than an implicit zero. Corrupt or incomplete compressed streams must terminate with failure. |
| Pattern traversal | Bounds include the cumulative trie offset. A matching prefix alone is insufficient. |
| CRC and tails | For v5–v10 the CRC begins at `max(cumulative pattern length, 32)`; v11 uses the header's pattern size. Require the whole CRC region and each tail byte, including exact-end boundary cases. Use FLIRT's byte-swapped CRC-16/X-25 result. |
| Public names | Visit every public name without consuming the iterator during lookahead. Retain mangled-name prefixes. Skip unresolved collisions and preserve user-defined names and entry points. |
| References | Check referenced function names through Ghidra references before naming a module. Unresolved references defer the match. |
| v11 public names | Read a big-endian 16-bit length, flags, exact name bytes and optional payloads before continuation flags. Apply signed cumulative public offsets and instruction mask/value constraints. |
| v11 sites | Read normal and alternative site tables and their payloads. Check instruction bits and require any complete alternative group. Treat ordinary named relocation sites as optional evidence; tiny-module and import-name sites require a matching reference. Resolve indirect imports through Ghidra data references. |
| Module memory | Read the contiguous bytes required by a signature module, including bytes beyond the first function's body, instead of assuming a module contains one function. |
| Analyzer lifecycle | Close signature streams, support cancellation, report invalid files and return a meaningful analysis status. |
| Function ID | Run at priority 800, after FID (799). Protect FID analysis bookmarks, its single/multiple-match plate comments and conflict labels, including when bookmark creation is disabled. |
| Multiple candidates | Collect every matching module and trie branch across all enabled files before mutation. Prune impossible reference dependencies; apply only globally unique names supported by resolved callees. Report different names without renaming. |
| Provenance | Append/update a delimited FLIRT plate-comment block with all agreeing signature sources, preserving unrelated comments. |
| Manual resolution | An explicitly selected current conflict candidate is applied in an undoable transaction as a user-defined name. Re-check Function ID, imported-name and entry-point protection before mutation; remove report rows only after commit. |
| Directory gates | Discover signatures per directory, preserving the legacy root group and disabled-file settings. An optional rules.yar controls only direct signatures, and native YARA errors skip that group without falling back to unfiltered signatures. |
| YARA target | Extract the original imported FileBytes once per analysis session. Use native count mode with a deadline and cancellation, rather than matching arbitrary stdout or scanning patched memory. |

The analyzer operates on functions already discovered by Ghidra. It does not
create functions, infer missing reference targets, or relax byte comparisons.
Signature selection remains per processor; select files for the program's ABI
and platform using the signature manager.

Supported versions are 5–11, uncompressed or zlib-compressed. Zstandard (feature
`0x40`) is rejected with an explicit diagnostic. Signature decompression and the
required matching buffer are limited to 64 MiB.
Files exceeding these supported limits are rejected and reported in the analysis log.

Version 11 support is deliberately conservative about name resolution: it does
not implement IDA's complete scoring, helper discovery or iterative name propagation.
The additional `0x40` per-name/site payload is parsed and preserved, but its
linker-relaxation semantics are not modeled. Available Ghidra references and
instruction masks are used; unresolved competing candidates remain conflicts.

## Reported IDA 9.5 signatures

The 0.4.2 investigation reproduced the reported failure: all 42 supplied files
used v11, which 0.4.1 rejected as an unsupported version. Accepting the version
alone was insufficient because both the header boundary and tree records changed.
All supplied files used uncompressed data and a 32-byte pattern size.

After the correction, the Java parser consumed all 42 files to end-of-stream.
An independently implemented Python reader agreed on all per-file counts:
11,155 nodes, 6,971 leaves, 10,120 modules, 19,867 public names and 56,383 sites.
The header count matched leaf counts in these files, so it is not used as a
module-count validation rule. All headers and 2,856 truncated-header variants
were also checked independently.

The supplied signatures and their symbol names are not included in the repository
or release. Matching is tested with synthetic Ghidra programs; no corresponding
original target binary was supplied, so this establishes parsing compatibility
and regression behavior, rather than full recognition parity with IDA 9.5.

## Public-corpus cross-check

In addition to synthetic fixtures, the header and complete parsed tree were
compared with angr using three public signatures from
[angr/flirt_signatures at eaf9234](https://github.com/angr/flirt_signatures/tree/eaf9234448ced5800497d8ec2c565b186c9f65e4).
Both implementations produced identical header values, stream positions and
tree counts. Canonical representations of the complete parsed trees also matched,
including patterns, module CRCs, public names, tail bytes and referenced names:

| Signature | Nodes | Modules | Public functions |
| --- | ---: | ---: | ---: |
| `armel/linux/debian_10.3_libgcc.sig` | 835 | 648 | 775 |
| `armhf/linux/debian_10.3_libdl.sig` | 5 | 6 | 6 |
| `x86_64/linux/rust/inline/1.39.0-O2.sig` | 534 | 375 | 3,712 |

This checks parsing of real files; it does not establish recognition accuracy
for every architecture, compiler or library. The corpus is not bundled with the extension.

## Reproducing regression tests

Run the synthetic regression suite and package the extension with:

```sh
./gradlew --no-daemon clean test buildExtension
src/test/run-headless.sh
```

Set `JAVA_HOME` to JDK 25 and `GHIDRA_INSTALL_DIR` to Ghidra 12.2 first, as
described in the README. The tests cover independently encoded FLIRT headers
and trees, malformed inputs and matching boundaries. Headless Ghidra smoke tests
exercise actual program memory and function renaming.
