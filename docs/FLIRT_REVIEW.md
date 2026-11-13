# FLIRT implementation review

Reviewed for SigAnalyzer 0.2.0 and extended in 0.3.0 against these implementations:

- [angr FLIRT parser](https://github.com/angr/angr/blob/8d4cbc652db70a6444a40b90c47326193c10d81b/angr/analyses/flirt/flirt_sig.py)
  and [matcher](https://github.com/angr/angr/blob/8d4cbc652db70a6444a40b90c47326193c10d81b/angr/analyses/flirt/flirt_matcher.py).
- [radare2 FLIRT parser and matcher](https://github.com/radareorg/radare2/blob/727682cf41063831f8b30de420033fa6cc38bf3e/libr/anal/flirt.c).
- [Rizin FLIRT parser](https://github.com/rizinorg/rizin/blob/73df0fc9b4e15fd996941225a59eec79edef2204/librz/sign/flirt.c),
  used to cross-check version-dependent tail/reference counts.

These are implementation references for the reverse-engineered format. No
proprietary signature files are included in the regression suite.

| Area | Finding and correction |
| --- | --- |
| Headers | Header fields are little-endian, including the v6 function count, v8 pattern size and v10 extra field. Treat the library-name length and function count as unsigned. Require complete fields and names. |
| Tree data | Tree integers use FLIRT's variable-length big-endian encodings, independently of header endianness. Preserve wide offsets and all 64 wildcard bits. |
| Versioned counts | Older versions have one tail/reference entry. v8/v9 use the two-byte encoding for counts; v10 uses the multi-byte encoding. |
| Input errors | EOF is an error rather than an implicit zero. Corrupt or incomplete compressed streams must terminate with failure. |
| Pattern traversal | Bounds include the cumulative trie offset. A matching prefix alone is insufficient. |
| CRC and tails | The CRC begins at `max(cumulative pattern length, 32)`. Require the whole CRC region and each tail byte, including exact-end boundary cases. Use FLIRT's byte-swapped CRC-16/X-25 result. |
| Public names | Visit every public name without consuming the iterator during lookahead. Retain mangled-name prefixes. Skip unresolved collisions and preserve user-defined names and entry points. |
| References | Check referenced function names through Ghidra references before naming a module. Unresolved references defer the match. |
| Module memory | Read the contiguous bytes required by a signature module, including bytes beyond the first function's body, instead of assuming a module contains one function. |
| Analyzer lifecycle | Close signature streams, support cancellation, report invalid files and return a meaningful analysis status. |
| Function ID | Run at priority 800, after FID (799). Protect FID analysis bookmarks, its single/multiple-match plate comments and conflict labels, including when bookmark creation is disabled. |
| Multiple candidates | Collect every matching module and trie branch across all enabled files before mutation. Prune impossible reference dependencies; apply only globally unique names supported by resolved callees. Report different names without renaming. |
| Provenance | Append/update a delimited FLIRT plate-comment block with all agreeing signature sources, preserving unrelated comments. |

The analyzer operates on functions already discovered by Ghidra. It does not
create functions, infer missing reference targets, or relax byte comparisons.
Signature selection remains per processor; select files for the program's ABI
and platform using the signature manager.

Signature decompression and the required matching buffer are limited to 64 MiB.
Files exceeding these supported limits are rejected and reported in the analysis log.

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
