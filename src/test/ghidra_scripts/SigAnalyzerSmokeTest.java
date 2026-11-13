// Synthetic end-to-end FLIRT checks in a real Ghidra Program.
// Run with analyzeHeadless, -noanalysis and -postScript SigAnalyzerSmokeTest.java.
// @category SigAnalyzer.Tests

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import siganalyzer.analyzer.ApplyFlirt;
import siganalyzer.analyzer.FlirtAnalysisSession;
import siganalyzer.analyzer.FlirtCandidate;

public class SigAnalyzerSmokeTest extends GhidraScript {
    private static final byte[] CRC_VECTOR = "123456789".getBytes(StandardCharsets.US_ASCII);

    @Override
    protected void run() throws Exception {
        currentProgram.getMemory().createInitializedBlock("flirt_smoke", toAddr(0x1000),
            0x2000, (byte) 0, monitor, false).setExecute(true);
        testMultipleExportsAndMangledName();
        testCrcBoundaryAndTailMismatch();
        testProtectedNamesAndCollision();
        testReferencedOperand();
        testOverlayAddressSpace();
        testFunctionIdExclusions();
        testConflictingModulesAndTreeBranches();
        testCrossFileConflicts();
        testDuplicateNamesAndComments();
        testLateReferenceCandidateDoesNotHideConflict();
        testAmbiguousCalleeDoesNotRenameCaller();
        testUniqueReferenceAcrossFiles();
        testStaleAnalysisNameDoesNotResolveAmbiguousCallee();
        testInvalidCandidateNameCannotResolveCaller();
        testCommentExcludesUnresolvedDuplicateSource();
        println("SIGANALYZER_SMOKE_TEST_PASSED");
    }

    private void testMultipleExportsAndMangledName() throws Exception {
        byte[] pattern = pattern((byte) 0x90);
        put(0x1000, pattern);
        put(0x1020, CRC_VECTOR);
        put(0x1029, new byte[] {0x7a});
        Function first = function(0x1000, 32, null);
        Function second = function(0x1040, 32, null);
        byte[] exports = concat(export(0, "?decorated@@YAXXZ", 1),
            export(64, "second_export", 2), new byte[] {1, 0, 0x7a});
        apply(signature(pattern, 0, 9, 0x6e90, 96, exports));
        check("?decorated@@YAXXZ".equals(first.getName()), "C++ mangled name preserved");
        check("second_export".equals(second.getName()), "all module exports applied");
    }

    private void testCrcBoundaryAndTailMismatch() throws Exception {
        byte[] pattern = pattern((byte) 0x91);
        put(0x1200, pattern);
        byte[] wrongCrc = CRC_VECTOR.clone();
        wrongCrc[wrongCrc.length - 1] ^= 1;
        put(0x1220, wrongCrc);
        Function crcFunction = function(0x1200, 41, null);
        String original = crcFunction.getName();
        apply(signature(pattern, 0, 9, 0x6e90, 41, export(0, "must_not_match_crc", 0)));
        check(original.equals(crcFunction.getName()), "CRC checked at exact buffer end");

        put(0x1220, CRC_VECTOR);
        put(0x1229, new byte[] {0x7b});
        apply(signature(pattern, 0, 9, 0x6e90, 42,
            concat(export(0, "must_not_match_tail", 2), new byte[] {1, 0, 0x7a})));
        check(original.equals(crcFunction.getName()), "mismatching tail rejects module");
    }

    private void testProtectedNamesAndCollision() throws Exception {
        byte[] pattern = pattern((byte) 0x92);
        put(0x1400, pattern);
        Function named = function(0x1400, 32, "user_supplied_name");
        apply(signature(pattern, 0, 0, 0, 32, export(0, "replacement", 0)));
        check("user_supplied_name".equals(named.getName()), "user-defined name retained");

        put(0x1500, pattern);
        Function collision = function(0x1500, 32, null);
        String original = collision.getName();
        // An export's function flag byte precedes its name; 8 means unresolved collision.
        apply(signature(pattern, 0, 0, 0, 32,
            concat(new byte[] {0, 8}, "collision".getBytes(StandardCharsets.US_ASCII),
                new byte[] {0})));
        check(original.equals(collision.getName()), "unresolved collision is not renamed");

        put(0x1600, pattern);
        Function entry = function(0x1600, 32, null);
        currentProgram.getSymbolTable().addExternalEntryPoint(entry.getEntryPoint());
        String entryName = entry.getName();
        apply(signature(pattern, 0, 0, 0, 32, export(0, "entry_replacement", 0)));
        check(entryName.equals(entry.getName()), "external entry-point name retained");
    }

    private void testOverlayAddressSpace() throws Exception {
        byte[] pattern = pattern((byte) 0x94);
        Address overlay = currentProgram.getMemory().createInitializedBlock("flirt_overlay",
            toAddr(0x1000), 32, (byte) 0x94, monitor, true).getStart();
        Function overlayFunction = currentProgram.getFunctionManager().createFunction(null,
            overlay, new AddressSet(overlay, overlay.add(31)), SourceType.DEFAULT);
        Function defaultFunction = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000));
        String defaultName = defaultFunction.getName();
        apply(signature(pattern, 0, 0, 0, 32, export(0, "overlay_export", 0)));
        check("overlay_export".equals(overlayFunction.getName()), "overlay export applied in its address space");
        check(defaultName.equals(defaultFunction.getName()), "default address-space function retained");
    }

    private void testReferencedOperand() throws Exception {
        byte[] pattern = pattern((byte) 0x90);
        pattern[0] = (byte) 0xe8; // call rel32
        int displacement = 0x1c00 - 0x1805;
        for (int i = 0; i < 4; i++) {
            pattern[i + 1] = (byte) (displacement >>> (8 * i));
        }
        pattern[5] = (byte) 0xc3;
        put(0x1800, pattern);
        put(0x1c00, new byte[] {(byte) 0xc3});
        Function caller = function(0x1800, 32, null);
        Function callee = function(0x1c00, 1, "known_target");
        disassemble(toAddr(0x1800));
        check(currentProgram.getListing().getInstructionContaining(toAddr(0x1801)) != null,
            "relocation operand belongs to an instruction");

        byte[] referenceName = "known_target".getBytes(StandardCharsets.US_ASCII);
        byte[] extras = concat(export(0, "resolved_caller", 4),
            new byte[] {1, 1, (byte) referenceName.length}, referenceName);
        // Four relocation bytes are wildcards; reference offset 1 is inside the operand.
        long mask = (1L << 30) | (1L << 29) | (1L << 28) | (1L << 27);
        callee.setName("other_target", SourceType.USER_DEFINED);
        String original = caller.getName();
        apply(signature(pattern, mask, 0, 0, 32, extras));
        check(original.equals(caller.getName()), "unresolved reference rejects module");
        callee.setName("known_target", SourceType.USER_DEFINED);
        apply(signature(pattern, mask, 0, 0, 32, extras));
        check("resolved_caller".equals(caller.getName()), "reference inside operand resolves");
    }

    private void testFunctionIdExclusions() throws Exception {
        // SourceType.ANALYSIS alone is deliberately insufficient to identify FID output.
        // FID's optional bookmarks and its always-written plate comments are independent markers.
        for (int marker = 0; marker < 4; marker++) {
            long address = 0x2000 + marker * 0x40;
            byte[] pattern = pattern((byte) (0xa0 + marker));
            put(address, pattern);
            Function identified = function(address, 32, null);
            identified.setName("fid_identified_" + marker, SourceType.ANALYSIS);
            if (marker == 0) {
                currentProgram.getBookmarkManager().setBookmark(identified.getEntryPoint(),
                    BookmarkType.ANALYSIS, "Function ID Analyzer", "synthetic FID match");
            }
            else if (marker == 1) {
                identified.setComment("Library Function - Single Match\nsynthetic FID library");
            }
            else if (marker == 2) {
                currentProgram.getBookmarkManager().setBookmark(identified.getEntryPoint(),
                    BookmarkType.ANALYSIS, "Function ID Conflict", "synthetic ambiguous FID match");
            }
            else {
                identified.setComment("Library Function - Multiple Matches\nsynthetic candidates");
            }
            String name = identified.getName();
            String comment = identified.getComment();
            FlirtAnalysisSession session = analyze(new String[] {"fid-protected.sig"},
                signature(pattern, 0, 0, 0, 32, export(0, "flirt_replacement", 0)));
            check(name.equals(identified.getName()), "FID name retained for marker " + marker);
            check(java.util.Objects.equals(comment, identified.getComment()),
                "FID comment retained for marker " + marker);
            check(session.getConflicts().isEmpty(), "FID function excluded from conflicts");
        }
    }

    private void testConflictingModulesAndTreeBranches() throws Exception {
        byte[] pattern = pattern((byte) 0xa4);
        put(0x2140, pattern);
        Function sameLeaf = function(0x2140, 32, null);
        String original = sameLeaf.getName();
        byte[] extraModule = concat(export(0, "leaf_candidate_a", 8),
            encodedNumber(32), export(0, "leaf_candidate_b", 0));
        FlirtAnalysisSession leafSession = analyze(new String[] {"same-leaf.sig"},
            signature(pattern, 0, 0, 0, 32, extraModule));
        check(original.equals(sameLeaf.getName()), "multiple modules do not choose the first name");
        check(namesAt(leafSession, sameLeaf).equals(Set.of("leaf_candidate_a", "leaf_candidate_b")),
            "all matching modules reported");

        byte[] branchPattern = pattern((byte) 0xa5);
        put(0x2180, branchPattern);
        Function sameBranch = function(0x2180, 32, null);
        String branchOriginal = sameBranch.getName();
        byte[] tree = concat(header("branch-library"), new byte[] {2},
            treeNode(branchPattern, 0, 0, 0, 32, export(0, "branch_candidate_a", 0)),
            treeNode(branchPattern, 0, 0, 0, 32, export(0, "branch_candidate_b", 0)));
        FlirtAnalysisSession branchSession = analyze(new String[] {"sibling-branches.sig"}, tree);
        check(branchOriginal.equals(sameBranch.getName()), "multiple trie branches do not pick a name");
        check(namesAt(branchSession, sameBranch).equals(Set.of("branch_candidate_a", "branch_candidate_b")),
            "all matching trie branches reported");
    }

    private void testCrossFileConflicts() throws Exception {
        byte[] pattern = pattern((byte) 0xa6);
        put(0x21c0, pattern);
        Function ambiguous = function(0x21c0, 32, null);
        String original = ambiguous.getName();
        FlirtAnalysisSession session = analyze(new String[] {"left.sig", "right.sig"},
            signature(pattern, 0, 0, 0, 32, export(0, "left_name", 0)),
            signature(pattern, 0, 0, 0, 32, export(0, "right_name", 0)));
        check(original.equals(ambiguous.getName()), "cross-file ambiguity is not renamed");
        check(ambiguous.getComment() == null, "conflicting match does not get FLIRT success comment");
        check(namesAt(session, ambiguous).equals(Set.of("left_name", "right_name")),
            "cross-file candidate names reported");
        Set<String> sources = session.getConflicts().stream()
            .filter(candidate -> candidate.address().equals(ambiguous.getEntryPoint()))
            .map(FlirtCandidate::signatureFile).collect(Collectors.toSet());
        check(sources.stream().anyMatch(name -> name.endsWith("left.sig")) &&
            sources.stream().anyMatch(name -> name.endsWith("right.sig")),
            "conflict report retains each signature source");
    }

    private void testDuplicateNamesAndComments() throws Exception {
        byte[] pattern = pattern((byte) 0xa7);
        put(0x2200, pattern);
        Function unique = function(0x2200, 32, null);
        unique.setComment("Existing analyst comment.");
        byte[] first = concat(header("first-library"),
            new byte[] {1}, treeNode(pattern, 0, 0, 0, 32, export(0, "unique_export", 0)));
        byte[] second = concat(header("second-library"),
            new byte[] {1}, treeNode(pattern, 0, 0, 0, 32, export(0, "unique_export", 0)));
        String[] files = new String[] {"duplicate-left.sig", "duplicate-right.sig"};
        FlirtAnalysisSession session = analyze(files, first, second);
        check("unique_export".equals(unique.getName()), "same-name duplicates are applied");
        check(session.getConflicts().isEmpty(), "same-name duplicates are not a conflict");
        check(session.getAppliedCount() == 1, "same-name duplicates rename a function once");
        String comment = unique.getComment();
        check(comment.contains("Existing analyst comment."), "existing comment preserved");
        for (String expected : new String[] {"FLIRT", "unique_export", "duplicate-left.sig",
                "duplicate-right.sig", "first-library", "second-library"}) {
            check(comment.contains(expected), "FLIRT plate comment contains " + expected);
        }
        analyze(files, first, second);
        check(comment.equals(unique.getComment()), "rerun does not duplicate or rewrite identical FLIRT comment");
    }

    private void testLateReferenceCandidateDoesNotHideConflict() throws Exception {
        // The second callee name only becomes viable through a caller in a later file.
        // Renaming the first candidate while scanning files would hide this ambiguity.
        byte[] callerPattern = pattern((byte) 0xb1);
        callerPattern[0] = (byte) 0xc3;
        put(0x2300, callerPattern);
        Function caller = function(0x2300, 32, null);
        byte[] calleePattern = callPattern(0x2340, 0x2300, (byte) 0xb2);
        put(0x2340, calleePattern);
        Function callee = function(0x2340, 32, null);
        disassemble(toAddr(0x2340));
        String original = callee.getName();
        FlirtAnalysisSession session = analyze(
            new String[] {"a-early.sig", "b-dependent.sig", "z-caller.sig"},
            signature(calleePattern, callMask(), 0, 0, 32, export(0, "early_name", 0)),
            signature(calleePattern, callMask(), 0, 0, 32,
                referencedExport("late_name", "later_caller")),
            signature(callerPattern, 0, 0, 0, 32, export(0, "later_caller", 0)));
        check(original.equals(callee.getName()), "late reference-dependent candidate prevents early rename");
        check("later_caller".equals(caller.getName()), "independent unique dependency applied");
        check(namesAt(session, callee).equals(Set.of("early_name", "late_name")),
            "late reference-dependent candidate included in final conflicts");
    }

    private void testAmbiguousCalleeDoesNotRenameCaller() throws Exception {
        byte[] calleePattern = pattern((byte) 0xb3);
        calleePattern[0] = (byte) 0xc3;
        put(0x23c0, calleePattern);
        Function callee = function(0x23c0, 32, null);
        byte[] callerPattern = callPattern(0x2380, 0x23c0, (byte) 0xb4);
        put(0x2380, callerPattern);
        Function caller = function(0x2380, 32, null);
        disassemble(toAddr(0x2380));
        String callerOriginal = caller.getName();
        FlirtAnalysisSession session = analyze(
            new String[] {"caller.sig", "callee-a.sig", "callee-b.sig"},
            signature(callerPattern, callMask(), 0, 0, 32,
                referencedExport("unsafe_caller", "ambiguous_callee_a")),
            signature(calleePattern, 0, 0, 0, 32, export(0, "ambiguous_callee_a", 0)),
            signature(calleePattern, 0, 0, 0, 32, export(0, "ambiguous_callee_b", 0)));
        check(callerOriginal.equals(caller.getName()), "ambiguous callee cannot authorize caller rename");
        check(namesAt(session, callee).equals(Set.of("ambiguous_callee_a", "ambiguous_callee_b")),
            "ambiguous callee candidates reported");
    }

    private void testUniqueReferenceAcrossFiles() throws Exception {
        byte[] calleePattern = pattern((byte) 0xb5);
        calleePattern[0] = (byte) 0xc3;
        put(0x2440, calleePattern);
        Function callee = function(0x2440, 32, null);
        byte[] callerPattern = callPattern(0x2400, 0x2440, (byte) 0xb6);
        put(0x2400, callerPattern);
        Function caller = function(0x2400, 32, null);
        disassemble(toAddr(0x2400));
        FlirtAnalysisSession session = analyze(new String[] {"a-caller.sig", "z-callee.sig"},
            signature(callerPattern, callMask(), 0, 0, 32,
                referencedExport("cross_file_caller", "cross_file_callee")),
            signature(calleePattern, 0, 0, 0, 32, export(0, "cross_file_callee", 0)));
        check("cross_file_caller".equals(caller.getName()), "unique caller resolves before callee file order");
        check("cross_file_callee".equals(callee.getName()), "reference-free callee resolved across files");
        check(session.getAppliedCount() == 2, "unique dependency chain applies both functions");
        check(session.getConflicts().isEmpty(), "unique dependency chain has no conflicts");
    }

    private void testStaleAnalysisNameDoesNotResolveAmbiguousCallee() throws Exception {
        byte[] calleePattern = pattern((byte) 0xc0);
        calleePattern[0] = (byte) 0xc3;
        put(0x2480, calleePattern);
        Function callee = function(0x2480, 32, null);
        // Deliberately lacks a SigAnalyzer comment: other analyzers also write ANALYSIS names.
        callee.setName("stale_analysis_name", SourceType.ANALYSIS);
        byte[] callerPattern = callPattern(0x24c0, 0x2480, (byte) 0xc1);
        put(0x24c0, callerPattern);
        Function caller = function(0x24c0, 32, null);
        disassemble(toAddr(0x24c0));
        String callerOriginal = caller.getName();
        FlirtAnalysisSession session = analyze(
            new String[] {"stale-caller.sig", "current-a.sig", "current-b.sig"},
            signature(callerPattern, callMask(), 0, 0, 32,
                referencedExport("must_not_use_stale_name", "stale_analysis_name")),
            signature(calleePattern, 0, 0, 0, 32, export(0, "stale_analysis_name", 0)),
            signature(calleePattern, 0, 0, 0, 32, export(0, "alternative_current_name", 0)));
        check(callerOriginal.equals(caller.getName()),
            "unmarked stale ANALYSIS name cannot resolve an ambiguous current callee");
        check(namesAt(session, callee).equals(Set.of("stale_analysis_name", "alternative_current_name")),
            "current candidates retain ambiguity despite existing ANALYSIS name");
    }

    private void testInvalidCandidateNameCannotResolveCaller() throws Exception {
        String[] invalidNames = new String[] {"x".repeat(2101), "invalid callee name"};
        for (int i = 0; i < invalidNames.length; i++) {
            long calleeAddress = 0x2500 + i * 0x80;
            long callerAddress = calleeAddress + 0x40;
            byte[] calleePattern = pattern((byte) (0xd0 + i));
            calleePattern[0] = (byte) 0xc3;
            put(calleeAddress, calleePattern);
            Function callee = function(calleeAddress, 32, null);
            byte[] callerPattern = callPattern(callerAddress, calleeAddress, (byte) (0xd2 + i));
            put(callerAddress, callerPattern);
            Function caller = function(callerAddress, 32, null);
            disassemble(toAddr(callerAddress));
            String calleeOriginal = callee.getName();
            String callerOriginal = caller.getName();
            FlirtAnalysisSession session = analyze(
                new String[] {"invalid-caller.sig", "invalid-callee.sig"},
                signature(callerPattern, callMask(), 0, 0, 32,
                    referencedExport("must_not_use_invalid_name_" + i, invalidNames[i])),
                signature(calleePattern, 0, 0, 0, 32, export(0, invalidNames[i], 0)));
            check(calleeOriginal.equals(callee.getName()), "invalid candidate name rejected before mutation");
            check(callerOriginal.equals(caller.getName()),
                "unusable Ghidra name cannot authorize a caller rename");
            check(session.getAppliedCount() == 0, "invalid name does not produce a resolved dependency");
        }
    }

    private void testCommentExcludesUnresolvedDuplicateSource() throws Exception {
        byte[] calleePattern = pattern((byte) 0xe1);
        calleePattern[0] = (byte) 0xc3;
        put(0x2600, calleePattern);
        Function callee = function(0x2600, 32, null);
        byte[] callerPattern = callPattern(0x2640, 0x2600, (byte) 0xe0);
        put(0x2640, callerPattern);
        Function caller = function(0x2640, 32, null);
        disassemble(toAddr(0x2640));
        FlirtAnalysisSession session = analyze(new String[] {"trusted-reference-free.sig",
                "unresolved-reference.sig", "support-a.sig", "support-b.sig"},
            signature(callerPattern, callMask(), 0, 0, 32, export(0, "supported_name", 0)),
            signature(callerPattern, callMask(), 0, 0, 32,
                referencedExport("supported_name", "ambiguous_support_a")),
            signature(calleePattern, 0, 0, 0, 32, export(0, "ambiguous_support_a", 0)),
            signature(calleePattern, 0, 0, 0, 32, export(0, "ambiguous_support_b", 0)));
        check("supported_name".equals(caller.getName()), "reference-free duplicate supplies a unique name");
        check(caller.getComment().contains("trusted-reference-free.sig"),
            "successful source is included in FLIRT provenance");
        check(!caller.getComment().contains("unresolved-reference.sig"),
            "unresolved duplicate source is excluded from success provenance");
        check(namesAt(session, callee).equals(Set.of("ambiguous_support_a", "ambiguous_support_b")),
            "supporting callee remains ambiguous");
    }

    private static Set<String> namesAt(FlirtAnalysisSession session, Function function) {
        return session.getConflicts().stream()
            .filter(candidate -> candidate.address().equals(function.getEntryPoint()))
            .map(FlirtCandidate::name).collect(Collectors.toSet());
    }

    private FlirtAnalysisSession analyze(String[] names, byte[]... signatures) throws Exception {
        Path directory = Files.createTempDirectory("siganalyzer-session-");
        List<java.io.File> files = new java.util.ArrayList<>();
        try {
            for (int i = 0; i < signatures.length; i++) {
                Path file = directory.resolve(names[i]);
                Files.write(file, signatures[i]);
                files.add(file.toFile());
            }
            FlirtAnalysisSession session = new FlirtAnalysisSession(currentProgram);
            MessageLog log = new MessageLog();
            check(session.run(files, monitor, log), "analysis session accepted signatures: " + log);
            return session;
        }
        finally {
            for (java.io.File file : files) {
                Files.deleteIfExists(file.toPath());
            }
            Files.deleteIfExists(directory);
        }
    }

    private static byte[] referencedExport(String name, String target) {
        byte[] targetBytes = target.getBytes(StandardCharsets.US_ASCII);
        byte[] length = targetBytes.length < 256 ? new byte[] {(byte) targetBytes.length} :
            concat(new byte[] {0}, encodedNumber(targetBytes.length));
        return concat(export(0, name, 4), new byte[] {1, 1}, length, targetBytes);
    }

    private static byte[] callPattern(long caller, long callee, byte filler) {
        byte[] pattern = pattern(filler);
        pattern[0] = (byte) 0xe8;
        int displacement = (int) (callee - caller - 5);
        for (int i = 0; i < 4; i++) {
            pattern[i + 1] = (byte) (displacement >>> (8 * i));
        }
        pattern[5] = (byte) 0xc3;
        return pattern;
    }

    private static long callMask() {
        return (1L << 30) | (1L << 29) | (1L << 28) | (1L << 27);
    }

    private void apply(byte[] signature) throws Exception {
        Path file = Files.createTempFile("siganalyzer-smoke-", ".sig");
        try {
            Files.write(file, signature);
            ApplyFlirt apply = new ApplyFlirt(currentProgram, file.toFile());
            check(apply.run(monitor), "signature accepted: " + apply.getErrorMessage());
        }
        finally {
            Files.deleteIfExists(file);
        }
    }

    private Function function(long offset, int size, String name) throws Exception {
        Address entry = toAddr(offset);
        return currentProgram.getFunctionManager().createFunction(name, entry,
            new AddressSet(entry, entry.add(size - 1)),
            name == null ? SourceType.DEFAULT : SourceType.USER_DEFINED);
    }

    private void put(long offset, byte[] bytes) throws Exception {
        currentProgram.getMemory().setBytes(toAddr(offset), bytes);
    }

    private static byte[] pattern(byte value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, value);
        return bytes;
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static byte[] signature(byte[] pattern, long mask, int crcLength, int crc,
            int moduleLength, byte[] exports) {
        return concat(header(""), new byte[] {1},
            treeNode(pattern, mask, crcLength, crc, moduleLength, exports));
    }

    private static byte[] header(String library) {
        byte[] name = library.getBytes(StandardCharsets.US_ASCII);
        byte[] header = new byte[45 + name.length];
        System.arraycopy("IDASGN".getBytes(StandardCharsets.US_ASCII), 0, header, 0, 6);
        header[6] = 10;
        header[34] = (byte) name.length;
        header[37] = 1;
        header[41] = 32;
        System.arraycopy(name, 0, header, 45, name.length);
        return header;
    }

    private static byte[] treeNode(byte[] pattern, long mask, int crcLength, int crc,
            int moduleLength, byte[] exports) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(pattern.length);
        number(out, mask);
        for (int i = 0; i < pattern.length; i++) {
            if ((mask & (1L << (pattern.length - i - 1))) == 0) {
                out.write(pattern[i]);
            }
        }
        out.write(0); // leaf
        out.write(crcLength);
        out.write(crc >>> 8);
        out.write(crc);
        number(out, moduleLength);
        out.writeBytes(exports);
        return out.toByteArray();
    }

    private static byte[] encodedNumber(long value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, value);
        return out.toByteArray();
    }

    private static byte[] export(int offsetDelta, String name, int flags) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, offsetDelta);
        out.writeBytes(name.getBytes(StandardCharsets.US_ASCII));
        out.write(flags);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] bytes : arrays) {
            out.writeBytes(bytes);
        }
        return out.toByteArray();
    }

    private static void number(ByteArrayOutputStream out, long value) {
        if (value < 0x80) {
            out.write((int) value);
        }
        else if (value < 0x4000) {
            out.write(0x80 | (int) (value >>> 8));
            out.write((int) value);
        }
        else if (value < 0x20000000) {
            out.write(0xc0 | (int) (value >>> 24));
            out.write((int) (value >>> 16));
            out.write((int) (value >>> 8));
            out.write((int) value);
        }
        else {
            out.write(0xe0);
            out.write((int) (value >>> 24));
            out.write((int) (value >>> 16));
            out.write((int) (value >>> 8));
            out.write((int) value);
        }
    }
}
