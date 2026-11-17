// Synthetic end-to-end FLIRT checks in a real Ghidra Program.
// Run with analyzeHeadless, -noanalysis and -postScript SigAnalyzerSmokeTest.java.
// @category SigAnalyzer.Tests

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import siganalyzer.analyzer.ApplyFlirt;
import siganalyzer.analyzer.FlirtAnalysisSession;
import siganalyzer.analyzer.FlirtAnalysisResults;
import siganalyzer.analyzer.FlirtCandidate;
import siganalyzer.analyzer.FlirtConflictResolution;
import siganalyzer.analyzer.YaraSignatureGate;
import siganalyzer.analyzer.YaraConfiguration;
import siganalyzer.analyzer.SignatureRepository;
import siganalyzer.analyzer.SignatureSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;

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
        testManualConflictChoiceAndUndo();
        testManualConflictGuardsAndRollback();
        testNativeYaraRules();
        testYaraFailureTimeoutAndCancellation();
        testGroupedSignatureSelection();
        testGroupedSignatureProvenance();
        testClosingProgramClearsOverlayReport();
        testYaraToolOptionsExecutableSelection();
        testVersion11SignaturesAndReferences();
        testVersion11InstructionBitsAndCrcBase();
        testVersion11OptionalAndTinySites();
        testVersion11AlternativeSites();
        testVersion11OptionalEvidenceDoesNotHideAConflict();
        testVersion11InternalAndMutualSites();
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

    private ProgramDB independentProgram(String name) throws Exception {
        ProgramDB program = new ProgramDB(name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(
                currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int transaction = program.startTransaction("Initialize manual-choice fixture");
        boolean commit = false;
        try {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            program.getMemory().createInitializedBlock("manual", start, 0x100, (byte) 0x90,
                monitor, false);
            program.getFunctionManager().createFunction("original_user_name", start,
                new AddressSet(start, start.add(31)), SourceType.USER_DEFINED);
            Address second = start.add(0x40);
            program.getFunctionManager().createFunction(null, second,
                new AddressSet(second, second.add(31)), SourceType.DEFAULT);
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        return program;
    }

    private void testClosingProgramClearsOverlayReport() throws Exception {
        ProgramDB program = independentProgram("closed-overlay-report");
        boolean released = false;
        try {
            int transaction = program.startTransaction("Create overlay conflict fixture");
            Address overlay;
            try {
                Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                overlay = program.getMemory().createInitializedBlock("close_overlay", base,
                    32, (byte) 0x90, monitor, true).getStart();
                program.getFunctionManager().createFunction(null, overlay,
                    new AddressSet(overlay, overlay.add(31)), SourceType.DEFAULT);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            FlirtAnalysisResults.publish(program, List.of(
                new FlirtCandidate(overlay, "overlay_a", "a.sig", ""),
                new FlirtCandidate(overlay, "overlay_b", "b.sig", "")));
            check(FlirtAnalysisResults.get(program).size() == 2, "overlay conflict report is cached while open");
            program.release(this);
            released = true;
            check(program.isClosed(), "independent overlay program has closed");
            check(FlirtAnalysisResults.get(program).isEmpty(),
                "closing a program clears its cached overlay candidates without manual cleanup");
        }
        finally {
            if (!released) {
                program.release(this);
            }
        }
    }

    private void testManualConflictChoiceAndUndo() throws Exception {
        ProgramDB program = independentProgram("manual-success");
        try {
            Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            Address other = entry.add(0x40);
            int setup = program.startTransaction("Keep an existing analyst comment");
            program.getFunctionManager().getFunctionAt(entry).setComment("Manual analyst comment.");
            program.endTransaction(setup, true);
            FlirtCandidate selected = new FlirtCandidate(entry, "chosen_name", "chosen-one.sig", "first library");
            FlirtCandidate duplicate = new FlirtCandidate(entry, "chosen_name", "chosen-two.sig", "second library");
            FlirtCandidate alternative = new FlirtCandidate(entry, "other_name", "alternative.sig", "other library");
            List<FlirtCandidate> unrelated = List.of(
                new FlirtCandidate(other, "unrelated_a", "a.sig", ""),
                new FlirtCandidate(other, "unrelated_b", "b.sig", ""));
            FlirtAnalysisResults.publish(program, List.of(selected, duplicate, alternative,
                unrelated.get(0), unrelated.get(1)));
            check(FlirtConflictResolution.canApply(program, selected), "current candidate is applicable while idle");
            List<FlirtCandidate> remaining = FlirtConflictResolution.apply(program, selected);
            Function function = program.getFunctionManager().getFunctionAt(entry);
            check("chosen_name".equals(function.getName()), "explicit choice replaces an ordinary user-defined name");
            check(function.getSymbol().getSource() == SourceType.USER_DEFINED,
                "explicit choice is protected as a user-defined name");
            check(function.getComment().contains("Manual analyst comment."), "manual choice preserves analyst comment");
            check(function.getComment().contains("chosen-one.sig") && function.getComment().contains("chosen-two.sig"),
                "manual choice records all sources of the selected name");
            check(!function.getComment().contains("alternative.sig"), "unselected candidate is not success provenance");
            check(remaining.equals(unrelated) && FlirtAnalysisResults.get(program).equals(unrelated),
                "applying a choice removes every alternative only at that address");
            check(program.getCurrentTransactionInfo() == null, "manual choice closes its transaction");
            check(program.canUndo(), "manual choice is undoable in Ghidra");
            program.undo();
            flushProgramEvents(program);
            Function undone = program.getFunctionManager().getFunctionAt(entry);
            check("original_user_name".equals(undone.getName()), "one undo restores the previous name");
            check("Manual analyst comment.".equals(undone.getComment()), "one undo restores the previous comment");
            check(Set.copyOf(FlirtAnalysisResults.get(program)).equals(Set.of(selected, duplicate,
                alternative, unrelated.get(0), unrelated.get(1))), "undo restores every conflict row at the chosen address");
            check(program.canRedo(), "manual choice remains redoable after report restoration");
            program.redo();
            flushProgramEvents(program);
            check("chosen_name".equals(program.getFunctionManager().getFunctionAt(entry).getName()),
                "redo reapplies the chosen name");
            check(Set.copyOf(FlirtAnalysisResults.get(program)).equals(Set.copyOf(unrelated)),
                "redo hides resolved conflict alternatives again");
        }
        finally {
            FlirtAnalysisResults.clear(program);
            program.release(this);
        }
    }

    private void testManualConflictGuardsAndRollback() throws Exception {
        ProgramDB program = independentProgram("manual-guards");
        try {
            Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            Function function = program.getFunctionManager().getFunctionAt(entry);
            FlirtCandidate selected = new FlirtCandidate(entry, "selected", "selected.sig", "");
            FlirtCandidate alternative = new FlirtCandidate(entry, "alternative", "alternative.sig", "");
            FlirtAnalysisResults.publish(program, List.of(alternative));
            check(!FlirtConflictResolution.canApply(program, selected), "stale candidate disabled");
            expectManualRejection(program, selected);
            check("original_user_name".equals(function.getName()), "stale candidate cannot rename a function");

            FlirtAnalysisResults.publish(program, List.of(selected, alternative));
            int transaction = program.startTransaction("Program is busy");
            try {
                function.setComment("Outer transaction retained.");
                check(!FlirtConflictResolution.canApply(program, selected), "candidate disabled while program is busy");
                expectManualRejection(program, selected);
                check(program.getCurrentTransactionInfo() != null, "rejection leaves the caller's transaction open");
            }
            finally {
                program.endTransaction(transaction, true);
            }
            check("Outer transaction retained.".equals(function.getComment()), "busy rejection does not abort another transaction");

            for (int protection = 0; protection < 3; protection++) {
                transaction = program.startTransaction("Protect candidate function");
                String protectedName = "protected_name_" + protection;
                try {
                    function.setComment(protection == 0 ? "Library Function - Single Match\nFID library" : null);
                    function.setName(protectedName, protection == 1 ? SourceType.IMPORTED : SourceType.USER_DEFINED);
                    if (protection == 2) {
                        program.getSymbolTable().addExternalEntryPoint(entry);
                    }
                }
                finally {
                    program.endTransaction(transaction, true);
                }
                check(!FlirtConflictResolution.canApply(program, selected), "protected candidate disabled: " + protection);
                expectManualRejection(program, selected);
                check(protectedName.equals(function.getName()), "protected name retained: " + protection);
                check(FlirtAnalysisResults.get(program).size() == 2, "protected rejection preserves conflict rows");
            }

            transaction = program.startTransaction("Remove guards before rename failure");
            function.setName("original_user_name", SourceType.USER_DEFINED);
            function.setComment("Retain on failure.");
            program.getSymbolTable().removeExternalEntryPoint(entry);
            program.endTransaction(transaction, true);
            FlirtCandidate invalid = new FlirtCandidate(entry, "invalid chosen name", "invalid.sig", "");
            List<FlirtCandidate> before = List.of(invalid, alternative);
            FlirtAnalysisResults.publish(program, before);
            try {
                FlirtConflictResolution.apply(program, invalid);
                throw new AssertionError("invalid manual name must fail");
            }
            catch (InvalidInputException expected) {
                check("original_user_name".equals(function.getName()), "failed rename rolls back the name");
                check("Retain on failure.".equals(function.getComment()), "failed rename rolls back the comment");
                check(FlirtAnalysisResults.get(program).equals(before), "failed rename retains conflict report");
                check(program.getCurrentTransactionInfo() == null, "failed rename closes its transaction");
            }
        }
        finally {
            FlirtAnalysisResults.clear(program);
            program.release(this);
        }
    }

    private static void expectManualRejection(ProgramDB program, FlirtCandidate candidate) throws Exception {
        try {
            FlirtConflictResolution.apply(program, candidate);
            throw new AssertionError("inapplicable candidate must be rejected at the mutation boundary");
        }
        catch (IllegalArgumentException | IllegalStateException expected) {
            // The user may leave a menu open while analysis or another tool updates the program.
        }
    }

    private static void flushProgramEvents(ProgramDB program) throws Exception {
        program.flushEvents();
        javax.swing.SwingUtilities.invokeAndWait(() -> { });
    }

    private static String nativeYara() {
        return System.getenv().getOrDefault("SIGANALYZER_TEST_YARA", "yara");
    }

    private void testNativeYaraRules() throws Exception {
        Path directory = Files.createTempDirectory("siganalyzer-native-yara-");
        byte original = currentProgram.getMemory().getByte(toAddr(0));
        try {
            // The imported fixture is C3, but mapped memory is now CC. YARA must scan FileBytes.
            currentProgram.getMemory().setByte(toAddr(0), (byte) 0xcc);
            Path matching = Files.writeString(directory.resolve("matching.yar"),
                "rule original_byte { strings: $ret = { C3 } condition: filesize == 1 and $ret at 0 }");
            Path nonmatching = Files.writeString(directory.resolve("nonmatching.yar"),
                "rule mapped_byte { strings: $trap = { CC } condition: $trap at 0 }");
            Path logging = Files.writeString(directory.resolve("logging.yar"),
                "import \"console\"\nrule logs_without_match { condition: console.log(\"1\") and false }");
            Files.writeString(directory.resolve("included.yar"), "rule included_rule { condition: filesize == 1 }");
            Path including = Files.writeString(directory.resolve("including.yar"), "include \"included.yar\"");
            try (YaraSignatureGate gate = new YaraSignatureGate(currentProgram, nativeYara(), 10)) {
                check(gate.matches(matching, monitor), "native YARA matches original imported bytes");
                check(!gate.matches(nonmatching, monitor), "native YARA ignores modified mapped bytes");
                check(!gate.matches(logging, monitor), "console.log output cannot masquerade as a YARA match");
                check(gate.matches(including, monitor), "relative includes resolve in the rule group directory");
            }
            Path malformed = Files.writeString(directory.resolve("malformed.yar"), "rule broken { condition: }");
            try (YaraSignatureGate gate = new YaraSignatureGate(currentProgram, nativeYara(), 10)) {
                expectYaraFailure(gate, malformed, "invalid native YARA syntax must be an error");
            }
            try (YaraSignatureGate gate = new YaraSignatureGate(currentProgram,
                    directory.resolve("missing-yara-executable").toString(), 10)) {
                expectYaraFailure(gate, matching, "missing YARA executable must be an error");
            }
            ProgramDB noFileBytes = independentProgram("yara-no-file-bytes");
            try (YaraSignatureGate gate = new YaraSignatureGate(noFileBytes, nativeYara(), 10)) {
                expectYaraFailure(gate, matching, "missing original FileBytes must be an error");
            }
            finally {
                noFileBytes.release(this);
            }
            ProgramDB multipleImports = independentProgram("a.exe");
            try {
                int transaction = multipleImports.startTransaction("Store imports with identical basenames");
                try {
                    multipleImports.getMemory().createFileBytes("/other/a.exe", 0, 1,
                        new ByteArrayInputStream(new byte[] {0x11}), monitor);
                    multipleImports.getMemory().createFileBytes("/main/a.exe", 0, 1,
                        new ByteArrayInputStream(new byte[] {0x22}), monitor);
                    multipleImports.setExecutablePath("/main/a.exe");
                }
                finally {
                    multipleImports.endTransaction(transaction, true);
                }
                Path exactSource = Files.writeString(directory.resolve("exact-source.yar"),
                    "rule exact_executable_store { condition: filesize == 1 and uint8(0) == 0x22 }");
                try (YaraSignatureGate gate = new YaraSignatureGate(multipleImports, nativeYara(), 10)) {
                    check(gate.matches(exactSource, monitor),
                        "exact executable path wins over an earlier imported file with the same basename");
                }
            }
            finally {
                multipleImports.release(this);
            }
        }
        finally {
            currentProgram.getMemory().setByte(toAddr(0), original);
            removeTemporaryDirectory(directory);
        }
    }

    private void testYaraFailureTimeoutAndCancellation() throws Exception {
        Path directory = Files.createTempDirectory("siganalyzer-yara-process-");
        try {
            Path rule = Files.writeString(directory.resolve("rules.yar"), "rule test { condition: true }");
            Path sleeper = Files.writeString(directory.resolve("slow-yara"), "#!/bin/sh\nexec sleep 10\n");
            check(sleeper.toFile().setExecutable(true), "slow YARA test executable created");
            long started = System.nanoTime();
            try (YaraSignatureGate gate = new YaraSignatureGate(currentProgram, sleeper.toString(), 1)) {
                expectYaraFailure(gate, rule, "unresponsive YARA process must time out");
            }
            check(System.nanoTime() - started < 5_000_000_000L, "YARA timeout does not wait for the slow process");

            TaskMonitorAdapter cancellable = new TaskMonitorAdapter(true);
            Thread cancel = new Thread(() -> {
                try {
                    Thread.sleep(200);
                    cancellable.cancel();
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            cancel.start();
            started = System.nanoTime();
            try (YaraSignatureGate gate = new YaraSignatureGate(currentProgram, sleeper.toString(), 10)) {
                try {
                    gate.matches(rule, cancellable);
                    throw new AssertionError("cancellation must interrupt a running YARA process");
                }
                catch (CancelledException expected) {
                    check(System.nanoTime() - started < 5_000_000_000L, "YARA cancellation returns promptly");
                }
            }
            finally {
                cancel.join(1000);
            }

            Path targetRecord = directory.resolve("target-path.txt");
            Path recorder = Files.writeString(directory.resolve("recording-yara"),
                "#!/bin/sh\nfor target_path in \"$@\"; do :; done\nprintf '%s\\n' \"$target_path\" > '" +
                    targetRecord + "'\nprintf '0\\n'\n");
            check(recorder.toFile().setExecutable(true), "YARA target recorder created");
            Path target;
            try (YaraSignatureGate gate = new YaraSignatureGate(currentProgram, recorder.toString(), 5)) {
                check(!gate.matches(rule, monitor), "valid native count zero means no match");
                target = Path.of(Files.readString(targetRecord).strip());
                check(Files.isRegularFile(target), "original-file temporary target exists during gate use");
            }
            check(!Files.exists(target), "gate close removes the original-file temporary target");
        }
        finally {
            removeTemporaryDirectory(directory);
        }
    }

    private void expectYaraFailure(YaraSignatureGate gate, Path rule, String message) throws Exception {
        try {
            gate.matches(rule, monitor);
            throw new AssertionError(message);
        }
        catch (java.io.IOException expected) {
            check(expected.getMessage() != null && !expected.getMessage().isBlank(), "YARA failure has diagnostic text");
        }
    }

    private void testGroupedSignatureSelection() throws Exception {
        Path root = Files.createTempDirectory("siganalyzer-group-selection-");
        try {
            SignatureRepository repository = new SignatureRepository(root);
            Path plain = Files.write(root.resolve("plain.sig"), new byte[] {1});
            Path matchingDirectory = repository.createGroup("matching").directory();
            Path matching = Files.write(matchingDirectory.resolve("matching.sig"), new byte[] {2});
            Files.writeString(matchingDirectory.resolve(SignatureRepository.RULE_FILE),
                "rule original_fixture { condition: filesize == 1 and uint8(0) == 0xc3 }");
            Path parentDirectory = repository.createGroup("not-matching").directory();
            Path skipped = Files.write(parentDirectory.resolve("skipped.sig"), new byte[] {3});
            Files.writeString(parentDirectory.resolve(SignatureRepository.RULE_FILE),
                "rule does_not_match { condition: false }");
            Path childDirectory = repository.createGroup("not-matching/child").directory();
            Path child = Files.write(childDirectory.resolve("child.sig"), new byte[] {4});
            Path invalidDirectory = repository.createGroup("invalid-rule").directory();
            Path invalid = Files.write(invalidDirectory.resolve("invalid.sig"), new byte[] {5});
            Files.writeString(invalidDirectory.resolve(SignatureRepository.RULE_FILE),
                "rule invalid { condition: }");
            MessageLog log = new MessageLog();
            SignatureSelection.Result result = SignatureSelection.select(repository, currentProgram,
                nativeYara(), 10, monitor, log);
            Set<Path> selected = result.signatures().stream().map(java.io.File::toPath)
                .collect(Collectors.toSet());
            check(selected.equals(Set.of(plain, matching, child)),
                "only matched groups and unconditional direct groups are selected");
            check(!selected.contains(skipped) && !selected.contains(invalid),
                "nonmatching and invalid rule groups are skipped");
            check(!result.success(), "invalid rule is reported as an error for its group");
            repository.setEnabled(invalid, false);
            result = SignatureSelection.select(repository, currentProgram, nativeYara(), 10,
                monitor, new MessageLog());
            check(result.success(), "ordinary no-match is successful and disabled groups are not gated");

            result = SignatureSelection.select(repository, currentProgram,
                root.resolve("missing-yara").toString(), 1, monitor, new MessageLog());
            check(!result.success(), "missing YARA marks gated selection as failed");
            check(result.signatures().stream().map(java.io.File::toPath).collect(Collectors.toSet())
                .equals(Set.of(plain, child)), "unconditional groups remain usable without a YARA executable");

            ProgramDB noOriginal = independentProgram("grouped-without-original-file");
            try {
                result = SignatureSelection.select(repository, noOriginal, nativeYara(), 10,
                    monitor, new MessageLog());
                check(!result.success(), "missing original bytes are reported for gated groups");
                check(result.signatures().stream().map(java.io.File::toPath).collect(Collectors.toSet())
                    .equals(Set.of(plain, child)), "missing original bytes do not block unconditional groups");
            }
            finally {
                noOriginal.release(this);
            }
        }
        finally {
            removeTemporaryDirectory(root);
        }
    }

    private void testYaraToolOptionsExecutableSelection() throws Exception {
        Path root = Files.createTempDirectory("siganalyzer-tool-yara-");
        ToolOptions options = new ToolOptions(YaraConfiguration.TOOL_OPTIONS);
        try {
            SignatureRepository repository = new SignatureRepository(root);
            Path group = repository.createGroup("gated").directory();
            Path signature = Files.write(group.resolve("gated.sig"), new byte[] {1});
            Files.writeString(group.resolve(SignatureRepository.RULE_FILE),
                "rule original_fixture { condition: filesize == 1 and uint8(0) == 0xc3 }");
            Path executables = Files.createDirectories(root.resolve("non default YARA paths"));
            Path firstMarker = root.resolve("first-executable-called");
            Path first = Files.writeString(executables.resolve("first yara executable"),
                "#!/bin/sh\nprintf 'called\\n' >> " + shellQuote(firstMarker.toString()) +
                    "\nexec " + shellQuote(nativeYara()) + " \"$@\"\n");
            check(first.toFile().setExecutable(true), "first configured YARA executable created");
            YaraConfiguration.registerToolOptions(options);
            options.setFile(YaraConfiguration.EXECUTABLE_OPTION, first.toFile());
            SignatureSelection.Result selected = SignatureSelection.select(repository, currentProgram,
                YaraConfiguration.executable(options, "missing-yara-fallback"), 10, monitor, new MessageLog());
            check(selected.success() && selected.signatures().equals(List.of(signature.toFile())),
                "tool-configured executable path runs the real native YARA gate");
            check(Files.exists(firstMarker), "native YARA was launched through the selected custom path");

            Path secondMarker = root.resolve("changed-executable-called");
            Path second = Files.writeString(executables.resolve("changed yara executable"),
                "#!/bin/sh\nprintf 'called\\n' >> " + shellQuote(secondMarker.toString()) +
                    "\nexec " + shellQuote(nativeYara()) + " \"$@\"\n");
            check(second.toFile().setExecutable(true), "changed configured YARA executable created");
            options.setFile(YaraConfiguration.EXECUTABLE_OPTION, second.toFile());
            selected = SignatureSelection.select(repository, currentProgram,
                YaraConfiguration.executable(options, "missing-yara-fallback"), 10, monitor, new MessageLog());
            check(selected.success() && selected.signatures().equals(List.of(signature.toFile())),
                "changed tool setting is honored on the next YARA selection");
            check(Files.exists(secondMarker), "the changed executable path is launched");
            check(Files.readAllLines(firstMarker).size() == 1, "the previous executable is not cached after a settings change");
        }
        finally {
            options.dispose();
            removeTemporaryDirectory(root);
        }
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private void testVersion11SignaturesAndReferences() throws Exception {
        Path directory = Files.createTempDirectory("siganalyzer-v11-smoke-");
        try {
            for (int compressed = 0; compressed < 2; compressed++) {
                long callerAddress = 0x2700 + compressed * 0x80;
                long calleeAddress = callerAddress + 0x40;
                byte[] pattern = callPattern(callerAddress, calleeAddress, (byte) (0x83 + compressed));
                put(callerAddress, pattern);
                put(callerAddress + 32, CRC_VECTOR);
                put(calleeAddress, new byte[] {(byte) 0xc3});
                Function caller = function(callerAddress, 41, null);
                Function callee = function(calleeAddress, 1, "unrelated_v11_target_" + compressed);
                disassemble(toAddr(callerAddress));
                String target = "expected_v11_target_" + compressed;
                String name = "synthetic_v11_export_" + compressed;
                byte[] reference = target.getBytes(StandardCharsets.US_ASCII);
                byte[] exports = concat(exportV11(0, name, 0, 4),
                    new byte[] {1, 1, (byte) reference.length}, reference);
                byte[] body = concat(new byte[] {1}, treeNode(pattern, callMask(), 9,
                    0x6e90, 41, exports));
                byte[] header = header(11, "Independent v11 smoke");
                header[16] = (byte) (compressed == 1 ? 0x10 : 0);
                byte[] encodedBody = compressed == 1 ? zlib(body) : body;
                Path file = Files.write(directory.resolve(compressed == 1 ?
                    "v11-compressed.sig" : "v11-plain.sig"), concat(header, encodedBody));
                // Exercise the same complete-file metadata path used by the signature manager.
                try (var input = new java.io.DataInputStream(Files.newInputStream(file))) {
                    var info = siganalyzer.analyzer.FlirtHeaderParser.parseHeader(input);
                    check(info != null && info.getVersion() == 11, "full v11 signature accepted by header importer");
                    check("Independent v11 smoke".equals(info.getLibraryName()), "v11 library name starts after toolchain byte");
                    check((info.getV11().toolchain & 0xff) == 0xa5, "v11 toolchain byte retained");
                    check(input.available() == encodedBody.length, "v11 header importer leaves the entire tree unread");
                }
                String original = caller.getName();
                ApplyFlirt apply = new ApplyFlirt(currentProgram, file.toFile());
                check(apply.run(monitor), "v11 signature tree parses before reference resolution");
                check(original.equals(caller.getName()), "v11 mismatching reference rejects rename");
                callee.setName(target, SourceType.USER_DEFINED);
                check(apply.run(monitor), "v11 signature accepted after reference resolution");
                check(name.equals(caller.getName()), "v11 export applied for plain and zlib trees");
                check(caller.getComment().contains("Independent v11 smoke") &&
                    caller.getComment().contains(file.getFileName().toString()), "v11 rename carries parsed signature provenance");
            }
            byte[] unsupported = header(11, "Synthetic unsupported compression");
            unsupported[16] = 0x40;
            Path zstd = Files.write(directory.resolve("v11-zstd.sig"), concat(unsupported,
                new byte[] {0x28, (byte) 0xb5, 0x2f, (byte) 0xfd}));
            ApplyFlirt apply = new ApplyFlirt(currentProgram, zstd.toFile());
            check(!apply.run(monitor), "unsupported Zstandard signatures are rejected explicitly");
            String diagnostic = String.valueOf(apply.getErrorMessage()).toLowerCase(java.util.Locale.ROOT);
            check(diagnostic.contains("zstd") || diagnostic.contains("zstandard"),
                "unsupported Zstandard compression has a specific diagnostic");
        }
        finally {
            removeTemporaryDirectory(directory);
        }
    }

    private void testVersion11InstructionBitsAndCrcBase() throws Exception {
        byte[] wildcardPattern = new byte[32];
        byte[] publicMemory = pattern((byte) 0x90);
        publicMemory[0] = 0x54;
        put(0x2800, publicMemory);
        Function publicBits = function(0x2800, 32, null);
        String publicOriginal = publicBits.getName();
        byte[] publicSignature = v11Signature(wildcardPattern, 0xffffffffL, 0, 0, 32,
            exportV11(0, "v11_public_instruction_bits", 0x80, 0,
                instructionBits(0xff, 0x12340055)), 32);
        apply(publicSignature);
        check(publicOriginal.equals(publicBits.getName()), "v11 public instruction-bit mismatch rejects rename");
        put(0x2800, new byte[] {0x55});
        apply(publicSignature);
        check("v11_public_instruction_bits".equals(publicBits.getName()),
            "v11 instruction matching ignores expected-value bits outside the mask");

        byte[] sitePattern = pattern((byte) 0x85);
        put(0x2900, sitePattern);
        put(0x2928, new byte[] {0x54, 0x33, 0x22, 0x11});
        Function siteBits = function(0x2900, 32, null);
        String siteOriginal = siteBits.getName();
        byte[] sites = concat(exportV11(0, "v11_distant_instruction_bits", 0, 0x20),
            new byte[] {1}, siteV11(40, "", 0x80, instructionBits(0xff, 0x12340055)));
        byte[] siteSignature = v11Signature(sitePattern, 0, 0, 0, 44, sites, 32);
        apply(siteSignature);
        check(siteOriginal.equals(siteBits.getName()), "v11 site instruction-bit mismatch rejects rename");
        put(0x2928, new byte[] {0x55});
        apply(siteSignature);
        check("v11_distant_instruction_bits".equals(siteBits.getName()),
            "v11 matching reads instruction bits beyond the pattern and first function body");

        byte[] crcPattern = pattern((byte) 0x86);
        put(0x2a00, crcPattern);
        put(0x2a20, CRC_VECTOR); // a valid decoy at the legacy 32-byte CRC offset
        byte[] wrong = CRC_VECTOR.clone();
        wrong[0] ^= 1;
        put(0x2a40, wrong);
        Function crcFunction = function(0x2a00, 32, null);
        String crcOriginal = crcFunction.getName();
        byte[] crcSignature = v11Signature(crcPattern, 0, 9, 0x6e90, 73,
            exportV11(0, "v11_header_pattern_crc", 0, 0), 64);
        apply(crcSignature);
        check(crcOriginal.equals(crcFunction.getName()), "v11 CRC uses the header pattern length rather than a 32-byte leaf");
        put(0x2a40, CRC_VECTOR);
        apply(crcSignature);
        check("v11_header_pattern_crc".equals(crcFunction.getName()), "v11 CRC matches at the header's 64-byte offset");
    }

    private void testVersion11OptionalAndTinySites() throws Exception {
        String expected = "ordinary_v11_site_target";
        for (int evidence = 0; evidence < 3; evidence++) {
            long callerAddress = 0x2b00 + evidence * 0x80;
            long calleeAddress = callerAddress + 0x40;
            byte[] pattern = callPattern(callerAddress, calleeAddress, (byte) (0x87 + evidence));
            put(callerAddress, pattern);
            put(calleeAddress, new byte[] {(byte) 0xc3});
            Function caller = function(callerAddress, 32, null);
            function(calleeAddress, 1, evidence == 0 ? null :
                evidence == 1 ? expected : "mismatching_v11_site_target");
            disassemble(toAddr(callerAddress));
            String original = caller.getName();
            String renamed = "v11_optional_site_" + evidence;
            byte[] sites = concat(exportV11(0, renamed, 0, 0x20), new byte[] {1},
                siteV11(1, expected, 0, new byte[0]));
            apply(v11Signature(pattern, callMask(), 0, 0, 32, sites, 32));
            check((evidence == 2 ? original : renamed).equals(caller.getName()),
                "ordinary v11 site handles unknown, matching and mismatching names: " + evidence);
        }

        byte[] tiny = Arrays.copyOf(callPattern(0x2c80, 0x2cc0, (byte) 0x8a), 12);
        put(0x2c80, tiny);
        put(0x2cc0, new byte[] {(byte) 0xc3});
        Function caller = function(0x2c80, 12, null);
        function(0x2cc0, 1, null);
        disassemble(toAddr(0x2c80));
        String original = caller.getName();
        byte[] sites = concat(exportV11(0, "v11_tiny_unproven", 0, 0x20), new byte[] {1},
            siteV11(1, "unknown_tiny_v11_target", 0, new byte[0]));
        long tinyMask = (1L << 10) | (1L << 9) | (1L << 8) | (1L << 7);
        apply(v11Signature(tiny, tinyMask, 0, 0, 12, sites, 32));
        check(original.equals(caller.getName()), "tiny v11 modules require positive site-name evidence");
    }

    private void testVersion11AlternativeSites() throws Exception {
        for (int matches = 0; matches < 2; matches++) {
            long callerAddress = 0x2d00 + matches * 0x80;
            long calleeAddress = callerAddress + 0x40;
            byte[] pattern = callPattern(callerAddress, calleeAddress, (byte) (0x8b + matches));
            put(callerAddress, pattern);
            put(calleeAddress, new byte[] {(byte) 0xc3});
            Function caller = function(callerAddress, 32, null);
            function(calleeAddress, 1, matches == 1 ? "matching_v11_alternative_target" :
                "different_v11_alternative_target");
            disassemble(toAddr(callerAddress));
            String original = caller.getName();
            String renamed = "v11_alternative_site_" + matches;
            byte[] alternatives = concat(exportV11(0, renamed, 0, 0x40),
                new byte[] {2, 1}, siteV11(1, "wrong_v11_alternative_target", 0, new byte[0]),
                new byte[] {1}, siteV11(1, "matching_v11_alternative_target", 0, new byte[0]));
            apply(v11Signature(pattern, callMask(), 0, 0, 32, alternatives, 32));
            check((matches == 1 ? renamed : original).equals(caller.getName()),
                "v11 alternative site tables match any one complete alternative: " + matches);
        }
    }

    private void testVersion11OptionalEvidenceDoesNotHideAConflict() throws Exception {
        byte[] callerPattern = callPattern(0x2e00, 0x2e40, (byte) 0x8d);
        byte[] helperPattern = callPattern(0x2e40, 0x2ec0, (byte) 0x8e);
        put(0x2e00, callerPattern);
        put(0x2e40, helperPattern);
        put(0x2ec0, new byte[] {(byte) 0xc3});
        Function caller = function(0x2e00, 32, null);
        Function helper = function(0x2e40, 32, null);
        function(0x2ec0, 1, "concrete_required_mismatch");
        disassemble(toAddr(0x2e00));
        disassemble(toAddr(0x2e40));
        String callerOriginal = caller.getName();
        String helperOriginal = helper.getName();
        byte[] optional = concat(exportV11(0, "optional_v11_a", 0, 0x20), new byte[] {1},
            siteV11(1, "expected_optional_v11_target", 0, new byte[0]));
        byte[] missing = "missing_grounded_reference".getBytes(StandardCharsets.US_ASCII);
        byte[] impossible = concat(exportV11(0, "impossible_v11_callee_y", 0, 4),
            new byte[] {1, 1, (byte) missing.length}, missing);
        FlirtAnalysisSession session = analyze(new String[] {"optional-a.sig", "unconditional-z.sig",
                "invalid-helper.sig"},
            v11Signature(callerPattern, callMask(), 0, 0, 32, optional, 32),
            v11Signature(callerPattern, callMask(), 0, 0, 32,
                exportV11(0, "unconditional_v11_z", 0, 0), 32),
            v11Signature(helperPattern, callMask(), 0, 0, 32, impossible, 32));
        check(helperOriginal.equals(helper.getName()), "impossible mandatory helper candidate is pruned");
        check(callerOriginal.equals(caller.getName()), "temporary optional mismatch must not select an arbitrary winner");
        check(namesAt(session, caller).equals(Set.of("optional_v11_a", "unconditional_v11_z")),
            "optional candidate remains in conflicts when contrary helper evidence disappears");
    }

    private void testVersion11InternalAndMutualSites() throws Exception {
        byte[] internalPattern = callPattern(0x2f00, 0x2f40, (byte) 0x8f);
        put(0x2f00, internalPattern);
        put(0x2f40, new byte[] {(byte) 0xc3});
        Function first = function(0x2f00, 32, null);
        Function second = function(0x2f40, 32, null);
        disassemble(toAddr(0x2f00));
        byte[] exports = concat(exportV11(0, "v11_internal_first", 0, 1),
            exportV11(64, "v11_internal_second", 0, 0x20), new byte[] {1},
            siteV11(1, "v11_internal_second", 0, new byte[0]));
        apply(v11Signature(internalPattern, callMask(), 0, 0, 96, exports, 32));
        check("v11_internal_first".equals(first.getName()) &&
            "v11_internal_second".equals(second.getName()),
            "ordinary calls to another export in the same module do not block both exports");

        byte[] firstPattern = callPattern(0x2f80, 0x2fc0, (byte) 0x93);
        byte[] secondPattern = callPattern(0x2fc0, 0x2f80, (byte) 0x94);
        put(0x2f80, firstPattern);
        put(0x2fc0, secondPattern);
        Function mutualFirst = function(0x2f80, 32, null);
        Function mutualSecond = function(0x2fc0, 32, null);
        disassemble(toAddr(0x2f80));
        disassemble(toAddr(0x2fc0));
        byte[] firstSite = concat(exportV11(0, "v11_mutual_soft_a", 0, 0x20), new byte[] {1},
            siteV11(1, "v11_mutual_soft_b", 0, new byte[0]));
        byte[] secondSite = concat(exportV11(0, "v11_mutual_soft_b", 0, 0x20), new byte[] {1},
            siteV11(1, "v11_mutual_soft_a", 0, new byte[0]));
        FlirtAnalysisSession session = analyze(new String[] {"mutual-a.sig", "mutual-b.sig"},
            v11Signature(firstPattern, callMask(), 0, 0, 32, firstSite, 32),
            v11Signature(secondPattern, callMask(), 0, 0, 32, secondSite, 32));
        check("v11_mutual_soft_a".equals(mutualFirst.getName()) &&
            "v11_mutual_soft_b".equals(mutualSecond.getName()),
            "unique compatible ordinary-site candidates can reference each other");
        check(session.getAppliedCount() == 2 && session.getConflicts().isEmpty(),
            "mutual optional references do not create a false conflict or unresolved hard cycle");
    }

    private static byte[] v11Signature(byte[] pattern, long mask, int crcLength, int crc,
            int moduleLength, byte[] exports, int patternLength) {
        byte[] header = header(11, "Independent v11 matching");
        header[41] = (byte) patternLength;
        header[42] = (byte) (patternLength >>> 8);
        return concat(header, new byte[] {1}, treeNode(pattern, mask, crcLength, crc,
            moduleLength, exports));
    }

    private static byte[] instructionBits(long mask, long value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, mask);
        number(out, value);
        return out.toByteArray();
    }

    private static byte[] siteV11(int offset, String name, int flags, byte[] metadata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, offset);
        byte[] encoded = name.getBytes(StandardCharsets.US_ASCII);
        out.write(encoded.length >>> 8);
        out.write(encoded.length);
        out.writeBytes(encoded);
        out.write(flags);
        out.writeBytes(metadata);
        return out.toByteArray();
    }

    private static byte[] exportV11(int delta, String name, int publicFlags, int parseFlags) {
        return exportV11(delta, name, publicFlags, parseFlags, new byte[0]);
    }

    private static byte[] exportV11(int delta, String name, int publicFlags, int parseFlags,
            byte[] metadata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, delta);
        byte[] encoded = name.getBytes(StandardCharsets.US_ASCII);
        out.write(encoded.length >>> 8);
        out.write(encoded.length);
        out.write(publicFlags);
        out.writeBytes(encoded);
        out.writeBytes(metadata);
        out.write(parseFlags);
        return out.toByteArray();
    }

    private static byte[] zlib(byte[] bytes) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (var compressed = new java.util.zip.DeflaterOutputStream(out)) {
            compressed.write(bytes);
        }
        return out.toByteArray();
    }

    private void testGroupedSignatureProvenance() throws Exception {
        Path root = Files.createTempDirectory("siganalyzer-group-provenance-");
        try {
            byte[] pattern = pattern((byte) 0xf0);
            put(0x2680, pattern);
            Function function = function(0x2680, 32, null);
            byte[] encoded = signature(pattern, 0, 0, 0, 32, export(0, "same_grouped_export", 0));
            Path left = Files.createDirectories(root.resolve("left"));
            Path right = Files.createDirectories(root.resolve("right"));
            Path first = Files.write(left.resolve("same.sig"), encoded);
            Path second = Files.write(right.resolve("same.sig"), encoded);
            FlirtAnalysisSession session = new FlirtAnalysisSession(currentProgram);
            check(session.run(List.of(first.toFile(), second.toFile()), root,
                monitor, new MessageLog()), "grouped signatures accepted");
            check("same_grouped_export".equals(function.getName()), "same-name grouped exports applied");
            check(function.getComment().contains("left/same.sig") &&
                function.getComment().contains("right/same.sig"),
                "relative group paths keep identical basenames distinct in provenance");
            check(session.getConflicts().isEmpty(), "same-name grouped exports do not conflict");
        }
        finally {
            removeTemporaryDirectory(root);
        }
    }

    private static void removeTemporaryDirectory(Path directory) throws Exception {
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
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
        return header(10, library);
    }

    private static byte[] header(int version, String library) {
        byte[] name = library.getBytes(StandardCharsets.US_ASCII);
        int fixedLength = version >= 11 ? 46 : 45;
        byte[] header = new byte[fixedLength + name.length];
        System.arraycopy("IDASGN".getBytes(StandardCharsets.US_ASCII), 0, header, 0, 6);
        header[6] = (byte) version;
        header[34] = (byte) name.length;
        header[37] = 1;
        header[41] = 32;
        if (version >= 11) {
            header[45] = (byte) 0xa5;
        }
        System.arraycopy(name, 0, header, fixedLength, name.length);
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
