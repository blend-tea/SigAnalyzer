// Synthetic end-to-end FLIRT checks in a real Ghidra Program.
// Run with analyzeHeadless, -noanalysis and -postScript SigAnalyzerSmokeTest.java.
// @category SigAnalyzer.Tests

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import siganalyzer.analyzer.ApplyFlirt;

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
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] header = new byte[45]; // v10 header, empty library name
        System.arraycopy("IDASGN".getBytes(StandardCharsets.US_ASCII), 0, header, 0, 6);
        header[6] = 10;
        header[37] = 1; // little-endian function count
        header[41] = 32; // little-endian pattern size
        out.writeBytes(header);
        out.write(1); // one root child
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
