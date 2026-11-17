package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.listing.Program;

public class ApplyFlirtTest {
    private final ApplyFlirt apply = new ApplyFlirt((Program) Proxy.newProxyInstance(
        Program.class.getClassLoader(), new Class<?>[] {Program.class},
        (proxy, method, args) -> null), null);

    private static Class<?> nested(String name) throws Exception {
        return Class.forName(ApplyFlirt.class.getName() + "$" + name);
    }

    private static Object create(String name) throws Exception {
        Constructor<?> constructor = nested(name).getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }

    private static Object get(Object object, String name) throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(object);
    }

    private static void set(Object object, String name, Object value) throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(object, value);
    }

    private Object call(String name, Class<?>[] parameterTypes, Object... arguments)
            throws Exception {
        Method method = ApplyFlirt.class.getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        try {
            return method.invoke(apply, arguments);
        }
        catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }

    private Object parse(byte[] bytes) throws Exception {
        Constructor<?> constructor = nested("Flirt").getDeclaredConstructor(DataInputStream.class);
        constructor.setAccessible(true);
        Object flirt = constructor.newInstance(
            new DataInputStream(new ByteArrayInputStream(bytes)));
        return call("flirtParse", new Class<?>[] {nested("Flirt")}, flirt);
    }

    private static Object first(Object object, String listField) throws Exception {
        return ((List<?>) get(object, listField)).get(0);
    }

    private static byte[] oneExportTree(int version) {
        byte[] pattern = new byte[32];
        Arrays.fill(pattern, (byte) 0x90);
        return FlirtTestFixtures.tree(version, pattern, 0, 0, 0, 32,
            FlirtTestFixtures.export(version, 0, "synthetic_function", 0));
    }

    @Test
    public void parsesCompressedAndUncompressedTreesInEverySupportedVersion() throws Exception {
        for (int version = 5; version <= 11; version++) {
            for (boolean compressed : new boolean[] {false, true}) {
                Object root = parse(FlirtTestFixtures.signature(version, 32,
                    oneExportTree(version), compressed));
                assertNotNull("version " + version + ", compressed " + compressed, root);
                Object module = first(first(root, "childList"), "moduleList");
                assertEquals("synthetic_function", get(first(module, "publicFunctions"), "name"));
            }
        }
    }

    @Test(timeout = 3000)
    public void rejectsTruncatedAndInvalidCompressedBodiesWithoutHanging() throws Exception {
        for (int version : new int[] {5, 6, 7, 10, 11}) {
            byte[] file = FlirtTestFixtures.signature(version, 32, oneExportTree(version), true);
            assertNull("version " + version + " missing compressed trailer",
                parse(Arrays.copyOf(file, file.length - 1)));
            assertNull("version " + version + " invalid compressed stream",
                parse(FlirtTestFixtures.concat(
                    FlirtTestFixtures.header(version, 0x10, 32, "synthetic", 1),
                    new byte[] {1, 2, 3})));
        }
    }

    @Test
    public void rejectsEveryTruncatedUncompressedTree() throws Exception {
        for (int version : new int[] {5, 8, 9, 10, 11}) {
            byte[] body = oneExportTree(version);
            for (int length = 0; length < body.length; length++) {
                assertNull("version " + version + ", body length " + length,
                    parse(FlirtTestFixtures.signature(version, 32,
                        Arrays.copyOf(body, length), false)));
            }
        }
    }

    @Test
    public void rejectsUnsupportedFutureVersionTwelve() throws Exception {
        byte[] file = FlirtTestFixtures.signature(11, 32, oneExportTree(11), false);
        file[6] = 12;
        assertNull(parse(file));
    }

    @Test
    public void v11LongNodesUseVar15LengthsAndLittleEndianWildcardBitmaps() throws Exception {
        byte[] pattern = new byte[130];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = (byte) (i + 1);
        }
        boolean[] wildcards = new boolean[pattern.length];
        wildcards[0] = true;
        wildcards[64] = true;
        wildcards[129] = true;
        byte[] body = FlirtTestFixtures.longNodeV11(pattern, wildcards,
            FlirtTestFixtures.export(11, 0, "long_v11_pattern", 0));
        Object root = parse(FlirtTestFixtures.signature(11, pattern.length, body, false));
        assertNotNull(root);
        Object node = first(root, "childList");
        assertEquals(130, ((Number) get(node, "length")).intValue());
        assertArrayEquals(wildcards, (boolean[]) get(node, "variantBoolArray"));
        byte[] parsed = (byte[]) get(node, "patternBytes");
        for (int i = 0; i < pattern.length; i++) {
            if (!wildcards[i]) {
                assertEquals("literal index " + i, pattern[i], parsed[i]);
            }
        }
    }

    @Test
    public void v11PublicMetadataDoesNotMisalignTheFollowingModule() throws Exception {
        ByteArrayOutputStream metadata = new ByteArrayOutputStream();
        FlirtTestFixtures.number(metadata, 0xffffffffL); // instruction mask
        FlirtTestFixtures.number(metadata, 0x12345678L); // instruction value
        FlirtTestFixtures.number(metadata, 0x87654321L); // 0x40 extension
        FlirtTestFixtures.bytes(metadata, new byte[] {(byte) 0xab, (byte) 0xcd, (byte) 0xff});
        byte[] exports = FlirtTestFixtures.concat(
            FlirtTestFixtures.exportV11(0, "metadata_public", 0xc0, 8, metadata.toByteArray()),
            new byte[] {64}, FlirtTestFixtures.export(11, 0, "following_public", 0));
        Object root = parse(FlirtTestFixtures.signature(11, 32,
            FlirtTestFixtures.tree(11, new byte[32], 0, 0, 0, 64, exports), false));
        assertNotNull(root);
        List<?> modules = (List<?>) get(first(root, "childList"), "moduleList");
        assertEquals(2, modules.size());
        assertEquals("metadata_public", get(first(modules.get(0), "publicFunctions"), "name"));
        assertEquals("following_public", get(first(modules.get(1), "publicFunctions"), "name"));
    }

    @Test
    public void v11PublicFlagCanSubtractTheNextOffsetDelta() throws Exception {
        byte[] exports = FlirtTestFixtures.concat(
            FlirtTestFixtures.exportV11(32, "later_export", 0, 1, new byte[0]),
            FlirtTestFixtures.exportV11(8, "earlier_export", 0x10, 0, new byte[0]));
        Object root = parse(FlirtTestFixtures.signature(11, 32,
            FlirtTestFixtures.tree(11, new byte[32], 0, 0, 0, 64, exports), false));
        assertNotNull(root);
        Object module = first(first(root, "childList"), "moduleList");
        List<?> publics = (List<?>) get(module, "publicFunctions");
        assertEquals(32L, ((Number) get(publics.get(0), "offset")).longValue());
        assertEquals(24L, ((Number) get(publics.get(1), "offset")).longValue());
    }

    @Test
    public void v11TailCountIsUnsignedAndLegacyReferenceHasItsOwnLengthEncoding() throws Exception {
        ByteArrayOutputStream extras = new ByteArrayOutputStream();
        FlirtTestFixtures.bytes(extras, FlirtTestFixtures.export(11, 0, "v11_constraints", 6));
        extras.write(128); // v11 stores the tail count as one unsigned byte
        for (int i = 0; i < 128; i++) {
            FlirtTestFixtures.number(extras, i);
            extras.write(i);
        }
        extras.write(127); // v11 ignores this legacy reference-count byte and reads one reference
        FlirtTestFixtures.number(extras, 3);
        extras.write(0);
        FlirtTestFixtures.offset(extras, 8, 300); // extended name length is var15
        FlirtTestFixtures.bytes(extras, "r".repeat(299).getBytes(StandardCharsets.US_ASCII));
        extras.write(0); // trailing NUL means negative reference offset
        Object root = parse(FlirtTestFixtures.signature(11, 32,
            FlirtTestFixtures.tree(11, new byte[32], 0, 0, 0, 256, extras.toByteArray()), false));
        assertNotNull(root);
        Object module = first(first(root, "childList"), "moduleList");
        assertEquals(128, ((List<?>) get(module, "tailBytes")).size());
        assertEquals(1, ((List<?>) get(module, "referencedFunctions")).size());
        Object reference = first(module, "referencedFunctions");
        assertEquals("r".repeat(299), get(reference, "name"));
        assertEquals(3L, ((Number) get(reference, "offset")).longValue());
        assertEquals(true, get(reference, "negativeOffset"));
    }

    @Test
    public void v11SiteAndAlternativeMetadataAreReadWithoutMisaligningTheTree() throws Exception {
        ByteArrayOutputStream extras = new ByteArrayOutputStream();
        FlirtTestFixtures.bytes(extras, FlirtTestFixtures.export(11, 0, "v11_sites", 0x60));
        FlirtTestFixtures.number(extras, 1);
        v11Site(extras, 4, "synthetic_site", 0x88);
        FlirtTestFixtures.number(extras, 0x00ff00ff);
        FlirtTestFixtures.number(extras, 0x00110022);
        FlirtTestFixtures.number(extras, 33);
        FlirtTestFixtures.number(extras, 1); // alternative list count
        FlirtTestFixtures.number(extras, 1); // one site in that alternative
        v11Site(extras, 8, "alternative_site", 0x40);
        FlirtTestFixtures.number(extras, 9);
        FlirtTestFixtures.bytes(extras, new byte[] {(byte) 0xab, (byte) 0xcd, 0x12});
        Object root = parse(FlirtTestFixtures.signature(11, 32,
            FlirtTestFixtures.tree(11, new byte[32], 0, 0, 0, 32, extras.toByteArray()), false));
        assertNotNull(root);
        Object module = first(first(root, "childList"), "moduleList");
        assertEquals(1, ((List<?>) get(module, "sites")).size());
        Object site = first(module, "sites");
        assertEquals("synthetic_site", get(site, "name"));
        assertEquals(4L, ((Number) get(site, "offset")).longValue());
        assertEquals(33L, ((Number) get(site, "extra08")).longValue());
        Object bits = get(site, "instructionBits");
        assertEquals(0x00ff00ffL, ((Number) get(bits, "mask")).longValue());
        assertEquals(0x00110022L, ((Number) get(bits, "value")).longValue());
        List<?> alternatives = (List<?>) get(module, "alternativeSites");
        assertEquals(1, alternatives.size());
        Object alternative = ((List<?>) alternatives.get(0)).get(0);
        assertEquals("alternative_site", get(alternative, "name"));
        Object extension = get(alternative, "extra40");
        assertEquals(9L, ((Number) get(extension, "a")).longValue());
        assertEquals(0xabcd, ((Number) get(extension, "b")).intValue());
        assertEquals(0x12, ((Number) get(extension, "c")).intValue());
    }

    private static void v11Site(ByteArrayOutputStream output, int offset, String name, int flags) {
        FlirtTestFixtures.number(output, offset);
        byte[] bytes = name.getBytes(StandardCharsets.US_ASCII);
        output.write(bytes.length >>> 8);
        output.write(bytes.length);
        FlirtTestFixtures.bytes(output, bytes);
        output.write(flags);
    }

    @Test
    public void preservesUnsigned64BitVariantMaskLowWord() throws Exception {
        byte[] pattern = new byte[64];
        Arrays.fill(pattern, (byte) 0x5a);
        Object root = parse(FlirtTestFixtures.signature(10, 64,
            FlirtTestFixtures.tree(10, pattern, 0x80000000L, 0, 0, 64,
                FlirtTestFixtures.export(10, 0, "wide_pattern", 0)), false));
        assertNotNull(root);
        boolean[] variants = (boolean[]) get(first(root, "childList"), "variantBoolArray");
        for (int i = 0; i < variants.length; i++) {
            assertEquals("variant index " + i, i == 32, variants[i]);
        }
    }

    @Test
    public void retainsUnsignedLengthsOffsetsAndCrcLength() throws Exception {
        byte[] exports = FlirtTestFixtures.concat(
            FlirtTestFixtures.export(10, 0, "first", 1),
            FlirtTestFixtures.export(10, 0x10001, "second", 0));
        Object root = parse(FlirtTestFixtures.signature(10, 32,
            FlirtTestFixtures.tree(10, new byte[32], 0, 0x80, 0xabcd, 0x12345678,
                exports), false));
        assertNotNull(root);
        Object module = first(first(root, "childList"), "moduleList");
        assertEquals(128, ((Number) get(module, "crcLength")).intValue());
        assertEquals(0x12345678L, ((Number) get(module, "length")).longValue());
        Object second = ((List<?>) get(module, "publicFunctions")).get(1);
        assertEquals(0x10001L, ((Number) get(second, "offset")).longValue());
    }

    @Test
    public void readsUnsignedTailAndReferenceCounts() throws Exception {
        for (int version : new int[] {8, 9, 10}) {
        for (boolean tails : new boolean[] {false, true}) {
            ByteArrayOutputStream extras = new ByteArrayOutputStream();
            FlirtTestFixtures.bytes(extras,
                FlirtTestFixtures.export(version, 0, "many_entries", tails ? 2 : 4));
            FlirtTestFixtures.offset(extras, version >= 10 ? 10 : 8, 128);
            for (int i = 0; i < 128; i++) {
                FlirtTestFixtures.offset(extras, version, i);
                if (tails) {
                    extras.write(i);
                }
                else {
                    extras.write(3);
                    FlirtTestFixtures.bytes(extras, "ref".getBytes(StandardCharsets.US_ASCII));
                }
            }
            Object root = parse(FlirtTestFixtures.signature(version, 32,
                FlirtTestFixtures.tree(version, new byte[32], 0, 0, 0, 256,
                    extras.toByteArray()), false));
            assertNotNull(root);
            Object module = first(first(root, "childList"), "moduleList");
            assertEquals(128, ((List<?>) get(module,
                tails ? "tailBytes" : "referencedFunctions")).size());
        }
        }
    }

    @Test
    public void computesFlirtCrcKnownVectorAndSlice() throws Exception {
        byte[] vector = "123456789".getBytes(StandardCharsets.US_ASCII);
        assertEquals(0x6e90, call("crc16", new Class<?>[] {byte[].class, int.class, int.class},
            vector, 0, vector.length));
        byte[] padded = "xx123456789yy".getBytes(StandardCharsets.US_ASCII);
        assertEquals(0x6e90, call("crc16", new Class<?>[] {byte[].class, int.class, int.class},
            padded, 2, 9));
        assertEquals(0, call("crc16", new Class<?>[] {byte[].class, int.class, int.class},
            vector, 0, 0));
    }

    @Test
    public void rejectsPatternThatRunsPastAvailableBytesAtDeeperNode() throws Exception {
        Object node = create("FlirtNode");
        set(node, "length", 3);
        set(node, "patternBytes", new byte[] {1, 2, 3});
        set(node, "variantBoolArray", new boolean[3]);
        assertEquals(false, call("nodePatternMatch",
            new Class<?>[] {nested("FlirtNode"), byte[].class, int.class, int.class},
            node, new byte[] {0, 0, 1, 2}, 2, 4));
    }

    private Object module(int crcLength, int crc, long length) throws Exception {
        Object module = create("FlirtModule");
        set(module, "version", 10);
        set(module, "patternSize", 32);
        set(module, "crcLength", crcLength);
        set(module, "crc16", crc);
        set(module, "length", length);
        set(module, "publicFunctions", Collections.emptyList());
        set(module, "tailBytes", Collections.emptyList());
        set(module, "referencedFunctions", Collections.emptyList());
        set(module, "sites", Collections.emptyList());
        set(module, "alternativeSites", Collections.emptyList());
        return module;
    }

    private boolean match(Object module, byte[] bytes, int patternLength) throws Exception {
        return (boolean) call("moduleMatchBuffer", new Class<?>[] {
            nested("FlirtModule"), byte[].class, long.class, int.class, int.class},
            module, bytes, 0L, bytes.length, patternLength);
    }

    @Test
    public void checksCrcWhenTheCrcEndsExactlyAtTheBufferEnd() throws Exception {
        byte[] buffer = new byte[41];
        System.arraycopy("123456789".getBytes(StandardCharsets.US_ASCII), 0, buffer, 32, 9);
        assertTrue(match(module(9, 0x6e90, 41), buffer, 32));
        assertFalse(match(module(9, 0x6e91, 41), buffer, 32));
        assertFalse(match(module(9, 0x6e90, 41), Arrays.copyOf(buffer, 40), 32));
    }

    @Test
    public void usesTheFullTreePatternLengthAsCrcBase() throws Exception {
        byte[] buffer = new byte[49];
        System.arraycopy("123456789".getBytes(StandardCharsets.US_ASCII), 0, buffer, 40, 9);
        assertTrue(match(module(9, 0x6e90, 49), buffer, 40));
        buffer[40] ^= 1;
        assertFalse(match(module(9, 0x6e90, 49), buffer, 40));
    }

    @Test
    public void requiresEveryTailByteToBePresentAndEqual() throws Exception {
        Object module = module(0, 0, 34);
        Object tail = create("FlirtTailByte");
        set(tail, "offset", 1L);
        set(tail, "value", (byte) 0x7a);
        set(module, "tailBytes", Collections.singletonList(tail));
        byte[] buffer = new byte[34];
        buffer[33] = 0x7a;
        assertTrue(match(module, buffer, 32));
        buffer[33] = 0x7b;
        assertFalse(match(module, buffer, 32));
        assertFalse(match(module, Arrays.copyOf(buffer, 33), 32));
    }

    @Test
    public void rejectsExtremeSparseTailExtentBeforeAllocatingMatchBuffer() throws Exception {
        Object module = module(0, 0, 32);
        Object tail = create("FlirtTailByte");
        set(tail, "offset", 0xffffffffL);
        set(tail, "value", (byte) 0);
        set(module, "tailBytes", Collections.singletonList(tail));
        Object root = create("FlirtNode");
        set(root, "length", 32);
        set(root, "moduleList", Collections.singletonList(module));
        try {
            call("nodeMatchFunctions", new Class<?>[] {nested("FlirtNode")}, root);
            fail("an extreme sparse tail must not allocate a multi-gigabyte byte array");
        }
        catch (IOException expected) {
            assertTrue(expected.getMessage().contains("buffer size"));
        }
    }

}
