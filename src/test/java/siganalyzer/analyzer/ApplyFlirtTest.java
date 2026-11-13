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
        for (int version = 5; version <= 10; version++) {
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
        for (int version : new int[] {5, 6, 7, 10}) {
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
        for (int version : new int[] {5, 8, 9, 10}) {
            byte[] body = oneExportTree(version);
            for (int length = 0; length < body.length; length++) {
                assertNull("version " + version + ", body length " + length,
                    parse(FlirtTestFixtures.signature(version, 32,
                        Arrays.copyOf(body, length), false)));
            }
        }
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
        set(module, "crcLength", crcLength);
        set(module, "crc16", crc);
        set(module, "length", length);
        set(module, "publicFunctions", Collections.emptyList());
        set(module, "tailBytes", Collections.emptyList());
        set(module, "referencedFunctions", Collections.emptyList());
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
