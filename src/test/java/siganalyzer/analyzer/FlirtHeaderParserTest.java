package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.Arrays;

import org.junit.Test;

public class FlirtHeaderParserTest {
    private static FlirtHeaderParser.HeaderInfo parse(byte[] bytes) {
        return FlirtHeaderParser.parseHeader(new DataInputStream(new ByteArrayInputStream(bytes)));
    }

    @Test
    public void readsLittleEndianMetadataInEverySupportedVersion() {
        for (int version = 5; version <= 10; version++) {
            long count = version == 5 ? 0xf234 : 0x81234567L;
            FlirtHeaderParser.HeaderInfo info = parse(
                FlirtTestFixtures.header(version, 0x10, 0x0123, "Synthetic library", count));
            assertNotNull("version " + version, info);
            assertEquals(version, info.getVersion());
            assertEquals(count, info.getFunctionCount());
            assertEquals("Synthetic library", info.getLibraryName());
            assertEquals(0x00040000, info.getV5().fileTypes);
            assertEquals(0x0200, info.getV5().appTypes & 0xffff);
            assertEquals(0x1234, info.getV5().crc16 & 0xffff);
            if (version >= 8) {
                assertEquals(0x0123, info.getV8V9().patternSize & 0xffff);
            }
            if (version >= 10) {
                assertEquals(0x1234, info.getV10().unknown & 0xffff);
            }
        }
    }

    @Test
    public void readsTheFullUnsignedLibraryNameLengthAndLeavesBodyUnread() throws Exception {
        for (int size : new int[] {0, 127, 128, 255}) {
            String name = "a".repeat(size);
            byte[] header = FlirtTestFixtures.header(10, 0, 32, name, 1);
            byte[] file = Arrays.copyOf(header, header.length + 1);
            file[header.length] = 0x5a;
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(file));
            FlirtHeaderParser.HeaderInfo info = FlirtHeaderParser.parseHeader(input);
            assertNotNull("name length " + size, info);
            assertEquals(name, info.getLibraryName());
            assertEquals(0x5a, input.readUnsignedByte());
        }
    }

    @Test
    public void rejectsEveryTruncatedHeaderAndLibraryName() {
        for (int version = 5; version <= 10; version++) {
            byte[] full = FlirtTestFixtures.header(version, 0, 32, "Library", 1);
            for (int length = 0; length < full.length; length++) {
                assertNull("version " + version + ", length " + length,
                    parse(Arrays.copyOf(full, length)));
            }
        }
    }

    @Test
    public void rejectsInvalidMagicAndUnsupportedVersions() {
        byte[] file = FlirtTestFixtures.header(10, 0, 32, "Library", 1);
        file[0] = 'X';
        assertNull(parse(file));
        for (int version : new int[] {0, 4, 11, 255}) {
            file = FlirtTestFixtures.header(10, 0, 32, "Library", 1);
            file[6] = (byte) version;
            assertNull("version " + version, parse(file));
        }
    }
}
