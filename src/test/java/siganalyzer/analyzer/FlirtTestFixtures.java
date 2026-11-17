package siganalyzer.analyzer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;

/** Small, independently authored FLIRT files; no vendor signature data is used. */
final class FlirtTestFixtures {
    private FlirtTestFixtures() {}

    static byte[] header(int version, int features, int patternSize, String libraryName,
            long functionCount) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bytes(out, "IDASGN".getBytes(StandardCharsets.US_ASCII));
        out.write(version);
        out.write(0); // x86
        littleEndian(out, 0x00040000, 4); // ELF
        littleEndian(out, 0x0010, 2); // Unix
        littleEndian(out, 0x0200, 2); // 64-bit application
        littleEndian(out, features, 2);
        littleEndian(out, functionCount, 2);
        littleEndian(out, 0x1234, 2);
        bytes(out, new byte[12]);
        byte[] name = libraryName.getBytes(StandardCharsets.UTF_8);
        if (name.length > 255) {
            throw new IllegalArgumentException("library name exceeds unsigned byte length");
        }
        out.write(name.length);
        littleEndian(out, 0x5678, 2);
        if (version >= 6) {
            littleEndian(out, functionCount, 4);
        }
        if (version >= 8) {
            littleEndian(out, patternSize, 2);
        }
        if (version >= 10) {
            littleEndian(out, 0x1234, 2);
        }
        if (version >= 11) {
            out.write(0xa5); // independent, nonzero toolchain metadata
        }
        bytes(out, name);
        return out.toByteArray();
    }

    static byte[] signature(int version, int patternSize, byte[] body, boolean compressed) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bytes(out, header(version, compressed ? 0x10 : 0, patternSize, "synthetic", 1));
        bytes(out, compressed ? compress(body, version <= 6) : body);
        return out.toByteArray();
    }

    static byte[] tree(int version, byte[] pattern, long mask, int crcLength, int crc,
            long moduleLength, byte[] exportsAndExtras) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, 1); // root has one child
        if (version >= 10) {
            offset(out, 8, pattern.length); // node lengths use var15, not var32
        }
        else {
            out.write(pattern.length);
        }
        if (pattern.length < 16) {
            offset(out, 8, mask);
        }
        else if (pattern.length <= 32) {
            number(out, mask & 0xffffffffL);
        }
        else {
            number(out, mask >>> 32);
            number(out, mask & 0xffffffffL);
        }
        for (int i = 0; i < pattern.length; i++) {
            if ((mask & (1L << (pattern.length - i - 1))) == 0) {
                out.write(pattern[i]);
            }
        }
        number(out, 0); // child is a leaf
        out.write(crcLength);
        out.write(crc >>> 8);
        out.write(crc);
        offset(out, version, moduleLength);
        bytes(out, exportsAndExtras);
        return out.toByteArray();
    }

    static byte[] export(int version, long delta, String name, int flags) {
        if (version >= 11) {
            return exportV11(delta, name, 0, flags, new byte[0]);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        offset(out, version, delta);
        bytes(out, name.getBytes(StandardCharsets.UTF_8));
        out.write(flags);
        return out.toByteArray();
    }

    static byte[] exportV11(long delta, String name, int publicFlags, int parseFlags,
            byte[] metadata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, delta);
        byte[] encoded = name.getBytes(StandardCharsets.UTF_8);
        out.write(encoded.length >>> 8);
        out.write(encoded.length);
        out.write(publicFlags);
        bytes(out, encoded);
        bytes(out, metadata);
        out.write(parseFlags);
        return out.toByteArray();
    }

    static byte[] longNodeV11(byte[] pattern, boolean[] wildcards, byte[] exports) {
        if (pattern.length <= 64 || wildcards.length != pattern.length) {
            throw new IllegalArgumentException("requires a long v11 node and one wildcard per byte");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        number(out, 1);
        offset(out, 8, pattern.length);
        for (int firstBit = 0; firstBit < pattern.length; firstBit += 8) {
            int bitmap = 0;
            for (int bit = 0; bit < 8 && firstBit + bit < pattern.length; bit++) {
                if (wildcards[pattern.length - firstBit - bit - 1]) {
                    bitmap |= 1 << bit;
                }
            }
            out.write(bitmap);
        }
        for (int i = 0; i < pattern.length; i++) {
            if (!wildcards[i]) {
                out.write(pattern[i]);
            }
        }
        number(out, 0);
        bytes(out, new byte[] {0, 0, 0}); // no CRC bytes, zero CRC
        number(out, pattern.length);
        bytes(out, exports);
        return out.toByteArray();
    }

    static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            bytes(out, array);
        }
        return out.toByteArray();
    }

    static byte[] compress(byte[] input, boolean raw) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, raw);
        try {
            deflater.setInput(input);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[256];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        }
        finally {
            deflater.end();
        }
    }

    static void number(ByteArrayOutputStream out, long value) {
        if (value < 0 || value > 0xffffffffL) {
            throw new IllegalArgumentException("not an unsigned 32-bit number");
        }
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

    static void offset(ByteArrayOutputStream out, int version, long value) {
        if (version >= 9) {
            number(out, value);
        }
        else if (value < 0x80) {
            out.write((int) value);
        }
        else if (value <= 0x7fff) {
            out.write(0x80 | (int) (value >>> 8));
            out.write((int) value);
        }
        else {
            throw new IllegalArgumentException("v5-v8 offset exceeds 15 bits");
        }
    }

    static void littleEndian(ByteArrayOutputStream out, long value, int width) {
        for (int i = 0; i < width; i++) {
            out.write((int) (value >>> (i * 8)));
        }
    }

    static void bytes(ByteArrayOutputStream out, byte[] bytes) {
        out.write(bytes, 0, bytes.length);
    }
}
