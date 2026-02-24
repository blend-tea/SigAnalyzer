package siganalyzer.analyzer;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * Parser for FLIRT signature file headers.
 * Extracts header information including library name, version, and function count.
 */
public class FlirtHeaderParser {

	/**
	 * FLIRT signature file header structure (version 5+)
	 */
	public static class IdasigV5 {
		public byte[] magic = new byte[6];
		public byte version;
		public byte arch;
		public int fileTypes;
		public short osTypes;
		public short appTypes;
		public short features;
		public short oldNFunctions;
		public short crc16;
		public byte[] ctype = new byte[12];
		public byte libraryNameLen;
		public short ctypesCrc16;
	}

	/**
	 * FLIRT signature file header structure (version 6-7)
	 */
	public static class IdasigV6V7 {
		public int nFunctions;
	}

	/**
	 * FLIRT signature file header structure (version 8-9)
	 */
	public static class IdasigV8V9 {
		public short patternSize;
	}

	/**
	 * FLIRT signature file header structure (version 10)
	 */
	public static class IdasigV10 {
		public short unknown;
	}

	/**
	 * Result of header parsing
	 */
	public static class HeaderInfo {
		private IdasigV5 v5;
		private IdasigV6V7 v6v7;
		private IdasigV8V9 v8v9;
		private IdasigV10 v10;
		private String libraryName;

		public HeaderInfo(IdasigV5 v5, IdasigV6V7 v6v7, IdasigV8V9 v8v9, IdasigV10 v10,
				String libraryName) {
			this.v5 = v5;
			this.v6v7 = v6v7;
			this.v8v9 = v8v9;
			this.v10 = v10;
			this.libraryName = libraryName;
		}

		public IdasigV5 getV5() {
			return v5;
		}

		public IdasigV6V7 getV6V7() {
			return v6v7;
		}

		public IdasigV8V9 getV8V9() {
			return v8v9;
		}

		public IdasigV10 getV10() {
			return v10;
		}

		public String getLibraryName() {
			return libraryName;
		}

		public byte getVersion() {
			return v5 != null ? v5.version : 0;
		}

		public int getFunctionCount() {
			return v6v7 != null ? v6v7.nFunctions : (v5 != null ? v5.oldNFunctions & 0xFFFF : -1);
		}
	}

	/**
	 * Reads a byte from the input stream
	 */
	private static byte readByte(DataInputStream dis) throws IOException {
		try {
			return dis.readByte();
		}
		catch (EOFException e) {
			return 0;
		}
	}

	/**
	 * Reads a short in big-endian format
	 */
	private static short readShort(DataInputStream dis) throws IOException {
		short high = (short) (readByte(dis) & 0xFF);
		short low = (short) (readByte(dis) & 0xFF);
		return (short) ((high << 8) | low);
	}

	/**
	 * Reads a short in little-endian format
	 */
	private static short readShortLE(DataInputStream dis) throws IOException {
		short low = (short) (readByte(dis) & 0xFF);
		short high = (short) (readByte(dis) & 0xFF);
		return (short) ((high << 8) | low);
	}

	/**
	 * Reads a word (4 bytes) in little-endian format
	 */
	private static int readWordLE(DataInputStream dis) throws IOException {
		int low = readShortLE(dis) & 0xFFFF;
		int high = readShortLE(dis) & 0xFFFF;
		return ((high << 16) | low);
	}

	/**
	 * Reads a word (4 bytes) in big-endian format
	 */
	private static int readWord(DataInputStream dis) throws IOException {
		int high = readShort(dis) & 0xFFFF;
		int low = readShort(dis) & 0xFFFF;
		return ((high << 16) | low);
	}

	/**
	 * Parses the V5 header structure
	 */
	private static IdasigV5 parseV5Header(DataInputStream dis) throws IOException {
		IdasigV5 header = new IdasigV5();
		dis.readFully(header.magic);
		header.version = readByte(dis);
		header.arch = readByte(dis);
		header.fileTypes = readWordLE(dis);
		header.osTypes = readShortLE(dis);
		header.appTypes = readShortLE(dis);
		header.features = readShortLE(dis);
		header.oldNFunctions = readShortLE(dis);
		header.crc16 = readShortLE(dis);
		dis.readFully(header.ctype);
		header.libraryNameLen = readByte(dis);
		header.ctypesCrc16 = readShortLE(dis);
		return header;
	}

	/**
	 * Parses the V6/V7 header structure
	 */
	private static IdasigV6V7 parseV6V7Header(DataInputStream dis) throws IOException {
		IdasigV6V7 header = new IdasigV6V7();
		header.nFunctions = readWord(dis);
		return header;
	}

	/**
	 * Parses the V8/V9 header structure
	 */
	private static IdasigV8V9 parseV8V9Header(DataInputStream dis) throws IOException {
		IdasigV8V9 header = new IdasigV8V9();
		header.patternSize = readShort(dis);
		return header;
	}

	/**
	 * Parses the V10 header structure
	 */
	private static IdasigV10 parseV10Header(DataInputStream dis) throws IOException {
		IdasigV10 header = new IdasigV10();
		header.unknown = readShort(dis);
		return header;
	}

	/**
	 * Parses the FLIRT signature file header
	 * 
	 * @param dis DataInputStream positioned at the start of the file
	 * @return HeaderInfo containing parsed header information, or null if parsing fails
	 */
	public static HeaderInfo parseHeader(DataInputStream dis) {
		try {
			// Parse V5 header
			IdasigV5 v5 = parseV5Header(dis);
			if (v5 == null) {
				return null;
			}

			// Verify magic bytes
			String magic = new String(v5.magic);
			if (!"IDASGN".equals(magic)) {
				return null;
			}

			byte version = v5.version;
			if (version < 5 || version > 10) {
				return null;
			}

			// Parse version-specific headers
			IdasigV6V7 v6v7 = null;
			IdasigV8V9 v8v9 = null;
			IdasigV10 v10 = null;

			if (version >= 6) {
				v6v7 = parseV6V7Header(dis);
				if (v6v7 == null) {
					return null;
				}

				if (version >= 8) {
					v8v9 = parseV8V9Header(dis);
					if (v8v9 == null) {
						return null;
					}

					if (version >= 10) {
						v10 = parseV10Header(dis);
						if (v10 == null) {
							return null;
						}
					}
				}
			}

			// Read library name
			String libraryName = "Unknown";
			byte libraryNameLen = v5.libraryNameLen;
			if (libraryNameLen > 0 && libraryNameLen < 256) {
				byte[] nameBytes = new byte[libraryNameLen & 0xFF];
				dis.readFully(nameBytes);
				libraryName = new String(nameBytes);
			}

			return new HeaderInfo(v5, v6v7, v8v9, v10, libraryName);
		}
		catch (IOException e) {
			return null;
		}
	}

	/**
	 * Extracts library name from a FLIRT signature file
	 * 
	 * @param dis DataInputStream positioned at the start of the file
	 * @return library name or "Unknown" if extraction fails
	 */
	public static String extractLibraryName(DataInputStream dis) {
		HeaderInfo info = parseHeader(dis);
		return info != null ? info.getLibraryName() : "Unknown";
	}
}
