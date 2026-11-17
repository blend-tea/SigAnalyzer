package siganalyzer.analyzer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ApplyFlirt {
    private static final int MAX_BUFFER_SIZE = 64 * 1024 * 1024;
    // Ghidra
    FunctionManager functionManager;
    Memory memory;
    Program program;
    File sigFile;
    private final String signatureName;
    /** Set of entry point addresses excluded from rename targets */
    private Set<Address> entryPointAddresses;
    private TaskMonitor monitor = TaskMonitor.DUMMY;
    private String errorMessage;
    private int appliedCount;
    private final List<FlirtAnalysisSession.ModuleMatch> collectedMatches = new ArrayList<>();
    private String libraryName = "";
    private AddressSpace matchingAddressSpace;

    public ApplyFlirt(Program program, File sigFile) {
        this(program, sigFile, sigFile == null ? "" : sigFile.getName());
    }

    ApplyFlirt(Program program, File sigFile, String signatureName) {
        this.program = program;
        this.sigFile = sigFile;
        this.signatureName = signatureName;
        this.functionManager = program.getFunctionManager();
        this.memory = program.getMemory();
    }

    /** Get program's entry point addresses (for rename exclusion) */
    private Set<Address> getEntryPointAddresses() {
        Set<Address> set = new HashSet<>();
        SymbolTable symbolTable = program.getSymbolTable();
        AddressIterator it = symbolTable.getExternalEntryPointIterator();
        while (it.hasNext()) {
            Address addr = it.next();
            if (addr != null) {
                set.add(addr);
            }
        }
        return set;
    }

    public boolean run() {
        try {
            return run(TaskMonitor.DUMMY);
        }
        catch (CancelledException e) {
            return false;
        }
    }

    public boolean run(TaskMonitor taskMonitor) throws CancelledException {
        FlirtAnalysisSession session = new FlirtAnalysisSession(program);
        boolean success = session.run(List.of(sigFile), taskMonitor, new MessageLog());
        appliedCount = session.getAppliedCount();
        errorMessage = session.getErrorMessage();
        taskMonitor.checkCancelled();
        FlirtAnalysisResults.publish(program, session.getConflicts());
        return success;
    }

    /** Collect every byte-matching module without changing program names or comments. */
    List<FlirtAnalysisSession.ModuleMatch> collectMatches(TaskMonitor taskMonitor)
            throws CancelledException, IOException {
        monitor = taskMonitor;
        collectedMatches.clear();
        errorMessage = null;
        monitor.checkCancelled();
        try (DataInputStream input = new DataInputStream(new FileInputStream(sigFile))) {
            FlirtNode node = flirtParse(new Flirt(input));
            monitor.checkCancelled();
            if (node == null) {
                throw new IOException(errorMessage != null ? errorMessage : "Invalid or unsupported FLIRT signature");
            }
            entryPointAddresses = getEntryPointAddresses();
            nodeMatchFunctions(node);
            return List.copyOf(collectedMatches);
        }
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public int getAppliedCount() {
        return appliedCount;
    }

    // Architecture flags
    private static final int IDASIG_ARCH_386 = 0;
    private static final int IDASIG_ARCH_Z80 = 1;
    private static final int IDASIG_ARCH_I860 = 2;
    private static final int IDASIG_ARCH_8051 = 3;
    private static final int IDASIG_ARCH_TMS = 4;
    private static final int IDASIG_ARCH_6502 = 5;
    private static final int IDASIG_ARCH_PDP = 6;
    private static final int IDASIG_ARCH_68K = 7;
    private static final int IDASIG_ARCH_JAVA = 8;
    private static final int IDASIG_ARCH_6800 = 9;
    private static final int IDASIG_ARCH_ST7 = 10;
    private static final int IDASIG_ARCH_MC6812 = 11;
    private static final int IDASIG_ARCH_MIPS = 12;
    private static final int IDASIG_ARCH_ARM = 13;
    private static final int IDASIG_ARCH_TMSC6 = 14;
    private static final int IDASIG_ARCH_PPC = 15;
    private static final int IDASIG_ARCH_80196 = 16;
    private static final int IDASIG_ARCH_Z8 = 17;
    private static final int IDASIG_ARCH_SH = 18;
    private static final int IDASIG_ARCH_NET = 19;
    private static final int IDASIG_ARCH_AVR = 20;
    private static final int IDASIG_ARCH_H8 = 21;
    private static final int IDASIG_ARCH_PIC = 22;
    private static final int IDASIG_ARCH_SPARC = 23;
    private static final int IDASIG_ARCH_ALPHA = 24;
    private static final int IDASIG_ARCH_HPPA = 25;
    private static final int IDASIG_ARCH_H8500 = 26;
    private static final int IDASIG_ARCH_TRICORE = 27;
    private static final int IDASIG_ARCH_DSP56K = 28;
    private static final int IDASIG_ARCH_C166 = 29;
    private static final int IDASIG_ARCH_ST20 = 30;
    private static final int IDASIG_ARCH_IA64 = 31;
    private static final int IDASIG_ARCH_I960 = 32;
    private static final int IDASIG_ARCH_F2MC = 33;
    private static final int IDASIG_ARCH_TMS320C54 = 34;
    private static final int IDASIG_ARCH_TMS320C55 = 35;
    private static final int IDASIG_ARCH_TRIMEDIA = 36;
    private static final int IDASIG_ARCH_M32R = 37;
    private static final int IDASIG_ARCH_NEC_78K0 = 38;
    private static final int IDASIG_ARCH_NEC_78K0S = 39;
    private static final int IDASIG_ARCH_M740 = 40;
    private static final int IDASIG_ARCH_M7700 = 41;
    private static final int IDASIG_ARCH_ST9 = 42;
    private static final int IDASIG_ARCH_FR = 43;
    private static final int IDASIG_ARCH_MC6816 = 44;
    private static final int IDASIG_ARCH_M7900 = 45;
    private static final int IDASIG_ARCH_TMS320C3 = 46;
    private static final int IDASIG_ARCH_KR1878 = 47;
    private static final int IDASIG_ARCH_AD218X = 48;
    private static final int IDASIG_ARCH_OAKDSP = 49;
    private static final int IDASIG_ARCH_TLCS900 = 50;
    private static final int IDASIG_ARCH_C39 = 51;
    private static final int IDASIG_ARCH_CR16 = 52;
    private static final int IDASIG_ARCH_MN102L00 = 53;
    private static final int IDASIG_ARCH_TMS320C1X = 54;
    private static final int IDASIG_ARCH_NEC_V850X = 55;
    private static final int IDASIG_ARCH_SCR_ADPT = 56;
    private static final int IDASIG_ARCH_EBC = 57;
    private static final int IDASIG_ARCH_MSP430 = 58;
    private static final int IDASIG_ARCH_SPU = 59;
    private static final int IDASIG_ARCH_DALVIK = 60;

    // File type flags
    private static final int IDASIG_FILE_DOS_EXE_OLD = 0x00000001;
    private static final int IDASIG_FILE_DOS_COM_OLD = 0x00000002;
    private static final int IDASIG_FILE_BIN = 0x00000004;
    private static final int IDASIG_FILE_DOSDRV = 0x00000008;
    private static final int IDASIG_FILE_NE = 0x00000010;
    private static final int IDASIG_FILE_INTELHEX = 0x00000020;
    private static final int IDASIG_FILE_MOSHEX = 0x00000040;
    private static final int IDASIG_FILE_LX = 0x00000080;
    private static final int IDASIG_FILE_LE = 0x00000100;
    private static final int IDASIG_FILE_NLM = 0x00000200;
    private static final int IDASIG_FILE_COFF = 0x00000400;
    private static final int IDASIG_FILE_PE = 0x00000800;
    private static final int IDASIG_FILE_OMF = 0x00001000;
    private static final int IDASIG_FILE_SREC = 0x00002000;
    private static final int IDASIG_FILE_ZIP = 0x00004000;
    private static final int IDASIG_FILE_OMFLIB = 0x00008000;
    private static final int IDASIG_FILE_AR = 0x00010000;
    private static final int IDASIG_FILE_LOADER = 0x00020000;
    private static final int IDASIG_FILE_ELF = 0x00040000;
    private static final int IDASIG_FILE_W32RUN = 0x00080000;
    private static final int IDASIG_FILE_AOUT = 0x00100000;
    private static final int IDASIG_FILE_PILOT = 0x00200000;
    private static final int IDASIG_FILE_DOS_EXE = 0x00400000;
    private static final int IDASIG_FILE_DOS_COM = 0x00800000;
    private static final int IDASIG_FILE_AIXAR = 0x01000000;

    // OS type flags
    private static final int IDASIG_OS_MSDOS = 0x01;
    private static final int IDASIG_OS_WIN = 0x02;
    private static final int IDASIG_OS_OS2 = 0x04;
    private static final int IDASIG_OS_NETWARE = 0x08;
    private static final int IDASIG_OS_UNIX = 0x10;
    private static final int IDASIG_OS_OTHER = 0x20;

    // Application type flags
    private static final int IDASIG_APP_CONSOLE = 0x0001;
    private static final int IDASIG_APP_GRAPHICS = 0x0002;
    private static final int IDASIG_APP_EXE = 0x0004;
    private static final int IDASIG_APP_DLL = 0x0008;
    private static final int IDASIG_APP_DRV = 0x0010;
    private static final int IDASIG_APP_SINGLE_THREADED = 0x0020;
    private static final int IDASIG_APP_MULTI_THREADED = 0x0040;
    private static final int IDASIG_APP_16_BIT = 0x0080;
    private static final int IDASIG_APP_32_BIT = 0x0100;
    private static final int IDASIG_APP_64_BIT = 0x0200;

    // Feature flags
    private static final int IDASIG_FEATURE_STARTUP = 0x01;
    private static final int IDASIG_FEATURE_CTYPE_CRC = 0x02;
    private static final int IDASIG_FEATURE_2BYTE_CTYPE = 0x04;
    private static final int IDASIG_FEATURE_ALT_CTYPE_CRC = 0x08;
    private static final int IDASIG_FEATURE_COMPRESSED = 0x10;
    private static final int IDASIG_FEATURE_ZSTD = 0x40;

    // Parsing flags
    private static final int IDASIG_PARSE_MORE_PUBLIC_NAMES = 0x01;
    private static final int IDASIG_PARSE_READ_TAIL_BYTES = 0x02;
    private static final int IDASIG_PARSE_READ_REFERENCED_FUNCTIONS = 0x04;
    private static final int IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC = 0x08;
    private static final int IDASIG_PARSE_MORE_MODULES = 0x10;

    // Function flags
    private static final int IDASIG_FUNCTION_LOCAL = 0x02;
    private static final int IDASIG_FUNCTION_UNRESOLVED_COLLISION = 0x08;

    // Structures
    private static class IdasigV5 {
        byte[] magic = new byte[6];
        byte version;
        byte arch;
        int fileTypes;
        short osTypes;
        short appTypes;
        short features;
        short oldNFunctions;
        short crc16;
        byte[] ctype = new byte[12];
        byte libraryNameLen;
        short ctypesCrc16;
    }

    private static class IdasigV6V7 {
        int nFunctions;
    }

    private static class IdasigV8V9 {
        short patternSize;
    }

    private static class IdasigV10 {
        short unknown;
    }
    /*
    arch             : target architecture
    file_types       : files where we expect to find the functions (exe, coff, ...)
    os_types         : os where we expect to find the functions
    app_types        : applications in which we expect to find the functions
    features         : signature file features
    old_n_functions  : number of functions
    crc16            : certainly crc16 of the tree
    ctype[12]        : unknown field
    library_name_len : length of the library name, which is right after the header
    ctypes_crc16     : unknown field
    n_functions      : number of functions
    pattern_size     : number of the leading pattern bytes
     */

    private static final int R_FLIRT_NAME_MAX = 4096;

    private static class FlirtTailByte {
        long offset;
        byte value;
    }

    private static class FlirtFunction {
        String name;
        long offset;
        int flags;
        FlirtInstructionBits instructionBits;
        FlirtExtra40 extra40;
        boolean negativeOffset;
        boolean isLocal;
        boolean isCollision;
    }

    private static class FlirtInstructionBits {
        long mask;
        long value;
    }

    private static class FlirtExtra40 {
        long a;
        int b;
        int c;
    }

    private static class FlirtSite {
        long offset;
        String name;
        int flags;
        FlirtInstructionBits instructionBits;
        FlirtExtra40 extra40;
        Long extra08;
    }

    private static class FlirtModule {
        int version;
        int patternSize;
        int parseFlags;
        int crcLength;
        int crc16;
        long length;
        List<FlirtFunction> publicFunctions;
        List<FlirtTailByte> tailBytes;
        List<FlirtFunction> referencedFunctions;
        List<FlirtSite> sites;
        List<List<FlirtSite>> alternativeSites;
    }

    // RFlirt 
    private static class Flirt {
        private byte version;
        private int patternSize = 32;
        private int headerSize;
        private DataInputStream b;
        private boolean bufEof;
        private boolean bufErr;

        Flirt(DataInputStream dis) {
            this.b = dis;
        }
    }

    private static class FlirtNode {
        List<FlirtNode> childList;
        List<FlirtModule> moduleList;
        int length;
        long variantMask;
        byte[] variantBitmap;
        byte[] patternBytes;
        boolean[] variantBoolArray;
    }

    // Port of Python crc16 (CRC16-X.25)
    private static final int POLY = 0x1021;
    private static int[] _crcTable = new int[256];
    private static boolean _tableInitialized = false;
    private static int _polyRev;

    // Reverse 8-bit value (avoid sign extension)
    private static int _rev8(int n) {
        n = n & 0xFF;
        int result = 0;
        for (int i = 0; i < 8; i++) {
            result = (result << 1) | (n & 1);
            n >>>= 1;
        }
        return result & 0xFF;
    }

    // Reverse 16-bit value (avoid sign extension)
    private static int _rev16(int n) {
        n = n & 0xFFFF;
        int result = 0;
        for (int i = 0; i < 16; i++) {
            result = (result << 1) | (n & 1);
            n >>>= 1;
        }
        return result & 0xFFFF;
    }

    // Initialize CRC table
    private static void _initTable() {
        if (_tableInitialized)
            return;

        _polyRev = _rev16(POLY);

        for (int i = 0; i < 256; i++) {
            int reversedI = _rev8(i);
            int crc = 0;
            int c = (reversedI << 8) & 0xFFFF;

            for (int j = 0; j < 8; j++) {
                if (((crc ^ c) & 0x8000) != 0) {
                    crc = ((crc << 1) ^ POLY) & 0xFFFF;
                }
                else {
                    crc = (crc << 1) & 0xFFFF;
                }
                c = (c << 1) & 0xFFFF;
            }

            crc = _rev16(crc);
            _crcTable[i] = crc;
        }
        _tableInitialized = true;
    }

    // CRC16-X.25 calculation (compatible with Python version)
    private int crc16(byte[] data, int offset, int length) {
        return crc16(data, offset, length, 0xFFFF);
    }

    private int crc16(byte[] data, int offset, int length, int startValue) {
        _initTable();

        if (length == 0) {
            return 0;
        }

        int out = startValue & 0xFFFF;

        for (int i = 0; i < length; i++) {
            int b = data[offset + i] & 0xFF;
            int tmp = (out ^ b) & 0xFF;
            out = ((out >>> 8) ^ _crcTable[tmp]) & 0xFFFF;
        }

        out = (out ^ 0xFFFF) & 0xFFFF;
        out = (((out & 0xFF) << 8) | ((out >>> 8) & 0xFF)) & 0xFFFF;
        return out & 0xFFFF;
    }

    // Slow CRC16 calculation (compatible with Python crc16slow)
    private int crc16slow(byte[] data, int offset, int length) {
        return crc16slow(data, offset, length, 0xFFFF);
    }

    private int crc16slow(byte[] data, int offset, int length, int startValue) {
        _initTable();

        int out = startValue & 0xFFFF;

        for (int i = 0; i < length; i++) {
            int b = data[offset + i] & 0xFF;
            for (int j = 0; j < 8; j++) {
                if (((out ^ b) & 1) == 1) {
                    out = ((out >>> 1) ^ _polyRev) & 0xFFFF;
                }
                else {
                    out = (out >>> 1) & 0xFFFF;
                }
                b >>>= 1;
            }
        }

        out = ((~out) & 0xFFFF);
        out = (((out & 0xFF) << 8) | ((out >>> 8) & 0xFF)) & 0xFFFF;
        return out & 0xFFFF;
    }

    private byte readByte(Flirt f) throws IOException {
        if (monitor.isCancelled()) {
            throw new IOException("Cancelled");
        }
        // EOF must reject the tree; treating missing bytes as zero can manufacture matches.
        return f.b.readByte();
    }

    private short readShort(Flirt flirt) throws IOException {
        // Same big-endian as C: high byte first
        short high = (short) (readByte(flirt) & 0xFF);
        short low = (short) (readByte(flirt) & 0xFF);
        return (short) ((high << 8) | low);
    }

    private short readShortLE(Flirt flirt) throws IOException {
        short low = (short) (readByte(flirt) & 0xFF);
        short high = (short) (readByte(flirt) & 0xFF);
        return (short) ((high << 8) | low);
    }

    private int readWordLE(Flirt flirt) throws IOException {
        int low = readShortLE(flirt) & 0xFFFF;
        int high = readShortLE(flirt) & 0xFFFF;
        return ((high << 16) | low);
    }

    private int readWord(Flirt flirt) throws IOException {
        int high = readShort(flirt) & 0xFFFF;
        int low = readShort(flirt) & 0xFFFF;
        return (high << 16) | low;
    }

    private short readMax2Bytes(Flirt flirt) throws IOException {
        short r = (short) (readByte(flirt) & 0xFF);
        return (r & 0x80) != 0 ? (short) (((r & 0x7F) << 8) | (readByte(flirt) & 0xFF)) : r;
    }

    private int readMultipleBytes(Flirt flirt) throws IOException {
        int r = readByte(flirt) & 0xFF;
        if ((r & 0x80) != 0x80) {
            return r;
        }
        if ((r & 0xC0) != 0xC0) {
            int result = ((r & 0x7F) << 8) | (readByte(flirt) & 0xFF);
            return result;
        }
        if ((r & 0xE0) != 0xE0) {
            r = ((r & 0x3F) << 24) | ((readByte(flirt) & 0xFF) << 16);
            r += (readShort(flirt) & 0xFFFF);
            return r;
        }
        return readWord(flirt);
    }

    private static void moduleFree(FlirtModule module) {
        if (module == null) {
            return;
        }
        if (module.publicFunctions != null) {
            module.publicFunctions.clear();
        }
        if (module.tailBytes != null) {
            module.tailBytes.clear();
        }
        if (module.referencedFunctions != null) {
            module.referencedFunctions.clear();
        }
    }

    private static void nodeFree(FlirtNode node) {
        if (node == null) {
            return;
        }
        if (node.variantBoolArray != null) {
            node.variantBoolArray = null;
        }
        if (node.patternBytes != null) {
            node.patternBytes = null;
        }
        if (node.moduleList != null) {
            node.moduleList.clear();
        }
        if (node.childList != null) {
            node.childList.clear();
        }
    }


    private boolean moduleMatchBuffer(FlirtModule module, byte[] b, long address,
            int bufSize, int patternLength) {
        int crcOffset = crcOffset(module, patternLength);
        if (module.version >= 11 && module.length > bufSize) {
            return false;
        }
        if (module.crcLength > 0 && (crcOffset > bufSize ||
            module.crcLength > bufSize - crcOffset)) {
            return false;
        }
        if ((module.crc16 & 0xffff) != crc16(b, crcOffset, module.crcLength)) {
            return false;
        }
        if (module.tailBytes != null) {
            for (FlirtTailByte tailByte : module.tailBytes) {
                long offset = (long) crcOffset + module.crcLength + tailByte.offset;
                if (offset < 0 || offset >= bufSize || b[(int) offset] != tailByte.value) {
                    return false;
                }
            }
        }
        // v11 encodes instruction constraints separately from wildcarded bytes.
        for (FlirtFunction function : module.publicFunctions) {
            if (!instructionMatches(function.instructionBits, function.offset, b, bufSize, address)) {
                return false;
            }
        }
        if (!siteInstructionsMatch(module.sites, b, bufSize, address)) {
            return false;
        }
        // Capture reference constraints now; resolve them after every signature was scanned.
        List<FlirtAnalysisSession.ReferenceConstraint> constraints = new ArrayList<>();
        if (module.referencedFunctions != null) {
            for (FlirtFunction reference : module.referencedFunctions) {
                var constraint = referenceConstraint(address, reference);
                if (constraint == null) {
                    return false;
                }
                constraints.add(constraint);
            }
        }
        if (module.version >= 11 && !siteConstraints(module.sites, module.length, address, constraints)) {
            return false;
        }
        List<List<FlirtAnalysisSession.ReferenceConstraint>> alternatives = new ArrayList<>();
        if (module.alternativeSites != null && !module.alternativeSites.isEmpty()) {
            for (List<FlirtSite> sites : module.alternativeSites) {
                List<FlirtAnalysisSession.ReferenceConstraint> alternative = new ArrayList<>();
                if (siteInstructionsMatch(sites, b, bufSize, address) &&
                    siteConstraints(sites, module.length, address, alternative)) {
                    alternatives.add(alternative);
                }
            }
            if (alternatives.isEmpty()) {
                return false;
            }
        }
        List<FlirtCandidate> candidates = new ArrayList<>();
        for (FlirtFunction publicFunction : module.publicFunctions) {
            if (publicFunction.isCollision || publicFunction.name.isEmpty() || publicFunction.name.equals("?")) {
                continue;
            }
            try {
                Address addr = matchingAddress(address).add(publicFunction.offset);
                Function function = functionManager.getFunctionAt(addr);
                if (function == null || entryPointAddresses.contains(addr) ||
                    FlirtFunctionMarkup.isFunctionId(function)) {
                    continue;
                }
                SourceType source = function.getSymbol().getSource();
                if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) {
                    continue;
                }
                SymbolUtilities.validateName(publicFunction.name);
                candidates.add(new FlirtCandidate(addr, publicFunction.name,
                    signatureName, libraryName));
            }
            catch (IllegalArgumentException | AddressOutOfBoundsException | InvalidInputException e) {
                // A bad export address must not prevent other exports being considered.
            }
        }
        if (!candidates.isEmpty()) {
            collectedMatches.add(new FlirtAnalysisSession.ModuleMatch(candidates, constraints, alternatives));
        }
        return true;
    }

    private static int crcOffset(FlirtModule module, int patternLength) {
        return module.version >= 11 ? module.patternSize : Math.max(32, patternLength);
    }

    private boolean instructionMatches(FlirtInstructionBits bits, long offset, byte[] bytes,
            int size, long address) {
        if (bits == null) {
            return true;
        }
        byte[] word = new byte[4];
        if (offset >= 0 && offset <= size - 4L) {
            System.arraycopy(bytes, (int) offset, word, 0, 4);
        }
        else if (offset < 0) {
            try {
                if (memory.getBytes(matchingAddress(address).add(offset), word) != 4) {
                    return false;
                }
            }
            catch (MemoryAccessException | IllegalArgumentException | AddressOutOfBoundsException e) {
                return false;
            }
        }
        else {
            return false;
        }
        long value = 0;
        boolean bigEndian = program.getLanguage().isBigEndian();
        for (int i = 0; i < 4; i++) {
            value |= (long) (word[i] & 0xff) << (8 * (bigEndian ? 3 - i : i));
        }
        return ((value ^ bits.value) & bits.mask) == 0;
    }

    private boolean siteInstructionsMatch(List<FlirtSite> sites, byte[] bytes, int size, long address) {
        if (sites != null) {
            for (FlirtSite site : sites) {
                if (!instructionMatches(site.instructionBits, site.offset, bytes, size, address)) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean siteConstraints(List<FlirtSite> sites, long length, long address,
            List<FlirtAnalysisSession.ReferenceConstraint> constraints) {
        if (sites == null) {
            return true;
        }
        for (FlirtSite site : sites) {
            boolean tiny = length <= 16;
            boolean named = site.name.length() >= 2 && (site.flags & 0x08) == 0;
            if (!named) {
                if (tiny) {
                    return false;
                }
                continue;
            }
            boolean required = tiny || site.name.startsWith("__imp_");
            if (!required && (site.flags & 0x20) != 0) {
                continue;
            }
            FlirtFunction reference = new FlirtFunction();
            reference.name = site.name;
            reference.offset = site.offset;
            var constraint = referenceConstraint(address, reference, true, required ? 0 : length);
            if (constraint == null) {
                if (required) {
                    return false;
                }
                continue;
            }
            constraints.add(new FlirtAnalysisSession.ReferenceConstraint(constraint.name(),
                constraint.targets(), constraint.knownNames(), constraint.existingNames(), !required, true));
        }
        return true;
    }

    private Address matchingAddress(long offset) {
        AddressSpace space = matchingAddressSpace != null ? matchingAddressSpace :
            program.getAddressFactory().getDefaultAddressSpace();
        return space.getAddress(offset);
    }

    private FlirtAnalysisSession.ReferenceConstraint referenceConstraint(long address,
            FlirtFunction reference) {
        return referenceConstraint(address, reference, false);
    }

    private FlirtAnalysisSession.ReferenceConstraint referenceConstraint(long address,
            FlirtFunction reference, boolean modernSite) {
        return referenceConstraint(address, reference, modernSite, 0);
    }

    private FlirtAnalysisSession.ReferenceConstraint referenceConstraint(long address,
            FlirtFunction reference, boolean modernSite, long ignoreWithinModule) {
        try {
            Address start = matchingAddress(address);
            Address refAddress = start.add(reference.negativeOffset ? -reference.offset : reference.offset);
            Instruction instruction = program.getListing().getInstructionContaining(refAddress);
            if (instruction == null) {
                return null;
            }
            Set<Address> targets = new LinkedHashSet<>();
            Set<Address> destinations = new LinkedHashSet<>();
            Set<String> knownNames = new LinkedHashSet<>();
            Map<Address, Set<String>> existingNames = new LinkedHashMap<>();
            for (Reference target : instruction.getReferencesFrom()) {
                Address destination = target.getToAddress();
                destinations.add(destination);
                if (modernSite && functionManager.getFunctionAt(destination) == null) {
                    // Indirect x86 imports refer to an IAT pointer whose outgoing data
                    // reference carries the external function's name.
                    Data data = program.getListing().getDataAt(destination);
                    if (data != null && data.getValue() instanceof Address pointer) {
                        destinations.add(pointer);
                    }
                    for (Reference indirect : program.getReferenceManager().getReferencesFrom(destination)) {
                        if (indirect.getReferenceType().isData()) {
                            destinations.add(indirect.getToAddress());
                        }
                    }
                }
            }
            for (Address destination : destinations) {
                if (!withinModule(destination, start, ignoreWithinModule)) {
                    collectTarget(destination, modernSite, targets, knownNames, existingNames);
                }
            }
            return targets.isEmpty() ? null : new FlirtAnalysisSession.ReferenceConstraint(
                reference.name, List.copyOf(targets), Set.copyOf(knownNames), existingNames);
        }
        catch (IllegalArgumentException | AddressOutOfBoundsException e) {
            return null;
        }
    }

    private static boolean withinModule(Address target, Address start, long length) {
        return length > 0 && target.getAddressSpace().equals(start.getAddressSpace()) &&
            Long.compareUnsigned(target.getOffset(), start.getOffset()) >= 0 &&
            Long.compareUnsigned(target.getOffset() - start.getOffset(), length) < 0;
    }

    private void collectTarget(Address destination, boolean ignoreDefaultNames, Set<Address> targets,
            Set<String> knownNames, Map<Address, Set<String>> existingNames) {
        targets.add(destination);
        Function callee = functionManager.getFunctionAt(destination);
        boolean priorFlirt = callee != null && FlirtFunctionMarkup.isFlirt(callee) &&
            !FlirtFunctionMarkup.isFunctionId(callee);
        if (callee != null) {
            if (!priorFlirt && (!ignoreDefaultNames || callee.getSymbol().getSource() != SourceType.DEFAULT)) {
                addExistingName(callee.getEntryPoint(), callee.getName(),
                    isTrustedName(callee), knownNames, existingNames);
            }
            Function thunked = callee.getThunkedFunction(true);
            if (thunked != null) {
                targets.add(thunked.getEntryPoint());
                if ((!FlirtFunctionMarkup.isFlirt(thunked) || FlirtFunctionMarkup.isFunctionId(thunked)) &&
                    (!ignoreDefaultNames || thunked.getSymbol().getSource() != SourceType.DEFAULT)) {
                    addExistingName(thunked.getEntryPoint(), thunked.getName(),
                        isTrustedName(thunked), knownNames, existingNames);
                }
            }
        }
        for (Symbol symbol : program.getSymbolTable().getSymbols(destination)) {
            if ((!priorFlirt || symbol.getSource() != SourceType.ANALYSIS) &&
                (!ignoreDefaultNames || symbol.getSource() != SourceType.DEFAULT)) {
                boolean trusted = symbol.getSource() == SourceType.USER_DEFINED ||
                    symbol.getSource() == SourceType.IMPORTED ||
                    (callee != null && FlirtFunctionMarkup.isFunctionId(callee));
                addExistingName(destination, symbol.getName(), trusted, knownNames, existingNames);
            }
        }
    }

    private static boolean isTrustedName(Function function) {
        SourceType source = function.getSymbol().getSource();
        return source == SourceType.USER_DEFINED || source == SourceType.IMPORTED ||
            FlirtFunctionMarkup.isFunctionId(function);
    }

    private static void addExistingName(Address address, String name, boolean trusted,
            Set<String> knownNames, Map<Address, Set<String>> existingNames) {
        if (trusted) {
            knownNames.add(name);
        }
        else {
            existingNames.computeIfAbsent(address, key -> new LinkedHashSet<>()).add(name);
        }
    }

    private boolean nodePatternMatch(FlirtNode node, byte[] b, int bufIndex, int bufSize) {
        if (bufIndex < 0 || bufIndex > bufSize || node.length > bufSize - bufIndex) {
            return false;
        }
        for (int i = 0; i < node.length; i++) {
            if (!node.variantBoolArray[i] && node.patternBytes[i] != b[bufIndex + i]) {
                return false;
            }
        }
        return true;
    }

    private boolean nodeMatchBuffer(FlirtNode node, byte[] b, long addr, int bufSize,
            int bufIndex) {
        if (!nodePatternMatch(node, b, bufIndex, bufSize)) {
            return false;
        }
        int patternLength = bufIndex + node.length;
        boolean matched = false;
        if (node.childList != null) {
            for (FlirtNode child : node.childList) {
                matched |= nodeMatchBuffer(child, b, addr, bufSize, patternLength);
            }
        }
        if (node.moduleList != null) {
            for (FlirtModule module : node.moduleList) {
                matched |= moduleMatchBuffer(module, b, addr, bufSize, patternLength);
            }
        }
        return matched;
    }

    private long maximumMatchExtent(FlirtNode node, long patternLength) {
        patternLength += node.length;
        long extent = patternLength;
        if (node.childList != null) {
            for (FlirtNode child : node.childList) {
                extent = Math.max(extent, maximumMatchExtent(child, patternLength));
            }
        }
        if (node.moduleList != null) {
            for (FlirtModule module : node.moduleList) {
                long crcEnd = (long) crcOffset(module, (int) patternLength) + module.crcLength;
                if (module.version >= 11) {
                    extent = Math.max(extent, module.length);
                }
                for (FlirtFunction function : module.publicFunctions) {
                    if (function.instructionBits != null && function.offset >= 0) {
                        extent = Math.max(extent, function.offset + 4);
                    }
                }
                extent = Math.max(extent, siteExtent(module.sites));
                if (module.alternativeSites != null) {
                    for (List<FlirtSite> sites : module.alternativeSites) {
                        extent = Math.max(extent, siteExtent(sites));
                    }
                }
                if (module.crcLength > 0) {
                    extent = Math.max(extent, crcEnd);
                }
                for (FlirtTailByte tail : module.tailBytes) {
                    extent = Math.max(extent, crcEnd + tail.offset + 1);
                }
            }
        }
        return extent;
    }

    private static long siteExtent(List<FlirtSite> sites) {
        long extent = 0;
        if (sites != null) {
            for (FlirtSite site : sites) {
                if (site.instructionBits != null) {
                    extent = Math.max(extent, site.offset + 4);
                }
            }
        }
        return extent;
    }

    private boolean nodeMatchFunctions(FlirtNode rootNode) throws CancelledException, IOException {
        long extent = maximumMatchExtent(rootNode, 0);
        if (extent > MAX_BUFFER_SIZE) {
            throw new IOException("FLIRT match extent exceeds the supported 64 MiB buffer size");
        }
        byte[] buffer = new byte[(int) extent];
        // Modules can span several functions. Collect every candidate before renaming any.
        FunctionIterator functions = functionManager.getFunctions(true);
        for (Function function : functions) {
            monitor.checkCancelled();
            try {
                matchingAddressSpace = function.getEntryPoint().getAddressSpace();
                int read = memory.getBytes(function.getEntryPoint(), buffer);
                nodeMatchBuffer(rootNode, buffer, function.getEntryPoint().getOffset(), read, 0);
            }
            catch (MemoryAccessException | IllegalArgumentException e) {
                // Unreadable memory cannot establish a signature match.
            }
        }
        return true;
    }

    private int readConstraintCount(Flirt f) throws IOException {
        long count = f.version >= 10 ? Integer.toUnsignedLong(readMultipleBytes(f)) :
            f.version >= 8 ? readMax2Bytes(f) & 0xffff : 1;
        // Each record consumes at least two bytes. Reject impossible counts before allocation.
        if (count > f.b.available() / 2) {
            throw new IOException("Invalid FLIRT constraint count");
        }
        return (int) count;
    }

    private long readOffset(Flirt f) throws IOException {
        return f.version >= 9 ? Integer.toUnsignedLong(readMultipleBytes(f)) :
            readMax2Bytes(f) & 0xffff;
    }

    private boolean readModuleTailBytes(Flirt f, FlirtModule module) {
        try {
            int count = f.version >= 11 ? readByte(f) & 0xff : readConstraintCount(f);
            for (int i = 0; i < count; i++) {
                FlirtTailByte tail = new FlirtTailByte();
                tail.offset = readOffset(f);
                tail.value = readByte(f);
                module.tailBytes.add(tail);
            }
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private boolean readModuleReferencedFunctions(Flirt f, FlirtModule module) {
        try {
            int count;
            if (f.version >= 11) {
                // IDA's v11 reader consumes this byte but reads one legacy reference.
                readByte(f);
                count = 1;
            }
            else {
                count = readConstraintCount(f);
            }
            for (int i = 0; i < count; i++) {
                FlirtFunction function = new FlirtFunction();
                function.offset = readOffset(f);
                long length = readByte(f) & 0xff;
                if (length == 0) {
                    length = f.version >= 11 ? readMax2Bytes(f) & 0xffff :
                        Integer.toUnsignedLong(readMultipleBytes(f));
                }
                if (length == 0 || length >= R_FLIRT_NAME_MAX) {
                    return false;
                }
                byte[] name = new byte[(int) length];
                f.b.readFully(name);
                function.negativeOffset = name[name.length - 1] == 0;
                int nameLength = name.length;
                while (nameLength > 0 && name[nameLength - 1] == 0) {
                    nameLength--;
                }
                function.name = new String(name, 0, nameLength, StandardCharsets.ISO_8859_1);
                if (function.name.isEmpty()) {
                    return false;
                }
                module.referencedFunctions.add(function);
            }
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private boolean readModulePublicFunctions(Flirt f, FlirtModule module, byte[] outFlags) {
        try {
            long offset = 0;
            int flags;
            do {
                FlirtFunction function = new FlirtFunction();
                long delta = readOffset(f);
                if (f.version >= 11) {
                    int length = readShort(f) & 0xffff;
                    function.flags = readByte(f) & 0xff;
                    function.name = readLengthPrefixedName(f, length);
                    function.instructionBits = readInstructionBits(f, function.flags);
                    function.extra40 = readExtra40(f, function.flags);
                    offset += (function.flags & 0x10) != 0 ? -delta : delta;
                    function.offset = offset;
                    function.isLocal = (function.flags & IDASIG_FUNCTION_LOCAL) != 0;
                    function.isCollision = (function.flags & IDASIG_FUNCTION_UNRESOLVED_COLLISION) != 0;
                    flags = readByte(f) & 0xff;
                }
                else {
                    offset += delta;
                    if (offset > 0xffffffffL) {
                        return false;
                    }
                    function.offset = offset;
                    int current = readByte(f) & 0xff;
                    if (current < 0x20) {
                        function.flags = current;
                        function.isLocal = (current & IDASIG_FUNCTION_LOCAL) != 0;
                        function.isCollision = (current & IDASIG_FUNCTION_UNRESOLVED_COLLISION) != 0;
                        current = readByte(f) & 0xff;
                    }
                    StringBuilder name = new StringBuilder();
                    while (current >= 0x20) {
                        if (name.length() >= R_FLIRT_NAME_MAX) {
                            return false;
                        }
                        name.append((char) current);
                        current = readByte(f) & 0xff;
                    }
                    if (name.length() == 0) {
                        return false;
                    }
                    function.name = name.toString();
                    flags = current;
                }
                module.publicFunctions.add(function);
            } while ((flags & IDASIG_PARSE_MORE_PUBLIC_NAMES) != 0);
            outFlags[0] = (byte) flags;
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private String readLengthPrefixedName(Flirt f, int length) throws IOException {
        byte[] bytes = new byte[length];
        f.b.readFully(bytes);
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private FlirtInstructionBits readInstructionBits(Flirt f, int flags) throws IOException {
        if ((flags & 0x80) == 0) {
            return null;
        }
        FlirtInstructionBits bits = new FlirtInstructionBits();
        bits.mask = Integer.toUnsignedLong(readMultipleBytes(f));
        bits.value = Integer.toUnsignedLong(readMultipleBytes(f));
        return bits;
    }

    private FlirtExtra40 readExtra40(Flirt f, int flags) throws IOException {
        if ((flags & 0x40) == 0) {
            return null;
        }
        FlirtExtra40 extra = new FlirtExtra40();
        extra.a = Integer.toUnsignedLong(readMultipleBytes(f));
        extra.b = readShort(f) & 0xffff;
        extra.c = readByte(f) & 0xff;
        return extra;
    }

    private List<FlirtSite> readSites(Flirt f) throws IOException {
        long count = Integer.toUnsignedLong(readMultipleBytes(f));
        if (count > f.b.available() / 4) {
            throw new IOException("Invalid FLIRT relocation-site count");
        }
        List<FlirtSite> sites = new ArrayList<>();
        for (long i = 0; i < count; i++) {
            FlirtSite site = new FlirtSite();
            site.offset = Integer.toUnsignedLong(readMultipleBytes(f));
            int length = readShort(f) & 0xffff;
            site.name = readLengthPrefixedName(f, length);
            site.flags = readByte(f) & 0xff;
            site.instructionBits = readInstructionBits(f, site.flags);
            site.extra40 = readExtra40(f, site.flags);
            if ((site.flags & 0x08) != 0) {
                site.extra08 = Integer.toUnsignedLong(readMultipleBytes(f));
            }
            sites.add(site);
        }
        return sites;
    }

    private boolean parseLeaf(Flirt f, FlirtNode node) {
        node.moduleList = new ArrayList<>();
        byte[] flags = new byte[1];
        try {
            do {
                int crcLength = readByte(f) & 0xff;
                int expectedCrc = readShort(f) & 0xffff;
                do {
                    FlirtModule module = new FlirtModule();
                    module.version = f.version & 0xff;
                    module.patternSize = f.patternSize;
                    module.publicFunctions = new ArrayList<>();
                    module.tailBytes = new ArrayList<>();
                    module.referencedFunctions = new ArrayList<>();
                    module.sites = new ArrayList<>();
                    module.alternativeSites = new ArrayList<>();
                    module.crcLength = crcLength;
                    module.crc16 = expectedCrc;
                    module.length = readOffset(f);
                    if (!readModulePublicFunctions(f, module, flags) ||
                        ((flags[0] & IDASIG_PARSE_READ_TAIL_BYTES) != 0 &&
                            !readModuleTailBytes(f, module)) ||
                        ((flags[0] & IDASIG_PARSE_READ_REFERENCED_FUNCTIONS) != 0 &&
                            !readModuleReferencedFunctions(f, module))) {
                        return false;
                    }
                    module.parseFlags = flags[0] & 0xff;
                    if (f.version >= 11) {
                        if ((module.parseFlags & 0x20) != 0) {
                            module.sites = readSites(f);
                        }
                        if ((module.parseFlags & 0x40) != 0) {
                            long count = Integer.toUnsignedLong(readMultipleBytes(f));
                            if (count > f.b.available()) {
                                return false;
                            }
                            for (long i = 0; i < count; i++) {
                                module.alternativeSites.add(readSites(f));
                            }
                        }
                        if ((module.parseFlags & 0x80) != 0) {
                            return false;
                        }
                    }
                    node.moduleList.add(module);
                } while ((flags[0] & IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC) != 0);
            } while ((flags[0] & IDASIG_PARSE_MORE_MODULES) != 0);
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private boolean readNodeLength(Flirt f, FlirtNode node) {
        try {
            node.length = f.version >= 10 ? readMax2Bytes(f) & 0xffff : readByte(f) & 0xff;
            if (node.length == 0 || node.length > f.patternSize) {
                return false;
            }
        }
        catch (IOException e) {
            return false;
        }
        return true;
    }

    private boolean readNodeVariantMask(Flirt f, FlirtNode node) {
        try {
            if (node.length < 0x10) {
                node.variantMask = readMax2Bytes(f) & 0xFFFF;
            }
            else if (node.length <= 0x20) {
                node.variantMask = readMultipleBytes(f) & 0xFFFFFFFFL;
            }
            else if (node.length <= 0x40) {
                node.variantMask = (Integer.toUnsignedLong(readMultipleBytes(f)) << 32) |
                    Integer.toUnsignedLong(readMultipleBytes(f));
            }
            else {
                // Long nodes store their mask as little-endian bitmap bytes, with the
                // most significant logical bit still describing the first pattern byte.
                node.variantBitmap = new byte[(node.length + 7) / 8];
                f.b.readFully(node.variantBitmap);
                int usedBits = node.length & 7;
                if (usedBits != 0) {
                    node.variantBitmap[node.variantBitmap.length - 1] &= (1 << usedBits) - 1;
                }
                return true;
            }
            return node.length == 64 || (node.variantMask >>> node.length) == 0;
        }
        catch (IOException e) {
            return false;
        }
    }

    private boolean readNodeBytes(Flirt f, FlirtNode node) {
        int i;
        if (node.length < 0) {
            return false;
        }
        node.patternBytes = new byte[node.length];
        node.variantBoolArray = new boolean[node.length];

        long currentMaskBit = 1L << (node.length - 1);
        for (i = 0; i < node.length; i++, currentMaskBit >>>= 1) {
            int bit = node.length - 1 - i;
            node.variantBoolArray[i] = node.variantBitmap != null ?
                (node.variantBitmap[bit >>> 3] & (1 << (bit & 7))) != 0 :
                (node.variantMask & currentMaskBit) != 0;
            if (node.variantBoolArray[i]) {
                node.patternBytes[i] = 0;
            }
            else {
                try {
                    node.patternBytes[i] = readByte(f);
                }
                catch (IOException e) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean parseTree(Flirt f, FlirtNode rootNode) {
        return parseTree(f, rootNode, 0, 0);
    }

    private boolean parseTree(Flirt f, FlirtNode rootNode, int depth) {
        return parseTree(f, rootNode, depth, 0);
    }

    private boolean parseTree(Flirt f, FlirtNode rootNode, int depth, int patternLength) {
        try {
            // Bound recursion on malformed files before the Java stack can overflow.
            if (depth > 256) {
                return false;
            }
            long count = f.version >= 11 ? readMax2Bytes(f) & 0xffff :
                Integer.toUnsignedLong(readMultipleBytes(f));
            if (count == 0) {
                return parseLeaf(f, rootNode);
            }
            if (count > f.b.available() / 3) {
                return false;
            }
            rootNode.childList = new ArrayList<>();
            for (long i = 0; i < count; i++) {
                FlirtNode child = new FlirtNode();
                if (!readNodeLength(f, child) || !readNodeVariantMask(f, child) ||
                    !readNodeBytes(f, child) ||
                    patternLength + child.length > f.patternSize ||
                    !parseTree(f, child, depth + 1, patternLength + child.length)) {
                    return false;
                }
                rootNode.childList.add(child);
            }
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private FlirtNode flirtParse(Flirt f) {
        String name = null;
        IdasigV5 header = null;
        byte[] buf = null;
        FlirtNode node = null;
        FlirtNode ret = null;

        f.bufEof = false;
        f.bufErr = false;

        FlirtHeaderParser.HeaderInfo headerInfo = FlirtHeaderParser.parseHeader(f.b);
        if (headerInfo == null) {
            return null;
        }

        FlirtHeaderParser.IdasigV5 parsedV5 = headerInfo.getV5();
        header = new IdasigV5();
        System.arraycopy(parsedV5.magic, 0, header.magic, 0, 6);
        header.version = parsedV5.version;
        header.arch = parsedV5.arch;
        header.fileTypes = parsedV5.fileTypes;
        header.osTypes = parsedV5.osTypes;
        header.appTypes = parsedV5.appTypes;
        header.features = parsedV5.features;
        header.oldNFunctions = parsedV5.oldNFunctions;
        header.crc16 = parsedV5.crc16;
        System.arraycopy(parsedV5.ctype, 0, header.ctype, 0, 12);
        header.libraryNameLen = parsedV5.libraryNameLen;
        header.ctypesCrc16 = parsedV5.ctypesCrc16;

        f.version = header.version;
        f.patternSize = headerInfo.getV8V9() != null ?
            headerInfo.getV8V9().patternSize & 0xffff : 32;

        String magic = new String(header.magic);
        if (!magic.equals("IDASGN")) {
            return null;
        }

        int version = header.version;

        name = headerInfo.getLibraryName();
        libraryName = name;

        try {
            f.headerSize = f.b.available();
        }
        catch (IOException e) {
            return null;
        }

        int size = 0;
        try {
            size = f.b.available();
        }
        catch (IOException e) {
            return null;
        }
        if (size < 1 || size > MAX_BUFFER_SIZE) {
            return null;
        }
        buf = new byte[size];
        try {
            f.b.readFully(buf);
        }
        catch (IOException e) {
            return null;
        }

        if ((header.features & IDASIG_FEATURE_ZSTD) != 0) {
            errorMessage = "Zstd-compressed FLIRT signatures are not supported";
            return null;
        }

        if ((header.features & IDASIG_FEATURE_COMPRESSED) != 0) {
            byte[] dbuf = null;
            if (version == 5 || version == 6) {
                dbuf = inflateRaw(buf, size);
            }
            else if (version >= 7) {
                dbuf = inflate(buf, size);
            }
            else {
                return null;
            }

            if (dbuf == null) {
                return null;
            }
            buf = dbuf;
            size = dbuf.length;
        }

        node = new FlirtNode();
        f.bufEof = false;
        f.bufErr = false;

        f.b = new DataInputStream(new ByteArrayInputStream(buf));

        try {
            if (parseTree(f, node) && f.b.available() == 0) {
                ret = node;
            }
        }
        catch (IOException e) {
            return null;
        }

        return ret;
    }

    private byte[] inflateRaw(byte[] input, int inputLength) {
        byte[] inflated = inflateData(input, inputLength, true);
        return inflated != null ? inflated : inflateData(input, inputLength, false);
    }

    private byte[] inflate(byte[] input, int inputLength) {
        byte[] inflated = inflateData(input, inputLength, false);
        return inflated != null ? inflated : inflateData(input, inputLength, true);
    }

    private byte[] inflateData(byte[] input, int inputLength, boolean raw) {
        Inflater inflater = new Inflater(raw);
        try {
            inflater.setInput(input, 0, inputLength);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                if (monitor.isCancelled()) {
                    return null;
                }
                int count = inflater.inflate(buffer);
                if (count == 0 && !inflater.finished()) {
                    // Truncated input/dictionaries cannot make progress. Never spin forever.
                    return null;
                }
                if (output.size() > MAX_BUFFER_SIZE - count) {
                    return null;
                }
                output.write(buffer, 0, count);
            }
            return inflater.getRemaining() == 0 ? output.toByteArray() : null;
        }
        catch (DataFormatException e) {
            return null;
        }
        finally {
            inflater.end();
        }
    }

    private int isFlirtSignature(DataInputStream buf) {
        int ret = 0;

        if (buf == null) {
            return 0;
        }

        byte[] magic = new byte[6];
        try {
            buf.readFully(magic);
        }
        catch (IOException e) {
            return 0;
        }

        String magicString = new String(magic);
        if (!"IDASGN".equals(magicString)) {
            return 0;
        }

        int version = 0;
        try {
            version = buf.read();
            if (version == -1) {
                return 0;
            }
        }
        catch (IOException e) {
            return 0;
        }

        ret = version & 0xFF;

        return ret;
    }

}
