package siganalyzer.analyzer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ApplyFlirt {
    // Ghidra
    FunctionManager functionManager;
    Memory memory;
    Program program;
    File sigFile;
    /** Set of entry point addresses excluded from rename targets */
    private Set<Address> entryPointAddresses;

    public ApplyFlirt(Program program, File sigFile) {
        this.program = program;
        this.sigFile = sigFile;
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
            Flirt flirt = new Flirt(new DataInputStream(new FileInputStream(sigFile)));
            FlirtNode node = flirtParse(flirt);
            if (node == null) {
                return false;
            }

            entryPointAddresses = getEntryPointAddresses();

            if (!nodeMatchFunctions(node)) {
                return false;
            }
            else {
                return true;
            }
        }
        catch (Exception e) {
            return false;
        }
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

    private static final int R_FLIRT_NAME_MAX = 1024;

    private static class FlirtTailByte {
        short offset;
        byte value;
    }

    private static class FlirtFunction {
        String name;
        short offset;
        boolean negativeOffset;
        boolean isLocal;
        boolean isCollision;
    }

    private static class FlirtModule {
        int crcLength;
        int crc16;
        short length;
        List<FlirtFunction> publicFunctions;
        List<FlirtTailByte> tailBytes;
        List<FlirtFunction> referencedFunctions;
    }

    // RFlirt 
    private static class Flirt {
        private byte version;
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
        byte r = 0;
        if (f.bufEof || f.bufErr) {
            return 0;
        }
        try {
            r = f.b.readByte();
        }
        catch (EOFException e) {
            f.bufEof = true;
            return 0;
        }
        return r;
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


    private boolean moduleMatchBuffer(FlirtModule module, byte[] b, long address, int bufSize) {
        Function nextModuleFunction = null;
        if (32 + module.crcLength < bufSize) {
            int calculatedCrc = crc16(b, 32, module.crcLength) & 0xFFFF;
            int expectedCrc = module.crc16 & 0xFFFF;
            if (expectedCrc != calculatedCrc) {
                return false;
            }
        }
        if (module.tailBytes != null) {
            for (FlirtTailByte tailByte : module.tailBytes) {
                if (32 + module.crcLength + tailByte.offset < bufSize &&
                    b[32 + module.crcLength + tailByte.offset] != tailByte.value) {
                    return false;
                }
            }
        }

        // TODO: Implement referenced function handling

        ListIterator<FlirtFunction> functionIt = module.publicFunctions.listIterator();
        while (functionIt.hasNext()) {
            FlirtFunction flirtFunction = functionIt.next();
            long functionAddr = address + flirtFunction.offset;
            Address addr =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(functionAddr);
            try {
                nextModuleFunction = functionManager.getFunctionAt(addr);
            }
            catch (Exception e) {
                nextModuleFunction = null;
            }
            if (nextModuleFunction != null) {
                String name;
                int nameOffs = 0;

                long flirtFcnSize = module.length - flirtFunction.offset;
                FlirtFunction nextFlirtFunc;
                ListIterator<FlirtFunction> nextFlirtFuncIt = functionIt;
                while (nextFlirtFuncIt.hasNext()) {
                    nextFlirtFunc = nextFlirtFuncIt.next();
                    if (!nextFlirtFunc.isLocal && !nextFlirtFunc.negativeOffset) {
                        flirtFcnSize = nextFlirtFunc.offset - flirtFunction.offset;
                        break;
                    }
                }

                while (nameOffs < flirtFunction.name.length() &&
                    flirtFunction.name.charAt(nameOffs) == '?') {
                    nameOffs++;
                }

                if (nameOffs < flirtFunction.name.length() &&
                    !entryPointAddresses.contains(nextModuleFunction.getEntryPoint())) {
                    name = flirtFunction.name.substring(nameOffs);

                    try {
                        String newName = name;
                        nextModuleFunction.setName(newName, SourceType.ANALYSIS);
                    }
                    catch (DuplicateNameException | InvalidInputException e) {
                        try {
                            String newName = name + "_" + System.currentTimeMillis();
                            nextModuleFunction.setName(newName, SourceType.ANALYSIS);
                        }
                        catch (Exception e2) {
                        }
                    }
                }
            }
        }
        return true;
    }

    private boolean nodePatternMatch(FlirtNode node, byte[] b, int bufIndex, int bufSize) {
        if (bufSize < node.length) {
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
        if (nodePatternMatch(node, b, bufIndex, bufSize)) {
            if (node.childList != null && !node.childList.isEmpty()) {
                for (FlirtNode child : node.childList) {
                    if (nodeMatchBuffer(child, b, addr, bufSize, bufIndex + node.length)) {
                        return true;
                    }
                }
            }
            else if (node.moduleList != null && !node.moduleList.isEmpty()) {
                for (FlirtModule module : node.moduleList) {
                    if (moduleMatchBuffer(module, b, addr, bufSize)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean nodeMatchFunctions(FlirtNode rootNode) {
        FunctionIterator functions = functionManager.getFunctions(true);
        for (Function function : functions) {
            try {
                byte[] funcBuf = new byte[(int) function.getBody().getNumAddresses()];
                memory.getBytes(function.getEntryPoint(), funcBuf);
                for (FlirtNode child : rootNode.childList) {
                    if (nodeMatchBuffer(child, funcBuf, function.getEntryPoint().getOffset(),
                        (int) function.getBody().getNumAddresses(), 0)) {
                        break;
                    }
                }
            }
            catch (Exception e) {
                continue;
            }
        }
        return true;
    }

    private boolean readModuleTailBytes(Flirt f, FlirtModule module) {
        byte numberOfTailBytes = 1;
        FlirtTailByte tailByte = null;

        if (module.tailBytes == null) {
            module.tailBytes = new ArrayList<>();
        }
        if (f.version >= 8) {
            try {
                numberOfTailBytes = readByte(f);
            }
            catch (IOException e) {
                module.tailBytes.clear();
                return false;
            }
        }
        for (int i = 0; i < numberOfTailBytes; i++) {
            tailByte = new FlirtTailByte();
            if (f.version >= 9) {
                try {
                    tailByte.offset = (short) readMultipleBytes(f);
                }
                catch (IOException e) {
                    module.tailBytes.clear();
                    return false;
                }
            }
            else {
                try {
                    tailByte.offset = readMax2Bytes(f);
                }
                catch (IOException e) {
                    module.tailBytes.clear();
                    return false;
                }
            }
            try {
                tailByte.value = readByte(f);
            }
            catch (IOException e) {
                module.tailBytes.clear();
                return false;
            }
            module.tailBytes.add(tailByte);
        }
        return true;
    }

    private boolean readModuleReferencedFunctions(Flirt f, FlirtModule module) {
        int i, j;
        byte numberOfReferencedFunctions;
        int refFunctionNameLength;
        FlirtFunction refFunction = new FlirtFunction();

        if (f.version >= 8) {
            try {
                numberOfReferencedFunctions = readByte(f);
            }
            catch (IOException e) {
                return false;
            }
        }
        else {
            numberOfReferencedFunctions = 1;
        }

        for (i = 0; i < numberOfReferencedFunctions; i++) {
            refFunction = new FlirtFunction();
            refFunction.name = "";
            if (f.version >= 9) {
                try {
                    refFunction.offset = (short) (readMultipleBytes(f) & 0xFFFF);
                }
                catch (IOException e) {
                    return false;
                }
            }
            else {
                try {
                    refFunction.offset = (short) (readMax2Bytes(f) & 0xFFFF);
                }
                catch (IOException e) {
                    return false;
                }
            }
            try {
                refFunctionNameLength = readByte(f) & 0xFF;
            }
            catch (IOException e) {
                return false;
            }
            if (refFunctionNameLength == 0) {
                try {
                    refFunctionNameLength = readMultipleBytes(f);
                }
                catch (IOException e) {
                    return false;
                }
            }
            if ((long) (refFunctionNameLength & 0xFFFFFFFFL) < 0 ||
                refFunctionNameLength >= R_FLIRT_NAME_MAX) {
                return false;
            }
            for (j = 0; j < refFunctionNameLength; j++) {
                try {
                    refFunction.name += (char) readByte(f);
                }
                catch (IOException e) {
                    return false;
                }
            }
            if (refFunction.name.charAt(refFunctionNameLength - 1) == 0) {
                refFunction.negativeOffset = true;
            }
            module.referencedFunctions.add(refFunction);
        }
        return true;
    }

    private boolean readModulePublicFunctions(Flirt f, FlirtModule module, byte[] outFlags) {
        int i;
        short offset = 0;
        byte currentByte;
        byte flags = 0;

        do {
            FlirtFunction function = new FlirtFunction();
            function.name = "";
            if (f.version >= 9) {
                try {
                    offset += readMultipleBytes(f);
                }
                catch (IOException e) {
                    return false;
                }
            }
            else {
                try {
                    offset += readMax2Bytes(f);
                }
                catch (IOException e) {
                    return false;
                }
            }
            function.offset = (short) offset;

            try {
                currentByte = readByte(f);
            }
            catch (IOException e) {
                return false;
            }
            if (currentByte < 0x20) {
                if ((currentByte & IDASIG_FUNCTION_LOCAL) != 0) {
                    function.isLocal = true;
                }
                if ((currentByte & IDASIG_FUNCTION_UNRESOLVED_COLLISION) != 0) {
                    function.isCollision = true;
                }
                try {
                    currentByte = readByte(f);
                }
                catch (IOException e) {
                    return false;
                }
            }
            for (i = 0; currentByte >= 0x20 && i < R_FLIRT_NAME_MAX; i++) {
                function.name += (char) currentByte;
                try {
                    currentByte = readByte(f);
                }
                catch (IOException e) {
                    return false;
                }
            }

            flags = currentByte;
            module.publicFunctions.add(function);
        }
        while ((flags & IDASIG_PARSE_MORE_PUBLIC_NAMES) != 0);

        outFlags[0] = flags;
        return true;
    }

    private boolean parseLeaf(Flirt f, FlirtNode node) {
        byte flags = 0;
        byte[] flagsArray = new byte[1];

        node.moduleList = new ArrayList<>();

        do {
            byte crcLength;
            try {
                crcLength = readByte(f);
            }
            catch (IOException e) {
                return false;
            }
            short crc16;
            try {
                crc16 = readShort(f);
            }
            catch (IOException e) {
                return false;
            }
            do {
                FlirtModule module = new FlirtModule();

                module.publicFunctions = new ArrayList<>();
                module.tailBytes = new ArrayList<>();
                module.referencedFunctions = new ArrayList<>();

                module.crcLength = crcLength;
                module.crc16 = crc16;
                if (f.version >= 9) {
                    try {
                        module.length = (short) readMultipleBytes(f);
                    }
                    catch (IOException e) {
                        return false;
                    }
                }
                else {
                    try {
                        module.length = readMax2Bytes(f);
                    }
                    catch (IOException e) {
                        return false;
                    }
                }
                if (!readModulePublicFunctions(f, module, flagsArray)) {
                    return false;
                }
                flags = flagsArray[0];
                if ((flags & IDASIG_PARSE_READ_TAIL_BYTES) != 0) {
                    if (!readModuleTailBytes(f, module)) {
                        return false;
                    }
                }
                if ((flags & IDASIG_PARSE_READ_REFERENCED_FUNCTIONS) != 0) {
                    if (!readModuleReferencedFunctions(f, module)) {
                        return false;
                    }
                }
                node.moduleList.add(module);
            }
            while ((flags & IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC) != 0);
        }
        while ((flags & IDASIG_PARSE_MORE_MODULES) != 0);
        return true;
    }

    private boolean readNodeLength(Flirt f, FlirtNode node) {
        try {
            node.length = readByte(f) & 0xFF;
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
                node.variantMask = ((long) readMultipleBytes(f) << 32) | readMultipleBytes(f);
            }
            return true;
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
        if (node.length > 63) {
            return false;
        }

        node.patternBytes = new byte[node.length];
        node.variantBoolArray = new boolean[node.length];

        long currentMaskBit = 1L << (node.length - 1);
        for (i = 0; i < node.length; i++, currentMaskBit >>= 1) {
            node.variantBoolArray[i] = (node.variantMask & currentMaskBit) != 0;
            if ((node.variantMask & currentMaskBit) != 0) {
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
        int i, treeNodes;
        try {
            treeNodes = readMultipleBytes(f);
        }
        catch (IOException e) {
            return false;
        }

        if (treeNodes == 0) {
            return parseLeaf(f, rootNode);
        }

        rootNode.childList = new ArrayList<>();
        for (i = 0; i < treeNodes; i++) {
            FlirtNode node = new FlirtNode();

            if (!readNodeLength(f, node)) {
                return false;
            }
            if (!readNodeVariantMask(f, node)) {
                return false;
            }
            if (!readNodeBytes(f, node)) {
                return false;
            }
            rootNode.childList.add(node);

            if (!parseTree(f, node)) {
                return false;
            }
        }
        return true;
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

        String magic = new String(header.magic);
        if (!magic.equals("IDASGN")) {
            return null;
        }

        int version = header.version;

        name = headerInfo.getLibraryName();

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
        if (size < 1) {
            return null;
        }
        buf = new byte[size];
        try {
            f.b.readFully(buf);
        }
        catch (IOException e) {
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

            if (dbuf != null) {
                buf = dbuf;
                size = dbuf.length;
            }
        }

        node = new FlirtNode();
        f.bufEof = false;
        f.bufErr = false;

        f.b = new DataInputStream(new ByteArrayInputStream(buf));

        if (parseTree(f, node)) {
            ret = node;
        }
        else {
            node = null;
        }

        return ret;
    }

    private byte[] inflateRaw(byte[] input, int inputLength) {
        try {
            Inflater inflater = new Inflater(true);
            inflater.setInput(input, 0, inputLength);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(inputLength * 4);
            byte[] buffer = new byte[1024];

            while (!inflater.finished()) {
                int count = 0;
                try {
                    count = inflater.inflate(buffer);
                }
                catch (DataFormatException e) {
                    inflater.end();
                    inflater = new Inflater();
                    inflater.setInput(input, 0, inputLength);
                    outputStream.reset();

                    try {
                        while (!inflater.finished()) {
                            count = inflater.inflate(buffer);
                            if (count > 0) {
                                outputStream.write(buffer, 0, count);
                            }
                        }
                        inflater.end();
                        return outputStream.toByteArray();
                    }
                    catch (DataFormatException e2) {
                        inflater.end();
                        return null;
                    }
                }
                if (count > 0) {
                    outputStream.write(buffer, 0, count);
                }
            }

            inflater.end();
            return outputStream.toByteArray();
        }
        catch (Exception e) {
            return null;
        }
    }

    private byte[] inflate(byte[] input, int inputLength) {
        try {
            Inflater inflater = new Inflater();
            inflater.setInput(input, 0, inputLength);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(inputLength * 4);
            byte[] buffer = new byte[1024];

            while (!inflater.finished()) {
                int count = 0;
                try {
                    count = inflater.inflate(buffer);
                }
                catch (DataFormatException e) {
                    inflater.end();
                    inflater = new Inflater(true);
                    inflater.setInput(input, 0, inputLength);
                    outputStream.reset();

                    try {
                        while (!inflater.finished()) {
                            count = inflater.inflate(buffer);
                            if (count > 0) {
                                outputStream.write(buffer, 0, count);
                            }
                        }
                        inflater.end();
                        return outputStream.toByteArray();
                    }
                    catch (DataFormatException e2) {
                        inflater.end();
                        return null;
                    }
                }
                if (count > 0) {
                    outputStream.write(buffer, 0, count);
                }
            }

            inflater.end();
            return outputStream.toByteArray();
        }
        catch (Exception e) {
            return null;
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
