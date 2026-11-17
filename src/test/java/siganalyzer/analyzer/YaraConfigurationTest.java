package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;

public class YaraConfigurationTest {
    @Rule
    public TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void executableIsAFileOptionAndSurvivesToolXmlPersistence() throws Exception {
        ToolOptions options = new ToolOptions(YaraConfiguration.TOOL_OPTIONS);
        ToolOptions restored = null;
        try {
            YaraConfiguration.registerToolOptions(options);
            assertTrue(options.isRegistered(YaraConfiguration.EXECUTABLE_OPTION));
            assertEquals(OptionType.FILE_TYPE, options.getType(YaraConfiguration.EXECUTABLE_OPTION));
            assertNull(options.getFile(YaraConfiguration.EXECUTABLE_OPTION, null));
            File executable = temporary.newFile("custom yara executable");
            options.setFile(YaraConfiguration.EXECUTABLE_OPTION, executable);
            restored = new ToolOptions(options.getXmlRoot(true));
            YaraConfiguration.registerToolOptions(restored);
            assertEquals(executable, restored.getFile(YaraConfiguration.EXECUTABLE_OPTION, null));
            assertEquals(executable.toPath().toAbsolutePath().normalize().toString(),
                YaraConfiguration.executable(restored, "legacy-yara"));
        }
        finally {
            options.dispose();
            if (restored != null) {
                restored.dispose();
            }
        }
    }

    @Test
    public void changesAreReadLiveAndDoNotLeakBetweenTools() throws Exception {
        ToolOptions first = new ToolOptions(YaraConfiguration.TOOL_OPTIONS);
        ToolOptions second = new ToolOptions(YaraConfiguration.TOOL_OPTIONS);
        try {
            YaraConfiguration.registerToolOptions(first);
            YaraConfiguration.registerToolOptions(second);
            File initial = temporary.newFile("first-yara");
            first.setFile(YaraConfiguration.EXECUTABLE_OPTION, initial);
            assertEquals(initial.toPath().toAbsolutePath().toString(),
                YaraConfiguration.executable(first, "legacy"));
            assertEquals("other-legacy", YaraConfiguration.executable(second, "other-legacy"));
            File changed = Path.of("tools", "..", "changed yara").toFile();
            first.setFile(YaraConfiguration.EXECUTABLE_OPTION, changed);
            assertEquals(changed.toPath().toAbsolutePath().normalize().toString(),
                YaraConfiguration.executable(first, "legacy"));
            first.setFile(YaraConfiguration.EXECUTABLE_OPTION, null);
            assertEquals("yara", YaraConfiguration.executable(first, "  "));
            assertEquals("legacy-custom", YaraConfiguration.executable(first, "  legacy-custom  "));
            first.setFile(YaraConfiguration.EXECUTABLE_OPTION, new File(""));
            assertEquals("yara", YaraConfiguration.executable(first, null));
            assertEquals("yara", YaraConfiguration.executable(second, ""));
        }
        finally {
            first.dispose();
            second.dispose();
        }
    }

    @Test
    public void headlessFallbackDoesNotCreateAnAnalysisManager() {
        Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] {Program.class}, (proxy, method, arguments) -> {
                switch (method.getName()) {
                    case "hashCode": return System.identityHashCode(proxy);
                    case "equals": return proxy == arguments[0];
                    case "toString": return "program without an analysis manager";
                    default: throw new AssertionError("Unexpected program initialization: " + method.getName());
                }
            });
        assertEquals("legacy-executable", YaraConfiguration.executable(program, " legacy-executable "));
        assertEquals("yara", YaraConfiguration.executable(program, ""));
    }
}
