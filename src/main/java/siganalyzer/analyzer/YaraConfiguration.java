package siganalyzer.analyzer;

import java.io.File;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

/** Machine-specific YARA executable configuration stored in the analysis tool. */
public final class YaraConfiguration {
    public static final String TOOL_OPTIONS = "SigAnalyzer";
    public static final String EXECUTABLE_OPTION = "YARA Executable";

    private YaraConfiguration() {
    }

    public static void registerToolOptions(ToolOptions options) {
        options.registerOption(EXECUTABLE_OPTION, OptionType.FILE_TYPE, null,
            new HelpLocation("SigAnalyzer", "YaraExecutable"),
            "Full path to the native YARA 4 executable. Leave empty to use the legacy " +
                "program analysis setting, or yara from PATH when that setting is empty/default. " +
                "This setting belongs to this tool, not to the program. Do not include command-line arguments.");
    }

    /** Resolve once per analysis run from the tool responsible for that program. */
    public static String executable(Program program, String legacyFallback) {
        if (program == null || SystemUtilities.isInHeadlessMode()) {
            return executable((ToolOptions) null, legacyFallback);
        }
        PluginTool tool = AutoAnalysisManager.hasAutoAnalysisManager(program)
            ? AutoAnalysisManager.getAnalysisManager(program).getAnalysisTool() : null;
        return executable(tool == null ? null : tool.getOptions(TOOL_OPTIONS), legacyFallback);
    }

    /** Read live options so changes take effect on the next run without restarting the tool. */
    public static String executable(ToolOptions options, String legacyFallback) {
        if (options != null && options.contains(EXECUTABLE_OPTION)) {
            File configured = options.getFile(EXECUTABLE_OPTION, null);
            if (configured != null && !configured.getPath().isBlank()) {
                // The YARA process runs in each rule's directory. Resolve relative
                // configured paths before that working directory is changed.
                return configured.toPath().toAbsolutePath().normalize().toString();
            }
        }
        return legacyFallback == null || legacyFallback.isBlank() ? "yara" : legacyFallback.strip();
    }
}
