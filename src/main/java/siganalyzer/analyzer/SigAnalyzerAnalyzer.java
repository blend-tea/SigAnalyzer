/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package siganalyzer.analyzer;

import java.io.IOException;
import java.nio.file.Path;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Apply FLIRT after Function ID has had the first opportunity to identify functions. */
public class SigAnalyzerAnalyzer extends AbstractAnalyzer {
    public static final String YARA_EXECUTABLE_OPTION = "YARA Executable";
    public static final String YARA_TIMEOUT_OPTION = "YARA Timeout Seconds";
    private String yaraExecutable = "yara";
    private int yaraTimeoutSeconds = 30;


	public SigAnalyzerAnalyzer() {

		// Name the analyzer and give it a description.

		super("SigAnalyzer", "Signature Analyzer", AnalyzerType.BYTE_ANALYZER);
		// FID runs at FUNCTION_ID_ANALYSIS.before(); demanglers run later.
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS);
		setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(YARA_EXECUTABLE_OPTION, "yara", null,
            "Legacy/headless YARA executable name or path. In the GUI, prefer Edit > Tool Options > " +
                "SigAnalyzer > YARA Executable. This value is used when the tool path is unset.");
        options.registerOption(YARA_TIMEOUT_OPTION, 30, null,
            "Maximum time in seconds for each signature group's YARA scan.");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        yaraExecutable = options.getString(YARA_EXECUTABLE_OPTION, "yara");
        yaraTimeoutSeconds = options.getInt(YARA_TIMEOUT_OPTION, 30);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        String processorName = program.getLanguage().getProcessor().toString();
        Path directory = Application.getUserSettingsDirectory().toPath()
            .resolve("signatures").resolve(processorName);
        try {
            SignatureRepository repository = new SignatureRepository(directory);
            String executable = YaraConfiguration.executable(program, yaraExecutable);
            SignatureSelection.Result selection = SignatureSelection.select(repository, program,
                executable, yaraTimeoutSeconds, monitor, log);
            FlirtAnalysisSession session = new FlirtAnalysisSession(program);
            boolean success = session.run(selection.signatures(), repository.root(), monitor, log);
            monitor.checkCancelled();
            // A failed gate skips only its own group. Publish useful results from other groups.
            FlirtAnalysisResults.publish(program, session.getConflicts());
            return selection.success() && success;
        }
        catch (IOException e) {
            monitor.checkCancelled();
            log.appendMsg("SigAnalyzer", "Cannot read signature repository: " + e.getMessage());
            FlirtAnalysisResults.publish(program, java.util.List.of());
            return false;
        }
    }
}
