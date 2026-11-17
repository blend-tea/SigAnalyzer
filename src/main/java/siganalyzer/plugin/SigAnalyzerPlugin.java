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
package siganalyzer.plugin;

import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import siganalyzer.analyzer.FlirtAnalysisResults;
import siganalyzer.analyzer.FlirtCandidate;
import siganalyzer.analyzer.YaraConfiguration;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Manage FLIRT signatures",
	description = "Manage IDA FLIRT signatures and apply library function names with SigAnalyzer."
)
//@formatter:on
public class SigAnalyzerPlugin extends ProgramPlugin {

	SigAnalyzerProvider provider;
	private final FlirtConflictsProvider conflictsProvider;
	private final FlirtAnalysisResults.Listener resultsListener = this::resultsChanged;
	private final Map<Program, List<FlirtCandidate>> seenReports = new WeakHashMap<>();
	private boolean disposed;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SigAnalyzerPlugin(PluginTool tool) {
		super(tool);
		YaraConfiguration.registerToolOptions(tool.getOptions(YaraConfiguration.TOOL_OPTIONS));

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new SigAnalyzerProvider(this, pluginName);
		conflictsProvider = new FlirtConflictsProvider(tool, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = "SigAnalyzer";
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));

		createActions();
		FlirtAnalysisResults.addListener(resultsListener);
	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
	}

	private void createActions() {
		DockingAction openAction = new DockingAction("Open SigAnalyzer", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showProvider();
			}
		};

		openAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "SigAnalyzer", "Open SigAnalyzer" }, "SigAnalyzer"));
		tool.addAction(openAction);

		DockingAction conflictsAction = new DockingAction("FLIRT Conflicts", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				refreshConflicts(currentProgram, true);
			}
		};
		conflictsAction.setMenuBarData(new MenuData(
			new String[] { "Tools", "SigAnalyzer", "FLIRT Conflicts" }, "SigAnalyzer"));
		conflictsAction.setHelpLocation(new HelpLocation("SigAnalyzer", "FlirtConflicts"));
		tool.addAction(conflictsAction);
	}

	private void resultsChanged(Program program, List<FlirtCandidate> candidates) {
		if (SystemUtilities.isInHeadlessMode()) {
			return;
		}
		Swing.runLater(() -> {
			if (!disposed && program == currentProgram && !program.isClosed()) {
				refreshConflicts(program, !FlirtAnalysisResults.get(program).isEmpty());
			}
		});
	}

	private void refreshConflicts(Program program, boolean show) {
		List<FlirtCandidate> candidates = program == null || program.isClosed() ?
			List.of() : FlirtAnalysisResults.get(program);
		conflictsProvider.setResults(program, candidates);
		if (program != null) {
			seenReports.put(program, candidates);
		}
		if (show) {
			if (!conflictsProvider.isInTool()) {
				conflictsProvider.addToTool();
			}
			conflictsProvider.setVisible(true);
			conflictsProvider.toFront();
		}
	}

	@Override
	protected void programActivated(Program program) {
		refreshSignatureManager();
		List<FlirtCandidate> candidates = FlirtAnalysisResults.get(program);
		refreshConflicts(program, !candidates.isEmpty() && seenReports.get(program) != candidates);
	}

	@Override
	protected void programDeactivated(Program program) {
		refreshSignatureManager();
		conflictsProvider.setResults(null, List.of());
	}

	@Override
	protected void programClosed(Program program) {
		refreshSignatureManager();
		seenReports.remove(program);
		if (program == currentProgram) {
			conflictsProvider.setResults(null, List.of());
		}
		if (program.isClosed()) {
			FlirtAnalysisResults.clear(program);
		}
	}

	@Override
	protected void dispose() {
		disposed = true;
		FlirtAnalysisResults.removeListener(resultsListener);
		seenReports.clear();
		conflictsProvider.dispose();
		provider.dispose();
		super.dispose();
	}

	private void showProvider() {
		if (!provider.isInTool()) {
			tool.addComponentProvider(provider, true);
		}
		provider.activateProvider();
		provider.toFront();
	}

	private void refreshSignatureManager() {
		Swing.runLater(() -> {
			if (!disposed && provider.isVisible()) {
				provider.refresh();
			}
		});
	}
}
