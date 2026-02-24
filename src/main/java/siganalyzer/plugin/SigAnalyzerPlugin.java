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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class SigAnalyzerPlugin extends ProgramPlugin {

	SigAnalyzerProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SigAnalyzerPlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new SigAnalyzerProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));

		createActions();
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
	}

	private void showProvider() {
		if (!provider.isInTool()) {
			tool.addComponentProvider(provider, true);
		}
		provider.activateProvider();
		provider.toFront();
	}
}
