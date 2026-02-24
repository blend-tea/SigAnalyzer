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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class SigAnalyzerAnalyzer extends AbstractAnalyzer {

	public SigAnalyzerAnalyzer() {

		// Name the analyzer and give it a description.

		super("SigAnalyzer", "Signature Analyzer", AnalyzerType.BYTE_ANALYZER);
		// Set priority to run before Demangler analyzers (Rust and Microsoft)
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before());
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

		// If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {

		// Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.

		String processorName = program.getLanguage().getProcessor().toString();
		File sigDir = new File(Application.getUserSettingsDirectory(), "signatures/" + processorName);
		if (!sigDir.exists()) {
			sigDir.mkdirs();
		}

		// Load config.json and get disabled files list
		Set<String> disabledFiles = loadDisabledFiles(sigDir);

		File[] sigFiles = sigDir.listFiles();
		if (sigFiles == null) {
			return false;
		}

		for (File sigFile : sigFiles) {
			if (sigFile.getName().endsWith(".sig")) {
				// Check if this file is in the disabled list
				String absolutePath = sigFile.getAbsolutePath();
				if (disabledFiles.contains(absolutePath)) {
					continue; // Skip disabled files
				}
				ApplyFlirt applyFlirt = new ApplyFlirt(program, sigFile);
				applyFlirt.run();
			}
		}
		return false;
	}

	/**
	 * Loads the disabled files list from config.json
	 * @param sigDir the signature directory
	 * @return set of absolute paths of disabled files
	 */
	private Set<String> loadDisabledFiles(File sigDir) {
		Set<String> disabledFiles = new HashSet<>();
		File configFile = new File(sigDir, "config.json");

		// If config.json doesn't exist, create an empty one
		if (!configFile.exists()) {
			createEmptyConfig(configFile);
			return disabledFiles;
		}

		// Read config.json
		try (FileReader reader = new FileReader(configFile)) {
			JsonElement jsonElement = JsonParser.parseReader(reader);
			if (jsonElement.isJsonObject()) {
				JsonObject jsonObject = jsonElement.getAsJsonObject();
				if (jsonObject.has("Disable") && jsonObject.get("Disable").isJsonArray()) {
					JsonArray disableArray = jsonObject.getAsJsonArray("Disable");
					for (JsonElement element : disableArray) {
						if (element.isJsonPrimitive()) {
							disabledFiles.add(element.getAsString());
						}
					}
				}
			}
		}
		catch (IOException e) {
			// If reading fails, return empty set
		}

		return disabledFiles;
	}

	/**
	 * Creates an empty config.json file
	 * @param configFile the config file to create
	 */
	private void createEmptyConfig(File configFile) {
		try {
			JsonObject jsonObject = new JsonObject();
			jsonObject.add("Disable", new JsonArray());
			
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			try (FileWriter writer = new FileWriter(configFile)) {
				gson.toJson(jsonObject, writer);
			}
		}
		catch (IOException e) {
			// If creation fails, silently ignore
		}
	}
}
