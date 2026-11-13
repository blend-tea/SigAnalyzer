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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonParseException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Apply FLIRT after Function ID has had the first opportunity to identify functions. */
public class SigAnalyzerAnalyzer extends AbstractAnalyzer {

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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		String processorName = program.getLanguage().getProcessor().toString();
		File sigDir = new File(Application.getUserSettingsDirectory(), "signatures/" + processorName);
		if (!sigDir.isDirectory() && !sigDir.mkdirs()) {
			log.appendMsg("SigAnalyzer", "Cannot create signature directory: " + sigDir);
			return false;
		}
		Set<String> disabledFiles = loadDisabledFiles(sigDir);
		File[] sigFiles = sigDir.listFiles(file -> file.isFile() &&
			file.getName().toLowerCase(Locale.ROOT).endsWith(".sig"));
		if (sigFiles == null) {
			log.appendMsg("SigAnalyzer", "Cannot list signature directory: " + sigDir);
			return false;
		}
		Arrays.sort(sigFiles, Comparator.comparing(File::getName));
		List<File> signatures = new ArrayList<>();
		for (File sigFile : sigFiles) {
			if (!disabledFiles.contains(sigFile.getAbsolutePath())) {
				signatures.add(sigFile);
			}
		}
		FlirtAnalysisSession session = new FlirtAnalysisSession(program);
		boolean success = session.run(signatures, monitor, log);
		monitor.checkCancelled();
		// Valid files can still produce a useful report when another file was invalid.
		FlirtAnalysisResults.publish(program, session.getConflicts());
		return success;
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
						if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
							disabledFiles.add(element.getAsString());
						}
					}
				}
			}
		}
		catch (IOException | JsonParseException e) {
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
