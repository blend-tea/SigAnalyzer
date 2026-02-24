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

import java.awt.BorderLayout;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import resources.Icons;
import siganalyzer.analyzer.FlirtHeaderParser;

/**
 * Provider class for SigAnalyzer plugin.
 */
public class SigAnalyzerProvider extends ComponentProvider {

	private static final String SIG_FILE_EXTENSION = ".sig";
	private static final String SIGNATURES_DIR = "signatures";
	private static final String UNKNOWN_LIBRARY = "Unknown";

	private JPanel panel;
	private PluginTool pluginTool;
	private GhidraTable sigFileTable;
	private GhidraTableFilterPanel<SigFileData> filterPanel;
	private List<SigFileData> sigFileDataList;
	private SigFileTableModel tableModel;

	/**
	 * Data class to hold signature file information
	 */
	private static class SigFileData {
		private String fileName;
		private String libraryName;
		private long lastModified;
		private boolean enabled;
		private String absolutePath;

		public SigFileData(String fileName, String libraryName, long lastModified, boolean enabled, String absolutePath) {
			this.fileName = fileName;
			this.libraryName = libraryName;
			this.lastModified = lastModified;
			this.enabled = enabled;
			this.absolutePath = absolutePath;
		}

		public String getFileName() {
			return fileName;
		}

		public String getLibraryName() {
			return libraryName;
		}

		public long getLastModified() {
			return lastModified;
		}

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getAbsolutePath() {
			return absolutePath;
		}
	}

	/**
	 * Table model for signature files
	 */
	private class SigFileTableModel extends AbstractSortedTableModel<SigFileData> {
		private static final String[] COLUMN_NAMES = { "Enabled", "File Name", "Library Name", "Last Modified" };
		private List<SigFileData> sigFileDataList;

		public SigFileTableModel(List<SigFileData> sigFileDataList) {
			super(0);
			this.sigFileDataList = sigFileDataList;
		}

		@Override
		public String getName() {
			return "Signature Files";
		}

		@Override
		public List<SigFileData> getModelData() {
			return sigFileDataList;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			if (columnIndex == 0) {
				return Boolean.class;
			}
			return super.getColumnClass(columnIndex);
		}

		@Override
		public Object getColumnValueForRow(SigFileData rowObject, int columnIndex) {
			return switch (columnIndex) {
				case 0 -> rowObject.isEnabled();
				case 1 -> rowObject.getFileName();
				case 2 -> rowObject.getLibraryName();
				case 3 -> new java.util.Date(rowObject.getLastModified());
				default -> null;
			};
		}

		@Override
		public void setValueAt(Object value, int rowIndex, int columnIndex) {
			if (columnIndex == 0 && value instanceof Boolean) {
				SigFileData data = sigFileDataList.get(rowIndex);
				boolean newValue = (Boolean) value;
				data.setEnabled(newValue);
				// Update JSON when checkbox state changes
				updateConfigJson(data.getAbsolutePath(), newValue);
				fireTableRowsUpdated(rowIndex, rowIndex);
			}
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return columnIndex == 0; // Only checkbox column is editable
		}

		@Override
		public int getColumnCount() {
			return COLUMN_NAMES.length;
		}

		@Override
		public String getColumnName(int column) {
			return COLUMN_NAMES[column];
		}
	}

	public SigAnalyzerProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), "SigAnalyzer", owner);
		this.pluginTool = plugin.getTool();
		this.sigFileDataList = new ArrayList<>();
		setTransient(); // do not show in Window menu/provider lists
		initializeComponents();
	}

	private void initializeComponents() {
		tableModel = new SigFileTableModel(sigFileDataList);
		sigFileTable = new GhidraTable(tableModel);
		filterPanel = new GhidraTableFilterPanel<>(sigFileTable, tableModel);
		
		panel = new JPanel(new BorderLayout());
		panel.add(new JScrollPane(sigFileTable), BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);
	}

	/**
	 * Loads signature files from UserSettingsDirectory/signatures/ProcessorName
	 */
	private void loadSigFiles() {
		sigFileDataList.clear();
		
		ProgramManager programManager = pluginTool.getService(ProgramManager.class);
		if (programManager == null) {
			tableModel.fireTableDataChanged();
			return;
		}

		Program currentProgram = programManager.getCurrentProgram();
		if (currentProgram == null) {
			tableModel.fireTableDataChanged();
			return;
		}

		String processorName = currentProgram.getLanguage().getProcessor().toString();
		File sigDir = new File(Application.getUserSettingsDirectory(), 
			SIGNATURES_DIR + "/" + processorName);
		
		if (!sigDir.exists() || !sigDir.isDirectory()) {
			tableModel.fireTableDataChanged();
			return;
		}

		// Load disabled files list from config.json
		Set<String> disabledFiles = loadConfigJson(sigDir);

		File[] sigFiles = sigDir.listFiles();
		if (sigFiles == null) {
			tableModel.fireTableDataChanged();
			return;
		}

		for (File sigFile : sigFiles) {
			if (sigFile.isFile() && sigFile.getName().endsWith(SIG_FILE_EXTENSION)) {
				String libraryName = extractLibraryName(sigFile);
				String absolutePath = sigFile.getAbsolutePath();
				// Check if file is in disabled list
				boolean enabled = !disabledFiles.contains(absolutePath);
				sigFileDataList.add(new SigFileData(
					sigFile.getName(),
					libraryName,
					sigFile.lastModified(),
					enabled,
					absolutePath
				));
			}
		}

		tableModel.fireTableDataChanged();
	}

	/**
	 * Extracts library name from sig file header
	 * @param sigFile the signature file
	 * @return library name or "Unknown" if extraction fails
	 */
	private String extractLibraryName(File sigFile) {
		try (DataInputStream dis = new DataInputStream(new FileInputStream(sigFile))) {
			return FlirtHeaderParser.extractLibraryName(dis);
		}
		catch (IOException e) {
			return UNKNOWN_LIBRARY;
		}
	}

	/**
	 * Creates actions for the provider
	 */
	private void createActions() {
		DockingAction addAction = new DockingAction("Add Signature File", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addSignatureFile();
			}
		};
		addAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		addAction.setEnabled(true);
		addAction.markHelpUnnecessary();
		addLocalAction(addAction);

		DockingAction removeAction = new DockingAction("Remove Signature File", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				removeSignatureFiles();
			}
		};
		removeAction.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
		removeAction.setEnabled(true);
		removeAction.markHelpUnnecessary();
		addLocalAction(removeAction);
	}

	/**
	 * Adds signature files by copying them to the appropriate directory
	 */
	private void addSignatureFile() {
		File sigDir = getOrCreateSignatureDirectory();
		if (sigDir == null) {
			return;
		}

		List<File> selectedFiles = showSignatureFileChooser();
		if (selectedFiles == null || selectedFiles.isEmpty()) {
			return;
		}

		FileOperationResult result = copySignatureFiles(selectedFiles, sigDir);
		showOperationResult(result, "add", "added");
		
		if (result.getSuccessCount() > 0) {
			loadSigFiles();
		}
	}

	/**
	 * Removes selected signature files from the directory
	 */
	private void removeSignatureFiles() {
		List<SigFileData> selectedItems = filterPanel.getSelectedItems();
		if (selectedItems == null || selectedItems.isEmpty()) {
			Msg.showInfo(this, panel, "Information", "No files selected");
			return;
		}

		// Show confirmation dialog
		String fileList = buildFileList(selectedItems);
		String message = String.format(
			"<html>Are you sure you want to delete the following %d file(s)?<br><br>%s",
			selectedItems.size(), fileList);
		
		int choice = OptionDialog.showYesNoDialog(
			panel,
			"Confirm Delete",
			message);
		
		if (choice != OptionDialog.YES_OPTION) {
			return; // User cancelled
		}

		File sigDir = getSignatureDirectory();
		if (sigDir == null) {
			return;
		}

		FileOperationResult result = deleteSignatureFiles(selectedItems, sigDir);
		showOperationResult(result, "remove", "removed");
		
		if (result.getSuccessCount() > 0) {
			loadSigFiles();
		}
	}

	/**
	 * Builds a formatted list of file names for display in the confirmation dialog
	 * @param selectedItems the selected file items
	 * @return formatted HTML string with file names
	 */
	private String buildFileList(List<SigFileData> selectedItems) {
		if (selectedItems.size() <= 5) {
			// Show all files if 5 or fewer
			StringBuilder sb = new StringBuilder();
			for (SigFileData item : selectedItems) {
				sb.append("• ").append(item.getFileName()).append("<br>");
			}
			return sb.toString();
		} else {
			// Show first 5 files and count of remaining
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < 5; i++) {
				sb.append("• ").append(selectedItems.get(i).getFileName()).append("<br>");
			}
			int remaining = selectedItems.size() - 5;
			sb.append("... and ").append(remaining).append(" more file(s)");
			return sb.toString();
		}
	}

	/**
	 * Gets the current program and validates it is available
	 * @return the current program, or null if not available
	 */
	private Program getCurrentProgram() {
		ProgramManager programManager = pluginTool.getService(ProgramManager.class);
		if (programManager == null) {
			Msg.showError(this, panel, "Error", "ProgramManager is not available");
			return null;
		}

		Program currentProgram = programManager.getCurrentProgram();
		if (currentProgram == null) {
			Msg.showError(this, panel, "Error", "No program is currently open");
			return null;
		}

		return currentProgram;
	}

	/**
	 * Gets the signature directory for the current processor
	 * @return the signature directory, or null if program is not available
	 */
	private File getSignatureDirectory() {
		Program currentProgram = getCurrentProgram();
		if (currentProgram == null) {
			return null;
		}

		String processorName = currentProgram.getLanguage().getProcessor().toString();
		File sigDir = new File(Application.getUserSettingsDirectory(), 
			SIGNATURES_DIR + "/" + processorName);
		
		if (!sigDir.exists() || !sigDir.isDirectory()) {
			Msg.showError(this, panel, "Error", "Signature directory does not exist");
			return null;
		}

		return sigDir;
	}

	/**
	 * Gets or creates the signature directory for the current processor
	 * @return the signature directory, or null if program is not available
	 */
	private File getOrCreateSignatureDirectory() {
		Program currentProgram = getCurrentProgram();
		if (currentProgram == null) {
			return null;
		}

		String processorName = currentProgram.getLanguage().getProcessor().toString();
		File sigDir = new File(Application.getUserSettingsDirectory(), 
			SIGNATURES_DIR + "/" + processorName);
		
		if (!sigDir.exists()) {
			sigDir.mkdirs();
		}

		return sigDir;
	}

	/**
	 * Shows a file chooser dialog for selecting signature files
	 * @return list of selected files, or empty list if cancelled
	 */
	private List<File> showSignatureFileChooser() {
		GhidraFileChooser chooser = new GhidraFileChooser(pluginTool.getToolFrame());
		chooser.setTitle("Select Signature Files");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setMultiSelectionEnabled(true);
		
		ExtensionFileFilter sigFilter = ExtensionFileFilter.forExtensions("Signature Files", "sig");
		chooser.addFileFilter(sigFilter);
		chooser.setSelectedFileFilter(sigFilter);
		
		List<File> selectedFiles = chooser.getSelectedFiles();
		chooser.dispose();
		
		return selectedFiles;
	}

	/**
	 * Validates that a file is a signature file
	 * @param file the file to validate
	 * @return true if the file is a valid signature file
	 */
	private boolean isValidSignatureFile(File file) {
		return file.exists() && file.getName().endsWith(SIG_FILE_EXTENSION);
	}

	/**
	 * Copies signature files to the destination directory
	 * @param selectedFiles the files to copy
	 * @param sigDir the destination directory
	 * @return operation result with success/error counts
	 */
	private FileOperationResult copySignatureFiles(List<File> selectedFiles, File sigDir) {
		FileOperationResult result = new FileOperationResult();

		for (File selectedFile : selectedFiles) {
			if (!isValidSignatureFile(selectedFile)) {
				result.addError("Not a signature file (.sig): " + selectedFile.getName());
				continue;
			}

			try {
				String originalFileName = selectedFile.getName();
				File destFile = new File(sigDir, originalFileName);
				
				// Check if file already exists
				if (destFile.exists()) {
					String resolvedFileName = resolveFileNameConflict(destFile, originalFileName);
					if (resolvedFileName == null) {
						// User cancelled
						result.addError("Skipped: " + originalFileName);
						continue;
					}
					destFile = new File(sigDir, resolvedFileName);
				}
				
				Files.copy(selectedFile.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
				result.incrementSuccess();
			}
			catch (IOException e) {
				result.addError("Failed to copy " + selectedFile.getName() + ": " + e.getMessage());
			}
		}

		return result;
	}

	/**
	 * Resolves file name conflict when a file already exists
	 * @param existingFile the existing file
	 * @param originalFileName the original file name
	 * @return resolved file name, or null if user cancelled
	 */
	private String resolveFileNameConflict(File existingFile, String originalFileName) {
		String baseName = originalFileName.substring(0, originalFileName.length() - SIG_FILE_EXTENSION.length());
		String autoRenamed = generateAutoRenamedFileName(existingFile.getParentFile(), baseName);
		
		String message = String.format(
			"<html>The file <b>%s</b> already exists.<br><br>" +
			"Choose an option:<br>" +
			"• <b>Yes</b>: Use auto-renamed name (%s)<br>" +
			"• <b>No</b>: Specify a different name<br>" +
			"• <b>Cancel</b>: Skip this file",
			originalFileName, autoRenamed);
		
		int choice = OptionDialog.showYesNoCancelDialog(
			panel,
			"File Already Exists",
			message);
		
		if (choice == OptionDialog.CANCEL_OPTION) {
			return null; // User cancelled
		}
		
		if (choice == OptionDialog.YES_OPTION) {
			// Use auto-renamed name
			return autoRenamed;
		}
		
		// User wants to specify a different name
		return promptForFileName(existingFile.getParentFile(), baseName, originalFileName);
	}

	/**
	 * Generates an auto-renamed file name (e.g., aaa.sig -> aaa(1).sig)
	 * @param directory the target directory
	 * @param baseName the base name without extension
	 * @return the auto-renamed file name
	 */
	private String generateAutoRenamedFileName(File directory, String baseName) {
		int counter = 1;
		String newFileName;
		File newFile;
		
		do {
			newFileName = baseName + "(" + counter + ")" + SIG_FILE_EXTENSION;
			newFile = new File(directory, newFileName);
			counter++;
		} while (newFile.exists() && counter < 1000); // Safety limit
		
		return newFileName;
	}

	/**
	 * Prompts the user to enter a custom file name
	 * @param directory the target directory
	 * @param baseName the base name without extension
	 * @param originalFileName the original file name
	 * @return the user-specified file name, or null if cancelled
	 */
	private String promptForFileName(File directory, String baseName, String originalFileName) {
		String initialValue = baseName + "(1)" + SIG_FILE_EXTENSION;
		
		while (true) {
			String userInput = OptionDialog.showInputSingleLineDialog(
				panel,
				"Enter File Name",
				"File name:",
				initialValue);
			
			if (userInput == null) {
				// User cancelled
				return null;
			}
			
			// Validate input
			userInput = userInput.trim();
			if (userInput.isEmpty()) {
				Msg.showError(this, panel, "Error", "File name cannot be empty");
				initialValue = baseName + "(1)" + SIG_FILE_EXTENSION;
				continue;
			}
			
			// Ensure .sig extension
			if (!userInput.endsWith(SIG_FILE_EXTENSION)) {
				userInput += SIG_FILE_EXTENSION;
			}
			
			// Check if the new name already exists
			File newFile = new File(directory, userInput);
			if (newFile.exists()) {
				int overwrite = OptionDialog.showYesNoDialog(
					panel,
					"File Already Exists",
					"The file " + userInput + " already exists. Overwrite?");
				
				if (overwrite == OptionDialog.YES_OPTION) {
					return userInput;
				}
				// User chose not to overwrite, prompt again
				initialValue = userInput;
				continue;
			}
			
			return userInput;
		}
	}

	/**
	 * Deletes signature files from the directory
	 * @param selectedItems the signature file data to delete
	 * @param sigDir the signature directory
	 * @return operation result with success/error counts
	 */
	private FileOperationResult deleteSignatureFiles(List<SigFileData> selectedItems, File sigDir) {
		FileOperationResult result = new FileOperationResult();

		for (SigFileData sigFileData : selectedItems) {
			File fileToDelete = new File(sigDir, sigFileData.getFileName());
			if (!fileToDelete.exists()) {
				result.addError("File does not exist: " + sigFileData.getFileName());
				continue;
			}

			if (!fileToDelete.delete()) {
				result.addError("Failed to delete: " + sigFileData.getFileName());
			} else {
				result.incrementSuccess();
			}
		}

		return result;
	}

	/**
	 * Shows operation result messages to the user
	 * @param result the operation result
	 * @param action the action name (e.g., "add", "remove")
	 * @param pastTense the past tense of the action (e.g., "added", "removed")
	 */
	private void showOperationResult(FileOperationResult result, String action, String pastTense) {
		int successCount = result.getSuccessCount();
		int errorCount = result.getErrorCount();

		if (successCount > 0) {
			String message = String.format("Successfully %s %d signature file(s)", pastTense, successCount);
			if (errorCount > 0) {
				message += String.format(" (%d error(s))", errorCount);
			}
			Msg.showInfo(this, panel, "Success", message);
		}

		if (errorCount > 0 && successCount == 0) {
			String errorMessage = String.format("Failed to %s signature files:\n%s", 
				action, String.join("\n", result.getErrorMessages()));
			Msg.showError(this, panel, "Error", errorMessage);
		}
	}

	/**
	 * Helper class to track file operation results
	 */
	private static class FileOperationResult {
		private int successCount = 0;
		private int errorCount = 0;
		private List<String> errorMessages = new ArrayList<>();

		public void incrementSuccess() {
			successCount++;
		}

		public void addError(String message) {
			errorCount++;
			errorMessages.add(message);
		}

		public int getSuccessCount() {
			return successCount;
		}

		public int getErrorCount() {
			return errorCount;
		}

		public List<String> getErrorMessages() {
			return errorMessages;
		}
	}

	/**
	 * Activates this provider and displays signature files
	 */
	public void activateProvider() {
		setVisible(true);
		createActions();
		loadSigFiles();
		sigFileTable.repaint();
		panel.revalidate();
	}

	/**
	 * Gets the config.json file for the current processor
	 * @return the config.json file, or null if program is not available
	 */
	private File getConfigJsonFile() {
		Program currentProgram = getCurrentProgram();
		if (currentProgram == null) {
			return null;
		}

		String processorName = currentProgram.getLanguage().getProcessor().toString();
		File sigDir = new File(Application.getUserSettingsDirectory(), 
			SIGNATURES_DIR + "/" + processorName);
		
		if (!sigDir.exists()) {
			sigDir.mkdirs();
		}

		return new File(sigDir, "config.json");
	}

	/**
	 * Loads the disabled files list from config.json
	 * @param sigDir the signature directory
	 * @return set of absolute paths of disabled files
	 */
	private Set<String> loadConfigJson(File sigDir) {
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

	/**
	 * Updates config.json when checkbox state changes
	 * @param absolutePath the absolute path of the file
	 * @param enabled true if enabled, false if disabled
	 */
	private void updateConfigJson(String absolutePath, boolean enabled) {
		File configFile = getConfigJsonFile();
		if (configFile == null) {
			return;
		}

		// Load current config
		JsonObject jsonObject;
		if (configFile.exists()) {
			try (FileReader reader = new FileReader(configFile)) {
				JsonElement jsonElement = JsonParser.parseReader(reader);
				if (jsonElement.isJsonObject()) {
					jsonObject = jsonElement.getAsJsonObject();
				} else {
					jsonObject = new JsonObject();
					jsonObject.add("Disable", new JsonArray());
				}
			}
			catch (IOException e) {
				jsonObject = new JsonObject();
				jsonObject.add("Disable", new JsonArray());
			}
		} else {
			jsonObject = new JsonObject();
			jsonObject.add("Disable", new JsonArray());
		}

		// Get or create Disable array
		JsonArray disableArray;
		if (jsonObject.has("Disable") && jsonObject.get("Disable").isJsonArray()) {
			disableArray = jsonObject.getAsJsonArray("Disable");
		} else {
			disableArray = new JsonArray();
			jsonObject.add("Disable", disableArray);
		}

		// Update the disable list
		if (enabled) {
			// Remove from disable list
			List<JsonElement> toRemove = new ArrayList<>();
			for (JsonElement element : disableArray) {
				if (element.isJsonPrimitive() && element.getAsString().equals(absolutePath)) {
					toRemove.add(element);
				}
			}
			for (JsonElement element : toRemove) {
				disableArray.remove(element);
			}
		} else {
			// Add to disable list if not already present
			boolean found = false;
			for (JsonElement element : disableArray) {
				if (element.isJsonPrimitive() && element.getAsString().equals(absolutePath)) {
					found = true;
					break;
				}
			}
			if (!found) {
				disableArray.add(absolutePath);
			}
		}

		// Save updated config
		try (FileWriter writer = new FileWriter(configFile)) {
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			gson.toJson(jsonObject, writer);
		}
		catch (IOException e) {
			Msg.showError(this, panel, "Error", "Failed to update config.json: " + e.getMessage());
		}
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
