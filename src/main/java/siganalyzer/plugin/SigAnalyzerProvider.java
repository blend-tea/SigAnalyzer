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
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;

import docking.ComponentProvider;
import docking.Tool;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import siganalyzer.analyzer.FlirtAnalysisResults;
import siganalyzer.analyzer.FlirtHeaderParser;
import siganalyzer.analyzer.SignatureRepository;
import siganalyzer.analyzer.SignatureRepository.Group;

/** Manage processor-specific signature directories and their optional YARA rules. */
public class SigAnalyzerProvider extends ComponentProvider {

    private final Tool pluginTool;
    private final JPanel panel = new JPanel(new BorderLayout(8, 8));
    private final JComboBox<GroupChoice> groupSelector = new JComboBox<>();
    private final JLabel processorLabel = new JLabel("Open a program to manage signatures.");
    private final JLabel directoryLabel = new JLabel(" ");
    private final JLabel ruleStatus = new JLabel(" ");
    private final JLabel operationStatus = new JLabel(" ");
    private final List<SigFileData> rows = new ArrayList<>();
    private final SigFileTableModel tableModel = new SigFileTableModel();
    private final GhidraTable sigFileTable = new GhidraTable(tableModel);
    private final GhidraTableFilterPanel<SigFileData> filterPanel =
        new GhidraTableFilterPanel<>(sigFileTable, tableModel);
    private final JButton createGroupButton = new JButton("New group...");
    private final JButton addButton = new JButton("Add signatures...");
    private final JButton moveButton = new JButton("Move selected...");
    private final JButton removeButton = new JButton("Remove selected");
    private final JButton enableButton = new JButton("Enable selected");
    private final JButton disableButton = new JButton("Disable selected");
    private final JButton editRuleButton = new JButton("Edit rule...");
    private final JButton importRuleButton = new JButton("Import rule...");
    private final JButton removeRuleButton = new JButton("Remove rule");
    private SignatureRepository repository;
    private boolean updatingGroups;

    private static final class SigFileData {
        private final Path path;
        private final String libraryName;
        private final Date modified;
        private boolean enabled;

        SigFileData(Path path, String libraryName, Date modified, boolean enabled) {
            this.path = path;
            this.libraryName = libraryName;
            this.modified = modified;
            this.enabled = enabled;
        }
    }

    private record GroupChoice(Group group) {
        @Override
        public String toString() {
            return group.name();
        }
    }

    private final class SigFileTableModel extends AbstractSortedTableModel<SigFileData> {
        private static final String[] COLUMNS = {
            "Enabled", "File Name", "Library Name", "Last Modified"
        };

        SigFileTableModel() {
            super(1);
        }

        @Override
        public String getName() {
            return "Signature Files";
        }

        @Override
        public List<SigFileData> getModelData() {
            return rows;
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return switch (column) {
                case 0 -> Boolean.class;
                case 3 -> Date.class;
                default -> String.class;
            };
        }

        @Override
        public boolean isSortable(int column) {
            return true;
        }

        @Override
        public Object getColumnValueForRow(SigFileData row, int column) {
            return switch (column) {
                case 0 -> row.enabled;
                case 1 -> row.path.getFileName().toString();
                case 2 -> row.libraryName;
                case 3 -> row.modified;
                default -> null;
            };
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int column) {
            if (column != 0 || !(value instanceof Boolean enabled)) {
                return;
            }
            // Resolve through the sorted model; a backing-list index may target another file.
            SigFileData row = getRowObject(rowIndex);
            if (row == null || !hasCurrentRepository() || row.enabled == enabled) {
                return;
            }
            try {
                repository.setEnabled(row.path, enabled);
                row.enabled = enabled;
                invalidateResults();
                fireTableRowsUpdated(rowIndex, rowIndex);
            }
            catch (IOException e) {
                showError("Could not update signature", e);
            }
        }
    }

    public SigAnalyzerProvider(Plugin plugin, String owner) {
        this(plugin.getTool(), owner);
    }

    public SigAnalyzerProvider(Tool tool, String owner) {
        super(tool, "SigAnalyzer", owner);
        pluginTool = tool;
        setTransient();
        initializeComponents();
    }

    private void initializeComponents() {
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        panel.setPreferredSize(new Dimension(880, 520));
        JPanel groupRow = new JPanel(new BorderLayout(8, 0));
        groupRow.add(new JLabel("Group:"), BorderLayout.WEST);
        groupSelector.getAccessibleContext().setAccessibleName("Signature group");
        groupRow.add(groupSelector, BorderLayout.CENTER);
        JPanel groupButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton refreshButton = new JButton("Refresh");
        groupButtons.add(createGroupButton);
        groupButtons.add(refreshButton);
        groupRow.add(groupButtons, BorderLayout.EAST);
        JPanel header = new JPanel(new BorderLayout(0, 6));
        header.add(processorLabel, BorderLayout.NORTH);
        header.add(groupRow, BorderLayout.CENTER);
        header.add(directoryLabel, BorderLayout.SOUTH);
        panel.add(header, BorderLayout.NORTH);

        sigFileTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        sigFileTable.getAccessibleContext().setAccessibleName("Signatures in selected group");
        sigFileTable.getColumnModel().getColumn(0).setMinWidth(80);
        sigFileTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        sigFileTable.getSelectionModel().addListSelectionListener(e -> updateButtons());
        JPanel tablePanel = new JPanel(new BorderLayout(0, 4));
        tablePanel.setBorder(BorderFactory.createTitledBorder("Signatures directly in this group"));
        tablePanel.add(new JScrollPane(sigFileTable), BorderLayout.CENTER);
        tablePanel.add(filterPanel, BorderLayout.SOUTH);
        panel.add(tablePanel, BorderLayout.CENTER);

        JPanel signatureButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (JButton button : List.of(addButton, moveButton, removeButton, enableButton, disableButton)) {
            signatureButtons.add(button);
        }
        JPanel rulePanel = new JPanel(new BorderLayout(0, 5));
        rulePanel.setBorder(BorderFactory.createTitledBorder("YARA rule (optional)"));
        rulePanel.add(new JLabel("Applies only to this folder. Without a rule, enabled signatures are always considered."),
            BorderLayout.NORTH);
        rulePanel.add(ruleStatus, BorderLayout.CENTER);
        JPanel ruleButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        ruleButtons.add(editRuleButton);
        ruleButtons.add(importRuleButton);
        ruleButtons.add(removeRuleButton);
        rulePanel.add(ruleButtons, BorderLayout.SOUTH);
        JPanel footer = new JPanel(new BorderLayout(0, 8));
        footer.add(signatureButtons, BorderLayout.NORTH);
        footer.add(rulePanel, BorderLayout.CENTER);
        footer.add(operationStatus, BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);

        groupSelector.addActionListener(e -> {
            if (!updatingGroups) {
                loadSelectedGroup();
            }
        });
        refreshButton.addActionListener(e -> refresh());
        createGroupButton.addActionListener(e -> createGroup());
        addButton.addActionListener(e -> addSignatures());
        moveButton.addActionListener(e -> moveSelected());
        removeButton.addActionListener(e -> removeSelected());
        enableButton.addActionListener(e -> setSelectedEnabled(true));
        disableButton.addActionListener(e -> setSelectedEnabled(false));
        editRuleButton.addActionListener(e -> editRule());
        importRuleButton.addActionListener(e -> importRule());
        removeRuleButton.addActionListener(e -> removeRule());
        updateButtons();
    }

    /** Reload after opening this provider or changing the active program. */
    public void refresh() {
        Group previous = selectedGroup();
        refresh(previous == null ? null : previous.directory());
    }

    private void refresh(Path preferredDirectory) {
        operationStatus.setText(" ");
        repository = null;
        rows.clear();
        updatingGroups = true;
        groupSelector.removeAllItems();
        Path root = currentRoot();
        try {
            if (root != null) {
                repository = new SignatureRepository(root);
                GroupChoice preferred = null;
                for (Group group : repository.groups()) {
                    GroupChoice choice = new GroupChoice(group);
                    groupSelector.addItem(choice);
                    if (group.directory().equals(preferredDirectory)) {
                        preferred = choice;
                    }
                }
                if (preferred != null) {
                    groupSelector.setSelectedItem(preferred);
                }
                processorLabel.setText("Processor: " + root.getFileName());
                processorLabel.setToolTipText(root.toString());
            }
            else {
                processorLabel.setText("Open a program to manage signatures.");
                processorLabel.setToolTipText(null);
            }
        }
        catch (IOException e) {
            repository = null;
            groupSelector.removeAllItems();
            showError("Could not load signature groups", e);
        }
        finally {
            updatingGroups = false;
        }
        loadSelectedGroup();
    }

    private Path currentRoot() {
        ProgramManager manager = pluginTool.getService(ProgramManager.class);
        Program program = manager == null ? null : manager.getCurrentProgram();
        if (program == null || program.isClosed()) {
            return null;
        }
        String processor = program.getLanguage().getProcessor().toString();
        Path root = Application.getUserSettingsDirectory().toPath().resolve("signatures")
            .resolve(processor).toAbsolutePath().normalize();
        try {
            return Files.exists(root) ? root.toRealPath() : root;
        }
        catch (IOException e) {
            return root;
        }
    }

    private boolean hasCurrentRepository() {
        Path root = currentRoot();
        if (repository == null || !repository.root().equals(root)) {
            refresh();
            return false;
        }
        return true;
    }

    private Group selectedGroup() {
        GroupChoice choice = (GroupChoice) groupSelector.getSelectedItem();
        return choice == null ? null : choice.group();
    }

    private Group groupForAction() {
        return hasCurrentRepository() ? selectedGroup() : null;
    }

    private void loadSelectedGroup() {
        rows.clear();
        Group group = selectedGroup();
        if (group != null && repository != null) {
            for (Path signature : group.signatures()) {
                try {
                    Path path = repository.validatePath(signature);
                    if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                        rows.add(new SigFileData(path, extractLibraryName(path),
                            new Date(Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toMillis()),
                            repository.isEnabled(path)));
                    }
                }
                catch (IOException e) {
                    Msg.warn(this, "Could not load signature " + signature + ": " + e.getMessage());
                }
            }
            directoryLabel.setText("Directory: " + group.directory());
            directoryLabel.setToolTipText(group.directory().toString());
            ruleStatus.setText(hasRule(group)
                ? "rules.yar present: signatures are considered only when a rule matches the program."
                : "No rules.yar: no YARA restriction.");
            ruleStatus.setToolTipText(group.directory().resolve(SignatureRepository.RULE_FILE).toString());
        }
        else {
            directoryLabel.setText(" ");
            directoryLabel.setToolTipText(null);
            ruleStatus.setText("Select a group to manage its rule.");
            ruleStatus.setToolTipText(null);
        }
        tableModel.fireTableDataChanged();
        updateButtons();
    }

    private static boolean hasRule(Group group) {
        return group != null && group.yaraRule() != null;
    }

    private void updateButtons() {
        boolean available = repository != null && selectedGroup() != null;
        boolean selected = available && !filterPanel.getSelectedItems().isEmpty();
        groupSelector.setEnabled(repository != null);
        createGroupButton.setEnabled(repository != null);
        addButton.setEnabled(available);
        moveButton.setEnabled(selected && groupSelector.getItemCount() > 1);
        removeButton.setEnabled(selected);
        enableButton.setEnabled(selected);
        disableButton.setEnabled(selected);
        editRuleButton.setEnabled(available);
        importRuleButton.setEnabled(available);
        removeRuleButton.setEnabled(available && hasRule(selectedGroup()));
    }

    private String extractLibraryName(Path path) {
        try (DataInputStream input = new DataInputStream(Files.newInputStream(path))) {
            return FlirtHeaderParser.extractLibraryName(input);
        }
        catch (IOException e) {
            return "Unknown (invalid header)";
        }
    }

    private void createGroup() {
        if (!hasCurrentRepository()) {
            return;
        }
        String name = OptionDialog.showInputSingleLineDialog(panel, "New Signature Group",
            "Group path relative to this processor (for example rust/windows):", "");
        if (name == null) {
            return;
        }
        try {
            Group group = repository.createGroup(name.trim());
            repositoryChanged(group.directory());
        }
        catch (IOException | IllegalArgumentException e) {
            showError("Could not create group", e);
        }
    }

    private void addSignatures() {
        Group group = groupForAction();
        if (group == null) {
            return;
        }
        List<File> files = chooseFiles("Add Signatures to " + group.name(), true,
            ExtensionFileFilter.forExtensions("FLIRT signatures", "sig"));
        int count = 0;
        List<String> errors = new ArrayList<>();
        for (File file : files) {
            try {
                Path source = file.toPath();
                if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) ||
                    !file.getName().toLowerCase(Locale.ROOT).endsWith(".sig")) {
                    throw new IOException("Select a regular .sig file");
                }
                try (DataInputStream input = new DataInputStream(Files.newInputStream(source))) {
                    if (FlirtHeaderParser.parseHeader(input) == null) {
                        throw new IOException("Invalid or unsupported FLIRT signature header");
                    }
                }
                Path destination = importDestination(group, file.getName());
                if (destination != null) {
                    Files.copy(source, destination);
                    count++;
                }
            }
            catch (IOException | IllegalArgumentException e) {
                errors.add(file.getName() + ": " + e.getMessage());
            }
        }
        if (count > 0) {
            repositoryChanged(group.directory());
        }
        else {
            refresh(group.directory());
        }
        reportOperation("Added", count, errors);
    }

    private Path importDestination(Group group, String fileName) throws IOException {
        String canonical = fileName.substring(0, fileName.length() - 4) + ".sig";
        Path destination = repository.validatePath(group.directory().resolve(canonical));
        if (!Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            return destination;
        }
        String base = canonical.substring(0, canonical.length() - 4);
        String renamed;
        int counter = 1;
        do {
            renamed = base + "(" + counter++ + ").sig";
        } while (Files.exists(group.directory().resolve(renamed), LinkOption.NOFOLLOW_LINKS));
        int choice = OptionDialog.showYesNoCancelDialog(panel, "Signature Already Exists",
            canonical + " already exists in " + group.name() + ".\n" +
            "Yes: use " + renamed + "\nNo: choose a name\nCancel: skip this file");
        if (choice == OptionDialog.CANCEL_OPTION) {
            return null;
        }
        if (choice == OptionDialog.YES_OPTION) {
            return repository.validatePath(group.directory().resolve(renamed));
        }
        while (true) {
            String name = OptionDialog.showInputSingleLineDialog(panel, "Signature File Name",
                "New file name (inside this group):", renamed);
            if (name == null) {
                return null;
            }
            name = name.trim();
            if (name.isBlank() || name.contains("/") || name.contains("\\") ||
                name.equals(".") || name.equals("..")) {
                Msg.showError(this, panel, "Invalid File Name", "Enter a file name without directory separators.");
                continue;
            }
            if (!name.toLowerCase(Locale.ROOT).endsWith(".sig")) {
                name += ".sig";
            }
            name = name.substring(0, name.length() - 4) + ".sig";
            destination = repository.validatePath(group.directory().resolve(name));
            if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
                Msg.showError(this, panel, "Signature Already Exists", "Choose a name that is not already registered.");
                continue;
            }
            return destination;
        }
    }

    private void moveSelected() {
        Group sourceGroup = groupForAction();
        if (sourceGroup == null) {
            return;
        }
        List<SigFileData> selected = List.copyOf(filterPanel.getSelectedItems());
        List<GroupChoice> destinations = new ArrayList<>();
        for (int i = 0; i < groupSelector.getItemCount(); i++) {
            GroupChoice choice = groupSelector.getItemAt(i);
            if (!choice.group().directory().equals(sourceGroup.directory())) {
                destinations.add(choice);
            }
        }
        if (selected.isEmpty() || destinations.isEmpty()) {
            return;
        }
        GroupChoice destination = (GroupChoice) JOptionPane.showInputDialog(panel,
            "Move " + selected.size() + " selected signature(s) to:", "Move Signatures",
            JOptionPane.QUESTION_MESSAGE, null, destinations.toArray(), destinations.get(0));
        if (destination == null) {
            return;
        }
        int count = 0;
        List<String> errors = new ArrayList<>();
        for (SigFileData row : selected) {
            try {
                repository.moveSignature(row.path, destination.group());
                count++;
            }
            catch (IOException e) {
                errors.add(row.path.getFileName() + ": " + e.getMessage());
            }
        }
        if (count > 0) {
            repositoryChanged(destination.group().directory());
        }
        else {
            refresh(sourceGroup.directory());
        }
        reportOperation("Moved", count, errors);
    }

    private void removeSelected() {
        Group group = groupForAction();
        if (group == null) {
            return;
        }
        List<SigFileData> selected = List.copyOf(filterPanel.getSelectedItems());
        if (selected.isEmpty() || OptionDialog.showYesNoDialog(panel, "Remove Signatures",
            "Delete " + selected.size() + " selected signature(s) from " + group.name() + "?") !=
            OptionDialog.YES_OPTION) {
            return;
        }
        int count = 0;
        List<String> errors = new ArrayList<>();
        for (SigFileData row : selected) {
            try {
                Files.delete(repository.validatePath(row.path));
                count++;
                repository.setEnabled(row.path, true);
            }
            catch (IOException e) {
                errors.add(row.path.getFileName() + ": " + e.getMessage());
            }
        }
        if (count > 0) {
            repositoryChanged(group.directory());
        }
        else {
            refresh(group.directory());
        }
        reportOperation("Removed", count, errors);
    }

    private void setSelectedEnabled(boolean enabled) {
        Group group = groupForAction();
        if (group == null) {
            return;
        }
        List<String> errors = new ArrayList<>();
        int count = 0;
        for (SigFileData row : List.copyOf(filterPanel.getSelectedItems())) {
            try {
                if (row.enabled != enabled) {
                    repository.setEnabled(row.path, enabled);
                    count++;
                }
            }
            catch (IOException e) {
                errors.add(row.path.getFileName() + ": " + e.getMessage());
            }
        }
        if (count > 0) {
            repositoryChanged(group.directory());
        }
        else {
            refresh(group.directory());
        }
        if (!errors.isEmpty()) {
            reportOperation(enabled ? "Enabled" : "Disabled", count, errors);
        }
    }

    private void editRule() {
        Group group = groupForAction();
        if (group == null) {
            return;
        }
        try {
            Path path = repository.validatePath(group.directory().resolve(SignatureRepository.RULE_FILE));
            String contents = hasRule(group) ? Files.readString(path, StandardCharsets.UTF_8) : "";
            JTextArea editor = new JTextArea(contents, 23, 85);
            editor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
            editor.setTabSize(4);
            editor.setCaretPosition(0);
            JPanel content = new JPanel(new BorderLayout(0, 8));
            content.add(new JLabel("rules.yar for " + group.name() +
                ". Syntax is checked by YARA during analysis."), BorderLayout.NORTH);
            content.add(new JScrollPane(editor), BorderLayout.CENTER);
            Object[] options = { "Save", "Cancel" };
            while (JOptionPane.showOptionDialog(panel, content, "Edit YARA Rule: " + group.name(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]) == 0) {
                if (editor.getText().isBlank()) {
                    Msg.showError(this, panel, "Empty YARA Rule",
                        "Enter a YARA rule. Use Remove rule to remove the YARA restriction.");
                    continue;
                }
                saveRule(group, editor.getText());
                break;
            }
        }
        catch (IOException e) {
            showError("Could not edit YARA rule", e);
        }
    }

    private void importRule() {
        Group group = groupForAction();
        if (group == null) {
            return;
        }
        List<File> files = chooseFiles("Import YARA Rule for " + group.name(), false,
            ExtensionFileFilter.forExtensions("YARA rules", "yar", "yara"));
        if (files.isEmpty()) {
            return;
        }
        if (hasRule(group) && OptionDialog.showYesNoDialog(panel, "Replace YARA Rule",
            "Replace rules.yar in " + group.name() + "?") != OptionDialog.YES_OPTION) {
            return;
        }
        try {
            Path source = files.get(0).toPath();
            if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Select a regular YARA rule file");
            }
            String text = Files.readString(source, StandardCharsets.UTF_8);
            if (text.isBlank()) {
                throw new IOException("The rule file is empty");
            }
            saveRule(group, text);
        }
        catch (IOException e) {
            showError("Could not import YARA rule", e);
        }
    }

    private void saveRule(Group group, String text) throws IOException {
        Path path = repository.validatePath(group.directory().resolve(SignatureRepository.RULE_FILE));
        Path temporary = Files.createTempFile(repository.validatePath(group.directory()), ".rules-", ".tmp");
        try {
            Files.writeString(temporary, text, StandardCharsets.UTF_8);
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        finally {
            Files.deleteIfExists(temporary);
        }
        repositoryChanged(group.directory());
    }

    private void removeRule() {
        Group group = groupForAction();
        if (group == null || !hasRule(group) || OptionDialog.showYesNoDialog(panel, "Remove YARA Rule",
            "Remove rules.yar from " + group.name() + "?\nEnabled signatures in this group will have no YARA restriction.") !=
            OptionDialog.YES_OPTION) {
            return;
        }
        try {
            Files.deleteIfExists(repository.validatePath(group.directory().resolve(SignatureRepository.RULE_FILE)));
            repositoryChanged(group.directory());
        }
        catch (IOException e) {
            showError("Could not remove YARA rule", e);
        }
    }

    private List<File> chooseFiles(String title, boolean multiple, ExtensionFileFilter filter) {
        GhidraFileChooser chooser = new GhidraFileChooser(panel);
        try {
            chooser.setTitle(title);
            chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
            chooser.setMultiSelectionEnabled(multiple);
            chooser.addFileFilter(filter);
            chooser.setSelectedFileFilter(filter);
            List<File> files = chooser.getSelectedFiles();
            return files == null ? List.of() : files;
        }
        finally {
            chooser.dispose();
        }
    }

    private void reportOperation(String verb, int count, List<String> errors) {
        if (!errors.isEmpty()) {
            Msg.showError(this, panel, "Signature Operation",
                verb + " " + count + " signature(s).\n\n" + String.join("\n", errors));
        }
        else if (count > 0) {
            Msg.showInfo(this, panel, "Signature Operation", verb + " " + count + " signature(s).");
        }
    }

    private void repositoryChanged(Path directory) {
        invalidateResults();
        refresh(directory);
        operationStatus.setText("Re-run SigAnalyzer to update matches.");
    }

    private void invalidateResults() {
        ProgramManager manager = pluginTool.getService(ProgramManager.class);
        Program program = manager == null ? null : manager.getCurrentProgram();
        if (program != null && !program.isClosed()) {
            FlirtAnalysisResults.clear(program);
        }
        operationStatus.setText("Re-run SigAnalyzer to update matches.");
    }

    private void showError(String title, Exception error) {
        Msg.showError(this, panel, title, error.getMessage());
    }

    public void activateProvider() {
        refresh();
        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void dispose() {
        filterPanel.dispose();
        if (isInTool()) {
            removeFromTool();
        }
    }
}
