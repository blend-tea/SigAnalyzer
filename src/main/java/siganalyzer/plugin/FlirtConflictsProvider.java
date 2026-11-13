package siganalyzer.plugin;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;

import docking.ComponentProvider;
import docking.Tool;
import docking.WindowPosition;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import siganalyzer.analyzer.FlirtCandidate;

/** Completed ambiguous matches, kept separate from the signature-file manager. */
public class FlirtConflictsProvider extends ComponentProvider {
    private final Tool tool;
    private final JPanel panel = new JPanel(new BorderLayout(0, 8));
    private final JLabel summary = new JLabel("No conflicting FLIRT candidates.");
    private final CandidateTableModel model = new CandidateTableModel();
    private final GhidraTable table = new GhidraTable(model);
    private final GhidraTableFilterPanel<FlirtCandidate> filterPanel =
        new GhidraTableFilterPanel<>(table, model);
    private Program program;

    public FlirtConflictsProvider(Tool tool, String owner) {
        super(tool, "FLIRT Conflicts", owner);
        this.tool = tool;
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setHelpLocation(new HelpLocation("SigAnalyzer", "FlirtConflicts"));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setToolTipText("Double-click a row or press Enter to go to the function.");
        table.getAccessibleContext().setAccessibleName("Conflicting FLIRT candidates");
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() == 2 && event.getButton() == MouseEvent.BUTTON1 &&
                    table.rowAtPoint(event.getPoint()) >= 0) {
                    goToSelectedFunction();
                }
            }
        });
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "goToFunction");
        table.getActionMap().put("goToFunction", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                goToSelectedFunction();
            }
        });
        panel.add(summary, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(filterPanel, BorderLayout.SOUTH);
        panel.setPreferredSize(new Dimension(900, 280));
    }

    public void setResults(Program program, List<FlirtCandidate> candidates) {
        this.program = program;
        model.candidates.clear();
        model.candidates.addAll(candidates);
        model.candidates.sort(Comparator.comparing(FlirtCandidate::address)
            .thenComparing(FlirtCandidate::name).thenComparing(FlirtCandidate::signatureFile));
        model.fireTableDataChanged();
        long functionCount = candidates.stream().map(FlirtCandidate::address).distinct().count();
        String programName = program == null ? "" : program.getName();
        setSubTitle(programName);
        if (functionCount == 0) {
            summary.setText("No conflicting FLIRT candidates.");
        }
        else {
            summary.setText(functionCount + (functionCount == 1 ? " function has" : " functions have") +
                " multiple FLIRT names. These functions were not renamed. " +
                "Double-click a candidate to inspect its function.");
        }
    }

    private void goToSelectedFunction() {
        FlirtCandidate candidate = filterPanel.getSelectedItem();
        if (candidate == null || program == null || program.isClosed()) {
            return;
        }
        GoToService goToService = tool.getService(GoToService.class);
        if (goToService != null) {
            goToService.goTo(candidate.address(), program);
        }
    }

    public void dispose() {
        program = null;
        model.candidates.clear();
        filterPanel.dispose();
        if (isInTool()) {
            removeFromTool();
        }
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private class CandidateTableModel extends AbstractSortedTableModel<FlirtCandidate> {
        private final String[] columns = {
            "Address", "Current Function", "FLIRT Candidate", "Signature File", "Library"
        };
        private final List<FlirtCandidate> candidates = new ArrayList<>();

        CandidateTableModel() {
            super(0);
        }

        @Override
        public String getName() {
            return "FLIRT Conflicts";
        }

        @Override
        public List<FlirtCandidate> getModelData() {
            return candidates;
        }

        @Override
        public boolean isSortable(int column) {
            return true;
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 0 ? Address.class : String.class;
        }

        @Override
        public Object getColumnValueForRow(FlirtCandidate row, int column) {
            return switch (column) {
                case 0 -> row.address();
                case 1 -> currentName(row.address());
                case 2 -> row.name();
                case 3 -> row.signatureFile();
                case 4 -> row.libraryName();
                default -> null;
            };
        }

        private String currentName(Address address) {
            if (program == null || program.isClosed()) {
                return "";
            }
            Function function = program.getFunctionManager().getFunctionAt(address);
            return function == null ? "" : function.getName();
        }
    }
}
