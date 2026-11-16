package siganalyzer.analyzer;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

/**
 * Latest completed conflict report per program. The analyzer can publish in a
 * headless session; UI listeners marshal their own work onto the Swing thread.
 */
public final class FlirtAnalysisResults {
    @FunctionalInterface
    public interface Listener {
        void resultsChanged(Program program, List<FlirtCandidate> candidates);
    }

    private static final Map<Program, List<FlirtCandidate>> RESULTS = new WeakHashMap<>();
    private static final Map<Program, ResolutionHistory> HISTORIES = new WeakHashMap<>();
    private static final CopyOnWriteArrayList<Listener> LISTENERS = new CopyOnWriteArrayList<>();
    private static final Pattern COMMENT_BLOCK = Pattern.compile("(?ms)^" +
        Pattern.quote(FlirtFunctionMarkup.COMMENT_START) + "\\R.*?^" +
        Pattern.quote(FlirtFunctionMarkup.COMMENT_END) + "(?=\\R|$)");

    private record ResolvedChoice(Address address, List<FlirtCandidate> rows, String name,
            String comment) {
        boolean isApplied(Program program) {
            Function function = program.getFunctionManager().getFunctionAt(address);
            return function != null && name.equals(function.getName()) &&
                function.getSymbol().getSource() == SourceType.USER_DEFINED &&
                Objects.equals(comment, ownedComment(function.getComment()));
        }
    }

    private static final class ResolutionHistory
            implements DomainObjectListener, DomainObjectClosedListener {
        private final WeakReference<Program> program;
        private final Map<Address, ResolvedChoice> choices = new LinkedHashMap<>();

        ResolutionHistory(Program program) {
            this.program = new WeakReference<>(program);
        }

        @Override
        public void domainObjectClosed(DomainObject object) {
            if (object instanceof Program closed) {
                clear(closed);
            }
        }

        @Override
        public void domainObjectChanged(DomainObjectChangedEvent event) {
            if (event.contains(DomainObjectEvent.RESTORED)) {
                try {
                    restoreReport(this);
                }
                catch (RuntimeException e) {
                    Program current = program.get();
                    if (current != null && !current.isClosed()) {
                        Msg.error(FlirtAnalysisResults.class, "Unable to restore FLIRT conflict results", e);
                    }
                }
            }
        }
    }

    private FlirtAnalysisResults() {
    }

    public static void publish(Program program, List<FlirtCandidate> candidates) {
        Objects.requireNonNull(program);
        List<FlirtCandidate> snapshot = List.copyOf(candidates);
        ResolutionHistory previous;
        ResolutionHistory current = new ResolutionHistory(program);
        synchronized (RESULTS) {
            previous = HISTORIES.put(program, current);
            RESULTS.put(program, snapshot);
        }
        detach(program, previous);
        attach(program, current);
        notifyListeners(program, get(program));
    }

    public static List<FlirtCandidate> get(Program program) {
        synchronized (RESULTS) {
            return RESULTS.getOrDefault(program, List.of());
        }
    }

    public static void clear(Program program) {
        ResolutionHistory previous;
        synchronized (RESULTS) {
            previous = HISTORIES.remove(program);
            RESULTS.remove(program);
        }
        detach(program, previous);
        notifyListeners(program, List.of());
    }

    /** Track the exact committed state so program undo/redo also restores/hides its report rows. */
    static List<FlirtCandidate> resolveChoice(Program program, FlirtCandidate candidate,
            String chosenComment) {
        ResolutionHistory history;
        boolean needsAttach = false;
        List<FlirtCandidate> updated;
        synchronized (RESULTS) {
            List<FlirtCandidate> current = RESULTS.getOrDefault(program, List.of());
            List<FlirtCandidate> rows = current.stream()
                .filter(row -> row.address().equals(candidate.address())).toList();
            history = HISTORIES.get(program);
            if (!rows.isEmpty()) {
                if (history == null) {
                    history = new ResolutionHistory(program);
                    HISTORIES.put(program, history);
                    needsAttach = true;
                }
                history.choices.put(candidate.address(), new ResolvedChoice(
                    candidate.address(), rows, candidate.name(), ownedComment(chosenComment)));
            }
            updated = current.stream()
                .filter(row -> !row.address().equals(candidate.address())).toList();
            RESULTS.put(program, updated);
        }
        if (needsAttach) {
            attach(program, history);
        }
        notifyListeners(program, updated);
        return updated;
    }

    private static void restoreReport(ResolutionHistory history) {
        Program program = history.program.get();
        if (program == null || program.isClosed()) {
            return;
        }
        List<ResolvedChoice> choices;
        synchronized (RESULTS) {
            if (HISTORIES.get(program) != history) {
                return;
            }
            choices = new ArrayList<>(history.choices.values());
        }
        if (choices.isEmpty()) {
            return;
        }
        // Read program state outside the report lock; undo callbacks can arrive on a worker thread.
        Map<ResolvedChoice, Boolean> states = new LinkedHashMap<>();
        for (ResolvedChoice choice : choices) {
            states.put(choice, choice.isApplied(program));
        }
        List<FlirtCandidate> updated;
        synchronized (RESULTS) {
            if (HISTORIES.get(program) != history) {
                return;
            }
            List<FlirtCandidate> current = RESULTS.getOrDefault(program, List.of());
            LinkedHashSet<FlirtCandidate> rows = new LinkedHashSet<>(current);
            for (var state : states.entrySet()) {
                ResolvedChoice choice = state.getKey();
                if (history.choices.get(choice.address()) != choice) {
                    continue; // A newer manual choice already owns this address.
                }
                rows.removeIf(row -> row.address().equals(choice.address()));
                if (!state.getValue()) {
                    rows.addAll(choice.rows());
                }
            }
            updated = rows.stream().sorted(Comparator.comparing(FlirtCandidate::address)
                .thenComparing(FlirtCandidate::name).thenComparing(FlirtCandidate::signatureFile)
                .thenComparing(FlirtCandidate::libraryName)).toList();
            if (updated.equals(current)) {
                return;
            }
            RESULTS.put(program, updated);
        }
        notifyListeners(program, updated);
    }

    private static void detach(Program program, ResolutionHistory history) {
        if (program != null && history != null) {
            program.removeListener(history);
            program.removeCloseListener(history);
        }
    }

    private static void attach(Program program, ResolutionHistory history) {
        if (program.isClosed()) {
            clear(program);
            return;
        }
        program.addCloseListener(history);
        if (!program.isClosed()) {
            program.addListener(history);
        }
        boolean obsolete;
        synchronized (RESULTS) {
            obsolete = HISTORIES.get(program) != history;
        }
        if (obsolete) {
            detach(program, history);
        }
        // Overlay addresses retain their Program internally, so weak keys alone cannot
        // release every report. CLOSED cleanup is required even before a manual choice.
        if (program.isClosed()) {
            clear(program);
            detach(program, history);
        }
    }

    private static String ownedComment(String comment) {
        if (comment == null) {
            return null;
        }
        Matcher matcher = COMMENT_BLOCK.matcher(comment);
        return matcher.find() ? matcher.group() : null;
    }

    public static void addListener(Listener listener) {
        LISTENERS.addIfAbsent(Objects.requireNonNull(listener));
    }

    public static void removeListener(Listener listener) {
        LISTENERS.remove(listener);
    }

    private static void notifyListeners(Program program, List<FlirtCandidate> candidates) {
        for (Listener listener : LISTENERS) {
            try {
                listener.resultsChanged(program, candidates);
            }
            catch (RuntimeException e) {
                // A failed UI listener must not turn a completed analysis into a failure.
                Msg.error(FlirtAnalysisResults.class, "Unable to update FLIRT conflict results", e);
            }
        }
    }
}
