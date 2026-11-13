package siganalyzer.analyzer;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.program.model.listing.Program;
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
    private static final CopyOnWriteArrayList<Listener> LISTENERS = new CopyOnWriteArrayList<>();

    private FlirtAnalysisResults() {
    }

    public static void publish(Program program, List<FlirtCandidate> candidates) {
        Objects.requireNonNull(program);
        List<FlirtCandidate> snapshot = List.copyOf(candidates);
        synchronized (RESULTS) {
            RESULTS.put(program, snapshot);
        }
        notifyListeners(program, snapshot);
    }

    public static List<FlirtCandidate> get(Program program) {
        synchronized (RESULTS) {
            return RESULTS.getOrDefault(program, List.of());
        }
    }

    public static void clear(Program program) {
        synchronized (RESULTS) {
            RESULTS.remove(program);
        }
        notifyListeners(program, List.of());
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
