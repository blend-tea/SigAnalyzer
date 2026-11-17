package siganalyzer.analyzer;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/** Collects and resolves all signatures before applying any function names. */
public final class FlirtAnalysisSession {
    record ReferenceConstraint(String name, List<Address> targets, Set<String> knownNames,
            Map<Address, Set<String>> existingNames, boolean optional, boolean importAliases) {
        ReferenceConstraint(String name, List<Address> targets, Set<String> knownNames,
                Map<Address, Set<String>> existingNames) {
            this(name, targets, knownNames, existingNames, false, false);
        }

        ReferenceConstraint {
            targets = List.copyOf(targets);
            knownNames = Set.copyOf(knownNames);
            Map<Address, Set<String>> snapshot = new LinkedHashMap<>();
            existingNames.forEach((address, values) -> snapshot.put(address, Set.copyOf(values)));
            existingNames = Map.copyOf(snapshot);
        }

        private boolean matches(String actual) {
            if (name.equals(actual)) {
                return true;
            }
            return importAliases && actual != null &&
                unimport(name).equals(unimport(actual));
        }

        private static String unimport(String value) {
            return value.startsWith("__imp_") ? value.substring(6) : value;
        }

        private boolean contains(Set<String> values) {
            return values.stream().anyMatch(this::matches);
        }

        private boolean hasEvidence(Map<Address, Set<String>> possibilities) {
            return !knownNames.isEmpty() || existingNames.values().stream().anyMatch(v -> !v.isEmpty()) ||
                targets.stream().anyMatch(target -> !possibilities.getOrDefault(target, Set.of()).isEmpty());
        }

        boolean possible(Map<Address, Set<String>> names) {
            // Optional evidence may disappear when another module's mandatory
            // reference is pruned. Keep it until resolution to avoid hiding an
            // alternative and turning a conflict into an arbitrary winner.
            if (optional) {
                return true;
            }
            return contains(knownNames) || targets.stream()
                .anyMatch(target -> contains(names.getOrDefault(target, Set.of()))) ||
                existingNames.values().stream().anyMatch(this::contains);
        }

        boolean resolved(Map<Address, String> names, Map<Address, Set<String>> possibilities) {
            return contains(knownNames) || targets.stream().anyMatch(target -> matches(names.get(target))) ||
                existingNames.entrySet().stream().anyMatch(entry -> {
                    Set<String> candidates = possibilities.get(entry.getKey());
                    // A mutable analysis name cannot prove a currently ambiguous target.
                    return contains(entry.getValue()) && (candidates == null ||
                        (candidates.size() == 1 && contains(candidates)));
                }) || (optional && (!hasEvidence(possibilities) ||
                    (knownNames.isEmpty() && existingNames.values().stream().allMatch(Set::isEmpty) &&
                        targets.stream().anyMatch(target -> {
                            Set<String> candidates = possibilities.getOrDefault(target, Set.of());
                            return candidates.size() == 1 && contains(candidates);
                        }))));
        }
    }

    record ModuleMatch(List<FlirtCandidate> candidates, List<ReferenceConstraint> references,
            List<List<ReferenceConstraint>> alternatives) {
        ModuleMatch(List<FlirtCandidate> candidates, List<ReferenceConstraint> references) {
            this(candidates, references, List.of());
        }

        ModuleMatch {
            candidates = List.copyOf(candidates);
            references = List.copyOf(references);
            alternatives = alternatives.stream().map(List::copyOf).toList();
        }

        boolean possible(Map<Address, Set<String>> names) {
            return references.stream().allMatch(ref -> ref.possible(names)) &&
                (alternatives.isEmpty() || alternatives.stream()
                    .anyMatch(group -> group.stream().allMatch(ref -> ref.possible(names))));
        }

        boolean resolved(Map<Address, String> names, Map<Address, Set<String>> possibilities) {
            return references.stream().allMatch(ref -> ref.resolved(names, possibilities)) &&
                (alternatives.isEmpty() || alternatives.stream()
                    .anyMatch(group -> group.stream().allMatch(ref -> ref.resolved(names, possibilities))));
        }
    }

    private final Program program;
    private List<FlirtCandidate> conflicts = List.of();
    private int appliedCount;
    private String errorMessage;

    public FlirtAnalysisSession(Program program) {
        this.program = program;
    }

    public boolean run(List<File> signatureFiles, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        return run(signatureFiles, null, monitor, log);
    }

    public boolean run(List<File> signatureFiles, Path signatureRoot, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        appliedCount = 0;
        errorMessage = null;
        conflicts = List.of();
        List<ModuleMatch> modules = new ArrayList<>();
        boolean success = true;
        for (File file : signatureFiles) {
            monitor.checkCancelled();
            String signatureName = file.getName();
            if (signatureRoot != null) {
                Path path = file.toPath().toAbsolutePath().normalize();
                Path root = signatureRoot.toAbsolutePath().normalize();
                if (!path.startsWith(root)) {
                    errorMessage = "Signature is outside the configured repository: " + file;
                    log.appendMsg("SigAnalyzer", errorMessage);
                    success = false;
                    continue;
                }
                signatureName = root.relativize(path).toString().replace('\\', '/');
            }
            monitor.setMessage("Reading FLIRT candidates: " + signatureName);
            try {
                modules.addAll(new ApplyFlirt(program, file, signatureName).collectMatches(monitor));
            }
            catch (IOException | IllegalArgumentException e) {
                monitor.checkCancelled();
                success = false;
                errorMessage = signatureName + ": " + e.getMessage();
                log.appendMsg("SigAnalyzer", errorMessage);
            }
        }

        // Remove modules whose reference names cannot be supplied by existing symbols or
        // any byte-matching candidate. This phase never makes an arbitrary name choice.
        boolean removed;
        do {
            monitor.checkCancelled();
            Map<Address, Set<String>> possibleNames = namesByAddress(modules);
            removed = false;
            for (var iterator = modules.iterator(); iterator.hasNext();) {
                monitor.checkCancelled();
                ModuleMatch module = iterator.next();
                if (!module.possible(possibleNames)) {
                    iterator.remove();
                    removed = true;
                }
            }
        } while (removed);

        Map<Address, Set<String>> names = namesByAddress(modules);
        Map<Address, List<FlirtCandidate>> candidates = candidatesByAddress(modules);
        List<FlirtCandidate> ambiguous = new ArrayList<>();
        for (var entry : candidates.entrySet()) {
            if (names.get(entry.getKey()).size() > 1) {
                ambiguous.addAll(entry.getValue());
            }
        }
        conflicts = List.copyOf(ambiguous);

        // Apply unique names in dependency order. Mandatory references need a
        // successful rename (or an already-correct name); optional v11 sites may
        // also use independently unique byte-matching candidates.
        Map<Address, String> resolved = new LinkedHashMap<>();
        Set<Address> failed = new LinkedHashSet<>();
        boolean progress;
        do {
            monitor.checkCancelled();
            progress = false;
            for (ModuleMatch module : modules) {
                monitor.checkCancelled();
                if (!module.resolved(resolved, names)) {
                    continue;
                }
                for (FlirtCandidate candidate : module.candidates()) {
                    monitor.checkCancelled();
                    Address address = candidate.address();
                    if (names.get(address).size() != 1 || resolved.containsKey(address) ||
                        failed.contains(address)) {
                        continue;
                    }
                    Function function = program.getFunctionManager().getFunctionAt(address);
                    if (!canApply(function)) {
                        failed.add(address);
                        continue;
                    }
                    try {
                        if (!candidate.name().equals(function.getName())) {
                            function.setName(candidate.name(), SourceType.ANALYSIS);
                            appliedCount++;
                        }
                        resolved.put(address, candidate.name());
                        progress = true;
                    }
                    catch (DuplicateNameException | InvalidInputException e) {
                        failed.add(address);
                        log.appendMsg("SigAnalyzer", "Cannot apply " + candidate.name() + " at " +
                            address + ": " + e.getMessage());
                    }
                }
            }
        } while (progress);

        // A possible but unresolved source must not be recorded as a successful match.
        List<ModuleMatch> confirmed = modules.stream().filter(module ->
            module.resolved(resolved, names)).toList();
        for (var entry : candidatesByAddress(confirmed).entrySet()) {
            monitor.checkCancelled();
            Address address = entry.getKey();
            String name = resolved.get(address);
            if (name == null) {
                continue;
            }
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (!canApply(function)) {
                continue;
            }
            FlirtFunctionMarkup.addFlirtComment(function, entry.getValue());
        }
        return success;
    }

    private boolean canApply(Function function) {
        if (function == null || FlirtFunctionMarkup.isFunctionId(function) ||
            program.getSymbolTable().isExternalEntryPoint(function.getEntryPoint())) {
            return false;
        }
        SourceType source = function.getSymbol().getSource();
        return source != SourceType.USER_DEFINED && source != SourceType.IMPORTED;
    }

    private static Map<Address, Set<String>> namesByAddress(List<ModuleMatch> modules) {
        Map<Address, Set<String>> names = new TreeMap<>();
        for (ModuleMatch module : modules) {
            for (FlirtCandidate candidate : module.candidates()) {
                names.computeIfAbsent(candidate.address(), key -> new LinkedHashSet<>()).add(candidate.name());
            }
        }
        return names;
    }

    private static Map<Address, List<FlirtCandidate>> candidatesByAddress(List<ModuleMatch> modules) {
        Map<Address, Set<FlirtCandidate>> unique = new TreeMap<>();
        for (ModuleMatch module : modules) {
            for (FlirtCandidate candidate : module.candidates()) {
                unique.computeIfAbsent(candidate.address(), key -> new LinkedHashSet<>()).add(candidate);
            }
        }
        Comparator<FlirtCandidate> order = Comparator.comparing(FlirtCandidate::name)
            .thenComparing(FlirtCandidate::signatureFile).thenComparing(FlirtCandidate::libraryName);
        Map<Address, List<FlirtCandidate>> candidates = new TreeMap<>();
        unique.forEach((address, values) -> candidates.put(address, values.stream().sorted(order).toList()));
        return candidates;
    }

    public List<FlirtCandidate> getConflicts() {
        return conflicts;
    }

    public int getAppliedCount() {
        return appliedCount;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
