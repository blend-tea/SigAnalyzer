package siganalyzer.analyzer;

import java.io.File;
import java.io.IOException;
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
            Map<Address, Set<String>> existingNames) {
        ReferenceConstraint {
            targets = List.copyOf(targets);
            knownNames = Set.copyOf(knownNames);
            Map<Address, Set<String>> snapshot = new LinkedHashMap<>();
            existingNames.forEach((address, values) -> snapshot.put(address, Set.copyOf(values)));
            existingNames = Map.copyOf(snapshot);
        }

        boolean possible(Map<Address, Set<String>> names) {
            return knownNames.contains(name) || targets.stream()
                .anyMatch(target -> names.getOrDefault(target, Set.of()).contains(name)) ||
                existingNames.values().stream().anyMatch(values -> values.contains(name));
        }

        boolean resolved(Map<Address, String> names, Map<Address, Set<String>> possibilities) {
            return knownNames.contains(name) || targets.stream()
                .anyMatch(target -> name.equals(names.get(target))) ||
                existingNames.entrySet().stream().anyMatch(entry -> {
                    Set<String> candidates = possibilities.get(entry.getKey());
                    // An old mutable analysis name is not proof when the current
                    // signatures disagree with it or give more than one choice.
                    return entry.getValue().contains(name) && (candidates == null ||
                        (candidates.size() == 1 && candidates.contains(name)));
                });
        }
    }

    record ModuleMatch(List<FlirtCandidate> candidates, List<ReferenceConstraint> references) {
        ModuleMatch {
            candidates = List.copyOf(candidates);
            references = List.copyOf(references);
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
        appliedCount = 0;
        errorMessage = null;
        conflicts = List.of();
        List<ModuleMatch> modules = new ArrayList<>();
        boolean success = true;
        for (File file : signatureFiles) {
            monitor.checkCancelled();
            monitor.setMessage("Reading FLIRT candidates: " + file.getName());
            try {
                modules.addAll(new ApplyFlirt(program, file).collectMatches(monitor));
            }
            catch (IOException | IllegalArgumentException e) {
                monitor.checkCancelled();
                success = false;
                errorMessage = file.getName() + ": " + e.getMessage();
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
                if (!module.references().stream().allMatch(ref -> ref.possible(possibleNames))) {
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

        // Apply unique names in dependency order. Only a successful rename (or an
        // already-correct name) becomes proof for another function's references.
        Map<Address, String> resolved = new LinkedHashMap<>();
        Set<Address> failed = new LinkedHashSet<>();
        boolean progress;
        do {
            monitor.checkCancelled();
            progress = false;
            for (ModuleMatch module : modules) {
                monitor.checkCancelled();
                if (!module.references().stream().allMatch(ref -> ref.resolved(resolved, names))) {
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
            module.references().stream().allMatch(ref -> ref.resolved(resolved, names))).toList();
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
