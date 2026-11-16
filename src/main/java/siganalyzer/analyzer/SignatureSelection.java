package siganalyzer.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Select registered signatures, applying each directory's optional YARA gate once. */
public final class SignatureSelection {
    public record Result(List<File> signatures, boolean success) {
        public Result {
            signatures = List.copyOf(signatures);
        }
    }

    private SignatureSelection() {
    }

    public static Result select(SignatureRepository repository, Program program, String executable,
            int timeoutSeconds, TaskMonitor monitor, MessageLog log)
            throws IOException, CancelledException {
        List<File> selected = new ArrayList<>();
        boolean success = true;
        try (YaraSignatureGate gate = new YaraSignatureGate(program, executable, timeoutSeconds)) {
            for (SignatureRepository.Group group : repository.groups()) {
                monitor.checkCancelled();
                var enabled = group.signatures().stream().filter(repository::isEnabled).toList();
                if (enabled.isEmpty()) {
                    continue;
                }
                if (group.yaraRule() != null) {
                    monitor.setMessage("Checking YARA for signature group: " + group.name());
                    try {
                        boolean matched = gate.matches(repository.validatePath(group.yaraRule()), monitor);
                        log.appendMsg("SigAnalyzer", "YARA [" + group.name() + "]: " +
                            (matched ? "matched" : "no match; group skipped"));
                        if (!matched) {
                            continue;
                        }
                    }
                    catch (IOException e) {
                        monitor.checkCancelled();
                        log.appendMsg("SigAnalyzer", "YARA [" + group.name() + "]: group skipped: " + e.getMessage());
                        success = false;
                        continue;
                    }
                }
                for (var signature : enabled) {
                    selected.add(repository.validatePath(signature).toFile());
                }
            }
        }
        return new Result(selected, success);
    }
}
