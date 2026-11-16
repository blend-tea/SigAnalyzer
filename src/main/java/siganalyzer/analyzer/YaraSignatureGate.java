package siganalyzer.analyzer;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Runs native YARA against the original imported file stored in the program database.
 * A gate is scoped to one analysis session and prepares its temporary target only when used.
 * If several imports are stored, the executable filename is preferred, followed by the
 * program name, then the first stored import. FileBytes offsets into archive containers
 * are not prepended to the extracted member's bytes.
 */
public final class YaraSignatureGate implements AutoCloseable {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final int OUTPUT_LIMIT = 32 * 1024;
    private static final int LINE_LIMIT = 8192;
    private static final int DIAGNOSTIC_LIMIT = 2000;

    private final Program program;
    private final String executable;
    private final int timeoutSeconds;
    private Path target;
    private IOException preparationFailure;
    private boolean closed;

    public YaraSignatureGate(Program program, String executable, int timeoutSeconds) {
        this.program = Objects.requireNonNull(program);
        this.executable = executable == null || executable.isBlank() ? "yara" : executable.strip();
        this.timeoutSeconds = timeoutSeconds;
    }

    /**
     * A valid zero match count returns false. An unavailable engine, invalid rule,
     * timeout or unexpected CLI response is an error so the caller can report the
     * skipped group rather than mistake a failure for a normal non-match.
     */
    public boolean matches(Path ruleFile, TaskMonitor monitor)
            throws IOException, CancelledException {
        Objects.requireNonNull(ruleFile);
        Objects.requireNonNull(monitor);
        if (closed) {
            throw new IOException("The YARA signature gate is closed");
        }
        if (timeoutSeconds <= 0) {
            throw new IOException("YARA Timeout Seconds must be greater than zero");
        }
        monitor.checkCancelled();
        Path rule = ruleFile.toAbsolutePath().normalize();
        if (!Files.isRegularFile(rule)) {
            throw new IOException("YARA rule file does not exist: " + rule);
        }
        Path scanTarget = prepareTarget(monitor);
        monitor.checkCancelled();

        // Count mode also avoids mistaking console.log() output for a rule match.
        ProcessBuilder builder = new ProcessBuilder(executable, "-c",
            "--timeout=" + timeoutSeconds, rule.toString(), scanTarget.toString());
        builder.directory(rule.getParent().toFile());
        long started = System.nanoTime();
        long timeoutNanos = TimeUnit.SECONDS.toNanos(timeoutSeconds);
        Process process;
        try {
            process = builder.start();
        }
        catch (IOException e) {
            throw new IOException("Cannot start YARA executable '" + executable + "': " +
                e.getMessage(), e);
        }
        ProcessOutput stdout = new ProcessOutput(process.getInputStream());
        ProcessOutput stderr = new ProcessOutput(process.getErrorStream());
        Thread stdoutThread = drainer(stdout, "stdout");
        Thread stderrThread = drainer(stderr, "stderr");
        try {
            process.getOutputStream().close();
            while (!process.waitFor(100, TimeUnit.MILLISECONDS)) {
                checkRunning(monitor, started, timeoutNanos);
            }
            while (stdoutThread.isAlive() || stderrThread.isAlive()) {
                checkRunning(monitor, started, timeoutNanos);
                stdoutThread.join(50);
                stderrThread.join(50);
            }
            monitor.checkCancelled();
            if (process.exitValue() != 0) {
                String diagnostic = stderr.diagnostic();
                if (diagnostic.isEmpty()) {
                    diagnostic = stdout.diagnostic();
                }
                throw new IOException("YARA exited with status " + process.exitValue() +
                    (diagnostic.isEmpty() ? "" : ": " + diagnostic));
            }
            if (stdout.failure != null || stderr.failure != null) {
                throw new IOException("Cannot read YARA output",
                    stdout.failure != null ? stdout.failure : stderr.failure);
            }
            String count = stdout.lastNonEmptyLine;
            if (count == null || !count.matches("[0-9]+")) {
                throw new IOException("YARA did not return a valid match count");
            }
            try {
                return Long.parseLong(count) > 0;
            }
            catch (NumberFormatException e) {
                throw new IOException("YARA returned an invalid match count", e);
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            monitor.checkCancelled();
            throw new IOException("Interrupted while waiting for YARA", e);
        }
        finally {
            terminate(process);
            closeQuietly(process.getInputStream());
            closeQuietly(process.getErrorStream());
            closeQuietly(process.getOutputStream());
        }
    }

    private static void checkRunning(TaskMonitor monitor, long started, long timeoutNanos)
            throws CancelledException, IOException {
        monitor.checkCancelled();
        if (System.nanoTime() - started >= timeoutNanos) {
            throw new IOException("YARA scan timed out");
        }
    }

    private Path prepareTarget(TaskMonitor monitor) throws IOException, CancelledException {
        if (target != null) {
            return target;
        }
        if (preparationFailure != null) {
            throw new IOException(preparationFailure.getMessage(), preparationFailure);
        }
        Path temporary = null;
        try {
            FileBytes source = selectOriginalBytes();
            temporary = Files.createTempFile("siganalyzer-yara-", ".bin");
            try (OutputStream output = Files.newOutputStream(temporary)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                long offset = 0;
                while (offset < source.getSize()) {
                    monitor.checkCancelled();
                    int length = (int) Math.min(buffer.length, source.getSize() - offset);
                    int read = source.getOriginalBytes(offset, buffer, 0, length);
                    if (read <= 0 || read > length) {
                        throw new IOException("Cannot read the original imported file bytes");
                    }
                    output.write(buffer, 0, read);
                    offset += read;
                }
            }
            monitor.checkCancelled();
            target = temporary;
            temporary = null;
            return target;
        }
        catch (ConcurrentModificationException | IndexOutOfBoundsException e) {
            preparationFailure = new IOException("The original imported file bytes changed", e);
            throw preparationFailure;
        }
        catch (IOException e) {
            preparationFailure = e;
            throw e;
        }
        finally {
            if (temporary != null) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private FileBytes selectOriginalBytes() throws IOException {
        List<FileBytes> sources = program.getMemory().getAllFileBytes();
        if (sources.isEmpty()) {
            throw new IOException("No original imported file bytes are stored in this program");
        }
        String executablePath = program.getExecutablePath();
        if (executablePath != null && !executablePath.isEmpty()) {
            for (FileBytes source : sources) {
                if (Objects.equals(source.getFilename(), executablePath)) {
                    return source;
                }
            }
            for (FileBytes source : sources) {
                if (basename(source.getFilename()).equals(basename(executablePath))) {
                    return source;
                }
            }
        }
        String programName = program.getName();
        for (FileBytes source : sources) {
            if (basename(source.getFilename()).equals(basename(programName))) {
                return source;
            }
        }
        return sources.get(0);
    }

    private static String basename(String filename) {
        if (filename == null) {
            return "";
        }
        String normalized = filename.replace('\\', '/');
        return normalized.substring(normalized.lastIndexOf('/') + 1);
    }

    private static Thread drainer(ProcessOutput output, String stream) {
        Thread thread = new Thread(output, "SigAnalyzer-YARA-" + stream);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void terminate(Process process) {
        if (process.isAlive()) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            try {
                process.waitFor(250, TimeUnit.MILLISECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void closeQuietly(Closeable stream) {
        try {
            stream.close();
        }
        catch (IOException e) {
            // The process is already finished or being terminated.
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
        if (target != null) {
            Files.deleteIfExists(target);
            target = null;
        }
    }

    private static final class ProcessOutput implements Runnable {
        private final InputStream input;
        private final ByteArrayOutputStream preview = new ByteArrayOutputStream();
        private final StringBuilder line = new StringBuilder();
        private boolean longLine;
        private String lastNonEmptyLine;
        private IOException failure;

        ProcessOutput(InputStream input) {
            this.input = input;
        }

        @Override
        public void run() {
            try (input) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    int retained = Math.min(count, OUTPUT_LIMIT - preview.size());
                    if (retained > 0) {
                        preview.write(buffer, 0, retained);
                    }
                    for (int i = 0; i < count; i++) {
                        int value = buffer[i] & 0xff;
                        if (value == '\n') {
                            finishLine();
                        }
                        else if (line.length() < LINE_LIMIT) {
                            line.append((char) value);
                        }
                        else {
                            longLine = true;
                        }
                    }
                }
                finishLine();
            }
            catch (IOException e) {
                failure = e;
            }
        }

        private void finishLine() {
            String value = line.toString().strip();
            if (longLine) {
                lastNonEmptyLine = "[YARA output line exceeded supported length]";
            }
            else if (!value.isEmpty()) {
                lastNonEmptyLine = value;
            }
            line.setLength(0);
            longLine = false;
        }

        String diagnostic() {
            String value = preview.toString(StandardCharsets.UTF_8).strip();
            return value.length() > DIAGNOSTIC_LIMIT ?
                value.substring(0, DIAGNOSTIC_LIMIT) + "..." : value;
        }
    }
}
