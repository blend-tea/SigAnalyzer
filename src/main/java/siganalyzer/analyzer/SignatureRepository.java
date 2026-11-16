package siganalyzer.analyzer;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

/** Processor-specific signature groups. Each directory owns only its direct signatures. */
public final class SignatureRepository {
    public static final String RULE_FILE = "rules.yar";

    public record Group(Path directory, String name, List<Path> signatures, Path yaraRule) {
        public Group {
            signatures = List.copyOf(signatures);
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private final Path root;
    private Set<Path> disabled;

    public SignatureRepository(Path directory) throws IOException {
        Files.createDirectories(directory);
        root = directory.toRealPath();
        disabled = readDisabled(readConfig());
    }

    public Path root() {
        return root;
    }

    /** Validate both existing and not-yet-created paths, without following group symlinks. */
    public Path validatePath(Path path) throws IOException {
        Path normalized = (path.isAbsolute() ? path : root.resolve(path)).toAbsolutePath().normalize();
        if (!normalized.startsWith(root)) {
            throw new IOException("Path is outside the signature repository: " + path);
        }
        Path current = root;
        for (Path element : root.relativize(normalized)) {
            current = current.resolve(element);
            if (Files.isSymbolicLink(current)) {
                throw new IOException("Symbolic links are not supported in signature groups: " + current);
            }
        }
        return normalized;
    }

    public List<Group> groups() throws IOException {
        List<Path> directories;
        try (var paths = Files.walk(root)) {
            directories = paths.filter(path -> Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
                .sorted(Comparator.comparing(path -> root.relativize(path).toString())).toList();
        }
        List<Group> result = new ArrayList<>();
        for (Path directory : directories) {
            result.add(group(directory));
        }
        return List.copyOf(result);
    }

    private Group group(Path directory) throws IOException {
        List<Path> signatures;
        try (var paths = Files.list(directory)) {
            signatures = paths.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".sig"))
                .sorted(Comparator.comparing(path -> path.getFileName().toString())).toList();
        }
        Path rule = directory.resolve(RULE_FILE);
        return new Group(directory, root.equals(directory) ? "(default)" : relativeName(directory),
            signatures, Files.exists(rule, LinkOption.NOFOLLOW_LINKS) ? rule : null);
    }

    public Group createGroup(String name) throws IOException {
        if (name == null || name.isBlank()) {
            throw new IOException("Group name cannot be empty");
        }
        Path relative;
        try {
            relative = Path.of(name);
        }
        catch (IllegalArgumentException e) {
            throw new IOException("Invalid group name", e);
        }
        if (relative.isAbsolute()) {
            throw new IOException("Group name must be relative to the signature directory");
        }
        for (Path element : relative) {
            if (element.toString().equals("..") || element.toString().equals(".")) {
                throw new IOException("Group names cannot contain '.' or '..' components");
            }
        }
        Path directory = validatePath(relative);
        if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Group already exists: " + name);
        }
        Files.createDirectories(directory);
        return group(directory);
    }

    public boolean isEnabled(Path signature) {
        Path path = (signature.isAbsolute() ? signature : root.resolve(signature)).normalize();
        return !disabled.contains(path);
    }

    public void setEnabled(Path signature, boolean enabled) throws IOException {
        Path path = signaturePath(signature);
        JsonObject config = readConfig();
        Set<Path> updated = readDisabled(config);
        if (enabled) {
            updated.remove(path);
        }
        else {
            updated.add(path);
        }
        writeConfig(config, updated);
        disabled = updated;
    }

    public Path moveSignature(Path signature, Group destination) throws IOException {
        Path source = signaturePath(signature);
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Source signature no longer exists or is not a file: " + source);
        }
        Path directory = validatePath(destination.directory());
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Destination group no longer exists");
        }
        Path target = signaturePath(directory.resolve(source.getFileName()));
        if (source.equals(target)) {
            return source;
        }
        JsonObject config = readConfig();
        Set<Path> updated = readDisabled(config);
        boolean wasDisabled = updated.remove(source);
        updated.remove(target);
        if (wasDisabled) {
            updated.add(target);
        }
        Files.move(source, target);
        try {
            writeConfig(config, updated);
        }
        catch (IOException e) {
            try {
                Files.move(target, source);
            }
            catch (IOException rollback) {
                e.addSuppressed(rollback);
            }
            throw e;
        }
        disabled = updated;
        return target;
    }

    public String relativeName(Path path) {
        return root.relativize(path.toAbsolutePath().normalize()).toString().replace('\\', '/');
    }

    private Path signaturePath(Path path) throws IOException {
        Path validated = validatePath(path);
        if (!validated.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".sig")) {
            throw new IOException("Expected a .sig file: " + path);
        }
        return validated;
    }

    private JsonObject readConfig() throws IOException {
        Path config = validatePath(root.resolve("config.json"));
        if (!Files.exists(config, LinkOption.NOFOLLOW_LINKS)) {
            return new JsonObject();
        }
        try (Reader reader = Files.newBufferedReader(config, StandardCharsets.UTF_8)) {
            JsonElement value = JsonParser.parseReader(reader);
            if (!value.isJsonObject()) {
                throw new IOException("Signature config.json must contain an object");
            }
            return value.getAsJsonObject();
        }
        catch (JsonParseException e) {
            throw new IOException("Invalid signature config.json: " + e.getMessage(), e);
        }
    }

    private Set<Path> readDisabled(JsonObject config) throws IOException {
        Set<Path> paths = new LinkedHashSet<>();
        JsonElement values = config.get("Disable");
        if (values == null) {
            return paths;
        }
        if (!values.isJsonArray()) {
            throw new IOException("Signature config.json Disable must be an array");
        }
        for (JsonElement value : values.getAsJsonArray()) {
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
                throw new IOException("Signature config.json Disable entries must be strings");
            }
            try {
                Path path = Path.of(value.getAsString());
                path = (path.isAbsolute() ? path : root.resolve(path)).normalize();
                // Existing releases stored absolute paths; new writes use portable relative paths.
                if (path.startsWith(root)) {
                    paths.add(path);
                }
            }
            catch (IllegalArgumentException e) {
                throw new IOException("Invalid disabled signature path", e);
            }
        }
        return paths;
    }

    private void writeConfig(JsonObject config, Set<Path> paths) throws IOException {
        JsonArray values = new JsonArray();
        paths.stream().map(this::relativeName).sorted().forEach(values::add);
        config.add("Disable", values);
        Path temporary = Files.createTempFile(root, ".config-", ".json");
        try {
            Files.writeString(temporary, new GsonBuilder().setPrettyPrinting().create().toJson(config),
                StandardCharsets.UTF_8);
            try {
                Files.move(temporary, root.resolve("config.json"), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            }
            catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, root.resolve("config.json"), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        finally {
            Files.deleteIfExists(temporary);
        }
    }
}
