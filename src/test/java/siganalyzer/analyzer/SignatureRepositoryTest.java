package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.Gson;

public class SignatureRepositoryTest {
    @Rule
    public TemporaryFolder temporary = new TemporaryFolder();

    private Path root() throws IOException {
        return temporary.newFolder("signatures").toPath().toAbsolutePath();
    }

    private static SignatureRepository.Group group(SignatureRepository repository, Path directory)
            throws IOException {
        return repository.groups().stream().filter(group -> group.directory().equals(directory))
            .findFirst().orElseThrow(() -> new AssertionError("Missing group " + directory));
    }

    @Test
    public void flatSignaturesAndLegacyDisabledFilesRemainUsable() throws Exception {
        Path root = root();
        Path enabled = Files.write(root.resolve("enabled.sig"), new byte[] {1});
        Path disabled = Files.write(root.resolve("disabled.sig"), new byte[] {2});
        Files.writeString(root.resolve("config.json"), new Gson().toJson(
            Map.of("Disable", List.of(disabled.toString()))));
        SignatureRepository repository = new SignatureRepository(root);
        SignatureRepository.Group flat = group(repository, root);
        assertEquals(2, flat.signatures().size());
        assertTrue(flat.signatures().contains(enabled));
        assertTrue(flat.signatures().contains(disabled));
        assertNull(flat.yaraRule());
        assertTrue(repository.isEnabled(enabled));
        assertFalse(repository.isEnabled(disabled));
        repository.setEnabled(disabled, true);
        assertTrue(new SignatureRepository(root).isEnabled(disabled));
    }

    @Test
    public void groupsContainOnlyDirectSignaturesAndDoNotInheritParentRules() throws Exception {
        Path root = root();
        Path parent = Files.createDirectories(root.resolve("parent"));
        Path child = Files.createDirectories(parent.resolve("child"));
        Path parentSig = Files.write(parent.resolve("parent.sig"), new byte[] {1});
        Path childSig = Files.write(child.resolve("child.sig"), new byte[] {2});
        Path rule = Files.writeString(parent.resolve(SignatureRepository.RULE_FILE),
            "rule parent_gate { condition: true }");
        SignatureRepository repository = new SignatureRepository(root);
        assertEquals(List.of(parentSig), group(repository, parent).signatures());
        assertEquals(rule, group(repository, parent).yaraRule());
        assertEquals(List.of(childSig), group(repository, child).signatures());
        assertNull("a rule belongs only to its own directory", group(repository, child).yaraRule());
        assertNull(group(repository, root).yaraRule());
        SignatureRepository.Group created = repository.createGroup("empty-group");
        assertEquals(root.resolve("empty-group"), created.directory());
        assertTrue(group(repository, created.directory()).signatures().isEmpty());
    }

    @Test
    public void movingADisabledSignaturePreservesItsSettingAcrossReloads() throws Exception {
        Path root = root();
        SignatureRepository repository = new SignatureRepository(root);
        SignatureRepository.Group sourceGroup = repository.createGroup("source");
        SignatureRepository.Group destination = repository.createGroup("destination");
        Path source = Files.write(sourceGroup.directory().resolve("library.sig"), new byte[] {1, 2, 3});
        repository.setEnabled(source, false);
        Path moved = repository.moveSignature(source, destination);
        assertEquals(destination.directory().resolve("library.sig"), moved);
        assertFalse(Files.exists(source));
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(moved));
        assertFalse(repository.isEnabled(moved));
        SignatureRepository reloaded = new SignatureRepository(root);
        assertFalse(reloaded.isEnabled(moved));
        reloaded.setEnabled(moved, true);
        assertTrue(new SignatureRepository(root).isEnabled(moved));
    }

    @Test
    public void movingDoesNotOverwriteADifferentSignatureWithTheSameFilename() throws Exception {
        Path root = root();
        SignatureRepository repository = new SignatureRepository(root);
        Path source = Files.write(root.resolve("library.sig"), new byte[] {1});
        SignatureRepository.Group destination = repository.createGroup("destination");
        Path existing = Files.write(destination.directory().resolve("library.sig"), new byte[] {2});
        try {
            repository.moveSignature(source, destination);
            fail("an existing destination must not be silently overwritten");
        }
        catch (IOException expected) {
            assertArrayEquals(new byte[] {1}, Files.readAllBytes(source));
            assertArrayEquals(new byte[] {2}, Files.readAllBytes(existing));
        }
    }

    @Test
    public void aDirectoryWithASignatureSuffixCannotBeMovedAsAFile() throws Exception {
        Path root = root();
        SignatureRepository repository = new SignatureRepository(root);
        Path fakeSignature = Files.createDirectory(root.resolve("directory.sig"));
        Files.writeString(fakeSignature.resolve("contents.txt"), "unrelated contents");
        SignatureRepository.Group destination = repository.createGroup("destination");
        try {
            repository.moveSignature(fakeSignature, destination);
            fail("a directory is not a signature file");
        }
        catch (IOException expected) {
            assertTrue(Files.isDirectory(fakeSignature));
            assertTrue(Files.exists(fakeSignature.resolve("contents.txt")));
            assertFalse(Files.exists(destination.directory().resolve("directory.sig")));
        }
    }
}
