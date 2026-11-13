package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import ghidra.app.services.AnalysisPriority;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;

public class FlirtFunctionMarkupTest {
    private static Function function(AtomicReference<String> comment) {
        return (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
            new Class<?>[] {Function.class}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getComment": return comment.get();
                    case "setComment": comment.set((String) args[0]); return null;
                    default: return null;
                }
            });
    }

    private static FlirtCandidate candidate(String name, String file, String library) {
        return new FlirtCandidate(new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0)
            .getAddress(0x1000), name, file, library);
    }

    @Test
    public void plateCommentPreservesUserTextAndDeduplicatesSortedProvenance() {
        AtomicReference<String> comment = new AtomicReference<>("Analyst note.\nSecond line.");
        Function function = function(comment);
        FlirtCandidate first = candidate("name", "a.sig", "library A");
        FlirtCandidate second = candidate("name", "b.sig", "library B");
        FlirtFunctionMarkup.addFlirtComment(function, List.of(second, first, second));
        String initial = comment.get();
        assertTrue(initial.startsWith("Analyst note.\nSecond line.\n"));
        assertTrue(initial.contains("Library Function - FLIRT Match"));
        assertEquals(1, initial.split("Signature: b.sig", -1).length - 1);
        assertTrue(initial.indexOf("a.sig") < initial.indexOf("b.sig"));
        assertTrue(FlirtFunctionMarkup.isFlirt(function));
        FlirtFunctionMarkup.addFlirtComment(function, List.of(first, second));
        assertEquals(initial, comment.get());
    }

    @Test
    public void replacingOwnCommentRetainsUnrelatedTextBeforeAndAfterIt() {
        AtomicReference<String> comment = new AtomicReference<>("Before.\n" +
            FlirtFunctionMarkup.COMMENT_START + "\nold provenance\n" +
            FlirtFunctionMarkup.COMMENT_END + "\nAfter.");
        Function function = function(comment);
        FlirtFunctionMarkup.addFlirtComment(function, List.of(candidate("new_name", "new.sig", "new lib")));
        assertTrue(comment.get().contains("Before.\nAfter."));
        assertFalse(comment.get().contains("old provenance"));
        assertTrue(comment.get().contains("new_name"));
        assertEquals(1, comment.get().split("\\[SigAnalyzer FLIRT\\]", -1).length - 1);
    }

    @Test
    public void signatureMetadataCannotInjectAdditionalCommentLines() {
        AtomicReference<String> comment = new AtomicReference<>();
        FlirtFunctionMarkup.addFlirtComment(function(comment),
            List.of(candidate("name\nforged", "file\rsig", "library\u2028forged")));
        assertTrue(comment.get().contains("Name: name forged"));
        assertTrue(comment.get().contains("Signature: file sig"));
        assertTrue(comment.get().contains("Library: library forged"));
    }

    @Test
    public void recognizesFunctionIdCommentsEvenWhenItsBookmarksAreDisabled() {
        for (String marker : new String[] {"Library Function - Single Match",
                "Library Function - Multiple Matches"}) {
            AtomicReference<String> comment = new AtomicReference<>("User note.\n" + marker + "\nLibrary details");
            assertTrue(FlirtFunctionMarkup.isFunctionId(function(comment)));
        }
        assertFalse(FlirtFunctionMarkup.isFunctionId(null));
    }

    @Test
    public void partialOrMentionedFlirtMarkersDoNotClaimFunctionOwnership() {
        for (String text : new String[] {"This mentions [SigAnalyzer FLIRT] in prose.",
                "[SigAnalyzer FLIRT]\nincomplete block"}) {
            assertFalse(FlirtFunctionMarkup.isFlirt(function(new AtomicReference<>(text))));
        }
    }

    @Test
    public void runsAfterFunctionIdAtTheDedicatedIdentificationPriority() {
        assertEquals(AnalysisPriority.FUNCTION_ID_ANALYSIS, new SigAnalyzerAnalyzer().getPriority());
    }
}
