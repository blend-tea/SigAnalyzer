package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;

public class FlirtAnalysisResultsTest {
    private static Program program() {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] {Program.class}, (proxy, method, arguments) -> {
                switch (method.getName()) {
                    case "hashCode": return System.identityHashCode(proxy);
                    case "equals": return proxy == arguments[0];
                    case "toString": return "synthetic program";
                    default: return null;
                }
            });
    }

    private static FlirtCandidate candidate(String name) {
        return new FlirtCandidate(new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0)
            .getAddress(0x1000), name, "synthetic.sig", "synthetic library");
    }

    @Test
    public void snapshotsAreImmutableAndSeparateForEachProgram() {
        Program first = program();
        Program second = program();
        List<FlirtCandidate> mutable = new ArrayList<>(List.of(candidate("first")));
        try {
            FlirtAnalysisResults.publish(first, mutable);
            mutable.clear();
            FlirtAnalysisResults.publish(second, List.of(candidate("second")));
            assertEquals("first", FlirtAnalysisResults.get(first).get(0).name());
            assertEquals("second", FlirtAnalysisResults.get(second).get(0).name());
            try {
                FlirtAnalysisResults.get(first).clear();
                fail("a caller must not modify the completed report");
            }
            catch (UnsupportedOperationException expected) {
                // Completed reports are immutable snapshots.
            }
        }
        finally {
            FlirtAnalysisResults.clear(first);
            FlirtAnalysisResults.clear(second);
        }
    }

    @Test
    public void clearingAProgramPublishesAnEmptyReportAndDetachedListenersStayDetached() {
        Program program = program();
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<List<FlirtCandidate>> last = new AtomicReference<>();
        FlirtAnalysisResults.Listener listener = (changed, candidates) -> {
            assertSame(program, changed);
            calls.incrementAndGet();
            last.set(candidates);
        };
        try {
            FlirtAnalysisResults.addListener(listener);
            FlirtAnalysisResults.addListener(listener);
            FlirtAnalysisResults.publish(program, List.of(candidate("candidate")));
            assertEquals(1, calls.get());
            assertEquals(1, last.get().size());
            FlirtAnalysisResults.clear(program);
            assertTrue(FlirtAnalysisResults.get(program).isEmpty());
            assertTrue(last.get().isEmpty());
            assertEquals(2, calls.get());
            FlirtAnalysisResults.removeListener(listener);
            FlirtAnalysisResults.publish(program, List.of(candidate("later")));
            assertEquals(2, calls.get());
        }
        finally {
            FlirtAnalysisResults.removeListener(listener);
            FlirtAnalysisResults.clear(program);
        }
    }

    @Test
    public void aFailedWindowListenerDoesNotLoseTheReportOrOtherNotifications() {
        Program program = program();
        AtomicInteger delivered = new AtomicInteger();
        FlirtAnalysisResults.Listener broken = (changed, candidates) -> {
            throw new IllegalStateException("synthetic disposed window");
        };
        FlirtAnalysisResults.Listener remaining = (changed, candidates) -> delivered.incrementAndGet();
        try {
            FlirtAnalysisResults.addListener(broken);
            FlirtAnalysisResults.addListener(remaining);
            FlirtAnalysisResults.publish(program, List.of(candidate("retained")));
            assertEquals("retained", FlirtAnalysisResults.get(program).get(0).name());
            assertEquals(1, delivered.get());
        }
        finally {
            FlirtAnalysisResults.removeListener(broken);
            FlirtAnalysisResults.removeListener(remaining);
            FlirtAnalysisResults.clear(program);
        }
    }
}
