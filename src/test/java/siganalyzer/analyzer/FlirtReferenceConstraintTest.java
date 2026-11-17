package siganalyzer.analyzer;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

public class FlirtReferenceConstraintTest {
    @Test
    public void optionalEvidenceIsDeferredUntilMandatoryCandidatesHaveBeenPruned() {
        Address target = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0).getAddress(0x1000);
        var optional = new FlirtAnalysisSession.ReferenceConstraint("expected", List.of(target),
            Set.of(), Map.of(), true, true);
        Map<Address, Set<String>> temporaryEvidence = Map.of(target, Set.of("wrong_candidate"));
        assertTrue(optional.possible(temporaryEvidence));
        assertTrue(optional.possible(Map.of()));
        assertFalse(optional.resolved(Map.of(), temporaryEvidence));
        assertTrue(optional.resolved(Map.of(), Map.of()));

        var mandatory = new FlirtAnalysisSession.ReferenceConstraint("expected", List.of(target),
            Set.of(), Map.of());
        assertFalse(mandatory.possible(temporaryEvidence));
        assertTrue(mandatory.possible(Map.of(target, Set.of("expected"))));
    }
}
