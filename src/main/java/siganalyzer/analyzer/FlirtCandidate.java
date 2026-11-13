package siganalyzer.analyzer;

import java.util.Objects;

import ghidra.program.model.address.Address;

/** A verified FLIRT name and the signature that supplied it. */
public record FlirtCandidate(Address address, String name, String signatureFile,
        String libraryName) {
    public FlirtCandidate {
        Objects.requireNonNull(address);
        Objects.requireNonNull(name);
        Objects.requireNonNull(signatureFile);
        libraryName = libraryName == null ? "" : libraryName;
    }
}
