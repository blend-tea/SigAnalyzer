package siganalyzer.analyzer;

import java.util.List;

import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/** Applies an explicitly selected, still-current conflict candidate. */
public final class FlirtConflictResolution {
    private FlirtConflictResolution() {
    }

    public static boolean canApply(Program program, FlirtCandidate candidate) {
        try {
            requireApplicable(program, candidate, false);
            return true;
        }
        catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * The explicit choice may replace an ordinary user-defined name. FID,
     * imported names and external entry points remain protected. The selected
     * name and its plate comment are one undoable program transaction.
     *
     * @return the remaining conflict rows, published only after the transaction commits
     */
    public static List<FlirtCandidate> apply(Program program, FlirtCandidate candidate)
            throws DuplicateNameException, InvalidInputException {
        requireApplicable(program, candidate, false);
        int transaction = program.startTransaction("Apply FLIRT candidate " + candidate.name());
        boolean commit = false;
        boolean committed;
        String chosenComment = null;
        try {
            TransactionInfo info = program.getCurrentTransactionInfo();
            if (info == null || info.getOpenSubTransactions().size() != 1) {
                // Avoid marking a concurrent transaction aborted when no changes were made.
                commit = true;
                throw new IllegalStateException("The program became busy. Wait for analysis to finish.");
            }
            Function function = requireApplicable(program, candidate, true);
            List<FlirtCandidate> current = FlirtAnalysisResults.get(program);
            if (!current.contains(candidate)) {
                throw new IllegalArgumentException("This candidate is no longer in the current conflict results.");
            }
            List<FlirtCandidate> provenance = current.stream()
                .filter(row -> row.address().equals(candidate.address()) &&
                    row.name().equals(candidate.name()))
                .toList();
            function.setName(candidate.name(), SourceType.USER_DEFINED);
            FlirtFunctionMarkup.addFlirtComment(function, provenance);
            chosenComment = function.getComment();
            commit = true;
        }
        finally {
            // A nested transaction is not a committed edit. Never remove its report rows early.
            committed = program.endTransaction(transaction, commit);
        }
        if (!committed) {
            throw new IllegalStateException("The FLIRT choice was not committed. Conflict results were kept.");
        }
        return FlirtAnalysisResults.resolveChoice(program, candidate, chosenComment);
    }

    private static Function requireApplicable(Program program, FlirtCandidate candidate,
            boolean insideTransaction) {
        if (program == null || program.isClosed()) {
            throw new IllegalStateException("The program is closed.");
        }
        if (!program.isChangeable()) {
            throw new IllegalStateException("The program is read-only.");
        }
        if (!insideTransaction && (program.isLocked() || program.getCurrentTransactionInfo() != null)) {
            throw new IllegalStateException("The program is busy. Wait for analysis to finish.");
        }
        if (candidate == null || !FlirtAnalysisResults.get(program).contains(candidate)) {
            throw new IllegalArgumentException("This candidate is no longer in the current conflict results.");
        }
        Function function = program.getFunctionManager().getFunctionAt(candidate.address());
        if (function == null) {
            throw new IllegalStateException("The candidate's function no longer exists.");
        }
        if (FlirtFunctionMarkup.isFunctionId(function)) {
            throw new IllegalStateException("Function ID has identified this function.");
        }
        if (function.isExternal() || function.getSymbol().getSource() == SourceType.IMPORTED) {
            throw new IllegalStateException("Imported function names are protected.");
        }
        if (program.getSymbolTable().isExternalEntryPoint(candidate.address())) {
            throw new IllegalStateException("Program entry points are protected.");
        }
        return function;
    }
}
