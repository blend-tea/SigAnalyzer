package siganalyzer.analyzer;

import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;

import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

/** Function-identification provenance used when deciding whether FLIRT may rename a function. */
public final class FlirtFunctionMarkup {
    public static final String COMMENT_START = "[SigAnalyzer FLIRT]";
    public static final String COMMENT_END = "[/SigAnalyzer FLIRT]";

    private static final Pattern FLIRT_COMMENT = Pattern.compile(
        "(?ms)^" + Pattern.quote(COMMENT_START) + "\\R.*?^" +
            Pattern.quote(COMMENT_END) + "(?:\\R|$)");
    private static final Pattern FID_COMMENT = Pattern.compile(
        "(?m)^\\h*Library Function - (?:Single Match|Multiple Matches)\\b");

    private FlirtFunctionMarkup() {
    }

    /**
     * FID's bookmarks are optional, but its plate comment is written even when
     * bookmark creation is disabled. Check conflict labels as well, since an
     * ambiguous FID identification must not be replaced by FLIRT either.
     */
    public static boolean isFunctionId(Function function) {
        if (function == null) {
            return false;
        }
        String comment = function.getComment();
        if (comment != null && FID_COMMENT.matcher(comment).find()) {
            return true;
        }
        Program program = function.getProgram();
        BookmarkManager bookmarks = program.getBookmarkManager();
        if (bookmarks.getBookmark(function.getEntryPoint(), BookmarkType.ANALYSIS,
            ApplyFidEntriesCommand.FID_BOOKMARK_CATEGORY) != null ||
            bookmarks.getBookmark(function.getEntryPoint(), BookmarkType.ANALYSIS,
                ApplyFidEntriesCommand.FIDCONFLICT_BOOKMARK_CATEGORY) != null) {
            return true;
        }
        for (Symbol symbol : program.getSymbolTable().getSymbols(function.getEntryPoint())) {
            if (symbol.getName().startsWith(ApplyFidEntriesCommand.FID_CONFLICT)) {
                return true;
            }
        }
        return false;
    }

    /** True only when the function has a complete SigAnalyzer-owned plate-comment block. */
    public static boolean isFlirt(Function function) {
        if (function == null) {
            return false;
        }
        String comment = function.getComment();
        return comment != null && FLIRT_COMMENT.matcher(comment).find();
    }

    /**
     * Add or replace only our delimited block, retaining existing user comments.
     * Sorted provenance makes duplicate signatures and repeated analysis stable.
     */
    public static void addFlirtComment(Function function, List<FlirtCandidate> candidates) {
        if (candidates.isEmpty()) {
            return;
        }
        TreeSet<String> names = new TreeSet<>();
        TreeSet<String> provenance = new TreeSet<>();
        for (FlirtCandidate candidate : candidates) {
            names.add(singleLine(candidate.name()));
            String library = singleLine(candidate.libraryName());
            provenance.add("Signature: " + singleLine(candidate.signatureFile()) +
                "\nLibrary: " + (library.isEmpty() ? "(unnamed library)" : library));
        }
        StringBuilder block = new StringBuilder(COMMENT_START)
            .append("\nLibrary Function - FLIRT Match\nName: ")
            .append(String.join(", ", names));
        for (String source : provenance) {
            block.append('\n').append(source);
        }
        block.append('\n').append(COMMENT_END);

        String existing = function.getComment();
        String preserved = existing == null ? "" :
            FLIRT_COMMENT.matcher(existing).replaceAll("").stripTrailing();
        String updated = preserved.isEmpty() ? block.toString() : preserved + "\n\n" + block;
        if (!updated.equals(existing)) {
            function.setComment(updated);
        }
    }

    private static String singleLine(String text) {
        return text.replaceAll("[\\p{Cntrl}\\p{Zl}\\p{Zp}]", " ");
    }
}
