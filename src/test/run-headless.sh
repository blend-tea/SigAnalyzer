#!/usr/bin/env bash
set -euo pipefail

# Run after ./gradlew test buildExtension against the same Ghidra installation.
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to the Ghidra installation directory}"
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ghidra_dir=$(cd "$GHIDRA_INSTALL_DIR" && pwd)
test -x "$ghidra_dir/support/analyzeHeadless"
shopt -s nullglob
archives=("$repo_dir"/dist/ghidra_*_SigAnalyzer-*.zip)
if (( ${#archives[@]} != 1 )); then
    echo 'Expected one extension ZIP in dist; run ./gradlew clean test buildExtension first.' >&2
    exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/siganalyzer-headless.XXXXXX")
extension_dir="$ghidra_dir/Ghidra/Extensions/SigAnalyzer"
installed=false
cleanup() {
    if [[ "$installed" == true ]]; then
        rm -rf -- "$extension_dir"
    fi
    if [[ -d "$work_dir/previous-extension" ]]; then
        mv "$work_dir/previous-extension" "$extension_dir"
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT
if [[ -e "$extension_dir" ]]; then
    mv "$extension_dir" "$work_dir/previous-extension"
fi
installed=true
unzip -q "${archives[0]}" -d "$ghidra_dir/Ghidra/Extensions"
printf '\303' > "$work_dir/fixture.bin"
mkdir "$work_dir/project"
"$ghidra_dir/support/analyzeHeadless" "$work_dir/project" SigAnalyzerSmoke \
    -import "$work_dir/fixture.bin" -loader BinaryLoader \
    -processor x86:LE:64:default -cspec gcc -noanalysis \
    -scriptPath "$repo_dir/src/test/ghidra_scripts" \
    -postScript SigAnalyzerSmokeTest.java -deleteProject 2>&1 | tee "$work_dir/headless.log"
# Ghidra can return zero even when a post-script throws an exception.
grep -q 'SIGANALYZER_SMOKE_TEST_PASSED' "$work_dir/headless.log"
