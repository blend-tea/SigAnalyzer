[日本語版README](README_ja.md)
# SigAnalyzer
A Ghidra plugin that applies IDA's FLIRT signatures to Ghidra.

## Installation

Use **Ghidra 12.2** with **JDK 25**. Download the extension ZIP from
[Releases](https://github.com/blend-tea/SigAnalyzer/releases), install it using
**File → Install Extensions** in the Ghidra project window, and restart Ghidra.
Enable **SigAnalyzerPlugin** in the CodeBrowser's plugin configuration if its menu
is not visible. Extension archives are specific to the Ghidra version they were built against.

SigAnalyzer is added to the Analyzer.

A menu is added under **Tools** where you can add/remove signatures and choose which files to exclude from the Analyzer.

## Usage

### Adding FLIRT Signatures

![Open SigAnalyzer](./images/OpenSigAnalyzer.png)

Select **Tools → SigAnalyzer → Open SigAnalyzer**.

![SigAnalyzer Menu](./images/Menu.png)

From here you can add or remove FLIRT signatures.

## Added FLIRT Signatures
A new `signatures` folder is created under GhidraUserSettingsDir. Directories are created per processor name, and `.sig` files are copied there. Excluded files are listed in `config.json`.

## One Shot Analyze
You may need to run **Demangler Microsoft** or **Demangler Rust** as needed. With normal Auto Analyze, SigAnalyzer runs before the Demangler, so this is usually not required.

The analyzer applies names to existing functions and preserves program entry
points and user-defined names. Choose signatures for the program's processor,
platform and ABI. Referenced-function constraints must be resolved before a
module can match. SigAnalyzer does not discover or create missing functions.

## Function ID and ambiguous matches

SigAnalyzer runs after **Function ID** and before demanglers. Functions marked
by Function ID are excluded, including FID conflicts and matches for which
FID's analysis bookmarks were disabled. Identification uses FID bookmarks,
plate comments and conflict labels, rather than treating every analysis name
as a Function ID result.

All enabled FLIRT signatures are checked before a name is applied. When a
function has multiple distinct candidate names, its current name and comment
are retained. The **FLIRT Conflicts** window opens after analysis and lists the
address, current name, candidate name, signature file and library. Double-click
a row or press Enter to navigate to the function. Reopen the latest report with
**Tools → SigAnalyzer → FLIRT Conflicts**. The report is kept for the current
Ghidra session and is replaced when analysis completes again.

Several signatures that agree on the same name do not create a conflict.
Unique matches get a function-entry plate comment with a **SigAnalyzer FLIRT**
block listing the name and signature/library provenance. Existing comments are
preserved, and running the analyzer again updates the block without duplicating it.
Unresolved or ambiguous callee names cannot establish a referenced-function match.

## Build and test

Install JDK 25 and extract the official
[Ghidra 12.2 distribution](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build).
The Gradle wrapper downloads the pinned Gradle version and verifies its checksum.

```sh
export JAVA_HOME=/path/to/jdk-25
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew --no-daemon clean test buildExtension
src/test/run-headless.sh
```

The installable extension is written to `dist/`; JUnit results are in
`build/reports/tests/test/`. The headless test temporarily installs the built ZIP
and restores any existing SigAnalyzer extension afterwards.
See [the FLIRT implementation review](docs/FLIRT_REVIEW.md)
for format references and regression coverage.

## CI and releases

GitHub Actions tests and packages the extension on pushes and pull requests.
It downloads the pinned Ghidra distribution and verifies its SHA-256 checksum.
To release, update `version` in `gradle.properties`, commit the changes, and push
a matching `vX.Y.Z` tag. After the build and tests pass, the workflow publishes a
GitHub Release with the extension ZIP. The release job uses the repository's
`GITHUB_TOKEN` with `contents: write` permission.
