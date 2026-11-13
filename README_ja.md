# SigAnalyzer
IDAのFLIRTシグネチャをGhidraに適応するPlugin

## インストール

**Ghidra 12.2 / JDK 25** に対応しています。
[Releases](https://github.com/blend-tea/SigAnalyzer/releases) から拡張 ZIP を取得し、
Ghidra のプロジェクト画面で **File → Install Extensions** からインストールして再起動してください。
メニューが表示されない場合は CodeBrowser のプラグイン設定で **SigAnalyzerPlugin** を有効にします。
拡張 ZIP はビルド対象の Ghidra バージョン専用です。

AnalyzerにSigAnalyzerが追加される。

Toolsに追加されるメニューでsigの追加・削除、Analyzerから除外するファイルの選択ができる。

## 使い方

### FLIRTシグネチャの追加

![Open SigAnalyzer](./images/OpenSigAnalyzer.png)

Tools -> SigAnalyzer -> Open SigAnalyzer を選択する。

![SigAnalyzer Menu](./images/Menu.png)

ここからFLIRTシグネチャの追加・削除ができる。

## 追加したFLIRTシグネチャ
GhidraUserSettingsDirに新しくsignaturesが生成され、processorNameごとのDirectoryが生成され、ここに.sigファイルがコピーされる。
config.jsonに除外対象のファイルが記述される。

## One Shot Analyze
必要に応じてDemangler MicrosoftやDemangler Rustを実行する必要がある。
通常のAuto AnalyzeではDemanglerの前にSigAnalyzerが動くようになっているので不要。

既存の関数に名前を適用し、プログラムのエントリーポイントとユーザー定義の名前を保持します。
対象のプロセッサ・プラットフォーム・ABI に合うシグネチャを選んでください。
参照先関数の条件を確認できないモジュールは適用を保留します。
未定義の関数を新しく作成する機能はありません。

## ビルドとテスト

JDK 25 をインストールし、公式の
[Ghidra 12.2 配布物](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build)
を展開してください。Gradle Wrapper が指定バージョンの Gradle を取得し、チェックサムを検証します。

```sh
export JAVA_HOME=/path/to/jdk-25
export PATH="$JAVA_HOME/bin:$PATH"
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew --no-daemon clean test buildExtension
src/test/run-headless.sh
```

インストール用 ZIP は `dist/`、JUnit の結果は `build/reports/tests/test/` に生成されます。
headless テストは生成した ZIP を一時導入し、既存の SigAnalyzer 拡張があれば終了時に復元します。
FLIRT の比較対象と回帰テストの詳細は [実装レビュー](docs/FLIRT_REVIEW.md) を参照してください。

## CI / Release

GitHub Actions で push・pull request 時にテストと拡張のビルドを実行します。
Ghidra の配布物はバージョンを固定し、SHA-256 を確認して使用します。
リリース時は `gradle.properties` の `version` を更新してコミットし、対応する `vX.Y.Z` タグを push します。
ビルドとテストに成功すると、拡張 ZIP を添付した GitHub Release が作成されます。
公開ジョブには `contents: write` を付与したリポジトリの `GITHUB_TOKEN` を使用します。
