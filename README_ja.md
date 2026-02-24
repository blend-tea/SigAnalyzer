# SigAnalyzer
IDAのFLIRTシグネチャをGhidraに適応するPlugin

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