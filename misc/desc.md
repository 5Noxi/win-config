# Notepad++

You can either change it yourself in:
```
HKCR\batfile\shell\edit\command
```
or use the following batch, which selects [notepad++](https://notepad-plus-plus.org/downloads/) as default editor.

# StartAllBack Settings

Installation:
```ps
winget install StartIsBack.StartAllBack --scope machine
```

Use [StartMenu-Toggle.bat](https://github.com/5Noxi/win-config/tree/main/system/assets) to toggle the startmenu.

If the search input doesn't work after selecting `Enable`, make sure that `%windir%\System32\ctfmon.exe` exists.

All `StartAllBackCfg.exe` settings (tracked with `procmon` - <#1407139651017510922>), which I currently use:

![](https://github.com/5Noxi/win-config/blob/main/system/images/startallback.png?raw=true)


All values `StartAllBack` reads that are located in `HKCU\Software\StartIsBack` (after clicking on `Properties`):
```ps
"HKCU\Software\StartIsBack\CompactMenus","Length: 16"
"HKCU\Software\StartIsBack\Language","Length: 12"
"HKCU\Software\StartIsBack\Disabled","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\AlterStyle","Length: 12"
"HKCU\Software\StartIsBack\AlterStyle","Type: REG_SZ, Length: 2, Data: "
"HKCU\Software\StartIsBack\Start_LargeAllAppsIcons","Length: 12"
"HKCU\Software\StartIsBack\Start_LargeAllAppsIcons","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\AllProgramsFlyout","Length: 12"
"HKCU\Software\StartIsBack\AllProgramsFlyout","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\StartMetroAppsFolder","Length: 12"
"HKCU\Software\StartIsBack\StartMetroAppsFolder","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\Start_SortOverride","Length: 12"
"HKCU\Software\StartIsBack\Start_SortOverride","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_NotifyNewApps","Length: 12"
"HKCU\Software\StartIsBack\Start_NotifyNewApps","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_AutoCascade","Length: 12"
"HKCU\Software\StartIsBack\Start_AutoCascade","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_LargeSearchIcons","Length: 12"
"HKCU\Software\StartIsBack\Start_LargeSearchIcons","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_AskCortana","Length: 12"
"HKCU\Software\StartIsBack\Start_AskCortana","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\HideUserFrame","Length: 12"
"HKCU\Software\StartIsBack\HideUserFrame","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\Start_RightPaneIcons","Length: 12"
"HKCU\Software\StartIsBack\Start_RightPaneIcons","Type: REG_DWORD, Length: 4, Data: 2"
"HKCU\Software\StartIsBack\Start_ShowUser","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowMyDocs","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowMyDocs","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\Start_ShowMyPics","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowMyPics","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowMyMusic","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowMyMusic","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowVideos","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowDownloads","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowDownloads","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowSkyDrive","Length: 12"
"HKCU\Software\StartIsBack\StartMenuFavorites","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowRecentDocs","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowRecentDocs","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowNetPlaces","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowNetPlaces","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowNetConn","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowNetConn","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowMyComputer","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowMyComputer","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowControlPanel","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowControlPanel","Type: REG_DWORD, Length: 4, Data: 2"
"HKCU\Software\StartIsBack\Start_ShowPCSettings","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowPCSettings","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\Start_AdminToolsRoot","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowPrinters","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowPrinters","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowSetProgramAccessAndDefaults","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowSetProgramAccessAndDefaults","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowTerminal","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowCommandPrompt","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowCommandPrompt","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\Start_ShowRun","Length: 12"
"HKCU\Software\StartIsBack\Start_ShowRun","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\WinkeyFunction","Length: 16"
"HKCU\Software\StartIsBack\Start_MinMFU","Type: REG_DWORD, Length: 4, Data: 13"
"HKCU\Software\StartIsBack\Start_LargeMFUIcons","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\TaskbarStyle","Length: 12"
"HKCU\Software\StartIsBack\TaskbarStyle","Type: REG_SZ, Length: 32, Data: Plain8.msstyles"
"HKCU\Software\StartIsBack\OrbBitmap","Length: 12"
"HKCU\Software\StartIsBack\LegacyTaskbar","Length: 16"
"HKCU\Software\StartIsBack\TaskbarSpacierIcons","Type: REG_DWORD, Length: 4, Data: 4294967295"
"HKCU\Software\StartIsBack\TaskbarLargerIcons","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\TaskbarOneSegment","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\TaskbarCenterIcons","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\FatTaskbar","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\TaskbarGrouping","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\TaskbarTranslucentEffect","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\FrameStyle","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\NavBarGlass","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\OldSearch","Length: 16"
"HKCU\Software\StartIsBack\DriveGrouping","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\NoXAMLMenus","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\BottomDetails","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\RestyleControls","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\UndeadControlPanel","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\RestyleIcons","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\StartMenuColor","Length: 16"
"HKCU\Software\StartIsBack\StartMenuAlpha","Length: 16"
"HKCU\Software\StartIsBack\StartMenuBlur","Length: 16"
"HKCU\Software\StartIsBack\TaskbarColor","Length: 16"
"HKCU\Software\StartIsBack\TaskbarAlpha","Length: 16"
"HKCU\Software\StartIsBack\TaskbarBlur","Length: 16"
"HKCU\Software\StartIsBack\DarkMagic","Length: 16"
"HKCU\Software\StartIsBack\DarkMagic\Unround","Length: 16"
"HKCU\Software\StartIsBack\SysTrayStyle","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\SysTrayLocation","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\SysTrayMicrophone","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\SysTrayVolume","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\SysTrayNetwork","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\SysTrayPower","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\SysTrayInputSwitch","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\TaskbarControlCenter","Type: REG_DWORD, Length: 4, Data: 0"
"HKCU\Software\StartIsBack\SysTraySpacierIcons","Type: REG_DWORD, Length: 4, Data: 1"
"HKCU\Software\StartIsBack\MinimalSecondarySysTray","Length: 16"
"HKCU\Software\StartIsBack\DarkMagicDLL","Length: 16"
"HKCU\Software\StartIsBack\NoDarkRun","Length: 16"
"HKCU\Software\StartIsBack\JumpListBorder","Length: 16"
```

# System Informer

Since system informer is a lot better than the default task manager, it is recommended to replace it.

> https://systeminformer.io/

Undo it by removing the first line and executing the second command (delete the `::`), or just paste the second one in cmd.

Enable `Theme support` (dark mode) and disable `Check for updates automatically` with:
```ps
(gc "$env:appdata\SystemInformer\settings.xml") -replace '(?<=<setting name="ProcessHacker\.UpdateChecker\.PromptStart">)\d(?=</setting>)','0' -replace '(?<=<setting name="EnableThemeSupport">)\d(?=</setting>)','1' | sc "$appdata\SystemInformer\settings.xml"
```

# Registry Finder

An improved editor that supports dark mode, a far better `Find` tool, and much more. 

Installation:
```ps
winget install SergeyFilippov.RegistryFinder
```
You can replace it the same way as `System Informer` (edit the path if needed):
```ps
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe" /v Debugger /t REG_SZ /d "\"C:\Program Files\Registry Finder\RegistryFinder.exe\" -z" /f
```
Revert it by deleting the value or via `RegistryFinder --regedit`:
```ps
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger /f
```
> https://registry-finder.com

# 7-Zip Settings

7-Zip minimal context menu settings:

![](https://github.com/5Noxi/win-config/blob/main/misc/images/7zip.png?raw=true)

A good replacement would be NanaZip:
```ps
winget install M2Team.NanaZip
```
New features etc. can be found here:
> https://github.com/M2Team/NanaZip

# Disable VSC Telemetry

**Caution:** The revert currently deletes `settings.json`. Means any settings you used beside the ones which get applied using this option will get removed.

Stops VSC to send telemetry, crash reports, disable online experiments, turn off automatic updates (manual updates), prevent fetching release notes, stop automatic extension and git repository updates, limit extension recommendations to on demand requests, and block fetching package information from online sources like NPM or Bower.
```ts
export const enum TelemetryLevel {
	NONE = 0,
	CRASH = 1,
	ERROR = 2,
	USAGE = 3
}
```
```json
"config.autofetch": "When set to true, commits will automatically be fetched from the default remote of the current Git repository. Setting to `all` will fetch from all remotes.",
```
```json
"config.npm.fetchOnlinePackageInfo": "Fetch data from https://registry.npmjs.org and https://registry.bower.io to provide auto-completion and information on hover features on npm dependencies.",
```
```ts
'update.mode': {
	enum: ['none', 'manual', 'start', 'default'],
	description: localize('updateMode', "Configure whether you receive automatic updates. Requires a restart after change. The updates are fetched from a Microsoft online service."),
	enumDescriptions: [
		localize('manual', "Disable automatic background update checks. Updates will be available if you manually check for updates."),
```
> https://github.com/microsoft/vscode/blob/274d71002ec805c8b4f61ade3f058dd3cac1aceb/src/vs/workbench/contrib/extensions/common/extensions.ts#L185  
> https://github.com/microsoft/vscode/blob/274d71002ec805c8b4f61ade3f058dd3cac1aceb/extensions/git/package.nls.json#L155  
> https://github.com/microsoft/vscode/blob/274d71002ec805c8b4f61ade3f058dd3cac1aceb/extensions/npm/package.nls.json#L26  
> https://github.com/microsoft/vscode/blob/274d71002ec805c8b4f61ade3f058dd3cac1aceb/src/vs/platform/telemetry/common/telemetry.ts#L83  
> https://github.com/microsoft/vscode/blob/274d71002ec805c8b4f61ade3f058dd3cac1aceb/src/vs/workbench/services/assignment/common/assignmentService.ts#L110

# Disable VS Telemetry

Disables VS telemetry, SQM data collection, IntelliCode remote analysis, feedback features, and the `DiagnosticsHub` logger. Disabling `VSStandardCollectorService150` could cause issues, I added it as a comment.

```ps
"14.0" = "VS 2015"
"15.0" = "VS 2017" 
"16.0" = "VS 2019"
"17.0" = "VS 2022"
```
Remove VS logs, telemetry & feedback data:
```bat
for %%p in (
 "%APPDATA%\vstelemetry"
 "%LOCALAPPDATA%\Microsoft\VSApplicationInsights"
 "%LOCALAPPDATA%\Microsoft\VSCommon\14.0\SQM"
 "%LOCALAPPDATA%\Microsoft\VSCommon\15.0\SQM"
 "%LOCALAPPDATA%\Microsoft\VSCommon\16.0\SQM"
 "%LOCALAPPDATA%\Microsoft\VSCommon\17.0\SQM"
 "%PROGRAMDATA%\Microsoft\VSApplicationInsights"
 "%PROGRAMDATA%\vstelemetry"
 "%TEMP%\Microsoft\VSApplicationInsights"
 "%TEMP%\Microsoft\VSFeedbackCollector"
 "%TEMP%\VSFaultInfo"
 "%TEMP%\VSFeedbackIntelliCodeLogs"
 "%TEMP%\VSFeedbackPerfWatsonData"
 "%TEMP%\VSFeedbackVSRTCLogs"
 "%TEMP%\VSRemoteControl"
 "%TEMP%\VSTelem"
 "%TEMP%\VSTelem.Out"
) do rd /s /q "%%~p"
```
Remove VS licenses (could cause the need of a reactivation):
```bat
for %%g in (
 "77550D6B-6352-4E77-9DA3-537419DF564B"
 "E79B3F9C-6543-4897-BBA5-5BFB0A02BB5C"
 "4D8CFBCB-2F6A-4AD2-BABF-10E28F6F2C8F"
 "5C505A59-E312-4B89-9508-E162F8150517"
 "41717607-F34E-432C-A138-A3CFD7E25CDA"
 "1299B4B9-DFCC-476D-98F0-F65A2B46C96D"
) do reg delete "HKLM\SOFTWARE\Classes\Licenses\%%~g" /f
```
> https://github.com/jedipi/Visual-Studio-Key-Finder/blob/main/src/VsKeyFinder/Data/ProductData.cs

---

Miscellaneous notes:
```ps
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\17.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150" /v Start /t REG_DWORD /d 4 /f
```

# Disable MS Office Telemetry

Disables logging, data collection, opts out from CEIP, disables feedback collection and telemetry agent tasks.

> https://learn.microsoft.com/en-us/office/compatibility/data-that-the-telemetry-agent-collects-in-office