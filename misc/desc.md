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
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableEmailInput /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableFeedbackDialog /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v DisableScreenshotCapture /t REG_DWORD /d 1 /f
```
```ps
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\VSCommon\17.0\SQM" /v OptIn /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150" /v Start /t REG_DWORD /d 4 /f
```

# Disable MS Office Telemetry

Disables logging, data collection, opts out from CEIP, disables feedback collection and telemetry agent tasks.

| Category                                     | Where it appears | What the agent collects (by default)                                                                                                    | Scope / Versions                                                | Notes & Exceptions                                                                                                                                                                       |
| -------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recently opened documents & templates        | Documents                              | File name; file format/extension; total users; number of Office users/sessions                                                          | Office 2003–2019/2016 (agent supports multiple Office versions) | For network/SharePoint files: only file name + location. If MRU is disabled, no document inventory is collected. Outlook: no document inventory. OneNote: only notebook name + location. |
| Document details                             | Document details                       | User name; computer name; location (path/URL); size (KB); author; last loaded; title; Office version                                    | Office 2003–2019/2016                                           | Same exceptions as above (MRU off, Outlook, OneNote, network/SharePoint).                                                                                                                |
| Recently loaded add-ins & Apps for Office    | Solutions                              | Solution name; total users; number of Office users                                                                                      | Office 2003–2019/2016                                           | -                                                                                                                                                                                        |
| Add-in / App details                         | Solution details                       | User name; computer name; solution version; architecture (x86/x64/ARM); load time; description; size (KB); location (DLL/manifest path) | Office 2003–2019/2016                                           | -                                                                                                                                                                                        |
| User data (agents)                           | Agents                                 | User name; level (telemetry level); computer; last updated; label (1–4); agent version                                                  | All supported                                                   | -                                                                                                                                                                                        |
| Hardware & software inventory (per computer) | Telemetry Processor                    | Computer name; level; users; computers; last updated (date/time)                                                                        | All supported                                                   | -                                                                                                                                                                                        |
| Office deployment mix                        | Deployments                            | Office versions; # of 32-bit deployments; # of 64-bit deployments; # of ARM deployments                                                 | All supported                                                   | -                                                                                                                                                                                        |
| Runtime document telemetry                   | Documents (runtime fields)             | Success (%); sessions; critical compatibility issue or crash; informative compatibility issue or load failure                           | Office 2013/2016/2019 (Excel/Outlook/PowerPoint/Word)           | Shown only after the app is run and documents/solutions are opened.                                                                                                                      |
| Runtime document internals                   | Document details (runtime fields)      | Last loaded (date/time); flags: Has VBA? Has OLE? Has external data connection? Has ActiveX control? Has assembly reference?            | Office 2013/2016/2019 (Excel/Outlook/PowerPoint/Word)           | VBA/OLE/data/ActiveX/assembly info is logged starting from the second open of the document.                                                                                              |
| Runtime document events                      | Document sessions                      | Date/time of critical or informative events                                                                                             | Office 2013/2016/2019 (Excel/Outlook/PowerPoint/Word)           | -                                                                                                                                                                                        |
| Runtime add-in telemetry                     | Solutions (runtime fields)             | Success (%); sessions; critical compatibility issue or crash; informative compatibility issue or load failure; load time                | Office 2013/2016/2019 (Excel/Outlook/PowerPoint/Word)           | Shown only after the add-in/app is loaded during runtime.                                                                                                                                |
| Runtime solution issues                      | Solution issues                        | Event ID; title; explanation; more info; users; sessions                                                                                | Office 2013/2016/2019 (Excel/Outlook/PowerPoint/Word)           | -                                                                                                                                                                                        |
| Not collected (by design)                    | -                                      | File contents; info about files not in MRU                                                                                              | All                                                             | Data for Office Telemetry Dashboard stays in your org's SQL Server; it is not sent to Microsoft. Office diagnostic data is separate and managed by different settings.                   |

---

`HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications`

| Value Name        | Value Type | Value Description and Data                                                            |
| ----------------- | ---------- | ------------------------------------------------------------------------------------- |
| accesssolution    | REG_DWORD  | Prevents data for Access solutions from being reported to Office Telemetry Dashboard. |
| olksolution       | REG_DWORD  | Prevents data for Microsoft Outlook solutions.                                        |
| onenotesolution   | REG_DWORD  | Prevents data for OneNote solutions.                                                  |
| pptsolution       | REG_DWORD  | Prevents data for PowerPoint solutions.                                               |
| projectsolution   | REG_DWORD  | Prevents data for Project solutions.                                                  |
| publishersolution | REG_DWORD  | Prevents data for Publisher solutions.                                                |
| visiosolution     | REG_DWORD  | Prevents data for Visio solutions.                                                    |
| wdsolution        | REG_DWORD  | Prevents data for Word solutions.                                                     |
| xlsolution        | REG_DWORD  | Prevents data for Excel solutions.                                                    |

- `1` = Prevent reporting
- `0` = Allow reporting
- Default = `0` (Allow reporting)

---

`HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes`

| Value Name    | Value Type | Value Description and Data                                                  |
| ------------- | ---------- | --------------------------------------------------------------------------- |
| agave         | REG_DWORD  | Prevents data for apps for Office.                                          |
| appaddins     | REG_DWORD  | Prevents data for application-specific add-ins like Excel, PowerPoint, etc. |
| comaddins     | REG_DWORD  | Prevents data for COM add-ins.                                              |
| documentfiles | REG_DWORD  | Prevents data for Office document files.                                    |
| templatefiles | REG_DWORD  | Prevents data for Office template files.                                    |

- `1` = Prevent reporting
- `0` = Allow reporting
- Default = `0` (Allow reporting)

> https://learn.microsoft.com/en-us/office/compatibility/data-that-the-telemetry-agent-collects-in-office  
> https://learn.microsoft.com/en-us/office/compatibility/manage-the-privacy-of-data-monitored-by-telemetry-in-office

# Disable OneDrive

`DisableLibrariesDefaultSaveToOneDrive` sets local storage as the default save location, `DisableFileSync` disables OneDrive on Windows 8.1 including app and picker access removal and stops sync and hides the Explorer entry, `DisableFileSyncNGSC` disables OneDrive via the Next-Gen Sync Client with the same effect, `DisableMeteredNetworkFileSync` set to `0` blocks syncing on all metered connections, `PreventNetworkTrafficPreUserSignIn` stops the OneDrive client from generating network traffic until the user signs in, `System.IsPinnedToNameSpaceTree` set to `0` hides OneDrive from File Explorer's navigation pane in both CLSID locations.

```json
{
	"File":  "SkyDrive.admx",
	"NameSpace":  "Microsoft.Policies.OneDrive",
	"Class":  "Machine",
	"CategoryName":  "OneDrive",
	"DisplayName":  "Save documents to OneDrive by default",
	"ExplainText":  "This policy setting lets you disable OneDrive as the default save location. It does not prevent apps and users from saving files on OneDrive. If you disable this policy setting, files will be saved locally by default. Users will still be able to change the value of this setting to save to OneDrive by default. They will also be able to open and save files on OneDrive using the OneDrive app and file picker, and packaged Microsoft Store apps will still be able to access OneDrive using the WinRT API. If you enable or do not configure this policy setting, users with a connected account will save documents to OneDrive by default.",
	"Supported":  "Windows_6_3only",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\OneDrive",
	"KeyName":  "DisableLibrariesDefaultSaveToOneDrive",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SkyDrive.admx",
	"NameSpace":  "Microsoft.Policies.OneDrive",
	"Class":  "Machine",
	"CategoryName":  "OneDrive",
	"DisplayName":  "Prevent the usage of OneDrive for file storage on Windows 8.1",
	"ExplainText":  "This policy setting lets you prevent apps and features from working with files on OneDrive for Windows 8.1.If you enable this policy setting:* Users canâ€™t access OneDrive from the OneDrive app and file picker.* Packaged Microsoft Store apps canâ€™t access OneDrive using the WinRT API.* OneDrive doesnâ€™t appear in the navigation pane in File Explorer.* OneDrive files arenâ€™t kept in sync with the cloud.* Users canâ€™t automatically upload photos and videos from the camera roll folder.If you disable or do not configure this policy setting, apps and features can work with OneDrive file storage.",
	"Supported":  "Windows_6_3only",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\OneDrive",
	"KeyName":  "DisableFileSync",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SkyDrive.admx",
	"NameSpace":  "Microsoft.Policies.OneDrive",
	"Class":  "Machine",
	"CategoryName":  "OneDrive",
	"DisplayName":  "Prevent the usage of OneDrive for file storage",
	"ExplainText":  "This policy setting lets you prevent apps and features from working with files on OneDrive.If you enable this policy setting:* Users canâ€™t access OneDrive from the OneDrive app and file picker.* Packaged Microsoft Store apps canâ€™t access OneDrive using the WinRT API.* OneDrive doesnâ€™t appear in the navigation pane in File Explorer.* OneDrive files arenâ€™t kept in sync with the cloud.* Users canâ€™t automatically upload photos and videos from the camera roll folder.If you disable or do not configure this policy setting, apps and features can work with OneDrive file storage.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\OneDrive",
	"KeyName":  "DisableFileSyncNGSC",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SkyDrive.admx",
	"NameSpace":  "Microsoft.Policies.OneDrive",
	"Class":  "Machine",
	"CategoryName":  "OneDrive",
	"DisplayName":  "Block syncing on metered connections only when roaming",
	"ExplainText":  "This policy setting allows configuration of OneDrive file sync behavior on metered connections.",
	"Supported":  "Windows_6_3only",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows",
	"KeyName":  "OneDrive",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "DisableMeteredNetworkFileSync",
							"Items":  [
										{
											"DisplayName":  "Block syncing on all metered connections",
											"Value":  "0"
										},
										{
											"DisplayName":  "Block syncing on metered connections only when roaming",
											"Value":  "1"
										}
									]
						}
					]
},
{
	"File":  "SkyDrive.admx",
	"NameSpace":  "Microsoft.Policies.OneDrive",
	"Class":  "Machine",
	"CategoryName":  "OneDrive",
	"DisplayName":  "Prevent OneDrive from generating network traffic until the user signs in to OneDrive",
	"ExplainText":  "Enable this setting to prevent the OneDrive sync client (OneDrive.exe) from generating network traffic (checking for updates, etc.) until the user signs in to OneDrive or starts syncing files to the local computer.If you enable this setting, users must sign in to the OneDrive sync client on the local computer, or select to sync OneDrive or SharePoint files on the computer, for the sync client to start automatically.If this setting is not enabled, the OneDrive sync client will start automatically when users sign in to Windows.If you enable or disable this setting, do not return the setting to Not Configured. Doing so will not change the configuration and the last configured setting will remain in effect.",
	"Supported":  "Windows7",
	"KeyPath":  "SOFTWARE\\Microsoft\\OneDrive",
	"KeyName":  "PreventNetworkTrafficPreUserSignIn",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
```

# Disable Edge Features

Edge is a whole mess, I wouldn't recommend anyone to use it, but here's an option that applies the following values:

| Value | Disables / Hides |
| ----- | ----- |
| `AutoImportAtFirstRun` | Auto-import from other browsers at first run |
| `PersonalizationReportingEnabled` | Personalization (ads, news, browser suggestions) |
| `ShowRecommendationsEnabled` | Recommendations and desktop notifications |
| `HideFirstRunExperience` | First-run experience |
| `PinBrowserEssentialsToolbarButton` | Browser Essentials toolbar button |
| `DefaultBrowserSettingEnabled` | "Set Edge as default browser” prompts |
| `EdgeFollowEnabled` | Follow creators |
| `HubsSidebarEnabled` | Sidebar |
| `StandaloneHubsSidebarEnabled` | Standalone Sidebar |
| `SyncDisabled` | Sync (all kinds of data) |
| `HideRestoreDialogEnabled` | Restore pages dialog after crash |
| `EdgeShoppingAssistantEnabled` | Shopping features |
| `ShowMicrosoftRewards` | Microsoft Rewards |
| `QuickSearchShowMiniMenu` | Mini context menu (quick search) |
| `ImplicitSignInEnabled` | Implicit sign-in with Microsoft account |
| `EdgeCollectionsEnabled` | Collections |
| `SplitScreenEnabled` | Split screen |
| `UserFeedbackAllowed` | User feedback prompts |
| `SearchbarAllowed` | Floating Bing search bar |
| `StartupBoostEnabled` | Startup Boost |
| `NewTabPageHideDefaultTopSites` | Microsoft's default pinned sites on New Tab |
| `NewTabPageQuickLinksEnabled` | Quick links on New Tab |
| `NewTabPageAllowedBackgroundTypes` | New Tab background image (restricts types) |
| `NewTabPageContentEnabled` | Microsoft content on New Tab (news, highlights, etc.) |
| `DisableHelpSticker` | Windows help tips ("help stickers”) |
| `DisableMFUTracking` | Tracking of most-frequently-used apps |
| `DisableRecentApps` | Recent apps UI in upper-left corner |
| `DisableCharms` | Charms UI in upper-right corner |
| `TurnOffBackstack` | Switching between recent apps (backstack) |
| `AllowEdgeSwipe` | Edge swipe gestures (set to 0 to disable) |
| `TabServicesEnabled` | Tab-related background services (e.g., shopping/price tracking helpers) disabled |
| `TextPredictionEnabled` | Text predictions will not be provided in eligible text fields |
| `TrackingPrevention` | Tracking Prevention mode enforced |
| `DefaultSensorsSetting` | Site access to  sensors blocked |

See all edge policies here:

> https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies

```json
{
	"File":  "EdgeUI.admx",
	"NameSpace":  "Microsoft.Policies.EdgeUI",
	"Class":  "User",
	"CategoryName":  "EdgeUI",
	"DisplayName":  "Turn off switching between recent apps",
	"ExplainText":  "If you enable this setting, users will not be allowed to switch between recent apps. The App Switching option in the PC settings app will be disabled as well.If you disable or do not configure this policy setting, users will be allowed to switch between recent apps.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\EdgeUI",
	"KeyName":  "TurnOffBackstack",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "EdgeUI.admx",
	"NameSpace":  "Microsoft.Policies.EdgeUI",
	"Class":  "User",
	"CategoryName":  "EdgeUI",
	"DisplayName":  "Turn off tracking of app usage",
	"ExplainText":  "This policy setting prevents Windows from keeping track of the apps that are used and searched most frequently. If you enable this policy setting, apps will be sorted alphabetically in: - search results - the Search and Share panes - the drop-down app list in the Picker If you disable or don\u0027t configure this policy setting, Windows will keep track of the apps that are used and searched most frequently. Most frequently used apps will appear at the top.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\EdgeUI",
	"KeyName":  "DisableMFUTracking",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "EdgeUI.admx",
	"NameSpace":  "Microsoft.Policies.EdgeUI",
	"Class":  "User",
	"CategoryName":  "EdgeUI",
	"DisplayName":  "Do not show recent apps when the mouse is pointing to the upper-left corner of the screen",
	"ExplainText":  "This policy setting allows you to prevent the last app and the list of recent apps from appearing when the mouse is pointing to the upper-left corner of the screen.If you enable this policy setting, the user will no longer be able to switch to recent apps using the mouse. The user will still be able to switch apps using touch gestures, keyboard shortcuts, and the Start screen.If you disable or don\u0027t configure this policy setting, the recent apps will be available by default, and the user can configure this setting.",
	"Supported":  "Windows_6_3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\EdgeUI",
	"KeyName":  "DisableRecentApps",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "EdgeUI.admx",
	"NameSpace":  "Microsoft.Policies.EdgeUI",
	"Class":  "User",
	"CategoryName":  "EdgeUI",
	"DisplayName":  "Search, Share, Start, Devices, and Settings don\u0027t appear when the mouse is pointing to the upper-right corner of the screen",
	"ExplainText":  "This policy setting allows you to prevent Search, Share, Start, Devices, and Settings from appearing when the mouse is pointing to the upper-right corner of the screen.If you enable this policy setting, Search, Share, Start, Devices, and Settings will no longer appear when the mouse is pointing to the upper-right corner. They\u0027ll still be available if the mouse is pointing to the lower-right corner.If you disable or don\u0027t configure this policy setting, Search, Share, Start, Devices, and Settings will be available by default, and the user can configure this setting.",
	"Supported":  "Windows_6_3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\EdgeUI",
	"KeyName":  "DisableCharms",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "EdgeUI.admx",
	"NameSpace":  "Microsoft.Policies.EdgeUI",
	"Class":  "Both",
	"CategoryName":  "EdgeUI",
	"DisplayName":  "Disable help tips",
	"ExplainText":  "Disables help tips that Windows shows to the user.By default, Windows will show the user help tips until the user has successfully completed the scenarios.If this setting is enabled, Windows will not show any help tips to the user.",
	"Supported":  "Windows_6_3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\EdgeUI",
	"KeyName":  "DisableHelpSticker",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "EdgeUI.admx",
	"NameSpace":  "Microsoft.Policies.EdgeUI",
	"Class":  "Both",
	"CategoryName":  "EdgeUI",
	"DisplayName":  "Allow edge swipe",
	"ExplainText":  "If you disable this policy setting, users will not be able to invoke any system UI by swiping in from any screen edge.If you enable or do not configure this policy setting, users will be able to invoke system UI by swiping in from the screen edges.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\EdgeUI",
	"KeyName":  "AllowEdgeSwipe",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
```