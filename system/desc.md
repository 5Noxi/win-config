# Win32PrioritySeparation

"The value of this entry determines, in part, how much processor time the threads of a process receive each time they are scheduled, and how much the allotted time can vary. It also affects the relative priority of the threads of foreground and background processes. The value of this entry is a 6-bit bitmask consisting of three sets of two bits (AABBCC). Each set of two bits determines a different characteristic of the optimizing strategy.
- The highest two bits (AABBCC) determine whether each processor interval is relatively long or short.
- The middle two bits (AABBCC) determine whether the length of the interval varies or is fixed.
- The lowest two bits (AABBCC) determine whether the threads of foreground processes get more processor time than the threads of background processes each time they run."

Read trough the `.pdf` file, if you want to get more information about the bitmask. Calculate it yourself with [`bitmask-calc`](https://github.com/5Noxi/bitmask-calc).

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 24 /f
```
-> `0x00000018` = Long, Fixed Quantum, no boost. Using a boost (bit `1-2`) would set the threads of foreground processes (game/csrss/(dwm?)) `2-3` times higher than from background processes, which can cause issues. `26` dec would use a boost of `3x`.

As you can see in this [table](https://github.com/djdallmann/GamingPCSetup/blob/d865b755a9b6af65a470b8840af54729c75a6ae7/CONTENT/RESEARCH/FINDINGS/win32prisep0to271.csv), the values repeat. Using a extremely high number therefore won't do anything else. `Win32PrioritySeparation.ps1` can be used to get the info, increase `for ($i=0; $i -le 271; $i++) {` (`271`), if you want to see more. It's a lighter version of [win32prisepcalc](https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/SCRIPTS/win32prisepcalc.ps1).

Paste it into a terminal to see a table with all values:
```ps
for ($i=0; $i -le 271; $i++) {
    $bin = [Convert]::ToString($i,2).PadLeft(6,'0')[-6..-1]
    $interval = if (('00','10','11' -contains ($bin[0,1] -join''))) {'Shorter'} else {'Longer'}
    $time = if (('00','01','11' -contains ($bin[2,3] -join''))) {'Variable'} else {'Fixed'}
    $boost = switch ($bin[4,5] -join'') {'00' {'Equal and Fixed'} '01' {'2:1'} default {'3:1'}}
    if ($time -eq 'Fixed') {$qrvforeground = $qrvbackground = if ($interval -eq 'Longer') {36} else {18}} else {
        $values = @{ 
            'Shorter' = @{ '3:1' = @(18,6); '2:1' = @(12,6); 'Equal and Fixed' = @(6,6) }
            'Longer'  = @{ '3:1' = @(36,12); '2:1' = @(24,12); 'Equal and Fixed' = @(12,12) }
        }
        if ($values[$interval].ContainsKey($boost)) {$qrvforeground, $qrvbackground = $values[$interval][$boost]} else {$qrvforeground, $qrvbackground = $values[$interval]['Equal and Fixed']}
    }
	Write-Output "$i,0x$($i.ToString('X')),$interval,$time,$qrvforeground,$qrvbackground"
}
```

![](https://github.com/5Noxi/win-config/blob/main/system/images/w32ps.png?raw=true)

> [system/assets | Win32PrioritySeparation.pdf](https://github.com/5Noxi/win-config/blob/main/system/assets/Win32PrioritySeparation.pdf)

# System Responsiveness

*"Determines the percentage of CPU resources that should be guaranteed to low-priority tasks. For example, if this value is 20, then 20% of CPU resources are reserved for low-priority tasks. Note that values that are not evenly divisible by 10 are rounded down to the nearest multiple of 10. Values below 10 and above 100 are clamped to 20. A value of 100 disables MMCSS (driver returns `STATUS_SERVER_DISABLED`).*" (`mmcss.sys`)
> https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ProcThread/multimedia-class-scheduler-service.md#registry-settings

```c
DWORD = CiConfigReadDWORD(KeyHandle, 0x1C0011090LL, 100LL);

if ( DWORD - 10 > 0x5A )          // if DWORD < 10 or DWORD > 100
    v2 = 20LL;                    // fallback
else
    v2 = 10 * (DWORD / 0xA);      // round down to nearest multiple of 10

CiSystemResponsiveness = v2;

if ( CiSystemResponsiveness == 100 ) {
    WPP_SF_(WPP_GLOBAL_Control->AttachedDevice, 19LL, &WPP_350503daac883abe7be9cf63f89038d9_Traceguids);
    v0 = -1073741696;             // STATUS_SERVER_DISABLED
}
```
```c
// -1073741696 = 0xC0000080
0xC0000080 // STATUS_SERVER_DISABLED

The GUID allocation server is disabled at the moment.
```
> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

Calculation:
```c
CiSystemResponsiveness = 10 * (value / 10);

// Examples
< 10   -> 20   (fallback)
10-19  -> 10
20-29  -> 20
30-39  -> 30
40-49  -> 40
50-59  -> 50
60-69  -> 60
70-79  -> 70
80-89  -> 80
90-99  -> 90
== 100 -> 100  (STATUS_SERVER_DISABLED)
> 100  -> 20   (fallback)
```
Lowest effective value:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 10 /f
```
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/MultiMedia.txt  
> [system/assets | sysresp-CiConfigInitialize.c](https://github.com/5Noxi/win-config/blob/main/system/assets/sysresp-CiConfigInitialize.c)  

# Disable UAC

Disabling UAC stops the prompts for administrative permissions, allowing programs and processes to run with elevated rights without user confirmation. Save `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` before running it.

Remove the `Run as Administrator` context menu option (`.bat`, `.cmd` files) with:
```bat
reg delete "HKCR\batfile\shell\runas" /f
reg delete "HKCR\cmdfile\shell\runas" /f
```
Will cause issues like shows in the picture below, the two ones above might cause similar issues (if the app requests elevated permissions?). __Rather leave them alone.__
```
reg delete "HKCR\exefile\shell\runas" /f
```

UAC Values (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`) - `UserAccountControlSettings.exe`:
`Always notify me when: ...`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 2
PromptOnSecureDesktop - Data: 1
```
`Notify me only when apps try to make changes to my computer (default)`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 5
PromptOnSecureDesktop - Data: 1
```
`Notify me only when apps try to make changes to my computer (do not dim my desktop)`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 5
PromptOnSecureDesktop - Data: 0
```
`Never notify me when: ...`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 0
PromptOnSecureDesktop - Data: 0
```

Value: `FilterAdministratorToken`

| Value        | Meaning                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0x00000000` | Only the built-in administrator account (RID 500) should be placed into Full Token mode.                                                         |
| `0x00000001` | Only the built-in administrator account (RID 500) is placed into Admin Approval Mode. Approval is required when performing administrative tasks. |

Value: `ConsentPromptBehaviorAdmin`

| Value        | Meaning                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------- |
| `0x00000000` | Allows the admin to perform operations that require elevation without consent or credentials.                        |
| `0x00000001` | Prompts for username and password on the secure desktop when elevation is required.                                  |
| `0x00000002` | Prompts the admin to Permit or Deny an elevation request (secure desktop). Removes the need to re-enter credentials. |
| `0x00000003` | Prompts for credentials (admin username/password) when elevation is required.                                        |
| `0x00000004` | Prompts the admin to Permit or Deny elevation (non-secure desktop).                                                  |
| `0x00000005` | Default: Prompts admin to Permit or Deny elevation for non-Windows binaries on the secure desktop.                   |

Value: `ConsentPromptBehaviorUser`

| Value        | Meaning                                                                       |
| ------------ | ----------------------------------------------------------------------------- |
| `0x00000000` | Any operation requiring elevation fails for standard users.                   |
| `0x00000001` | Standard users are prompted for an admin's credentials to elevate privileges. |

Value: `EnableInstallerDetection`

| Value        | Meaning                                                            |
| ------------ | ------------------------------------------------------------------ |
| `0x00000000` | Disables automatic detection of installers that require elevation. |
| `0x00000001` | Enables heuristic detection of installers needing elevation.       |

Value: `ValidateAdminCodeSignatures`

| Value        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `0x00000000` | Does not enforce cryptographic signatures on elevated apps.                    |
| `0x00000001` | Enforces cryptographic signatures on any interactive app requesting elevation. |

Value: `EnableLUA`

| Value        | Meaning                                                                             |
| ------------ | ----------------------------------------------------------------------------------- |
| `0x00000000` | Disables the “Administrator in Admin Approval Mode” user type and all UAC policies. |
| `0x00000001` | Enables the “Administrator in Admin Approval Mode” and activates all UAC policies.  |

Value: `PromptOnSecureDesktop`

| Value        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `0x00000000` | Disables secure desktop prompting — prompts appear on the interactive desktop. |
| `0x00000001` | Forces all UAC prompts to occur on the secure desktop.                         |

Value: `EnableVirtualization`

| Value        | Meaning                                                                                       |
| ------------ | --------------------------------------------------------------------------------------------- |
| `0x00000000` | Disables data redirection for interactive processes.                                          |
| `0x00000001` | Enables file and registry redirection for legacy apps to allow writes in user-writable paths. |

> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/12867da0-2e4e-4a4f-9dc4-84a7f354c8d9  
> https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=reg

![](https://github.com/5Noxi/win-config/blob/main/system/images/uac.png?raw=true)

# Disable Service Splitting

Prevents services running under `svchost.exe` from being split into separate processes, keeping all grouped services within the same instance. This simplifies process management but increases the risk of system instability and reduces service isolation.

`Windows Internals 7th Edition, Part 2` handpicked snippets (shortened):
If system physical memory, obtained via `GlobalMemoryStatusEx`, exceeds the SvcHostSplitThresholdInKB registry value (default is `3.5 GB` on client systems and `3.7 GB` on server systems), Svchost service splitting is enabled.

Service splitting is allowed only if:  
- Splitting is globally enabled
- The service is not marked as critical (i.e., it doesn't reboot the machine on failure)
- The service is hosted in `svchost.exe`
- `SvcHostSplitDisable` is not set to `1` in the service registry key

Setting `SvcHostSplitDisable` to `0` for a critical service forces it to be split, but this can lead to issues.

Get the current amount of `svchost` process instances with:
```cmd
(get-process -Name "svchost" | measure).Count
```
```
\Registry\Machine\SYSTEM\ControlSet001\Control : SvcHostDebug
\Registry\Machine\SYSTEM\ControlSet001\Control : SvcHostSplitThresholdInKB
```
`SvcHostDebug` is set to `0` by default:
```c
v1 = 0;
if ( !RegistryValueWithFallbackW && Type == 4 )
    LOBYTE(v1) = Data != 0;
return v1;
```

> [system/assets | servicesplitting-ScReadSCMConfiguration.c](https://github.com/5Noxi/win-config/blob/main/system/assets/servicesplitting-ScReadSCMConfiguration.c)  
> https://github.com/5Noxi/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf (page `467`f)  
> https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring  
> https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex

![](https://github.com/5Noxi/win-config/blob/main/system/images/servicesplitting1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/servicesplitting2.png?raw=true)

---

Miscellaneous notes:
```bat
:: "If the total physical memory is above the threshold, it enables Svchost service splitting"
reg add HKLM\SYSTEM\CurrentControlSet\Control /t REG_DWORD /v SvcHostSplitThresholdInKB /d 4294967295 /f
```

# Disable Scheduled Tasks

Disables all kind of scheduled tasks most users don't need. Read through the list before switching the option.

Currently disables:
```ps
"\Microsoft\Windows\Application Experience\MareBackup",
"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp",
"\Microsoft\Windows\Application Experience\StartupAppTask",
"\Microsoft\Windows\ApplicationData\DsSvcCleanup",
"\Microsoft\Windows\Autochk\Proxy",
"\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
"\Microsoft\Windows\Defrag\ScheduledDefrag",
"\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",
"\Microsoft\Windows\Diagnosis\Scheduled",
"\Microsoft\Windows\Diagnosis\UnexpectedCodePath",
"\Microsoft\Windows\DiskCleanup\SilentCleanup",
"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
"\Microsoft\Windows\DiskFootprint\Diagnostics",
"\Microsoft\Windows\DiskFootprint\StorageSense",
"\Microsoft\Windows\Feedback\Siuf\DmClient",
"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
"\Microsoft\Windows\InstallService\ScanForUpdates",
"\Microsoft\Windows\InstallService\ScanForUpdatesAsUser",
"\Microsoft\Windows\InstallService\SmartRetry",
"\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates",
"\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates",
"\Microsoft\Windows\International\Synchronize Language Settings",
"\Microsoft\Windows\LanguageComponentsInstaller\Installation",
"\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources",
"\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation",
"\Microsoft\Windows\Maps\MapsUpdateTask",
"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
"\Microsoft\Windows\Registry\RegIdleBackup",
"\Microsoft\Windows\RetailDemo\CleanupOfflineContent",
"\Microsoft\Windows\Speech\SpeechModelDownloadTask",
"\Microsoft\Windows\Sysmain\ResPriStaticDbSync",
"\Microsoft\Windows\Sysmain\WsSwapAssessmentTask",
"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime",
"\Microsoft\Windows\Time Synchronization\SynchronizeTime",
"\Microsoft\Windows\UNP\RunUpdateNotificationMgr",
"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
```

---

Miscellaneous notes:
```ps
for %%a in (
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver",
    "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)",
    "\Microsoft\Windows\AppID\EDP Policy Manager",
    "\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives",
    "\Microsoft\Windows\BitLocker\BitLocker MDM Policy Refresh",
    "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask",
    "\Microsoft\Windows\CloudRestore\Backup",
    "\Microsoft\Windows\CloudRestore\Restore",
    "\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan",
    "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan",
    "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan For Crash Recovery",
    "\Microsoft\Windows\Device Information\Device",
    "\Microsoft\Windows\Device Information\Device User",
    "\Microsoft\Windows\Device Setup\Metadata Refresh",
    "\Microsoft\Windows\FileHistory\File History (maintenance mode)",
    "\Microsoft\Windows\Flighting\FeatureConfig\BootstrapUsageDataReporting",
    "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting",
    "\Microsoft\Windows\Flighting\OneSettings\RefreshCache",
    "\Microsoft\Windows\Printing\EduPrintProv",
    "\Microsoft\Windows\Printing\PrinterCleanupTask",
    "\Microsoft\Windows\Printing\PrintJobCleanupTask",
    "\Microsoft\Windows\Security\Pwdless\IntelligentPwdlessTask",
    # WU
    "\Microsoft\Windows\UpdateOrchestrator\Report policies",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
    "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work",
    "\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted",
    "\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate",
    "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
    "\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task",
    "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    "\Microsoft\Windows\WindowsUpdate\Refresh Group Policy Cache",
    # WiFi
    "\Microsoft\Windows\WlanSvc\CDSSync",
    "\Microsoft\Windows\WlanSvc\MoProfileManagement"
) do (
    schtasks.exe /change /disable /TN %%a
)

powershell -Command "Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -like 'MicrosoftEdgeUpdateTaskMachine*' } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath '\' }"
```

# Lock Screen

Disables the lock screen (skips the lock screen and go directly to the login screen). Revert it by removing the value (2nd command).

```json
{
    "File":  "ControlPanelDisplay.admx",
    "NameSpace":  "Microsoft.Policies.ControlPanelDisplay",
    "Class":  "Machine",
    "CategoryName":  "Personalization",
    "DisplayName":  "Do not display the lock screen",
    "ExplainText":  "This policy setting controls whether the lock screen appears for users.If you enable this policy setting, users that are not required to press CTRL + ALT + DEL before signing in will see their selected tile after locking their PC.If you disable or do not configure this policy setting, users that are not required to press CTRL + ALT + DEL before signing in will see a lock screen after locking their PC. They must dismiss the lock screen using touch, the keyboard, or by dragging it with the mouse.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Personalization",
    "KeyName":  "NoLockScreen",
    "Elements":  [

                    ]
},
{
    "File":  "ControlPanelDisplay.admx",
    "NameSpace":  "Microsoft.Policies.ControlPanelDisplay",
    "Class":  "Machine",
    "CategoryName":  "Personalization",
    "DisplayName":  "Force a specific default lock screen and logon image",
    "ExplainText":  "This setting allows you to force a specific default lock screen and logon image by entering the path (location) of the image file. The same image will be used for both the lock and logon screens.This setting lets you specify the default lock screen and logon image shown when no user is signed in, and also sets the specified image as the default for all users (it replaces the inbox default image).To use this setting, type the fully qualified path and name of the file that stores the default lock screen and logon image. You can type a local path, such as C:\\Windows\\Web\\Screen\\img104.jpg or a UNC path, such as \\\\Server\\Share\\Corp.jpg.This can be used in conjunction with the \"Prevent changing lock screen and logon image\" setting to always force the specified lock screen and logon image to be shown.Note: This setting only applies to Enterprise, Education, and Server SKUs.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows",
    "KeyName":  "Personalization",
    "Elements":  [
                        {
                            "ValueName":  "LockScreenImage",
                            "Type":  "Text"
                        },
                        {
                            "ValueName":  "LockScreenOverlaysDisabled",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        }
                    ]
},
```

---

Miscellaneous (`ControlPanelDisplay.admx`):  

Prevent lock screen background motion:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v AnimateLockScreenBackground /t REG_DWORD /d 1 /f
```
Prevent enabling lock screen slide show:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f
```
Show clear logon background:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /t REG_DWORD /d 1 /f
```

# Enable Game Mode

Game Mode should: "Prevents Windows Update from performing driver installations and sending restart notifications" Does it work? Not really, in my experience it tends to lower the priority and prevent driver updates (correct me if you've experienced otherwise) - It may also mess with process/thread priorities. Not all games support it, generally leave it enabled or benchmark the differences in equal scenarios.

It might set CPU affinites (`AffinitizeToExclusiveCpus`, `CpuExclusivityMaskHig`, `CpuExclusivityMaskLow`) for the game process and the maximum amount of cores the game uses (`MaxCpuCount`). The percentage of GPU memory (`PercentGpuMemoryAllocatedToGame`), GPU time (`PercentGpuTimeAllocatedToGame`) & system compositor (`PercentGpuMemoryAllocatedToSystemCompositor`) that will be dedicated to the game. It may also create a list of processes (`RelatedProcessNames`) that are gaming related, which means that they won't be affected from the game mode. These are just assumptions, I haven't looked into it in detail yet (`GamingHandlers.c`).

Disable game mode:
```bat
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f
```
Enable game mode (switch on/off):
```bat
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
```
Enabling/disabling it via the system settings only switches `AutoGameModeEnabled`:
```ps
SystemSettings.exe  HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled	Type: REG_DWORD, Length: 4, Data: 1
```
The value doesn't exist by default (not existing = `1`). Ignore `GameBar.txt`, it shows read values.

> [system/assets | gamemode-GamingHandlers.c](https://github.com/5Noxi/win-config/blob/main/system/assets/gamemode-GamingHandlers.c)  
> https://support.xbox.com/en-US/help/games-apps/game-setup-and-play/use-game-mode-gaming-on-pc  
> https://learn.microsoft.com/en-us/uwp/api/windows.gaming.preview.gamesenumeration?view=winrt-26100

---

Miscellaneous notes:
```ps
\Registry\User\S-ID\SOFTWARE\Microsoft\GameBar : GamepadDoublePressIntervalMs
\Registry\User\S-ID\SOFTWARE\Microsoft\GameBar : GamepadShortPressIntervalMs
```

# Disable Search Indexing

It builds a database of file names, properties, and contents to speed up searches, runs as `SearchIndexer.exe`, updates automatically. Disabling it slows down searches, but as shows below you should use everything anyway. Additionally you can disable content and property indexing per drive, by right clicking on the drive, then unticking the box as shown in the picture.

> https://learn.microsoft.com/en-us/windows/win32/search/-search-indexing-process-overview

![](https://github.com/5Noxi/win-config/blob/main/system/images/searchindex.png?raw=true)

Instead of using the explorer to search for a file or folder, use everything. It's a lot faster:
> https://www.voidtools.com/downloads/

The command below includes some of my personal settings. They're saved in:
```
%appdata%\Everything\Everything.ini
```
If you want to revert the changes, either remove the `Everything.ini` file or restore the settings via the options (`STRG + P`).
```ps
$nvp = "$env:appdata\Everything\Everything.ini";(gc $nvp) -replace '^normal_background_color=.*', 'normal_background_color=#353535' -replace '^normal_foreground_color=.*', 'normal_foreground_color=#ffffff' -replace '^single_click_open=.*', 'single_click_open=2' -replace '^hide_empty_search_results=.*', 'hide_empty_search_results=1' -replace '^double_click_path=.*', 'double_click_path=1' -replace '^show_mouseover=.*', 'show_mouseover=1' -replace '^show_number_of_results_with_selection=.*', 'show_number_of_results_with_selection=1' -replace '^tooltips=.*', 'tooltips=0' -replace '^search_history_enabled=.*', 'search_history_enabled=0' -replace '^run_history_enabled=.*', 'run_history_enabled=0' -replace '^index_date_modified=.*', 'index_date_modified=0' -replace '^exclude_list_enabled=.*', 'exclude_list_enabled=0' -replace '^language=.*', 'language=1033' | sc $nvp
```

The `WSearch` service is needed for CmdPals `File Search` extension to work.

# Enable HAGS

HAGS feature is introducedspecifically for the WDDM. If disables the CPU manages the GPU scheduling via a high-priority kernel thread, GPU context switches and task scheduling are handled by the CPU (CPU offloads graphics intensive tasks to the GPU for rendering). If enabled the GPU handles its own scheduling using a built in scheduler processor, context switching between GPU tasks is done directly on the GPU. It is especially beneficial, if you've a slow CPU, or if the CPU is heavily loaded with other tasks. 
"It depends on your hardware, if you want HAGS to be enabled or not. E.g if using a old GPU, it may not fully support the new scheduler."

HAGS should be enabled, there're many reasons like different threads... may add more information here soon.

> https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/  
> https://maxcloudon.com/hardware-accelerated-gpu-scheduling/

# Remove Windows.old

Removes old/previous windows installation files from `Windows.old`.

```
Ten days after you upgrade to Windows, your previous version of Windows will be automatically deleted from your PC. However, if you need to free up drive space, and you're confident that your files and settings are where you want them to be in Windows, you can safely delete it yourself.

If it's been fewer than 10 days since you upgraded to Windows, your previous version of Windows will be listed as a system file you can delete. You can delete it, but keep in mind that you'll be deleting your Windows.old folder, which contains files that give you the option to go back to your previous version of Windows. If you delete your previous version of Windows, this can't be undone (you won't be able to go back to your previous version of Windows).
```
> https://support.microsoft.com/en-us/windows/delete-your-previous-version-of-windows-f8b26680-e083-c710-b757-7567d69dbb74

# Disable Storage Sense

Storage Sense deletes temporary files automatically - revert it by changing it back to `1`.

![](https://github.com/5Noxi/win-config/blob/main/system/images/storagesen1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/storagesen2.png?raw=true)

# Reduce Shutdown Time

Forces hung apps and services to terminate faster.

```
\Registry\Machine\SYSTEM\ControlSet001\Control : WaitToKillServiceTimeout
\Registry\User\S-ID\Control Panel\Desktop : WaitToKillTimeout
\Registry\User\S-ID\Control Panel\Desktop : HungAppTimeout
\Registry\User\S-ID\Control Panel\Desktop : AutoEndTasks
```
`HungAppTimeout`-> `1500` (`1.5` sec; default is `5` sec)
`WaitToKillTimeout`-> `2500` (`2.5` sec)
`WaitToKillServiceTimeout`-> `2500` (`2.5` sec; default is `5` sec)
`WaitToKillAppTimeout` seems to not be used anymore (would have a default of `20000` (`20` sec))

More timeout related values located in `HKCU\Control Panel\Desktop`: `CriticalAppShutdownCleanupTimeout`, `CriticalAppShutdownTimeout`, `QuickResolverTimeout`, `ActiveWndTrkTimeout`, `CaretTimeout`, `ForegroundLockTimeout`, `LowLevelHooksTimeout`. I may add information about some of them soon.

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/ControlPanel-Desktop.txt

# Disable FTH

Used for preventing legacy or unstable applications from crashing, read through the picture below for more detailed information (`Windows Internals 7th Edition, Part 1, Page 347`).

> https://github.com/5Noxi/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf  
> https://learn.microsoft.com/en-us/windows/win32/win7appqual/fault-tolerant-heap  
> https://www.youtube.com/watch?v=4SvNNXAwoqE

![](https://github.com/5Noxi/win-config/blob/main/system/images/fth.png?raw=true)

# Disable Accessibility Features

Disables multiple accessibility features such as `Sticky Keys`, `Toggle Keys`, `Mouse Keys`, `Sound Sentry`, `High Contrast` and more (read trough the file for more).

Disable accessibility insights telemetry with:
```bat
reg add "HKLM\SOFTWARE\Policies\Accessibility Insights for Windows" /v DisableTelemetry /t REG_DWORD /d 1 /f
powershell -NoProfile -Command "$f='$env:LOCALAPPDATA\AccessibilityInsights\V1\Configurations\Configuration.json';if(Test-Path $f){$j=if((gc $f -Raw) -eq ''){@{}}else{gc $f -Raw|ConvertFrom-Json};$j.EnableTelemetry=$false;$j|ConvertTo-Json|sc $f -Encoding UTF8;Write-Host 'EnableTelemetry set to false in' $f}else{Write-Host 'JSON file not found.'}"
```
> https://github.com/microsoft/accessibility-insights-windows/blob/main/docs/TelemetryOverview.md#control-of-telemery

# Detailed Verbose Messages

Enables detailed messages at restart, shut down, sign out, and sign in, which can be helpful.

"Verbose status messages can be very helpful when debugging or troubleshooting certain Windows problems, including slow startup, shutdown, logon, or logoff behavior. If your Windows is just not shutting down, verbose status messages may tell you where exactly or at which stage it is getting ‘stuck'."

> https://www.thewindowsclub.com/enable-verbose-status-message-windows

# Disable Theme Mouse Changes

Prevent Themes from changing the mouse cursor.

# Disable Aero Shake

![HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced](https://www.techjunkie.com/wp-content/uploads/2018/10/windows-aero-shake-example.gif)

# Disable JPEG Reduction

Windows reduces the quality of JPEG images you set as the desktop background to `85%` by default, you can set it to `100%`, by using the following batch.

Pseudocode snippet:
```c
if ( JPEGImportQuality not present or error )
    v54 = 85.0f;
else
    v54 = max(JPEGImportQuality, 60.0f);
    if (v54 > 100.0f)
        v54 = 100.0f;
```
Default value is `85` -> `85%` (gets used if value isn't present), clamp range is `60-100`, if set above `100` it gets clamped to `100`, if set below `60`, it gets clamped to `60`.


Change your wallpaper via cmd:
```
reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d ""C:\Path\Picture.png"" /f
```

> [system/assets | jpeg-TranscodeImage.c](https://github.com/5Noxi/win-config/blob/main/system/assets/jpeg-TranscodeImage.c)

# Disable Low Disk Space Checks
Self explaining.

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/CV-Explorer.txt

![](https://github.com/5Noxi/win-config/blob/main/system/images/lowdiskspace.jpg?raw=true)

# Clean WinSxS Folder

Get the current size of the WinSxS folder, by pasting the following command into `cmd`:
```cmd
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
```
The output could look like:
```
C:\Users\Nohuxi>Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore

Component Store (WinSxS) information:

Windows Explorer Reported Size of Component Store : 5.00 GB

Actual Size of Component Store : 4.94 GB

    Shared with Windows : 2.82 GB
    Backups and Disabled Features : 2.12 GB
    Cache and Temporary Data :  0 bytes

Date of Last Cleanup : 2025-03-30 11:05:43

Number of Reclaimable Packages : 0
Component Store Cleanup Recommended : No
```
`Number of Reclaimable Packages : 0` -> This is the number of superseded packages on the system that component cleanup can remove.

> https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/determine-the-actual-size-of-the-winsxs-folder?view=windows-11&source=recommendations#analyze-the-component-store

Clean your folder with:
```cmd
Dism.exe /online /Cleanup-Image /StartComponentCleanup
```
or
```
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
```
, if you want to remove all superseded versions of every component in the component store. (no need, if there aren't any)

> https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/manage-the-component-store?view=windows-11  
> https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder?view=windows-11

Permanently remove outdated update files from `C:\Windows\WinSxS` to free space. Once applied, previous updates cannot be uninstalled:
```bat
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v DisableResetbase /t REG_DWORD /d 0 /f
```
The value doesn't exist on more recent versions.

# Enable Segment Heap

"With the introduction of Windows 10, Segment Heap, a new native heap implementation was also introduced. It is currently the native heap implementation used in Windows apps (formerly called Modern/Metro apps) and in certain system processes, while the older native heap implementation (NT Heap) is still the default for traditional applications."

Allows modern apps to use a more efficient memory allocator.

For a specific executeable:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
Image File Execution Options\(executable)
FrontEndHeapDebugOptions = (DWORD)
Bit 2 (0x04): Disable Segment Heap
Bit 3 (0x08): Enable Segment Heap
```
Globally:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap
Enabled = (DWORD)
0 : Disable Segment Heap
(Not 0): Enable Segment Heap
```
Enabling segment heap globally forces the system to use the newer segmented allocation model, which can end up with errors.

`heapmisc.c` includes info for the 4 comments (default values).

> https://blog.s-schoener.com/2024-11-05-segment-heap/  
> https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf  
> https://github.com/5Noxi/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf (Page `334`f.)  
> [system/assets | segment-RtlpHpApplySegmentHeapConfigurations.c](https://github.com/5Noxi/win-config/blob/main/system/assets/segment-RtlpHpApplySegmentHeapConfigurations.c)


![](https://github.com/5Noxi/win-config/blob/main/system/images/segment1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/segment2.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/segment3.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/segment4.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/segment5.png?raw=true)

---

Miscellaneous notes:
```c
INIT:0000000140C6A660                 dq offset aSessionManager_6 ; "Session Manager"
INIT:0000000140C6A668                 dq offset aHeapsegmentres ; "HeapSegmentReserve"
INIT:0000000140C6A670                 dq offset qword_140FC4228
INIT:0000000140C6A678                 dq 3 dup(0)
INIT:0000000140C6A690                 dq offset aSessionManager_6 ; "Session Manager"
INIT:0000000140C6A698                 dq offset aHeapsegmentcom ; "HeapSegmentCommit"
INIT:0000000140C6A6A0                 dq offset qword_140FC4220
INIT:0000000140C6A6A8                 align 20h
INIT:0000000140C6A6C0                 dq offset aSessionManager_6 ; "Session Manager"
INIT:0000000140C6A6C8                 dq offset aHeapdecommitto ; "HeapDeCommitTotalFreeThreshold"
INIT:0000000140C6A6D0                 dq offset qword_140FC4218
INIT:0000000140C6A6D8                 dq 3 dup(0)
INIT:0000000140C6A6F0                 dq offset aSessionManager_6 ; "Session Manager"
INIT:0000000140C6A6F8                 dq offset aHeapdecommitfr ; "HeapDeCommitFreeBlockThreshold"
INIT:0000000140C6A700                 dq offset qword_140FC4210
INIT:0000000140C6A708                 align 20h

ALMOSTRO:0000000140FC4210 qword_140FC4210 dq 1000h                ; DATA XREF: sub_1404F2FA0+2F9↑r
ALMOSTRO:0000000140FC4210                                         ; sub_14097DBCC+134↑r ...
ALMOSTRO:0000000140FC4218 qword_140FC4218 dq 10000h               ; DATA XREF: sub_1404F2FA0+31C↑r
ALMOSTRO:0000000140FC4218                                         ; sub_14097DBCC+127↑r ...
ALMOSTRO:0000000140FC4220 qword_140FC4220 dq 2000h                ; DATA XREF: sub_1404F2FA0+2DE↑r
ALMOSTRO:0000000140FC4220                                         ; sub_14097E0AC+1AD↑r ...
ALMOSTRO:0000000140FC4228 qword_140FC4228 dq 100000h              ; DATA XREF: sub_1404F2FA0+2C3↑r
ALMOSTRO:0000000140FC4228                                         ; sub_14097E0AC+19E↑r ...
```

# Disable Notifications

Disables lock screen, desktop, feature advertisement balloon notifications, notification area, notifications network usage and more.

"`WnsEndpoint` (`REG_SZ`) determines which Windows Notification Service (WNS) endpoint will be used to connect for Windows push notifications. If you disable or don't configure this setting, the push notifications will connect to the default endpoint of `client.wns.windows.com`. " Located in `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`. Block `client.wns.windows.com` via the hosts file.

Disable security center notifications with (`WindowsDefenderSecurityCenter.admx`):
```bat
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v FirewallDisableNotify /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v UpdatesDisableNotify /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Enterprise Customization" /v EnableForToasts /t REG_DWORD /d 0 /f
```

---

Miscellaneous notes:
```ps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v WnsEndpoint /t REG_SZ /d client.wns.windows.com /f
```

# Export Explorer/Taskbar Pins

Can be useful when creating your own image and trying to automate the installation and configuration part.

Quick access pins are saved in a file named `f01b4d95cf55d32a.automaticDestinations-ms`, located at:
```bat
%appdata%\Microsoft\Windows\Recent\AutomaticDestinations
```
You can either terminate `explorer` while copying it to the path, or just restart it afterwards.
```bat
copy /y ".\f01b4d95cf55d32a.automaticDestinations-ms" "%appdata%\Microsoft\Windows\Recent\AutomaticDestinations"
```
Taskbar pins are saved in a folder and a key, the folder includes the shortcuts:
```bat
%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar
```
```ps
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband # Only "Favorites" is needed
```
You can convert the exported `.reg` to `.ps1` with:
> https://reg2ps.azurewebsites.net/

Post install example (copy the `TaskBar` folder to any folder):
```ps
del "$env:appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" -Recurse -Force
xcopy ".\TaskBar" "%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" /e /i /y
```
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/xcopy

__Automate the process:__
Gets current values of `Favorites` (taskbar pins) & `UIOrderList` (system tray icons) and copies all necessary files to `$home\Desktop` (edit `$dest` & `$bat` to whatever you want).

# Disable Timestamp Interval

Disables the interval at which reliability events are timestamped (will not log regular timestamped reliability events).

```c
if ( !RegQueryValueExW(hKey[0], L"TimeStampEnabled", 0LL, 0LL, (LPBYTE)&Data, &cbData) )
if ( !RegQueryValueExW(hKey[0], L"TimeStampInterval", 0LL, 0LL, (LPBYTE)&v4, &cbData) && v4 <= 0x15180 ) // 86400 seconds = 24h?
```
`TimeStampInterval` has a max value of `86400` dec = 24h, `TimeStampEnabled` can probably be set to `0`/`1`.

```
\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability : TimeStampInterval
```
Only this path gets read, `TimeStampEnabled` doesn't get read?

> [system/assets | timestamp-OsEventsTimestampInterval.c](https://github.com/5Noxi/win-config/blob/main/system/assets/timestamp-OsEventsTimestampInterval.c)

# Disable Prefetch & Superfetch

Disables prefetcher (includes disabling `ApplicationLaunchPrefetching` & `ApplicationPreLaunch`) features, used to speed up the boot process and application startup by preloading data - **shouldn't be disabled**, leaving it for documentation reasons. Read through the pictures for more detailed information.

"`EnablePrefetcher` is a setting in the File-Based Write Filter (FBWF) and Enhanced Write Filter with HORM (EWF) packages. It specifies how to run Prefetch, a tool that can load application data into memory before it is demanded."

"`EnableSuperfetch` is a setting in the File-Based Write Filter (FBWF) and Enhanced Write Filter with HORM (EWF) packages. It specifies how to run SuperFetch, a tool that can load application data into memory before it is demanded. SuperFetch improves on Prefetch by monitoring which applications that you use the most and preloading those into system memory."

"`SfTracingState` belongs to `sftracing.exe`. This file most often belongs to product Office Server Search. This file most often has  description Office Server Search."

`EnableBoottrace` is used to trace the startup, `1`= enabled, `0` = disabled.

```
0 - Disables Prefetch
1 - Enables Prefetch when the application starts
2 - Enables Prefetch when the device starts up
3 - Enables Prefetch when the application or device starts up
```
The same applies to superfetch.

> https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794235(v=winembedded.60)?redirectedfrom=MSDN  
> https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794183(v=winembedded.60)?redirectedfrom=MSDN  
> https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps

More detailed information about prefetch and superfetch on page `413`f & `472`f.
> https://github.com/5Noxi/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf

![](https://github.com/5Noxi/win-config/blob/main/system/images/prefetch1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/prefetch2.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/prefetch3.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/prefetch4.png?raw=true)

# Optimize File System

If you're confused about `NTFSDisableLastAccessUpdate /t REG_DWORD /d 2147483649`:
> https://www.tenforums.com/tutorials/139015-enable-disable-ntfs-last-access-time-stamp-updates-windows-10-a.html

`NtfsMftZoneReservation` is currently set to `2` (valid range is 1-4 -> 4 MFT zone size to the maximum)
> https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/ntfs-reserves-space-for-mft

Scan current 8dot3 files names: `fsutil 8dot3name scan C:\`

Symlinksare shortcuts or references that point to a file or folder in another location, like a portal. They're not duplicates, just pointers.
File at: `C:\Projects\Game\assets\logo.png`
Symlink: `C:\Users\YourName\Desktop\logo.png`

> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior  
> https://github.com/MicrosoftDocs/windows-driver-docs/blob/5e03e46194f2a977da34fdf453f2703262370a23/windows-driver-docs-pr/ifs/offloaded-data-transfers.md?plain=1#L104  
> https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry  
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/FileSystem.txt

> [system/assets | filesystem-NtfsUpdateDynamicRegistrySettings.c](https://github.com/5Noxi/win-config/blob/main/system/assets/filesystem-NtfsUpdateDynamicRegistrySettings.c)

# Disable Clipboard

If you copy or cut something it gets stored to your clipboard.

Additional value, which get's read:
```
\Registry\Machine\SOFTWARE\Microsoft\Clipboard : IsCloudAndHistoryFeatureAvailable
```
To only disable the history, use:
```bat
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f
```
```json
{
    "File":  "TerminalServer.admx",
    "NameSpace":  "Microsoft.Policies.TerminalServer",
    "Class":  "Machine",
    "CategoryName":  "TS_REDIRECTION",
    "DisplayName":  "Do not allow Clipboard redirection",
    "ExplainText":  "This policy setting specifies whether to prevent the sharing of Clipboard contents (Clipboard redirection) between a remote computer and a client computer during a Remote Desktop Services session.You can use this setting to prevent users from redirecting Clipboard data to and from the remote computer and the local computer. By default, Remote Desktop Services allows Clipboard redirection.If you enable this policy setting, users cannot redirect Clipboard data.If you disable this policy setting, Remote Desktop Services always allows Clipboard redirection.If you do not configure this policy setting, Clipboard redirection is not specified at the Group Policy level.",
    "Supported":  "WindowsXP",
    "KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
    "KeyName":  "fDisableClip",
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
    "File":  "WindowsSandbox.admx",
    "NameSpace":  "Microsoft.Policies.WindowsSandbox",
    "Class":  "Machine",
    "CategoryName":  "WindowsSandbox",
    "DisplayName":  "Allow clipboard sharing with Windows Sandbox",
    "ExplainText":  "This policy setting enables or disables clipboard sharing with the sandbox.If you enable this policy setting, copy and paste between the host and Windows Sandbox are permitted. If you disable this policy setting, copy and paste in and out of Sandbox will be restricted.If you do not configure this policy setting, clipboard sharing will be enabled.",
    "Supported":  "Windows_11_0_NOSERVER_ENTERPRISE_EDUCATION_PRO_SANDBOX",
    "KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Sandbox",
    "KeyName":  "AllowClipboardRedirection",
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
    "File":  "OSPolicy.admx",
    "NameSpace":  "Microsoft.Policies.OSPolicy",
    "Class":  "Machine",
    "CategoryName":  "PolicyPolicies",
    "DisplayName":  "Allow Clipboard synchronization across devices",
    "ExplainText":  " This policy setting determines whether Clipboard contents can be synchronized across devices. If you enable this policy setting, Clipboard contents are allowed to be synchronized across devices logged in under the same Microsoft account or Azure AD account. If you disable this policy setting, Clipboard contents cannot be shared to other devices. Policy change takes effect immediately.",
    "Supported":  "Windows_10_0",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
    "KeyName":  "AllowCrossDeviceClipboard",
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
    "File":  "OSPolicy.admx",
    "NameSpace":  "Microsoft.Policies.OSPolicy",
    "Class":  "Machine",
    "CategoryName":  "PolicyPolicies",
    "DisplayName":  "Allow Clipboard History",
    "ExplainText":  " This policy setting determines whether history of Clipboard contents can be stored in memory. If you enable this policy setting, history of Clipboard contents are allowed to be stored. If you disable this policy setting, history of Clipboard contents are not allowed to be stored. Policy change takes effect immediately.",
    "Supported":  "Windows_10_0",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
    "KeyName":  "AllowClipboardHistory",
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

# Disable Background GP Updates

"This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users, and domain controllers.If you enable this policy setting, the system waits until the current user logs off the system before updating the computer and user settings.If you disable or do not configure this policy setting, updates can be applied while users are working."

```json
{
    "File":  "GroupPolicy.admx",
    "NameSpace":  "Microsoft.Policies.GroupPolicy",
    "Class":  "Machine",
    "CategoryName":  "PolicyPolicies",
    "DisplayName":  "Turn off background refresh of Group Policy",
    "ExplainText":  "This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users, and domain controllers.If you enable this policy setting, the system waits until the current user logs off the system before updating the computer and user settings.If you disable or do not configure this policy setting, updates can be applied while users are working. The frequency of updates is determined by the \"Set Group Policy refresh interval for computers\" and \"Set Group Policy refresh interval for users\" policy settings.Note: If you make changes to this policy setting, you must restart your computer for it to take effect.",
    "Supported":  "Win2k",
    "KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "KeyName":  "DisableBkGndGroupPolicy",
    "Elements":  [

                    ]
},
```

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-grouppolicy#disablebackgroundpolicy

---

Miscellaneous notes:
```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DenyUsersFromMachGP /t REG_DWORD /d 1 /f
```
Users aren't able to invoke a refresh of computer policy. Computer policy will still be applied at startup or when an official policy refresh occurs.

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-grouppolicy#disableusersfrommachgp

# Disable Memory Compression

Memory compression compresses rarely used or less frequently accessed data in RAM so it takes up less space. Windows does this to keep more data in physical memory and avoid writing to the pagefile, which reduces disk I/O. When the data is needed again, it's decompressed. It's faster than paging to disk, but it costs CPU.

Example:  
1. System looks for cold/rarely used data in RAM
2. It compresses that data, e.g. 24 MB -> 7 MB
3. The 17 MB saved is used for active apps
4. When the data is needed again, it's decompressed back to 24 MB

See the current memory compresstion state on your system via:
```ps
Get-MMAgent
```
```ps
ApplicationLaunchPrefetching : True
ApplicationPreLaunch         : True
MaxOperationAPIFiles         : 512
MemoryCompression            : True # Enabled
OperationAPI                 : True
PageCombining                : True
PSComputerName               :
```

![](https://github.com/5Noxi/win-config/blob/main/system/images/memcompress1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/memcompress2.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/memcompress3.png?raw=true)

> https://github.com/5Noxi/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf (P. 449)  
> https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps

# Disable Page Combining

Page combining spots identical RAM pages across processes and merges them into a single shared page. Instead of keeping 50 copies of the same DLL/data page, the memory manager keeps one, maps it to everyone, and marks it `copy-on-write`. As long as nobody changes it, everyone shares the same physical page and RAM usage drops. If a process writes to it, Windows gives that process its own private copy and leaves the shared one intact. It's a background RAM deduplicator, basically.

See the current page combining state on your system via:
```ps
Get-MMAgent
```
```ps
ApplicationLaunchPrefetching : True
ApplicationPreLaunch         : True
MaxOperationAPIFiles         : 512
MemoryCompression            : True
OperationAPI                 : True
PageCombining                : True # Enabled
PSComputerName               :
```

![](https://github.com/5Noxi/win-config/blob/main/system/images/pagecomb1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/pagecomb2.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/pagecomb3.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/pagecomb4.png?raw=true)

> https://github.com/5Noxi/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf (P. 459)  
> https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps

# Enable Detailed BSoD

| Aspect                    | New BSoD (Windows 8/10/11)                      | Old BSoD (Windows 7/classic)                                                      |
| ------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------- |
| Main look                 | Big blue screen, sad face, simple text, QR code | Plain blue text screen, no icons                                                  |
| Stop code shown           | e.g. CRITICAL_PROCESS_DIED                      | e.g. STOP 0x0000007E                                                              |
| Hex parameters            | Hidden                                          | Shown: (0x00000000, 0x00000000...)                                                |
| Faulty driver/module name | Hidden                                          | Often shown (e.g. nvlddmkm.sys)                                                   |
| Extra help                | QR code + link                                  | Text-only advice                                                                  |
| Purpose                   | Less scary, easier to tell support the code     | See the actual debug information                                                  |

Enabling the options includes setting `AutoReboot` to `0` ("The option specifies that Windows automatically restarts your computer").

> https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options#registry-values-for-startup-and-recovery  
> https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options

---

Disable BSoD smiley:
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v DisableEmoticon /t REG_DWORD /d 1 /f
```