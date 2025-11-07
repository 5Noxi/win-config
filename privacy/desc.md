# Disable General Telemetry

Prevents sending info about your computer to microsoft, disables the diagnostic log collection, media player diagnostics, bluetooth ads (`DataCollection.admx`), the inventory collector. It disables the ads ID ("Windows creates a unique advertising ID per user, allowing apps and ad networks to deliver targeted ads. When enabled, it works like a cookie, linking personal data to the ID for personalized ads. This setting only affects Windows apps using the advertising ID, not web-based ads or third-party methods.") which should be disabled by default, if you toggled all options off in the OS installation phase. See policy explanations below for more details.

```ps
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\DataCollection : AllowTelemetry_PolicyManager
```
Seems to be a fallback if `AllowTelemetry` isn't set.
> https://github.com/TechTech512/Win11Src/blob/840a61919419c94ed24a9b079ee1029f482d29f2/NT/onecore/base/telemetry/permission/product/telemetrypermission.cpp#L106


Miscellaneous notes:  

Telemetry for DCE usage?
```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DCEInUseTelemetryDisabled /t REG_DWORD /d 1 /f
```
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Winows-NT.txt

"This setting controls the Inventory Collector, which sends app, file, device, and driver data to Microsoft. Enabled = Collector off. Disabled/not configured = Collector on. Has no effect if CEIP is off." (`AppCompat.admx`):
```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
```
Kills the device and configuration data collection tool and telemetry collector and sender tasks.
```bat
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```
```ps
reg add "HKLM\SOFTWARE\Microsoft\wbem\Tracing" /v enableWinmgmtTelemetry /t REG_DWORD /d 0 /f
```

```json
{
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Both",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Send optional diagnostic data",
	"ExplainText":  "By configuring this policy setting you can adjust what diagnostic data is collected from Windows. This policy setting also restricts the user from increasing the amount of diagnostic data collection via the Settings app. The diagnostic data collected under this policy impacts the operating system and apps that are considered part of Windows and does not apply to any additional apps installed by your organization. - Diagnostic data off (not recommended). Using this value, no diagnostic data is sent from the device. This value is only supported on Enterprise, Education, and Server editions. - Send required diagnostic data. This is the minimum diagnostic data necessary to keep Windows secure, up to date, and performing as expected. Using this value disables the \"Optional diagnostic data\" control in the Settings app. - Send optional diagnostic data. Additional diagnostic data is collected that helps us to detect, diagnose and fix issues, as well as make product improvements. Required diagnostic data will always be included when you choose to send optional diagnostic data. Optional diagnostic data can also include diagnostic log files and crash dumps. Use the \"Limit Dump Collection\" and the \"Limit Diagnostic Log Collection\" policies for more granular control of what optional diagnostic data is sent.If you disable or do not configure this policy setting, the device will send required diagnostic data and the end user can choose whether to send optional diagnostic data from the Settings app.Note:The \"Configure diagnostic data opt-in settings user interface\" group policy can be used to prevent end users from changing their data collection settings.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows",
	"KeyName":  "DataCollection",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "AllowTelemetry",
							"Items":  [
										{
											"DisplayName":  "Diagnostic data off (not recommended)",
											"Value":  "0"
										},
										{
											"DisplayName":  "Send required diagnostic data",
											"Value":  "1"
										},
										{
											"DisplayName":  "Send optional diagnostic data",
											"Value":  "3"
										}
									]
						}
					]
},
{
	"File":  "AppCompat.admx",
	"NameSpace":  "Microsoft.Policies.ApplicationCompatibility",
	"Class":  "Machine",
	"CategoryName":  "AppCompat",
	"DisplayName":  "Turn off Application Telemetry",
	"ExplainText":  "The policy controls the state of the Application Telemetry engine in the system.Application Telemetry is a mechanism that tracks anonymous usage of specific Windows system components by applications.Turning Application Telemetry off by selecting \"enable\" will stop the collection of usage data.If the customer Experience Improvement program is turned off, Application Telemetry will be turned off regardless of how this policy is set.Disabling telemetry will take effect on any newly launched applications. To ensure that telemetry collection has stopped for all applications, please reboot your machine.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\AppCompat",
	"KeyName":  "AITEnable",
	"Elements":  [
						{
							"Value":  "0",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "1",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Disable OneSettings Downloads",
	"ExplainText":  "This policy setting controls whether Windows attempts to connect with the OneSettings service.If you enable this policy, Windows will not attempt to connect with the OneSettings Service.If you disable or don\u0027t configure this policy setting, Windows will periodically attempt to connect with the OneSettings service to download configuration settings.",
	"Supported":  "Windows_10_0_RS7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "DisableOneSettingsDownloads",
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Limit Diagnostic Log Collection",
	"ExplainText":  "This policy setting controls whether additional diagnostic logs are collected when more information is needed to troubleshoot a problem on the device. Diagnostic logs are only sent when the device has been configured to send optional diagnostic data.By enabling this policy setting, diagnostic logs will not be collected.If you disable or do not configure this policy setting, we may occasionally collect diagnostic logs if the device has been configured to send optional diagnostic data.",
	"Supported":  "Windows_10_0_RS7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "LimitDiagnosticLogCollection",
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Disable diagnostic data viewer",
	"ExplainText":  "This policy setting controls whether users can enable and launch the Diagnostic Data Viewer from the Diagnostic \u0026 feedback Settings page.If you enable this policy setting, the Diagnostic Data Viewer will not be enabled in Settings page, and it will prevent the viewer from showing diagnostic data collected by Microsoft from the device.If you disable or don\u0027t configure this policy setting, the Diagnostic Data Viewer will be enabled in Settings page.",
	"Supported":  "Windows_10_0_RS5",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "DisableDiagnosticDataViewer",
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Enable diagnostic data opt-in setings",
	"ExplainText":  "This policy setting determines whether an end user can change diagnostic data settings in the Settings app.If you set this policy setting to \"Disable diagnostic data opt-in settings\", diagnostic data settings are disabled in the Settings app.If you don\u0027t configure this policy setting, or you set it to \"Enable diagnostic data opt-in settings\", end users can change the device diagnostic settings in the Settings app.Note:To set a limit on the amount of diagnostic data that is sent to Microsoft by your organization, use the \"Allow Diagnostic Data\" policy setting.",
	"Supported":  "Windows_10_0_RS4",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "DisableTelemetryOptInSettingsUx",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "DisableTelemetryOptInSettingsUx",
							"Items":  [
										{
											"DisplayName":  "Disable diagnostic data opt-in settings",
											"Value":  "1"
										},
										{
											"DisplayName":  "Enable diagnostic data opt-in setings",
											"Value":  "0"
										}
									]
						},
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Limit Dump Collection",
	"ExplainText":  "This policy setting limits the type of dumps that can be collected when more information is needed to troubleshoot a problem. Dumps are only sent when the device has been configured to send optional diagnostic data.By enabling this setting, Windows Error Reporting is limited to sending kernel mini dumps and user mode triage dumps.If you disable or do not configure this policy setting, we may occasionally collect full or heap dumps if the user has opted to send optional diagnostic data.",
	"Supported":  "Windows_10_0_RS7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "LimitDumpCollection",
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Disable Desktop Analytics collection",
	"ExplainText":  "This policy setting, in combination with the \"Allow Diagnostic Data\" policy setting, enables organizations to send the minimum data required by Desktop Analytics.To enable the behavior described above, complete the following steps: 1. Enable this policy setting 2. Set the \"Allow Diagnostic Data\" policy to \"Send optional diagnostic data\" 3. Enable the \"Limit Dump Collection\" policy 4. Enable the \"Limit Diagnostic Log Collection\" policyWhen these policies are configured, Microsoft will collect only required diagnostic data and the events required by Desktop Analytics, which can be viewed at https://go.microsoft.com/fwlink/?linkid=2116020.If you disable or do not configure this policy setting, diagnostic data collection is determined by the \"Allow Diagnostic Data\" policy setting or by the end user from the Settings app.",
	"Supported":  "Windows_10_0_RS3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "LimitEnhancedDiagnosticDataWindowsAnalytics",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "LimitEnhancedDiagnosticDataWindowsAnalytics",
							"Items":  [
										{
											"DisplayName":  "Enable Desktop Analytics collection",
											"Value":  "1"
										},
										{
											"DisplayName":  "Disable Desktop Analytics collection",
											"Value":  "0"
										}
									]
						},
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Allow device name to be sent in Windows diagnostic data",
	"ExplainText":  "This policy allows the device name to be sent to Microsoft as part of Windows diagnostic data.If you disable or do not configure this policy setting, then device name will not be sent to Microsoft as part of Windows diagnostic data.",
	"Supported":  "Windows_10_0_RS4",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "AllowDeviceNameInTelemetry",
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
	"File":  "DataCollection.admx",
	"NameSpace":  "Microsoft.Policies.DataCollection",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Enable diagnostic data change notifications",
	"ExplainText":  "This policy setting controls whether notifications are shown, following a change to diagnostic data opt-in settings, on first logon and when the changes occur in settings.If you set this policy setting to \"Disable diagnostic data change notifications\", diagnostic data opt-in change notifications will not appear.If you set this policy setting to \"Enable diagnostic data change notifications\" or don\u0027t configure this policy setting, diagnostic data opt-in change notifications appear at first logon and when the changes occur in Settings.",
	"Supported":  "Windows_10_0_RS4",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "DisableTelemetryOptInChangeNotification",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "DisableTelemetryOptInChangeNotification",
							"Items":  [
										{
											"DisplayName":  "Disable diagnostic data change notifications",
											"Value":  "1"
										},
										{
											"DisplayName":  "Enable diagnostic data change notifications",
											"Value":  "0"
										}
									]
						},
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
	"File":  "AppCompat.admx",
	"NameSpace":  "Microsoft.Policies.ApplicationCompatibility",
	"Class":  "Machine",
	"CategoryName":  "AppCompat",
	"DisplayName":  "Turn off Inventory Collector",
	"ExplainText":  "This policy setting controls the state of the Inventory Collector. The Inventory Collector inventories applications, files, devices, and drivers on the system and sends the information to Microsoft. This information is used to help diagnose compatibility problems.If you enable this policy setting, the Inventory Collector will be turned off and data will not be sent to Microsoft. Collection of installation data through the Program Compatibility Assistant is also disabled.If you disable or do not configure this policy setting, the Inventory Collector will be turned on.Note: This policy setting has no effect if the Customer Experience Improvement Program is turned off. The Inventory Collector will be off.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\AppCompat",
	"KeyName":  "DisableInventory",
	"Elements":  [

					]
},
```

# Disable Automatic Map Downloads

Disables automatic network traffic on the settings page and prevents automatic downloading or updating of map data, limiting location-related data updates.

```c
v8 = 1; // Default
LOBYTE(a3) = 1;
v5 = 0;
MapsPersistedRegBoolean = RegUtils::GetMapsPersistedRegBoolean(this, L"AutoUpdateEnabled", a3, &v8);
if ( MapsPersistedRegBoolean >= 0 )
*a2 = v8 != 0;
else
return (unsigned int)ZTraceReportPropagation(
					   MapsPersistedRegBoolean,
					   "ServiceManager::GetAutoUpdateEnabledSetting",
					   3025,
					   this);
return v5;
```
```c
v8 = 1; // Default
LOBYTE(a3) = 1;
v5 = 0;
MapsPersistedRegBoolean = RegUtils::GetMapsPersistedRegBoolean(this, L"UpdateOnlyOnWifi", a3, &v8);
if ( MapsPersistedRegBoolean >= 0 )
*a2 = v8 != 0;
else
return (unsigned int)ZTraceReportPropagation(
					   MapsPersistedRegBoolean,
					   "ServiceManager::GetDownloadOnlyOnWifiSetting",
					   3043,
					   this);
return v5;
```
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-maps  
> [privacy/assets | maps.c](https://github.com/5Noxi/win-config/blob/main/privacy/assets/maps.c)


`AutoDownloadAndUpdateMapData` & `AllowUntriggeredNetworkTrafficOnSettingsPage`:
> https://gpsearch.azurewebsites.net/#13439  
> https://gpsearch.azurewebsites.net/#13350

# Disable Website Access to Language List

"Sets the HTTP Accept Language from the Language List opt-out setting." Disables `Let websites provide locally relevant content by accessing my language list`.

Using `Set-WinAcceptLanguageFromLanguageListOptOut`
```ps
Set-WinAcceptLanguageFromLanguageListOptOut -OptOut $True
```
does the same as the batch:
```c
// $True
"powershell.exe","RegSetValue","HKCU\Control Panel\International\User Profile\HttpAcceptLanguageOptOut","Type: REG_DWORD, Length: 4, Data: 1"
"powershell.exe","RegDeleteValue","HKCU\Software\Microsoft\Internet Explorer\International\AcceptLanguage",""
// $False
"powershell.exe","RegDeleteValue","HKCU\Control Panel\International\User Profile\HttpAcceptLanguageOptOut",""
"powershell.exe","RegSetValue","HKCU\Software\Microsoft\Internet Explorer\International\AcceptLanguage","Type: REG_SZ, Length: 54, Data: en-US;q=0.7,en;q=0.3"
```
> https://learn.microsoft.com/en-us/powershell/module/international/set-winacceptlanguagefromlanguagelistoptout?view=windowsserver2025-ps  
> https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#181-general

# Disable Auto Maintenance

Runs updates and scans daily when your PC is idle, it helps keep your system secure and efficient without affecting performance. Theres no actual reason to disable it, as it doesn't do anything while being active, however if you've any reason for not wanting it to run the tasks while being in idle, run  the batch. Revert it by setting it to `0` or remove the value. 

You can see your current maintenance tasks with:
```ps
Get-ScheduledTask | ? {$_.Settings.MaintenanceSettings}
```
`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance` trace:
```
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance : Activation Boundary
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance : MaintenanceDisabled
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance : Random Delay
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance : Randomized
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance : WakeUp
```

---

Miscellaneous notes:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository" /v MaintenanceInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Repository" /v MaintenanceInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v Random Delay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v Randomized /t REG_DWORD /d 0 /f
```

# Disable Xbox Game Bar

GameDVR is a built-in gameplay capture (Xbox Game Bar) for clips/screenshots, with optional background recording.

---

"Game Bar Presence Writer is a component that is notified when a game's "presence" state (i.e. is a game running in the foreground) changes. This functionality is available in Windows 10 and later operating systems. By default, the existing Game Bar Presence Writer will set a user's Xbox Live presence state for a running game if the Xbox App is installed, the user is signed into their Xbox account, and the user has enabled Xbox Live presence to be set when they run a game on their PC. It is possible for Windows Application developers to override this default behavior with their own implementation."

> https://learn.microsoft.com/en-us/windows/win32/devnotes/gamebar-presencewriter

---

Miscellaneous notes:
```ps
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : AppCaptureEnabled
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : CameraCaptureEnabledByDefault
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : HistoricalCaptureEnabled
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : HistoricalCaptureOnBatteryAllowed
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : HistoricalCaptureOnWirelessDisplayAllowed
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : KGLRevision
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : KGLToGCSUpdatedRevision
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : MicrophoneCaptureEnabled
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKSaveHistoricalVideo
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKTakeScreenshot
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleBroadcast
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCameraCapture
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom1
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom10
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom2
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom3
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom4
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom5
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom6
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom7
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom8
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleCustom9
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleGameBar
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleMicrophoneCapture
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleRecording
\Registry\User\S-0\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\GameDVR : VKToggleRecordingIndicator
```

# Disable PSR

"Steps Recorder, also known as Problems Steps Recorder (PSR) in Windows 7, is a Windows inbox program that records screenshots of the desktop along with the annotated steps while recording the activity on the screen. The screenshots and annotated text are saved to a file for later viewing."

It is a deprecated feature, as the banner shows:

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/psr.png?raw=true)

`PSR` = Problem Steps Recorder

Using the batch is enough - adding for information:
```bat
takeown /f %SystemRoot%\System32\psr.exe
icacls %SystemRoot%\System32\psr.exe /grant administrators:F
ren %SystemRoot%\System32\psr.exe psr.exe.bak
```

> https://support.microsoft.com/en-gb/windows/steps-recorder-deprecation-a64888d7-8482-4965-8ce3-25fb004e975f

```json
{
	"File":  "AppCompat.admx",
	"NameSpace":  "Microsoft.Policies.ApplicationCompatibility",
	"Class":  "Machine",
	"CategoryName":  "AppCompat",
	"DisplayName":  "Turn off Steps Recorder",
	"ExplainText":  "This policy setting controls the state of Steps Recorder.Steps Recorder keeps a record of steps taken by the user. The data generated by Steps Recorder can be used in feedback systems such as Windows Error Reporting to help developers understand and fix problems. The data includes user actions such as keyboard input and mouse input, user interface data, and screen shots. Steps Recorder includes an option to turn on and off data collection.If you enable this policy setting, Steps Recorder will be disabled.If you disable or do not configure this policy setting, Steps Recorder will be enabled.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\AppCompat",
	"KeyName":  "DisableUAR",
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

# Remove Product Key

"Some servicing operations require the product key to be available in the registry during Out of Box Experience (OOBE) operations. The /cpky option removes the product key from the registry to prevent this key from being stolen by malicious code. For retail installations that deploy keys, the best practice is to run this option. This option isn't required for MAK and KMS host keys, because this is the default behavior for those keys. This option is required only for other types of keys whose default behavior isn't to clear the key from the registry."

> https://learn.microsoft.com/en-us/windows-server/get-started/activation-slmgr-vbs-options#advanced-options

# Disable App Launch Tracking

`Privacy & security > General : Let Windows improve Start and search results by tracking app launches`

```bat
"Process Name","Operation","Path","Detail"
"SystemSettings.exe","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs","Type: REG_DWORD, Length: 4, Data: 0"
```

# Disable Location Access

Disables app access to your location, locating your system will be disabled, geolocation service gets disabled.

Disable Device Sensors:
"This policy setting turns off the sensor feature for this computer. If you enable this policy setting, the sensor feature is turned off, and all programs on this computer can't use the sensor feature."
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors#disablesensors_1

`Privacy & security` > `Location`:
```ps
"Process Name","Operation","Path","Detail"
"svchost.exe","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged\Value","Type: REG_SZ, Length: 10, Data: Deny"
"svchost.exe","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value","Type: REG_SZ, Length: 10, Data: Deny"
"svchost.exe","RegSetValue","HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value","Type: REG_SZ, Length: 10, Data: Deny"
"svchost.exe","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\ShowGlobalPrompts","Type: REG_DWORD, Length: 4, Data: 1"
```

---

Sensor related services:
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /v Start /t REG_DWORD /d 4 /f
```
Miscellaneous (ignore):
```
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\WinBio : RequireSecureSensors
\Registry\Machine\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor : CPU
\Registry\Machine\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor : ExternalResources
\Registry\Machine\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor : Flags
\Registry\Machine\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor : Importance
\Registry\Machine\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor : IO
\Registry\Machine\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LongRunningSensor : Memory
\Registry\Machine\SOFTWARE\Microsoft\Windows Defender\NIS\Consumers\IPS : DisableBmNetworkSensor
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\AutoRotation : SensorPresent
```

---

```json
{
	"File":  "Sensors.admx",
	"NameSpace":  "Microsoft.Policies.Sensors",
	"Class":  "Machine",
	"CategoryName":  "LocationAndSensors",
	"DisplayName":  "Turn off sensors",
	"ExplainText":  " This policy setting turns off the sensor feature for this computer. If you enable this policy setting, the sensor feature is turned off, and all programs on this computer cannot use the sensor feature. If you disable or do not configure this policy setting, all programs on this computer can use the sensor feature.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\LocationAndSensors",
	"KeyName":  "DisableSensors",
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
	"File":  "Sensors.admx",
	"NameSpace":  "Microsoft.Policies.Sensors",
	"Class":  "Machine",
	"CategoryName":  "LocationAndSensors",
	"DisplayName":  "Turn off location",
	"ExplainText":  " This policy setting turns off the location feature for this computer. If you enable this policy setting, the location feature is turned off, and all programs on this computer are prevented from using location information from the location feature. If you disable or do not configure this policy setting, all programs on this computer will not be prevented from using location information from the location feature.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\LocationAndSensors",
	"KeyName":  "DisableLocation",
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
	"File":  "Sensors.admx",
	"NameSpace":  "Microsoft.Policies.Sensors",
	"Class":  "Machine",
	"CategoryName":  "LocationAndSensors",
	"DisplayName":  "Turn off location scripting",
	"ExplainText":  " This policy setting turns off scripting for the location feature. If you enable this policy setting, scripts for the location feature will not run. If you disable or do not configure this policy setting, all location scripts will run.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\LocationAndSensors",
	"KeyName":  "DisableLocationScripting",
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
	"File":  "LocationProviderAdm.admx",
	"NameSpace":  "Microsoft.Policies.Sensors.WindowsLocationProvider",
	"Class":  "Machine",
	"CategoryName":  "WindowsLocationProvider",
	"DisplayName":  "Turn off Windows Location Provider",
	"ExplainText":  " This policy setting turns off the Windows Location Provider feature for this computer. If you enable this policy setting, the Windows Location Provider feature will be turned off, and all programs on this computer will not be able to use the Windows Location Provider feature. If you disable or do not configure this policy setting, all programs on this computer can use the Windows Location Provider feature.",
	"Supported":  "Windows8_Or_Windows_6_3_Only",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\LocationAndSensors",
	"KeyName":  "DisableWindowsLocationProvider",
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

> [privacy/assets | locationaccess-LocationApi.c](https://github.com/5Noxi/win-config/blob/main/privacy/assets/locationaccess-LocationApi.c)

# Disable Windows Insider

`AllowBuildPreview` is used up to W1 V1703, I'll still leave it. `Computer Configuration > Administrative Templates > Windows Component > Windows Update > Windows Update for Business : Manage Preview Builds` for W10+ versions.

> https://learn.microsoft.com/en-us/windows-insider/business/manage-builds

# Disable PowerShell & .NET Telemetry

PowerShell Telemetry:
"At startup, PowerShell sends diagnostic data including OS manufacturer, name, and version; PowerShell version; `POWERSHELL_DISTRIBUTION_CHANNEL`; Application Insights SDK version; approximate location from IP; command-line parameters (without values); current Execution Policy; and randomly generated GUIDs for the user and session."
```bat
setx POWERSHELL_TELEMETRY_OPTOUT 1
```
> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_telemetry?view=powershell-7.2

Disable NET Core CLI Telemetry:
"To opt out after you started the installer: close the installer, set the environment variable, and then run the installer again with that value set."
```bat
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
```
> https://learn.microsoft.com/en-us/dotnet/core/tools/telemetry#how-to-opt-out

# Disable Reserved Storage

"Windows reserves `~7 GB` of disk space to ensure updates and system processes run reliably. Temporary files and updates use this reserved area first. If it's full, Windows uses normal disk space or asks for external storage. Size increases with optional features or extra languages. Unused ones can be removed to reduce it."

`dism /online /Set-ReservedStorageState /State:Disabled /NoRestart` / `Set-WindowsReservedStorageState -State Disabled` set:
```bat
dismhost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager\DisableDeletes	Type: REG_DWORD, Length: 4, Data: 1
```
> https://learn.microsoft.com/en-us/powershell/module/dism/set-windowsreservedstoragestate?view=windowsserver2025-ps

# Disable Biometrics 

Biometric is used for fingerprint, facial recognition, and other biometric authentication methods in Windows Hello and related security features.

`Computer Configuration\Administrative Templates\Windows Components\Biometrics`
```ps
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{C1B650B7-6E19-4DF2-B4AE-00E5893C0487}Machine\Software\Policies\Microsoft\Biometrics\Enabled	Type: REG_DWORD, Length: 4, Data: 0
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{C1B650B7-6E19-4DF2-B4AE-00E5893C0487}Machine\Software\Policies\Microsoft\Biometrics\Credential Provider\Enabled	Type: REG_DWORD, Length: 4, Data: 0
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{C1B650B7-6E19-4DF2-B4AE-00E5893C0487}Machine\Software\Policies\Microsoft\Biometrics\Credential Provider\Domain Accounts	Type: REG_DWORD, Length: 4, Data: 0
```

# Disable Remote Desktop

Disables remote desktop, remote assistance, RPC traffic, and device redirection.
> https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-pc-connections-faq  
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktopservices

`RemoteAssistance.admx`:  
`CreateEncryptedOnlyTickets`: Allow only Windows Vista or later connections
`fAllowFullControl` (`0`): Allow helpers to only view the computer
`LoggingEnabled`: Turn on session logging

`RPC.admx`:  
`RestrictRemoteClients` (`2`): Authenticated without exceptions

`TerminalServer.admx`:  
`fDisableCdm`: Do not allow drive redirection

```json
{
	"File":  "RemoteAssistance.admx",
	"NameSpace":  "Microsoft.Policies.RemoteAssistance",
	"Class":  "Machine",
	"CategoryName":  "RemoteAssist",
	"DisplayName":  "Mailto",
	"ExplainText":  "This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.If you enable this policy setting, users on this computer can use email or file transfer to ask someone for help. Also, users can use instant messaging programs to allow connections to this computer, and you can configure additional Remote Assistance settings.If you disable this policy setting, users on this computer cannot use email or file transfer to ask someone for help. Also, users cannot use instant messaging programs to allow connections to this computer.If you do not configure this policy setting, users can turn on or turn off Solicited (Ask for) Remote Assistance themselves in System Properties in Control Panel. Users can also configure Remote Assistance settings.If you enable this policy setting, you have two ways to allow helpers to provide Remote Assistance: \"Allow helpers to only view the computer\" or \"Allow helpers to remotely control the computer.\"The \"Maximum ticket time\" policy setting sets a limit on the amount of time that a Remote Assistance invitation created by using email or file transfer can remain open.The \"Select the method for sending email invitations\" setting specifies which email standard to use to send Remote Assistance invitations. Depending on your email program, you can use either the Mailto standard (the invitation recipient connects through an Internet link) or the SMAPI (Simple MAPI) standard (the invitation is attached to your email message). This policy setting is not available in Windows Vista since SMAPI is the only method supported.If you enable this policy setting you should also enable appropriate firewall exceptions to allow Remote Assistance communications.",
	"Supported":  "WindowsXP",
	"KeyPath":  "Software\\policies\\Microsoft\\Windows NT\\Terminal Services",
	"KeyName":  "fAllowToGetHelp",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "fAllowFullControl",
							"Items":  [
										{
											"DisplayName":  "Allow helpers to remotely control the computer",
											"Value":  "1"
										},
										{
											"DisplayName":  "Allow helpers to only view the computer",
											"Value":  "0"
										}
									]
						},
						{
							"ValueName":  "MaxTicketExpiry",
							"MaxValue":  "99",
							"MinValue":  "1",
							"Type":  "Decimal"
						},
						{
							"Type":  "Enum",
							"ValueName":  "MaxTicketExpiryUnits",
							"Items":  [
										{
											"DisplayName":  "Minutes",
											"Value":  "0"
										},
										{
											"DisplayName":  "Hours",
											"Value":  "1"
										},
										{
											"DisplayName":  "Days",
											"Value":  "2"
										}
									]
						},
						{
							"Type":  "Enum",
							"ValueName":  "fUseMailto",
							"Items":  [
										{
											"DisplayName":  "Simple MAPI",
											"Value":  "0"
										},
										{
											"DisplayName":  "Mailto",
											"Value":  "1"
										}
									]
						},
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
	"File":  "TerminalServer.admx",
	"NameSpace":  "Microsoft.Policies.TerminalServer",
	"Class":  "Machine",
	"CategoryName":  "TS_REDIRECTION",
	"DisplayName":  "Do not allow drive redirection",
	"ExplainText":  "This policy setting specifies whether to prevent the mapping of client drives in a Remote Desktop Services session (drive redirection).By default, an RD Session Host server maps client drives automatically upon connection. Mapped drives appear in the session folder tree in File Explorer or Computer in the format \u003cdriveletter\u003e on \u003ccomputername\u003e. You can use this policy setting to override this behavior.If you enable this policy setting, client drive redirection is not allowed in Remote Desktop Services sessions, and Clipboard file copy redirection is not allowed on computers running Windows XP, Windows Server 2003, Windows Server 2012 (and later) or Windows 8 (and later).If you disable this policy setting, client drive redirection is always allowed. In addition, Clipboard file copy redirection is always allowed if Clipboard redirection is allowed.If you do not configure this policy setting, client drive redirection and Clipboard file copy redirection are not specified at the Group Policy level.",
	"Supported":  "WindowsXP",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
	"KeyName":  "fDisableCdm",
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
	"File":  "RemoteAssistance.admx",
	"NameSpace":  "Microsoft.Policies.RemoteAssistance",
	"Class":  "Machine",
	"CategoryName":  "RemoteAssist",
	"DisplayName":  "Allow only Windows Vista or later connections",
	"ExplainText":  "This policy setting enables Remote Assistance invitations to be generated with improved encryption so that only computers running this version (or later versions) of the operating system can connect. This policy setting does not affect Remote Assistance connections that are initiated by instant messaging contacts or the unsolicited Offer Remote Assistance.If you enable this policy setting, only computers running this version (or later versions) of the operating system can connect to this computer.If you disable this policy setting, computers running this version and a previous version of the operating system can connect to this computer.If you do not configure this policy setting, users can configure the setting in System Properties in the Control Panel.",
	"Supported":  "WindowsVista",
	"KeyPath":  "Software\\policies\\Microsoft\\Windows NT\\Terminal Services",
	"KeyName":  "CreateEncryptedOnlyTickets",
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
	"File":  "RemoteAssistance.admx",
	"NameSpace":  "Microsoft.Policies.RemoteAssistance",
	"Class":  "Machine",
	"CategoryName":  "RemoteAssist",
	"DisplayName":  "Turn on session logging",
	"ExplainText":  "This policy setting allows you to turn logging on or off. Log files are located in the user\u0027s Documents folder under Remote Assistance.If you enable this policy setting, log files are generated.If you disable this policy setting, log files are not generated.If you do not configure this setting, application-based settings are used.",
	"Supported":  "WindowsVista",
	"KeyPath":  "Software\\policies\\Microsoft\\Windows NT\\Terminal Services",
	"KeyName":  "LoggingEnabled",
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
	"File":  "RPC.admx",
	"NameSpace":  "Microsoft.Policies.RemoteProcedureCalls",
	"Class":  "Machine",
	"CategoryName":  "Rpc",
	"DisplayName":  "Authenticated without exceptions",
	"ExplainText":  "This policy setting controls how the RPC server runtime handles unauthenticated RPC clients connecting to RPC servers.This policy setting impacts all RPC applications. In a domain environment this policy setting should be used with caution as it can impact a wide range of functionality including group policy processing itself. Reverting a change to this policy setting can require manual intervention on each affected machine. This policy setting should never be applied to a domain controller.If you disable this policy setting, the RPC server runtime uses the value of \"Authenticated\" on Windows Client, and the value of \"None\" on Windows Server versions that support this policy setting. If you do not configure this policy setting, it remains disabled. The RPC server runtime will behave as though it was enabled with the value of \"Authenticated\" used for Windows Client and the value of \"None\" used for Server SKUs that support this policy setting. If you enable this policy setting, it directs the RPC server runtime to restrict unauthenticated RPC clients connecting to RPC servers running on a machine. A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically requested to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy setting.-- \"None\" allows all RPC clients to connect to RPC Servers running on the machine on which the policy setting is applied.-- \"Authenticated\" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. Exemptions are granted to interfaces that have requested them.-- \"Authenticated without exceptions\" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. No exceptions are allowed.Note: This policy setting will not be applied until the system is rebooted.",
	"Supported":  "WindowsXPSP2",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows NT",
	"KeyName":  "Rpc",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "RestrictRemoteClients",
							"Items":  [
										{
											"DisplayName":  "None",
											"Value":  "0"
										},
										{
											"DisplayName":  "Authenticated",
											"Value":  "1"
										},
										{
											"DisplayName":  "Authenticated without exceptions",
											"Value":  "2"
										}
									]
						}
					]
},
{
	"File":  "TerminalServer.admx",
	"NameSpace":  "Microsoft.Policies.TerminalServer",
	"Class":  "Machine",
	"CategoryName":  "TS_SECURITY",
	"DisplayName":  "Require secure RPC communication",
	"ExplainText":  "Specifies whether a Remote Desktop Session Host server requires secure RPC communication with all clients or allows unsecured communication.You can use this setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.If the status is set to Enabled, Remote Desktop Services accepts requests from RPC clients that support secure requests, and does not allow unsecured communication with untrusted clients.If the status is set to Disabled, Remote Desktop Services always requests security for all RPC traffic. However, unsecured communication is allowed for RPC clients that do not respond to the request.If the status is set to Not Configured, unsecured communication is allowed.Note: The RPC interface is used for administering and configuring Remote Desktop Services.",
	"Supported":  "WindowsNET",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
	"KeyName":  "fEncryptRPCTraffic",
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

---

Miscellaneous notes:`
```ps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fLogonDisabled /t REG_DWORD /d 1 /f
```
```ps
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server\WinStations : DWMFRAMEINTERVAL
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : GlassSessionId
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : NotificationTimeOut
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : SnapshotMonitors
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : TSAppCompat
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : TSUserEnabled
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server\WinStations : fUseHardwareGPU
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : CaptureStackTrace
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : ContainerMode
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : debug
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugFlags
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugFlagsEx
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : Debuglevel
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : Debuglsm
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebuglsmFlags
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebuglsmLevel
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebuglsmToDebugger
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugMaxFileSize
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : Debugsessionenv
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugsessionenvFlags
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugsessionenvLevel
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugsessionenvToDebugger
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : Debugtermsrv
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugtermsrvFlags
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugtermsrvLevel
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugtermsrvToDebugger
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugToDebugger
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugTS
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : Debugtstheme
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugtsthemeFlags
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugtsthemeLevel
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DebugtsthemeToDebugger
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DelayConMgrTimeout
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DelayReadyEventTimeout
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : DisableEnumUnlock
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : EnableTraceCorrelation
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : fDenyChildConnections
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : fDenyTSConnections
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : LSMBreakOnStart
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : MaxQueuedNotificationEvents
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : StartRCM
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server : TSServerDrainMode
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server\WinStations : ConsoleSecurity
\Registry\Machine\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\CONSOLE : SECURITY
```

# Deny App Access

Denies the access for everything, only leaving the microphone enabled.

Adding the `Deny` data in `HKLM` is probably enough, but the keys also exist in `HKCU` - Windows only edits it in `HKLM`, examples:
```c
// Notifications
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener\Value	Type: REG_SZ, Length: 10, Data: Deny

// Contacts
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts\Value	Type: REG_SZ, Length: 10, Data: Deny

// Pictures
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary\Value	Type: REG_SZ, Length: 10, Data: Deny
```
Disable app access to the microphone with (or apply it via the suboptions):
```ps
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged" /v Value /t REG_SZ /d Deny /f
```
Adding the `HKLM` value is enough, changing it via the settings would:
```ps
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Value	Type: REG_SZ, Length: 10, Data: Deny
```

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/appaccess.png?raw=true)

# Disable Inking & Typing Personalization

Used for better suggestions by creating a custom dictionary using your typing history and handwriting patterns. Disables autocorrection of misspelled words, highlight of misspelled words, and typing insights - would use AI to suggest words, autocorrect spelling mistakes etc. (`Privacy & security > Inking & typing personalization` & `Time & Language > Typing`).

```
\Registry\Machine\SOFTWARE\Microsoft\INPUT\TIPC : Enabled
\Registry\User\.Default\SOFTWARE\Microsoft\INPUT\TIPC : Enabled
\Registry\User\S-ID\SOFTWARE\Microsoft\INPUT\TIPC : Enabled
```

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/inking.png?raw=true)

```json
{
	"File":  "TextInput.admx",
	"NameSpace":  "Microsoft.Policies.TextInput",
	"Class":  "Machine",
	"CategoryName":  "TextInput",
	"DisplayName":  "Improve inking and typing recognition",
	"ExplainText":  "This policy setting controls the ability to send inking and typing data to Microsoft to improve the language recognition and suggestion capabilities of apps and services running on Windows.",
	"Supported":  "Windows_10_0_RS4",
	"KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\TextInput",
	"KeyName":  "AllowLinguisticDataCollection",
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
	"File":  "WindowsInkWorkspace.admx",
	"NameSpace":  "Microsoft.Policies.WindowsInkWorkspace",
	"Class":  "Machine",
	"CategoryName":  "WindowsInkWorkspace",
	"DisplayName":  "Allow suggested apps in Windows Ink Workspace",
	"ExplainText":  "Allow suggested apps in Windows Ink Workspace",
	"Supported":  "WIN10_RS1",
	"KeyPath":  "Software\\Policies\\Microsoft\\WindowsInkWorkspace",
	"KeyName":  "AllowSuggestedAppsInWindowsInkWorkspace",
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

# Disable Online Speech Recognition

`HasAccepted` disables online speech recognition, voice input to apps like Cortana, and data upload to Microsoft. `AllowSpeechModelUpdate` blocks automatic updates of speech recognition and synthesis models. I found`DisableSpeechInput` randomly while looking for `HasAccepted`, related to mixed reality environments.
> https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#bkmk-priv-speech  
> [privacy/assets | locationaccess-LocationApi.c](https://github.com/5Noxi/win-config/blob/main/privacy/assets/locationaccess-LocationApi.c)

# Disable Microsoft Copilot

"Microsoft introduced Windows Copilot in May 2023. It became available in Windows 11 starting with build 23493 (Dev), 22631.2129 (Beta), and 25982 (Canary). A public preview began rolling out on September 26, 2023, with build 22621.2361 (Windows 11 22H2 KB5030310). It adds integrated AI features to assist with tasks like summarizing web content, writing, and generating images. Windows Copilot appears as a sidebar docked to the right and runs alongside open apps. In Windows 10, Copilot is available in build 19045.3754 for eligible devices in the Release Preview Channel running version 22H2. Users must enable "Get the latest updates as soon as they're available" and check for updates. The rollout is phased via Controlled Feature Rollout (CFR). Windows 10 Pro devices managed by organizations, and all Enterprise or Education editions, are excluded from the initial rollout. Copilot requires signing in with a Microsoft account (MSA) or Azure Active Directory (Entra ID). Users with local accounts can use Copilot up to ten times before sign-in is enforced."

`CopilotDisabledReason`:
```c
ValueW = RegGetValueW(
    HKEY_CURRENT_USER,
    L"SOFTWARE\\Microsoft\\Windows\\Shell\\Copilot",
    L"CopilotDisabledReason",
    2u, // REG_SZ
    0LL,
    pvData,
    pcbData);

v16 = L"FailedToGetReason"; // if value is missing
```

```ps
reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v CopilotDisabledReason /t REG_SZ /d "" /f
```
```json
{
	"File":  "WindowsCopilot.admx",
	"NameSpace":  "Microsoft.Policies.WindowsCopilot",
	"Class":  "User",
	"CategoryName":  "WindowsCopilot",
	"DisplayName":  "Turn off Windows Copilot",
	"ExplainText":  " This policy setting allows you to turn off Windows Copilot. If you enable this policy setting, users will not be able to use Copilot. The Copilot icon will not appear on the taskbar either. If you disable or do not configure this policy setting, users will be able to use Copilot when it\u0027s available to them.",
	"Supported":  "Windows_11_0_NOSERVER_ENTERPRISE_EDUCATION_PRO_SANDBOX",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot",
	"KeyName":  "TurnOffWindowsCopilot",
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

# Disable Recall

"Allows you to control whether Windows saves snapshots of the screen and analyzes the user's activity on their device. If you enable this policy setting, Windows will not be able to save snapshots and users won't be able to search for or browse through their historical device activity using Recall. If you disable or do not configure this policy setting, Windows will save snapshots of the screen and users will be able to search for or browse through a timeline of their past activities using Recall." (`WindowsCopilot.admx`)

```json
{
	"File":  "WindowsCopilot.admx",
	"NameSpace":  "Microsoft.Policies.WindowsCopilot",
	"Class":  "User",
	"CategoryName":  "WindowsAI",
	"DisplayName":  "Turn off Saving Snapshots for Windows",
	"ExplainText":  " This policy setting allows you to control whether Windows saves snapshots of the screen and analyzes the user\u0027s activity on their device. If you enable this policy setting, Windows will not be able to save snapshots and users won\u0027t be able to search for or browse through their historical device activity using Recall. If you disable or do not configure this policy setting, Windows will save snapshots of the screen and users will be able to search for or browse through a timeline of their past activities using Recall.",
	"Supported":  "Windows_11_0_NOSERVER_ENTERPRISE_EDUCATION_PRO_SANDBOX",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI",
	"KeyName":  "DisableAIDataAnalysis",
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

---

Disables generative fill, cocreator & image creator in paint:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /v DisableGenerativeFill /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /v DisableCocreator /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /v DisableImageCreator /t REG_DWORD /d 1 /f
```

# Disable Lock Screen Camera

"Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.By default, users can enable invocation of an available camera on the lock screen.If you enable this setting, users will no longer be able to enable or disable lock screen camera access in PC Settings, and the camera cannot be invoked on the lock screen." (`ControlPanelDisplay.admx`)

Disable a camera on your system:
```bat
reg add "HKLM\Software\Policies\Microsoft\Camera" /v AllowCamera /t REG_DWORD /d 0 /f
```
> https://support.microsoft.com/en-us/windows/manage-cameras-with-camera-settings-in-windows-11-97997ed5-bb98-47b6-a13d-964106997757

```json
    {
        "File":  "ControlPanelDisplay.admx",
        "NameSpace":  "Microsoft.Policies.ControlPanelDisplay",
        "Class":  "Machine",
        "CategoryName":  "Personalization",
        "DisplayName":  "Prevent enabling lock screen camera",
        "ExplainText":  "Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.By default, users can enable invocation of an available camera on the lock screen.If you enable this setting, users will no longer be able to enable or disable lock screen camera access in PC Settings, and the camera cannot be invoked on the lock screen.",
        "Supported":  "Windows_6_3",
        "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Personalization",
        "KeyName":  "NoLockScreenCamera",
        "Elements":  [

                     ]
    },
```

# Disable Suggestions/Tips/Tricks

Disables all kind of suggestions: in start, text suggestions (multilingual...), in the timeline, content... It sets all `SubscribedContent-xxxxxEnabled` to `0` & removes the subkeys of `ID\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`. It's recommended to do a backup before running it.

Disable edge related suggestions with (search suggestions in address bar):
```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SearchSuggestEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v LocalProvidersEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v ShowSearchSuggestionsGlobal /t REG_DWORD /d 0 /f
```
Disable phone link suggestions:
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility" /v OptedIn /t REG_DWORD /d 0 /f
```

```json
{
	"File":  "CloudContent.admx",
	"NameSpace":  "Microsoft.Policies.CloudContent",
	"Class":  "User",
	"CategoryName":  "CloudContent",
	"DisplayName":  "Do not suggest third-party content in Windows spotlight",
	"ExplainText":  "If you enable this policy, Windows spotlight features like lock screen spotlight, suggested apps in Start menu or Windows tips will no longer suggest apps and content from third-party software publishers. Users may still see suggestions and tips to make them more productive with Microsoft features and apps.If you disable or do not configure this policy, Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content.",
	"Supported":  "Windows_10_0_NOSERVER",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
	"KeyName":  "DisableThirdPartySuggestions",
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
	"File":  "ControlPanel.admx",
	"NameSpace":  "Microsoft.Policies.ControlPanel",
	"Class":  "Machine",
	"CategoryName":  "ControlPanel",
	"DisplayName":  "Allow Online Tips",
	"ExplainText":  "Enables or disables the retrieval of online tips and help for the Settings app.If disabled, Settings will not contact Microsoft content services to retrieve tips and help content.",
	"Supported":  "Windows_10_0_RS3",
	"KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
	"KeyName":  "Explorer",
	"Elements":  [
						{
							"ValueName":  "AllowOnlineTips",
							"FalseValue":  "0",
							"TrueValue":  "1",
							"Type":  "Boolean"
						}
					]
},
{
	"File":  "StartMenu.admx",
	"NameSpace":  "Microsoft.Policies.StartMenu",
	"Class":  "Both",
	"CategoryName":  "StartMenu",
	"DisplayName":  "Remove Personalized Website Recommendations from the Recommended section in the Start Menu",
	"ExplainText":  "Remove Personalized Website Recommendations from the Recommended section in the Start Menu",
	"Supported":  "Windows_11_0_SE",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Explorer",
	"KeyName":  "HideRecommendedPersonalizedSites",
	"Elements":  [

					]
},
{
	"File":  "StartMenu.admx",
	"NameSpace":  "Microsoft.Policies.StartMenu",
	"Class":  "Both",
	"CategoryName":  "StartMenu",
	"DisplayName":  "Remove Recommended section from Start Menu",
	"ExplainText":  "This policy allows you to prevent the Start Menu from displaying a list of recommended applications and files.If you enable this policy setting, the Start Menu will no longer show the section containing a list of recommended files and apps.",
	"Supported":  "Windows_11_0_SE",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Explorer",
	"KeyName":  "HideRecommendedSection",
	"Elements":  [

					]
},
{
	"File":  "WindowsExplorer.admx",
	"NameSpace":  "Microsoft.Policies.WindowsExplorer",
	"Class":  "User",
	"CategoryName":  "WindowsExplorer",
	"DisplayName":  "Turn off display of recent search entries in the File Explorer search box",
	"ExplainText":  "Disables suggesting recent queries for the Search Box and prevents entries into the Search Box from being stored in the registry for future references.File Explorer shows suggestion pop-ups as users type into the Search Box. These suggestions are based on their past entries into the Search Box.Note: If you enable this policy, File Explorer will not show suggestion pop-ups as users type into the Search Box, and it will not store Search Box entries into the registry for future references. If the user types a property, values that match this property will be shown but no data will be saved in the registry or re-shown on subsequent uses of the search box.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Explorer",
	"KeyName":  "DisableSearchBoxSuggestions",
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

---

Miscellaneous notes:
```ps
for /f "skip=2 tokens=1" %%N in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" 2^>nul') do (
    echo %%N | findstr /R "SubscribedContent-[0-9]*Enabled" >nul && (
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "%%~nxN" /t REG_DWORD /d 0 /f
    )
)

powershell -command "Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\*' -Recurse"
```

# Disable Synchronization

Disables all kind of synchronization.

How the middle block works (`SettingSync.admx`):
```
KeyPath: Software\Policies\Microsoft\Windows\SettingSync,
KeyName: DisableSettingSync,

 ValueName: DisableSettingSyncUserOverride,
 FalseValue: 1,
 TrueValue: 0,

Value:  2,
Type:  EnabledValue
Value:  0,
Type:  DisabledValue
```

`DisableSyncOnPaidNetwork`: "Do not sync on metered connections"
> https://support.microsoft.com/en-us/windows/windows-backup-settings-catalog-deebcba2-5bc0-4e63-279a-329926955708#id0ebd=windows_11
> https://gpsearch.azurewebsites.net/#7999

```json
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync on metered connections",
	"ExplainText":  "Prevent syncing to and from this PC when on metered Internet connections. This turns off and disables \"sync your settings on metered connections\" switch on the \"sync your settings\" page in PC Settings.If you enable this policy setting, syncing on metered connections will be turned off, and no syncing will take place when this PC is on a metered connection.If you do not set or disable this setting, syncing on metered connections is configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableSyncOnPaidNetwork",
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
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync Apps",
	"ExplainText":  " Prevent the \"AppSync\" group from syncing to and from this PC. This turns off and disables the \"AppSync\" group on the \"sync your settings\" page in PC settings.If you enable this policy setting, the \"AppSync\" group will not be synced.Use the option \"Allow users to turn app syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"AppSync\" group is on by default and configurable by the user.",
	"Supported":  "Windows_6_3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableAppSyncSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableAppSyncSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync app settings",
	"ExplainText":  "Prevent the \"app settings\" group from syncing to and from this PC. This turns off and disables the \"app settings\" group on the \"sync your settings\" page in PC settings.If you enable this policy setting, the \"app settings\" group will not be synced.Use the option \"Allow users to turn app settings syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"app settings\" group is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableApplicationSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableApplicationSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync passwords",
	"ExplainText":  "Prevent the \"passwords\" group from syncing to and from this PC. This turns off and disables the \"passwords\" group on the \"sync your settings\" page in PC settings.If you enable this policy setting, the \"passwords\" group will not be synced.Use the option \"Allow users to turn passwords syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"passwords\" group is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableCredentialsSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableCredentialsSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync personalize",
	"ExplainText":  "Prevent the \"personalize\" group from syncing to and from this PC. This turns off and disables the \"personalize\" group on the \"sync your settings\" page in PC settings.If you enable this policy setting, the \"personalize\" group will not be synced.Use the option \"Allow users to turn personalize syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"personalize\" group is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisablePersonalizationSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisablePersonalizationSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync desktop personalization",
	"ExplainText":  "Prevent the \"desktop personalization\" group from syncing to and from this PC. This turns off and disables the \"desktop personalization\" group on the \"sync your settings\" page in PC settings.If you enable this policy setting, the \"desktop personalization\" group will not be synced.Use the option \"Allow users to turn desktop personalization syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"desktop personalization\" group is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableDesktopThemeSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableDesktopThemeSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync",
	"ExplainText":  "Prevent syncing to and from this PC. This turns off and disables the \"sync your settings\" switch on the \"sync your settings\" page in PC Settings.If you enable this policy setting, \"sync your settings\" will be turned off, and none of the \"sync your setting\" groups will be synced on this PC.Use the option \"Allow users to turn syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, \"sync your settings\" is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync start settings",
	"ExplainText":  " Prevent the \"Start layout\" group from syncing to and from this PC. This turns off and disables the \"Start layout\" group on the \"sync your settings\" page in PC settings. If you enable this policy setting, the \"Start layout\" group will not be synced. Use the option \"Allow users to turn start syncing on\" so that syncing is turned off by default but not disabled. If you do not set or disable this setting, syncing of the \"Start layout\" group is on by default and configurable by the user.",
	"Supported":  "Windows_6_3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableStartLayoutSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableStartLayoutSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync browser settings",
	"ExplainText":  "Prevent the \"browser\" group from syncing to and from this PC. This turns off and disables the \"browser\" group on the \"sync your settings\" page in PC settings. The \"browser\" group contains settings and info like history and favorites.If you enable this policy setting, the \"browser\" group, including info like history and favorites, will not be synced.Use the option \"Allow users to turn browser syncing on\" so that syncing is turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"browser\" group is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableWebBrowserSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableWebBrowserSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "SettingSync.admx",
	"NameSpace":  "Microsoft.Policies.SettingSync",
	"Class":  "Machine",
	"CategoryName":  "SettingSync",
	"DisplayName":  "Do not sync other Windows settings",
	"ExplainText":  "Prevent the \"Other Windows settings\" group from syncing to and from this PC. This turns off and disables the \"Other Windows settings\" group on the \"sync your settings\" page in PC settings.If you enable this policy setting, the \"Other Windows settings\" group will not be synced.Use the option \"Allow users to turn other Windows settings syncing on\" so that syncing it turned off by default but not disabled.If you do not set or disable this setting, syncing of the \"Other Windows settings\" group is on by default and configurable by the user.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\SettingSync",
	"KeyName":  "DisableWindowsSettingSync",
	"Elements":  [
						{
							"ValueName":  "DisableWindowsSettingSyncUserOverride",
							"FalseValue":  "1",
							"TrueValue":  "0",
							"Type":  "Boolean"
						},
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
```

# Disable Activity History

`EnableActivityFeed` enables or disables publishing and syncing of activities across devices. `PublishUserActivities` allows or blocks local publishing of user activities. `UploadUserActivities` allows or blocks uploading of user activities to the cloud, deletion is not affected.

`OSPolicy.admx`:
```bat
HKLM\Software\Policies\Microsoft\Windows\System
EnableActivityFeed = 0 (Disabled), 1 (Enabled)
PublishUserActivities = 0 (Disabled), 1 (Enabled)
UploadUserActivities = 0 (Disabled), 1 (Enabled)
```


# Disable Cross-Device Experiences

Disables Cross-Device experiences (allows you to use `Share Across Devices`/`Nearby Sharing` functionalities) & share accross devices. With `Share across devices`, you can continue app experiences on other devices connected to your account.
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-grouppolicy#enablecdp

```json
{
	"File":  "GroupPolicy.admx",
	"NameSpace":  "Microsoft.Policies.GroupPolicy",
	"Class":  "Machine",
	"CategoryName":  "PolicyPolicies",
	"DisplayName":  "Continue experiences on this device",
	"ExplainText":  "This policy setting determines whether the Windows device is allowed to participate in cross-device experiences (continue experiences).If you enable this policy setting, the Windows device is discoverable by other Windows devices that belong to the same user, and can participate in cross-device experiences.If you disable this policy setting, the Windows device is not discoverable by other devices, and cannot participate in cross-device experiences.If you do not configure this policy setting, the default behavior depends on the Windows edition. Changes to this policy take effect on reboot.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
	"KeyName":  "EnableCdp",
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

# Disable Phone Linking

"This policy allows IT admins to turn off the ability to Link a Phone with a PC to continue reading, emailing and other tasks that requires linking between Phone and PC.If you enable this policy setting, the Windows device will be able to enroll in Phone-PC linking functionality and participate in Continue on PC experiences.If you disable this policy setting, the Windows device is not allowed to be linked to Phones, will remove itself from the device list of any linked Phones, and cannot participate in Continue on PC experiences.If you do not configure this policy setting, the default behavior depends on the Windows edition. Changes to this policy take effect on reboot."

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity#allowphonepclinking

```json
{
	"File":  "GroupPolicy.admx",
	"NameSpace":  "Microsoft.Policies.GroupPolicy",
	"Class":  "Machine",
	"CategoryName":  "PolicyPolicies",
	"DisplayName":  "Phone-PC linking on this device",
	"ExplainText":  "This policy allows IT admins to turn off the ability to Link a Phone with a PC to continue reading, emailing and other tasks that requires linking between Phone and PC.If you enable this policy setting, the Windows device will be able to enroll in Phone-PC linking functionality and participate in Continue on PC experiences.If you disable this policy setting, the Windows device is not allowed to be linked to Phones, will remove itself from the device list of any linked Phones, and cannot participate in Continue on PC experiences.If you do not configure this policy setting, the default behavior depends on the Windows edition. Changes to this policy take effect on reboot.",
	"Supported":  "Windows_10_0_RS4",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
	"KeyName":  "EnableMmx",
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

# Disable File History

"File History automatically backs up versions of files in your user folders (Documents, Music, Pictures, Videos, Desktop) and offline OneDrive. It tracks changes via the NTFS change journal (fast, low overhead) and saves only changed files. You must choose a backup target (external drive or network share). If that target is unavailable, it caches copies locally and syncs them when the target returns. You can browse and restore any version or recover lost/deleted files."

```json
{
	"File":  "FileHistory.admx",
	"NameSpace":  "Microsoft.Policies.FileHistory",
	"Class":  "Machine",
	"CategoryName":  "FileHistory",
	"DisplayName":  "Turn off File History",
	"ExplainText":  "This policy setting allows you to turn off File History.If you enable this policy setting, File History cannot be activated to create regular, automatic backups.If you disable or do not configure this policy setting, File History can be activated to create regular, automatic backups.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\FileHistory",
	"KeyName":  "Disabled",
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

# Disable MDM Enrollment

`DisableRegistration`:  
"This policy setting specifies whether Mobile Device Management (MDM) Enrollment is allowed. When MDM is enabled, it allows the user to have the computer remotely managed by a MDM Server. If you do not configure this policy setting, MDM Enrollment will be enabled. If you enable this policy setting, MDM Enrollment will be disabled for all users. It will not unenroll existing MDM enrollments.If you disable this policy setting, MDM Enrollment will be enabled for all users."

`AutoEnrollMDM`:  
"This policy setting specifies whether to automatically enroll the device to the Mobile Device Management (MDM) service configured in Azure Active Directory (Azure AD). If the enrollment is successful, the device will remotely managed by the MDM service. Important: The device must be registered in Azure AD for enrollment to succeed. If you do not configure this policy setting, automatic MDM enrollment will not be initiated. If you enable this policy setting, a task is created to initiate enrollment of the device to MDM service specified in the Azure AD. If you disable this policy setting, MDM will be unenrolled."

```json
{
	"File":  "MDM.admx",
	"NameSpace":  "Microsoft.Policies.MDM",
	"Class":  "Machine",
	"CategoryName":  "MDM",
	"DisplayName":  "Disable MDM Enrollment",
	"ExplainText":  "This policy setting specifies whether Mobile Device Management (MDM) Enrollment is allowed. When MDM is enabled, it allows the user to have the computer remotely managed by a MDM Server. If you do not configure this policy setting, MDM Enrollment will be enabled. If you enable this policy setting, MDM Enrollment will be disabled for all users. It will not unenroll existing MDM enrollments.If you disable this policy setting, MDM Enrollment will be enabled for all users.",
	"Supported":  "Windows_10_0_NOSERVER",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\MDM",
	"KeyName":  "DisableRegistration",
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
	"File":  "MDM.admx",
	"NameSpace":  "Microsoft.Policies.MDM",
	"Class":  "Machine",
	"CategoryName":  "MDM",
	"DisplayName":  "Device Credential",
	"ExplainText":  " This policy setting specifies whether to automatically enroll the device to the Mobile Device Management (MDM) service configured in Azure Active Directory (Azure AD). If the enrollment is successful, the device will remotely managed by the MDM service. Important: The device must be registered in Azure AD for enrollment to succeed. If you do not configure this policy setting, automatic MDM enrollment will not be initiated. If you enable this policy setting, a task is created to initiate enrollment of the device to MDM service specified in the Azure AD. If you disable this policy setting, MDM will be unenrolled.",
	"Supported":  "Windows_10_0_NOSERVER",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\MDM",
	"KeyName":  "AutoEnrollMDM",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "UseAADCredentialType",
							"Items":  [
										{
											"DisplayName":  "User Credential",
											"Value":  "1"
										},
										{
											"DisplayName":  "Device Credential",
											"Value":  "2"
										}
									]
						},
						{
							"ValueName":  "MDMApplicationId",
							"Type":  "Text"
						},
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

# Disable Feedback Prompts

"This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.If you enable this policy setting, users will no longer see feedback notifications through the Windows Feedback app.If you disable or do not configure this policy setting, users may see notifications through the Windows Feedback app asking users for feedback.Note: If you disable or do not configure this policy setting, users can control how often they receive feedback questions."

Includes setting `Feedback Frequency` to `0` via `NumberOfSIUFInPeriod` & `PeriodInNanoSeconds`.

```json
{
	"File":  "FeedbackNotifications.admx",
	"NameSpace":  "Microsoft.Policies.FeedbackNotifications",
	"Class":  "Machine",
	"CategoryName":  "DataCollectionAndPreviewBuilds",
	"DisplayName":  "Do not show feedback notifications",
	"ExplainText":  "This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.If you enable this policy setting, users will no longer see feedback notifications through the Windows Feedback app.If you disable or do not configure this policy setting, users may see notifications through the Windows Feedback app asking users for feedback.Note: If you disable or do not configure this policy setting, users can control how often they receive feedback questions.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DataCollection",
	"KeyName":  "DoNotShowFeedbackNotifications",
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

# Disable CEIP

Voluntary program that collects usage data to help improve the quality and performance of its products.

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm

Opt out from windows SDK CEIP:
```
\Registry\Machine\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Ceip : OptIn
```
```bat
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Ceip" /v OptIn /t REG_DWORD /d 0 /f
```
Opt out from the internet explorer CEIP with:
```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v DisableCustomerImprovementProgram /t REG_DWORD /d 0 /f
```
Turn off Windows Messenger CEIP:
```bat
reg add "HKCU\Software\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disablecustomerexperienceimprovementprogramparticipation

```json
{
	"File":  "appv.admx",
	"NameSpace":  "Microsoft.Policies.AppV",
	"Class":  "Machine",
	"CategoryName":  "CAT_CEIP",
	"DisplayName":  "Microsoft Customer Experience Improvement Program (CEIP)",
	"ExplainText":  "The program collects information about computer hardware and how you use Microsoft Application Virtualization without interrupting you. This helps Microsoft identify which Microsoft Application Virtualization features to improve. No information collected is used to identify or contact you. For more details, read about the program online at http://go.microsoft.com/fwlink/?LinkID=184686.",
	"Supported":  "Windows7",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\AppV\\CEIP",
	"KeyName":  "CEIPEnable",
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
	"File":  "ICM.admx",
	"NameSpace":  "Microsoft.Policies.InternetCommunicationManagement",
	"Class":  "Machine",
	"CategoryName":  "InternetManagement_Settings",
	"DisplayName":  "Turn off Windows Customer Experience Improvement Program",
	"ExplainText":  "This policy setting turns off the Windows Customer Experience Improvement Program. The Windows Customer Experience Improvement Program collects information about your hardware configuration and how you use our software and services to identify trends and usage patterns. Microsoft will not collect your name, address, or any other personally identifiable information. There are no surveys to complete, no salesperson will call, and you can continue working without interruption. It is simple and user-friendly.If you enable this policy setting, all users are opted out of the Windows Customer Experience Improvement Program.If you disable this policy setting, all users are opted into the Windows Customer Experience Improvement Program.If you do not configure this policy setting, the administrator can use the Problem Reports and Solutions component in Control Panel to enable Windows Customer Experience Improvement Program for all users.",
	"Supported":  "WindowsVista",
	"KeyPath":  "Software\\Policies\\Microsoft\\SQMClient\\Windows",
	"KeyName":  "CEIPEnable",
	"Elements":  [
						{
							"Value":  "0",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "1",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "ICM.admx",
	"NameSpace":  "Microsoft.Policies.InternetCommunicationManagement",
	"Class":  "User",
	"CategoryName":  "InternetManagement_Settings",
	"DisplayName":  "Turn off the Windows Messenger Customer Experience Improvement Program",
	"ExplainText":  "This policy setting specifies whether Windows Messenger collects anonymous information about how Windows Messenger software and service is used.With the Customer Experience Improvement program, users can allow Microsoft to collect anonymous information about how the product is used. This information is used to improve the product in future releases.If you enable this policy setting, Windows Messenger does not collect usage information, and the user settings to enable the collection of usage information are not shown.If you disable this policy setting, Windows Messenger collects anonymous usage information, and the setting is not shown.If you do not configure this policy setting, users have the choice to opt in and allow information to be collected.",
	"Supported":  "WindowsXPSP2_Or_WindowsNET",
	"KeyPath":  "Software\\Policies\\Microsoft\\Messenger\\Client",
	"KeyName":  "CEIP",
	"Elements":  [
						{
							"Value":  "2",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "1",
							"Type":  "DisabledValue"
						}
					]
},
```

# Disable Cortana

"Cortana was a virtual assistant developed by Microsoft that used the Bing search engine to perform tasks such as setting reminders and answering questions for users."

> https://en.wikipedia.org/wiki/Cortana_(virtual_assistant)

# Hide Last Logged-In User

"This security setting determines whether the Windows sign-in screen will show the username of the last person who signed in on this PC."

```c
// Enabled
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName	Type: REG_DWORD, Length: 4, Data: 1

// Disabled
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName	Type: REG_DWORD, Length: 4, Data: 0
```

`Hide Username at Sign-In`:  
"This security setting determines whether the username of the person signing in to this PC appears at Windows sign-in, after credentials are entered, and before the PC desktop is shown."

```c
// Enabled
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName	Type: REG_DWORD, Length: 4, Data: 1

// Disabled
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName	Type: REG_DWORD, Length: 4, Data: 0
```

> https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-do-not-display-last-user-name

# Disable Background Apps

"This policy setting specifies whether Windows apps can run in the background.You can specify either a default setting for all apps or a per-app setting by specifying a Package Family Name. You can get the Package Family Name for an app by using the Get-AppPackage Windows PowerShell cmdlet. A per-app setting overrides the default setting.If you choose the \"User is in control\" option, employees in your organization can decide whether Windows apps can run in the background by using Settings Privacy on the device.If you choose the "Force Allow" option, Windows apps are allowed to run in the background and employees in your organization cannot change it.If you choose the "Force Deny" option, Windows apps are not allowed to run in the background and employees in your organization cannot change it.If you disable or do not configure this policy setting, employees in your organization can decide whether Windows apps can run in the background by using Settings Privacy on the device. If an app is open when this Group Policy object is applied on a device, employees must restart the app or device for the policy changes to be applied to the app."

```
Computer Configuration\Administrative Templates\Windows Components\App Privacy
```
`Enabled` -> `Deny All changes`:
```ps
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5D10D350-8BC7-4D14-9723-C79DF35A74B4}Machine\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsRunInBackground	Type: REG_DWORD, Length: 4, Data: 2
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5D10D350-8BC7-4D14-9723-C79DF35A74B4}Machine\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsRunInBackground_UserInControlOfTheseApps	Type: REG_MULTI_SZ, Length: 2, Data: 
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5D10D350-8BC7-4D14-9723-C79DF35A74B4}Machine\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsRunInBackground_ForceAllowTheseApps	Type: REG_MULTI_SZ, Length: 2, Data: 
mmc.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5D10D350-8BC7-4D14-9723-C79DF35A74B4}Machine\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsRunInBackground_ForceDenyTheseApps	Type: REG_MULTI_SZ, Length: 2, Data: 
```

```json
{
	"File":  "AppPrivacy.admx",
	"NameSpace":  "Microsoft.Policies.AppPrivacy",
	"Class":  "Machine",
	"CategoryName":  "AppPrivacy",
	"DisplayName":  "Force Deny",
	"ExplainText":  "This policy setting specifies whether Windows apps can run in the background.You can specify either a default setting for all apps or a per-app setting by specifying a Package Family Name. You can get the Package Family Name for an app by using the Get-AppPackage Windows PowerShell cmdlet. A per-app setting overrides the default setting.If you choose the \"User is in control\" option, employees in your organization can decide whether Windows apps can run in the background by using Settings \u003e Privacy on the device.If you choose the \"Force Allow\" option, Windows apps are allowed to run in the background and employees in your organization cannot change it.If you choose the \"Force Deny\" option, Windows apps are not allowed to run in the background and employees in your organization cannot change it.If you disable or do not configure this policy setting, employees in your organization can decide whether Windows apps can run in the background by using Settings \u003e Privacy on the device.If an app is open when this Group Policy object is applied on a device, employees must restart the app or device for the policy changes to be applied to the app.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows",
	"KeyName":  "AppPrivacy",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "LetAppsRunInBackground",
							"Items":  [
										{
											"DisplayName":  "User is in control",
											"Value":  "0"
										},
										{
											"DisplayName":  "Force Allow",
											"Value":  "1"
										},
										{
											"DisplayName":  "Force Deny",
											"Value":  "2"
										}
									]
						}
					]
},
```

# Disable WER

WER (Windows Error Reporting) sends error logs to Microsoft, disabling it keeps error data local.

`\Microsoft\Windows\Windows Error Reporting : QueueReporting` would run `%windir%\system32\wermgr.exe -upload`. `Error-Reporting.txt` shows a trace of `\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting`.

```
0.0.0.0 watson.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com
0.0.0.0 umwatsonc.events.data.microsoft.com
0.0.0.0 ceuswatcab01.blob.core.windows.net
0.0.0.0 ceuswatcab02.blob.core.windows.net
0.0.0.0 eaus2watcab01.blob.core.windows.net
0.0.0.0 eaus2watcab02.blob.core.windows.net
0.0.0.0 weus2watcab01.blob.core.windows.net
0.0.0.0 weus2watcab02.blob.core.windows.net
```
`DisableSendRequestAdditionalSoftwareToWER`: "Prevent Windows from sending an error report when a device driver requests additional software during installation"
`DisableSendGenericDriverNotFoundToWER`: "Do not send a Windows error report when a generic driver is installed on a device"

> https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/windows-error-reporting-diagnostics-enablement-guidance#configure-network-endpoints-to-be-allowed  
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-errorreporting  
> https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings  
> [privacy/assets | wer-PciGetSystemWideHackFlagsFromRegistry.c](https://github.com/5Noxi/win-config/blob/main/privacy/assets/wer-PciGetSystemWideHackFlagsFromRegistry.c)

`Disable DHA Report`:  
"This group policy enables Device Health Attestation reporting (DHA-report) on supported devices. It enables supported devices to send Device Health Attestation related information (device boot logs, PCR values, TPM certificate, etc.) to Device Health Attestation Service (DHA-Service) every time a device starts. Device Health Attestation Service validates the security state and health of the devices, and makes the findings accessible to enterprise administrators via a cloud based reporting portal. This policy is independent of DHA reports that are initiated by device manageability solutions (like MDM or SCCM), and will not interfere with their workflows."

```ps
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ArchiveFolderCountLimit
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : AutoApproveOSDumps
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : BypassDataThrottling
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : BypassNetworkCostThrottling
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : BypassPowerThrottling
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CabArchiveCreate
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CabArchiveFolder
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CabArchiveSeparate
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ChangeDumpTypeByTelemetryLevel
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ConfigureArchive
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CorporateWerPortNumber
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CorporateWerServer
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CorporateWerUploadOnFreeNetworksOnly
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CorporateWerUseAuthentication
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : CorporateWerUseSSL
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : DeferCabUpload
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : DisableArchive
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : Disabled
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : DisableEnterpriseAuthProxy
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : DisableWerUpload
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : DontSendAdditionalData
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : DontShowUI
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ForceEtw
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ForceHeapDump
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ForceMetadata
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ForceQueue
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : ForceUserModeCabCollection
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : LiveReportFlushInterval
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : LocalCompression
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : LoggingDisabled
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : MaxArchiveCount
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : MaxQueueCount
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : MaxRetriesForSasRenewal
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : MinFreeDiskSpace
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : MinQueueSize
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : NoHeapDumpOnQueue
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : OobeCompleted
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : QueueNoPesterInterval
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : QueuePesterInterval
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : QueueSizeMaxPercentFreeDisk
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : source
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : StorePath
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : UploadOnFreeNetworksOnly
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting : User
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting\Consent : DefaultConsent
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting\Consent : DefaultOverrideBehavior
\Registry\Machine\SOFTWARE\Microsoft\WINDOWS\Windows Error Reporting\Consent : NewUserDefaultConsent
```

---

Miscellaneous notes:  

```c
`EnableWerUserReporting`  
Default: `1` (`DbgkEnableWerUserReporting dd 1`)

"Session Manager\Kernel","EnableWerUserReporting","0xFFFFF800CF1C335C","0x00000000","0x00000000","0x00000000"
```

Related to PCIe advanced error reporting? Haven't found anything on this and haven't done much research myself:
```
\Registry\Machine\SYSTEM\ControlSet001\Control\PnP\pci : AerMultiErrorDisabled
```
Default is `0`, non zero would enable the behaviour? The value doesn't exist by default.
> https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_pci_express_rootport_aer_capability ?

```
\Registry\Machine\SYSTEM\ControlSet001\Control\StorPort : TelemetryErrorDataEnabled
\Registry\Machine\SYSTEM\ControlSet001\Control\Session Manager\Memory Management : PeriodicTelemetryReportFrequency
```

```json
{
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "Machine",
	"CategoryName":  "CAT_WindowsErrorReporting",
	"DisplayName":  "Display Error Notification",
	"ExplainText":  "This policy setting controls whether users are shown an error dialog box that lets them report an error.If you enable this policy setting, users are notified in a dialog box that an error has occurred, and can display more details about the error. If the Configure Error Reporting policy setting is also enabled, the user can also report the error.If you disable this policy setting, users are not notified that errors have occurred. If the Configure Error Reporting policy setting is also enabled, errors are reported, but users receive no notification. Disabling this policy setting is useful for servers that do not have interactive users.If you do not configure this policy setting, users can change this setting in Control Panel, which is set to enable notification by default on computers that are running Windows XP Personal Edition and Windows XP Professional Edition, and disable notification by default on computers that are running Windows Server.See also the Configure Error Reporting policy setting.",
	"Supported":  "WindowsNET_XP",
	"KeyPath":  "Software\\Policies\\Microsoft\\PCHealth\\ErrorReporting",
	"KeyName":  "ShowUI",
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
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "User",
	"CategoryName":  "CAT_WindowsErrorReporting",
	"DisplayName":  "Disable Windows Error Reporting",
	"ExplainText":  "This policy setting turns off Windows Error Reporting, so that reports are not collected or sent to either Microsoft or internal servers within your organization when software unexpectedly stops working or fails.If you enable this policy setting, Windows Error Reporting does not send any problem information to Microsoft. Additionally, solution information is not available in Security and Maintenance in Control Panel.If you disable or do not configure this policy setting, the Turn off Windows Error Reporting policy setting in Computer Configuration/Administrative Templates/System/Internet Communication Management/Internet Communication settings takes precedence. If Turn off Windows Error Reporting is also either disabled or not configured, user settings in Control Panel for Windows Error Reporting are applied.",
	"Supported":  "WindowsVista",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
	"KeyName":  "Disabled",
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
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "Machine",
	"CategoryName":  "CAT_WindowsErrorReporting",
	"DisplayName":  "Automatically send memory dumps for OS-generated error reports",
	"ExplainText":  "This policy setting controls whether memory dumps in support of OS-generated error reports can be sent to Microsoft automatically. This policy does not apply to error reports generated by 3rd-party products, or additional data other than memory dumps.If you enable or do not configure this policy setting, any memory dumps generated for error reports by Microsoft Windows are automatically uploaded, without notification to the user.If you disable this policy setting, then all memory dumps are uploaded according to the default consent and notification settings.",
	"Supported":  "Windows_6_3only",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
	"KeyName":  "AutoApproveOSDumps",
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
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "Machine",
	"CategoryName":  "CAT_WindowsErrorReporting",
	"DisplayName":  "Disable logging",
	"ExplainText":  "This policy setting controls whether Windows Error Reporting saves its own events and error messages to the system event log.If you enable this policy setting, Windows Error Reporting events are not recorded in the system event log.If you disable or do not configure this policy setting, Windows Error Reporting events and errors are logged to the system event log, as with other Windows-based programs.",
	"Supported":  "WindowsVista",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
	"KeyName":  "LoggingDisabled",
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
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "Machine",
	"CategoryName":  "CAT_WindowsErrorReporting",
	"DisplayName":  "Do not send additional data",
	"ExplainText":  "This policy setting controls whether additional data in support of error reports can be sent to Microsoft automatically.If you enable this policy setting, any additional data requests from Microsoft in response to a Windows Error Reporting report are automatically declined, without notification to the user.If you disable or do not configure this policy setting, then consent policy settings in Computer Configuration/Administrative Templates/Windows Components/Windows Error Reporting/Consent take precedence.",
	"Supported":  "WindowsVista",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
	"KeyName":  "DontSendAdditionalData",
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
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "Machine",
	"CategoryName":  "CAT_WindowsErrorReportingConsent",
	"DisplayName":  "Send all data",
	"ExplainText":  "This policy setting determines the default consent behavior of Windows Error Reporting.If you enable this policy setting, you can set the default consent handling for error reports. The following list describes the Consent level settings that are available in the pull-down menu in this policy setting:- Always ask before sending data: Windows prompts users for consent to send reports.- Send parameters: Only the minimum data that is required to check for an existing solution is sent automatically, and Windows prompts users for consent to send any additional data that is requested by Microsoft.- Send parameters and safe additional data: the minimum data that is required to check for an existing solution, along with data which Windows has determined (within a high probability) does not contain personally-identifiable information is sent automatically, and Windows prompts the user for consent to send any additional data that is requested by Microsoft.- Send all data: any error reporting data requested by Microsoft is sent automatically.If this policy setting is disabled or not configured, then the consent level defaults to the highest-privacy setting: Always ask before sending data.",
	"Supported":  "Windows_6_3ToVista",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
	"KeyName":  "Consent",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "DefaultConsent",
							"Items":  [
										{
											"DisplayName":  "Always ask before sending data",
											"Value":  "1"
										},
										{
											"DisplayName":  "Send parameters",
											"Value":  "2"
										},
										{
											"DisplayName":  "Send parameters and safe additional data",
											"Value":  "3"
										},
										{
											"DisplayName":  "Send all data",
											"Value":  "4"
										}
									]
						}
					]
},
{
	"File":  "ErrorReporting.admx",
	"NameSpace":  "Microsoft.Policies.WindowsErrorReporting",
	"Class":  "Machine",
	"CategoryName":  "CAT_WindowsErrorReportingConsent",
	"DisplayName":  "Ignore custom consent settings",
	"ExplainText":  "This policy setting determines the behavior of the Configure Default Consent setting in relation to custom consent settings.If you enable this policy setting, the default consent levels of Windows Error Reporting always override any other consent policy setting.If you disable or do not configure this policy setting, custom consent policy settings for error reporting determine the consent level for specified event types, and the default consent setting determines only the consent level of any other error reports.",
	"Supported":  "WindowsVista",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\Consent",
	"KeyName":  "DefaultOverrideBehavior",
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
	"File":  "DeviceSetup.admx",
	"NameSpace":  "Microsoft.Policies.DeviceSoftwareSetup",
	"Class":  "Machine",
	"CategoryName":  "DeviceInstall_Category",
	"DisplayName":  "Prevent Windows from sending an error report when a device driver requests additional software during installation",
	"ExplainText":  "Windows has a feature that allows a device driver to request additional software through the Windows Error Reporting infrastructure. This policy allows you to disable the feature.If you enable this policy setting, Windows will not send an error report to request additional software even if this is specified by the device driver.If you disable or do not configure this policy setting, Windows sends an error report when a device driver that requests additional software is installed.",
	"Supported":  "Windows_10_0_RS3ToWindows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings",
	"KeyName":  "DisableSendRequestAdditionalSoftwareToWER",
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
	"File":  "DeviceSetup.admx",
	"NameSpace":  "Microsoft.Policies.DeviceSoftwareSetup",
	"Class":  "Machine",
	"CategoryName":  "DeviceInstall_Category",
	"DisplayName":  "Do not send a Windows error report when a generic driver is installed on a device",
	"ExplainText":  "Windows has a feature that sends \"generic-driver-installed\" reports through the Windows Error Reporting infrastructure. This policy allows you to disable the feature.If you enable this policy setting, an error report is not sent when a generic driver is installed.If you disable or do not configure this policy setting, an error report is sent when a generic driver is installed.",
	"Supported":  "Windows_10_0_RS3ToVista",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings",
	"KeyName":  "DisableSendGenericDriverNotFoundToWER",
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
	"File":  "TPM.admx",
	"NameSpace":  "Microsoft.Policies.TrustedPlatformModule",
	"Class":  "Machine",
	"CategoryName":  "DSHACategory",
	"DisplayName":  "Enable Device Health Attestation Monitoring and Reporting",
	"ExplainText":  "This group policy enables Device Health Attestation reporting (DHA-report) on supported devices. It enables supported devices to send Device Health Attestation related information (device boot logs, PCR values, TPM certificate, etc.) to Device Health Attestation Service (DHA-Service) every time a device starts. Device Health Attestation Service validates the security state and health of the devices, and makes the findings accessible to enterprise administrators via a cloud based reporting portal. This policy is independent of DHA reports that are initiated by device manageability solutions (like MDM or SCCM), and will not interfere with their workflows.",
	"Supported":  "Windows_10_0_RS3",
	"KeyPath":  "Software\\Policies\\Microsoft\\DeviceHealthAttestationService",
	"KeyName":  "EnableDeviceHealthAttestationService",
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

# Disable Crash Dumps

Disables the crash dump, logging. Not all values may be read on your system.

```c
CrashDumpEnabled REG_DWORD 0x0 = None
CrashDumpEnabled REG_DWORD 0x1 = Complete memory dump
CrashDumpEnabled REG_DWORD 0x2 = Kernel memory dump
CrashDumpEnabled REG_DWORD 0x3 = Small memory dump (64 KB)
CrashDumpEnabled REG_DWORD 0x7 = Automatic memory dump
CrashDumpEnabled REG_DWORD 0x1 and FilterPages REG_DWORD 0x1 = Active memory dump
```

> https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options#registry-values-for-startup-and-recovery  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/automatic-memory-dump  
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/CrashControl.txt  
> [system/assets | crashdmp.c](https://github.com/5Noxi/win-config/blob/main/system/assets/crashdmp.c)

# Disable Sleep Study

Sleep Study tracks modern sleep states to analyze energy usage and pinpoint battery drain. It disables Sleep Study by making ETL logs read-only, disabling related diagnostics, and turning off the scheduled task.

```ps
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /e:false
svchost.exe	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SleepStudy/Diagnostic\Enabled	Type: REG_DWORD, Length: 4, Data: 0

wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /e:false
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Processor-Power/Diagnostic\Enabled	Type: REG_DWORD, Length: 4, Data: 0

wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /e:false
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserModePowerService/Diagnostic\Enabled	Type: REG_DWORD, Length: 4, Data: 0
```

> [system/assets | sleepstudy-FxLibraryGlobalsQueryRegistrySettings.c](https://github.com/5Noxi/win-config/blob/main/system/assets/sleepstudy-FxLibraryGlobalsQueryRegistrySettings.c)  
> [system/assets | sleepstudy-PoFxInitPowerManagement.c](https://github.com/5Noxi/win-config/blob/main/system/assets/sleepstudy-PoFxInitPowerManagement.c)

```
\Registry\Machine\SYSTEM\ControlSet001\Enum\ACPI\AMDI0010\3\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ACPI\AMDI0030\0\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ACPI\AMDIF030\0\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\Display\MSI3CB0\5&34f902e3&1&UID28931\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_149C&SUBSYS_87C01043&REV_00\4&231a312e&0&0341\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_43EE&SUBSYS_11421B21&REV_00\4&20e120c7&0&000A\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_790E&SUBSYS_87C01043&REV_51\3&11583659&0&A3\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_10DE&DEV_228B&SUBSYS_50521462&REV_A1\4&1d81e16&0&0119\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_8086&DEV_15F3&SUBSYS_87D21043&REV_02\6&102e3adf&0&0048020A\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ROOT\CompositeBus\0000\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ROOT\NdisVirtualBus\0000\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ROOT\SYSTEM\0002\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ROOT\UMBUS\0000\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ROOT\vdrvroot\0000\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\ROOT\VID\0000\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\ROOT_HUB30\5&2bce96aa&0&0\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\ROOT_HUB30\5&2c35141&0&0\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot00\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot01\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot02\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot03\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot04\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot05\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_046D&PID_C547&LAMPARRAY\7&1fc2034b&0&3_Slot06\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_05E3&PID_0610\6&3365fbaf&0&11\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_0B05&PID_1939&MI_00\7&40fe908&0&0000\Device Parameters\Wdf : SleepstudyState
\Registry\Machine\SYSTEM\ControlSet001\Enum\USB\VID_0CF2&PID_A102&MI_00\8&7b0cf2a&0&0000\Device Parameters\Wdf : SleepstudyState
```

Other:
```
\Registry\Machine\SYSTEM\ControlSet001\Services\NDIS\Parameters : EnableNicAutoPowerSaverInSleepStudy
\Registry\Machine\SYSTEM\ControlSet001\Services\NDIS\SharedState : EnableNicAutoPowerSaverInSleepStudy
\Registry\Machine\SYSTEM\ControlSet001\Control\Session Manager\Power : SleepStudyBufferSizeInMB
\Registry\Machine\SYSTEM\ControlSet001\Control\Session Manager\Power : SleepStudyTraceDirectory
```

> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

# Disable RSoP Logging

"This setting allows you to enable or disable Resultant Set of Policy (RSoP) logging on a client computer.RSoP logs information on Group Policy settings that have been applied to the client. This information includes details such as which Group Policy Objects (GPO) were applied where they came from and the client-side extension settings that were included.If you enable this setting RSoP logging is turned off.If you disable or do not configure this setting RSoP logging is turned on. By default RSoP logging is always on.Note: To view the RSoP information logged on a client computer you can use the RSoP snap-in in the Microsoft Management Console (MMC)."

> https://www.windows-security.org/370c915e44b6a75efac0d24669aa9434/turn-off-resultant-set-of-policy-logging

```
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon : RsopLogging
\Registry\Machine\SOFTWARE\Policies\Microsoft\Windows\SYSTEM : RsopLogging
```

> https://learn.microsoft.com/en-us/previous-versions/windows/desktop/Policy/developing-an-rsop-management-tool  
> [privacy/assets | rsop-IsDesktopHeapLoggingOn.c](https://github.com/5Noxi/win-config/blob/main/privacy/assets/rsop-IsDesktopHeapLoggingOn.c)

---

Another logging feature - `DesktopHeapLogging`. "It is meant to log information about desktop heap usage. This can be helpful when diagnosing issues where system resources for desktop objects might be strained." ([*](https://answers.microsoft.com/en-us/windows/forum/all/question-about-some-dwm-registry-settings/341cac5c-d85a-43e5-89d3-d9734f84da4e))

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DesktopHeapLogging /t REG_DWORD /d 0 /f
```

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Winows-NT.txt

# Disable Message Sync

"This policy setting allows backup and restore of cellular text messages to Microsoft's cloud services. Disable this feature to avoid information being stored on servers outside of your organization's control."

| Policy | Description | Values |
| ------ | ------ | ------ |
| AllowMessageSync | Controls whether SMS/MMS are synced to Microsoft's cloud so they can be backed up and restored; also decides if the user can toggle this in the UI. | 0 = sync not allowed, user cannot change - 1 = sync allowed, user can change (default) |

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-messaging

```json
{
	"File":  "messaging.admx",
	"NameSpace":  "Microsoft.Policies.Messaging",
	"Class":  "Machine",
	"CategoryName":  "Messaging_Category",
	"DisplayName":  "Allow Message Service Cloud Sync",
	"ExplainText":  "This policy setting allows backup and restore of cellular text messages to Microsoft\u0027s cloud services.",
	"Supported":  "Windows_10_0_RS3",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Messaging",
	"KeyName":  "AllowMessageSync",
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

# Disable Password Reveal

"This policy setting allows you to configure the display of the password reveal button in password entry user experiences.If you enable this policy setting, the password reveal button will not be displayed after a user types a password in the password entry text box.If you disable or do not configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box.By default, the password reveal button is displayed after a user types a password in the password entry text box."

```json
{
	"File":  "CredUI.admx",
	"NameSpace":  "Microsoft.Policies.CredentialsUI",
	"Class":  "Both",
	"CategoryName":  "CredUI",
	"DisplayName":  "Do not display the password reveal button",
	"ExplainText":  "This policy setting allows you to configure the display of the password reveal button in password entry user experiences.If you enable this policy setting, the password reveal button will not be displayed after a user types a password in the password entry text box.If you disable or do not configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box.By default, the password reveal button is displayed after a user types a password in the password entry text box. To display the password, click the password reveal button.The policy applies to all Windows components and applications that use the Windows system controls, including Internet Explorer.",
	"Supported":  "Windows8_Or_IE10",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CredUI",
	"KeyName":  "DisablePasswordReveal",
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

# Disable CSC

Disable Offline Files (CSC) via policy and services. Sets NetCache policy keys, disables `CSC`/`CscService`, disables the two `Offline Files` scheduled tasks (they're disabled by default), and renames `mobsync.exe` to block execution.

"Offline Files (Client-Side Caching, CSC) lets Windows cache files from network shares locally so users can keep working when the network/server is unavailable. Sync Center handles the background sync between the local CSC cache (`%SystemRoot%\CSC`) and the share. It's commonly paired with Folder Redirection so "known folders" (e.g., Documents) live on a server but remain available offline, with options like "Always Offline" for performance on slow links. You enable/disable it via Sync Center (Control Panel) or policy. When disabled, Sync Center has nothing to sync."

> https://learn.microsoft.com/en-us/windows-server/storage/folder-redirection/deploy-folder-redirection


```json
{
	"File":  "OfflineFiles.admx",
	"NameSpace":  "Microsoft.Policies.OfflineFiles",
	"Class":  "Machine",
	"CategoryName":  "Cat_OfflineFiles",
	"DisplayName":  "Allow or Disallow use of the Offline Files feature",
	"ExplainText":  "This policy setting determines whether the Offline Files feature is enabled. Offline Files saves a copy of network files on the user\u0027s computer for use when the computer is not connected to the network.If you enable this policy setting, Offline Files is enabled and users cannot disable it.If you disable this policy setting, Offline Files is disabled and users cannot enable it.If you do not configure this policy setting, Offline Files is enabled on Windows client computers, and disabled on computers running Windows Server, unless changed by the user.Note: Changes to this policy setting do not take effect until the affected computer is restarted.",
	"Supported":  "Win2k",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\NetCache",
	"KeyName":  "Enabled",
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
	"File":  "OfflineFiles.admx",
	"NameSpace":  "Microsoft.Policies.OfflineFiles",
	"Class":  "Machine",
	"CategoryName":  "Cat_OfflineFiles",
	"DisplayName":  "Configure Background Sync",
	"ExplainText":  "This policy setting controls when background synchronization occurs while operating in slow-link mode, and applies to any user who logs onto the specified machine while this policy is in effect. To control slow-link mode, use the \"Configure slow-link mode\" policy setting.If you enable this policy setting, you can control when Windows synchronizes in the background while operating in slow-link mode. Use the \u0027Sync Interval\u0027 and \u0027Sync Variance\u0027 values to override the default sync interval and variance settings. Use \u0027Blockout Start Time\u0027 and \u0027Blockout Duration\u0027 to set a period of time where background sync is disabled. Use the \u0027Maximum Allowed Time Without A Sync\u0027 value to ensure that all network folders on the machine are synchronized with the server on a regular basis.You can also configure Background Sync for network shares that are in user selected Work Offline mode. This mode is in effect when a user selects the Work Offline button for a specific share. When selected, all configured settings will apply to shares in user selected Work Offline mode as well.If you disable or do not configure this policy setting, Windows performs a background sync of offline folders in the slow-link mode at a default interval with the start of the sync varying between 0 and 60 additional minutes. In Windows 7 and Windows Server 2008 R2, the default sync interval is 360 minutes. In Windows 8 and Windows Server 2012, the default sync interval is 120 minutes.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\NetCache",
	"KeyName":  "BackgroundSyncEnabled",
	"Elements":  [
						{
							"ValueName":  "BackgroundSyncPeriodMin",
							"MaxValue":  "1440",
							"MinValue":  "1",
							"Type":  "Decimal"
						},
						{
							"ValueName":  "BackgroundSyncMaxStartMin",
							"MaxValue":  "3600",
							"MinValue":  "0",
							"Type":  "Decimal"
						},
						{
							"ValueName":  "BackgroundSyncIgnoreBlockOutAfterMin",
							"MaxValue":  "4294967295",
							"MinValue":  "0",
							"Type":  "Decimal"
						},
						{
							"ValueName":  "BackgroundSyncBlockOutStartTime",
							"MaxValue":  "2400",
							"MinValue":  "0",
							"Type":  "Decimal"
						},
						{
							"ValueName":  "BackgroundSyncBlockOutDurationMin",
							"MaxValue":  "1440",
							"MinValue":  "0",
							"Type":  "Decimal"
						},
						{
							"ValueName":  "BackgroundSyncEnabledForForcedOffline",
							"FalseValue":  "0",
							"TrueValue":  "1",
							"Type":  "Boolean"
						},
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
	"File":  "OfflineFiles.admx",
	"NameSpace":  "Microsoft.Policies.OfflineFiles",
	"Class":  "Machine",
	"CategoryName":  "Cat_OfflineFiles",
	"DisplayName":  "Turn off reminder balloons",
	"ExplainText":  "Hides or displays reminder balloons, and prevents users from changing the setting.Reminder balloons appear above the Offline Files icon in the notification area to notify users when they have lost the connection to a networked file and are working on a local copy of the file. Users can then decide how to proceed.If you enable this setting, the system hides the reminder balloons, and prevents users from displaying them.If you disable the setting, the system displays the reminder balloons and prevents users from hiding them.If this setting is not configured, reminder balloons are displayed by default when you enable offline files, but users can change the setting.To prevent users from changing the setting while a setting is in effect, the system disables the \"Enable reminders\" option on the Offline Files tabThis setting appears in the Computer Configuration and User Configuration folders. If both settings are configured, the setting in Computer Configuration takes precedence over the setting in User Configuration.Tip: To display or hide reminder balloons without establishing a setting, in Windows Explorer, on the Tools menu, click Folder Options, and then click the Offline Files tab. This setting corresponds to the \"Enable reminders\" check box.",
	"Supported":  "WindowsPreVista",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\NetCache",
	"KeyName":  "NoReminders",
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
	"File":  "OfflineFiles.admx",
	"NameSpace":  "Microsoft.Policies.OfflineFiles",
	"Class":  "Machine",
	"CategoryName":  "Cat_OfflineFiles",
	"DisplayName":  "Synchronize all offline files before logging off",
	"ExplainText":  "Determines whether offline files are fully synchronized when users log off.This setting also disables the \"Synchronize all offline files before logging off\" option on the Offline Files tab. This prevents users from trying to change the option while a setting controls it.If you enable this setting, offline files are fully synchronized. Full synchronization ensures that offline files are complete and current.If you disable this setting, the system only performs a quick synchronization. Quick synchronization ensures that files are complete, but does not ensure that they are current.If you do not configure this setting, the system performs a quick synchronization by default, but users can change this option.This setting appears in the Computer Configuration and User Configuration folders. If both settings are configured, the setting in Computer Configuration takes precedence over the setting in User Configuration.Tip: To change the synchronization method without changing a setting, in Windows Explorer, on the Tools menu, click Folder Options, click the Offline Files tab, and then select the \"Synchronize all offline files before logging off\" option.",
	"Supported":  "WindowsPreVista",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\NetCache",
	"KeyName":  "SyncAtLogoff",
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
	"File":  "OfflineFiles.admx",
	"NameSpace":  "Microsoft.Policies.OfflineFiles",
	"Class":  "User",
	"CategoryName":  "Cat_OfflineFiles",
	"DisplayName":  "Synchronize all offline files when logging on",
	"ExplainText":  "Determines whether offline files are fully synchronized when users log on.This setting also disables the \"Synchronize all offline files before logging on\" option on the Offline Files tab. This prevents users from trying to change the option while a setting controls it.If you enable this setting, offline files are fully synchronized at logon. Full synchronization ensures that offline files are complete and current. Enabling this setting automatically enables logon synchronization in Synchronization Manager.If this setting is disabled and Synchronization Manager is configured for logon synchronization, the system performs only a quick synchronization. Quick synchronization ensures that files are complete but does not ensure that they are current.If you do not configure this setting and Synchronization Manager is configured for logon synchronization, the system performs a quick synchronization by default, but users can change this option.This setting appears in the Computer Configuration and User Configuration folders. If both settings are configured, the setting in Computer Configuration takes precedence over the setting in User Configuration.Tip: To change the synchronization method without setting a setting, in Windows Explorer, on the Tools menu, click Folder Options, click the Offline Files tab, and then select the \"Synchronize all offline files before logging on\" option.",
	"Supported":  "WindowsPreVista",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\NetCache",
	"KeyName":  "SyncAtLogon",
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
	"File":  "OfflineFiles.admx",
	"NameSpace":  "Microsoft.Policies.OfflineFiles",
	"Class":  "Machine",
	"CategoryName":  "Cat_OfflineFiles",
	"DisplayName":  "Remove \"Work offline\" command",
	"ExplainText":  "This policy setting removes the \"Work offline\" command from Explorer, preventing users from manually changing whether Offline Files is in online mode or offline mode.If you enable this policy setting, the \"Work offline\" command is not displayed in File Explorer.If you disable or do not configure this policy setting, the \"Work offline\" command is displayed in File Explorer.",
	"Supported":  "Windows8",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\NetCache",
	"KeyName":  "WorkOfflineDisabled",
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

# Disable Cloud Content Search

"Cloud Content Search lets Windows Search include results from your signed-in cloud accounts personal Microsoft account (OneDrive, Outlook, Bing) and/or work/school (OneDrive for Business, SharePoint, Outlook) alongside local files. Turn it on per account to get those items and Bing-personalized suggestions, turn it off to keep search limited to local content (and non-personalized web)."

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/cloudsearch.png?raw=true)

# Disable Microsoft Accounts

"This setting prevents using the Settings app to add a Microsoft account for single sign-on (SSO) authentication for Microsoft services and some background services, or using a Microsoft account for single sign-on to other applications or services.

There are two options if this setting is enabled:

• Users can't add Microsoft accounts means that existing connected accounts can still sign in to the device (and appear on the Sign in screen). However, users cannot use the Settings app to add new connected accounts (or connect local accounts to Microsoft accounts).

• Users can't add or log on with Microsoft accounts means that users cannot add new connected accounts (or connect local accounts to Microsoft accounts) or use existing connected accounts through Settings.

This setting does not affect adding a Microsoft account for application authentication. For example, if this setting is enabled, a user can still provide a Microsoft account for authentication with an application such as Mail, but the user cannot use the Microsoft account for single sign-on authentication for other applications or services (in other words, the user will be prompted to authenticate for other applications or services).

By default, this setting is Not defined."

```c
// This policy is disabled
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser	Type: REG_DWORD, Length: 4, Data: 0

// Users can't add Microsoft accounts
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser	Type: REG_DWORD, Length: 4, Data: 1

// Users can't add or log on with Microsoft accounts
services.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser	Type: REG_DWORD, Length: 4, Data: 3
```

# Opt-Out KMS Activation Telemetry

Friendly name: `Turn off KMS Client Online AVS Validation`

"This policy setting lets you opt-out of sending KMS client activation data to Microsoft automatically. Enabling this setting prevents this computer from sending data to Microsoft regarding its activation state.

If you disable or don't configure this policy setting, KMS client activation data will be sent to Microsoft services when this device activates."

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-licensing#disallowkmsclientonlineavsvalidation

```json
{
	"File":  "AVSValidationGP.admx",
	"NameSpace":  "Microsoft.Policies.SoftwareProtectionPlatform",
	"Class":  "Machine",
	"CategoryName":  "SoftwareProtectionPlatform",
	"DisplayName":  "Turn off KMS Client Online AVS Validation",
	"ExplainText":  " This policy setting lets you opt-out of sending KMS client activation data to Microsoft automatically. Enabling this setting prevents this computer from sending data to Microsoft regarding its activation state. If you disable or do not configure this policy setting, KMS client activation data will be sent to Microsoft services when this device activates. Policy Options: - Not Configured (default -- data will be automatically sent to Microsoft) - Disabled (data will be automatically sent to Microsoft) - Enabled (data will not be sent to Microsoft)",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform",
	"KeyName":  "NoGenTicket",
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

# Disable Font Providers

"This policy setting determines whether Windows is allowed to download fonts and font catalog data from an online font provider.

If you enable this policy setting, Windows periodically queries an online font provider to determine whether a new font catalog is available. Windows may also download font data if needed to format or render text.

If you disable this policy setting, Windows does not connect to an online font provider and only enumerates locally-installed fonts."

```json
{
	"File":  "GroupPolicy.admx",
	"NameSpace":  "Microsoft.Policies.GroupPolicy",
	"Class":  "Machine",
	"CategoryName":  "NetworkFonts",
	"DisplayName":  "Enable Font Providers",
	"ExplainText":  " This policy setting determines whether Windows is allowed to download fonts and font catalog data from an online font provider. If you enable this policy setting, Windows periodically queries an online font provider to determine whether a new font catalog is available. Windows may also download font data if needed to format or render text. If you disable this policy setting, Windows does not connect to an online font provider and only enumerates locally-installed fonts. If you do not configure this policy setting, the default behavior depends on the Windows edition. Changes to this policy take effect on reboot.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
	"KeyName":  "EnableFontProviders",
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