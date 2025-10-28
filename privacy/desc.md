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

# Disable Game DVR

GameDVR is a built-in gameplay capture (Xbox Game Bar) for clips/screenshots, with optional background recording.

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

```ps
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