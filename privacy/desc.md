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

# Clear SRUM Data

Deletes the SRUM database file, which tracks app, service, and network usage.

Location:
```bat
%windir%\System32\sru
```
Read the SRUM data:
> https://github.com/MarkBaggett/srum-dump

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
```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableSensors /t REG_DWORD /d 1 /f
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
Disable app access to the microphone with:
```ps
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged" /v Value /t REG_SZ /d Deny /f
```
Adding the `HKLM` value is enough, changing it via the settings would:
```ps
svchost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Value	Type: REG_SZ, Length: 10, Data: Deny
```

---

Deny microphone access:
```ps
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged" /v Value /t REG_SZ /d Deny /f
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
```

# Disable Online Speech Recognition

`HasAccepted` disables online speech recognition, voice input to apps like Cortana, and data upload to Microsoft. `AllowSpeechModelUpdate` blocks automatic updates of speech recognition and synthesis models. I found`DisableSpeechInput` randomly while looking for `HasAccepted`, related to mixed reality environments.
> https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#bkmk-priv-speech  
> [privacy/assets | locationaccess-LocationApi.c](https://github.com/5Noxi/win-config/blob/main/privacy/assets/locationaccess-LocationApi.c)

``` ```
# Disable Microsoft Copilot

"Microsoft introduced Windows Copilot in May 2023. It became available in Windows 11 starting with build 23493 (Dev), 22631.2129 (Beta), and 25982 (Canary). A public preview began rolling out on September 26, 2023, with build 22621.2361 (Windows 11 22H2 KB5030310). It adds integrated AI features to assist with tasks like summarizing web content, writing, and generating images. Windows Copilot appears as a sidebar docked to the right and runs alongside open apps. In Windows 10, Copilot is available in build 19045.3754 for eligible devices in the Release Preview Channel running version 22H2. Users must enable "Get the latest updates as soon as they’re available" and check for updates. The rollout is phased via Controlled Feature Rollout (CFR). Windows 10 Pro devices managed by organizations, and all Enterprise or Education editions, are excluded from the initial rollout. Copilot requires signing in with a Microsoft account (MSA) or Azure Active Directory (Entra ID). Users with local accounts can use Copilot up to ten times before sign-in is enforced."

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