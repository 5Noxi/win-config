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

# Disable System Restore
Removes all copies (volume backups), see your current shadows with:
```cmd
vssadmin list shadows /for=<ForVolumeSpec> /shadow=<ShadowID>
```
`<ForVolumeSpec>` -> Volume
`<ShadowID>` -> Shadow copy specified by ShadowID

Remove it with:
```cmd
vssadmin delete shadows /all
```
Random fact: Creating a `.bat` file for it & sending it into a discord channel will detect it as a virus.

```ps
Disable-ComputerRestore -Drive "C:\"
```
Does:
```ps
"wmiprvse.exe", "RegSetValue","HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\RPSessionInterval","Type: REG_DWORD, Length: 4, Data: 0"
```

> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/disable-computerrestore?view=powershell-5.1  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-list-shadows  
> https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service

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

# Disable Windows Defender

You may have to boot into `safeboot` to apply the changes:
```bat
bcdedit /set safeboot minimal
::bcdedit /deletevalue safeboot
```
Disable windows firewall with (breaks microsoft store, netsh advfirewall, winget, sandbox, docker, WSL ([*](https://privacylearn.com/windows/privacy-over-security/disable-defender/disable-defender-firewall/disable-defender-firewall-services-and-drivers))):
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpsdrv" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v Start /t REG_DWORD /d 4 /f
netsh advfirewall set allprofiles state off
```
You'll need [powerrun](https://www.sordum.org/downloads/?power-run) to apply the edits.

If the `netsh` command doesn't work:
```ps
$paths = @('HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall','HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy')
'StandardProfile','PublicProfile','PrivateProfile','DomainProfile' | % {foreach ($p in $paths) {sp -Path "$p\$_" -Name EnableFirewall -Type DWord -Value 0 -Force}}
```
Remove defender from a mounted image with the code below. Obviously, you need to change the `mount` path before running it. You can remove task leftovers after installation or in the `oobeSystem` phase with:
```bat
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' | Unregister-ScheduledTask -Confirm:$false"
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender" /f
rmdir /s /q "%windir%\System32\Tasks\Microsoft\Windows\Windows Defender"
```
`smartscreen.exe` may still continue to run. Renaming it will block execution:
```bat
MinSudo -NoL -P -TI cmd /c ren "%windir%\System32\smartscreen.exe" "smartscreen.exee"
```

```ps
@echo off
setlocal

set "mount=%userprofile%\Desktop\DISMT\mount"

MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthSystray.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthService.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthAgent.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthHost.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthSSO.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthSsoUdk.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthCore.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthProxyStub.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthUdk.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\drivers\WdNisDrv.sys"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Windows\System32\SecurityHealth"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Program Files\Windows Defender Advanced Threat Protection"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Program Files\Windows Defender"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Program Files (x86)\Windows Defender"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\ProgramData\Microsoft\Windows Defender"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\ProgramData\Microsoft\Windows Security Health"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\smartscreen.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\smartscreenps.dll"

endlocal
```

> [privacy/assets | Windows-Defender.txt](https://github.com/5Noxi/win-config/blob/main/privacy/assets/Windows-Defender.txt)