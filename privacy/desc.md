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