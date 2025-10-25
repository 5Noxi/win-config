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

```json
{
  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MapsBroker": {
    "Start": {
      "Type": "REG_DWORD",
      "Data": 4
    }
  },
  "HKLM\\SYSTEM\\Maps": {
    "AutoUpdateEnabled": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "UpdateOnlyOnWifi": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  },
  "HKLM\\Software\\Policies\\Microsoft\\Windows\\Maps": {
    "AllowUntriggeredNetworkTrafficOnSettingsPage": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "AutoDownloadAndUpdateMapData": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

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

```json
{
  "apply": {
    "HKCU\\Control Panel\\International\\User Profile": {
      "HttpAcceptLanguageOptOut": {
        "Type": "REG_DWORD",
        "Data": 1
      }
    },
    "HKCU\\Software\\Microsoft\\Internet Explorer\\International": {
      "AcceptLanguage": {
        "Action": "DeleteValue"
      }
    }
  },
  "revert": {
    "HKCU\\Control Panel\\International\\User Profile": {
      "HttpAcceptLanguageOptOut": {
        "Type": "REG_DWORD",
        "Data": 0
      }
    }
  }
}
```